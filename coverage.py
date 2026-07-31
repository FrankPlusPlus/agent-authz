"""Machine-checkable evidence for declared Agent enforcement coverage.

The catalog says which business operations and entrypoints exist. A
``CoverageManifest`` records where an application actually installed a final
authorization guard, then reports gaps that a startup check or CI test can
fail on. It is deliberately an integration-governance tool, not a source-code
sandbox: application code that never registers a route, Tool, or task in the
catalog remains outside the model and must be found by normal code review.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Iterable, Mapping

from authz_sdk.catalog import Catalog


@dataclass(frozen=True)
class CoverageIssue:
    """One deterministic coverage gap suitable for CI output."""

    code: str
    operation: str = ""
    entrypoint: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "operation": self.operation,
            "entrypoint": self.entrypoint,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CoverageReport:
    """Immutable result of checking declared operations against guards."""

    required_operations: tuple[str, ...]
    enforced_entrypoints: tuple[dict[str, Any], ...]
    data_boundaries: tuple[dict[str, str], ...]
    exemptions: Mapping[str, str]
    issues: tuple[CoverageIssue, ...]

    @property
    def ready(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "required_operations": list(self.required_operations),
            "enforced_entrypoints": [dict(item) for item in self.enforced_entrypoints],
            "data_boundaries": [dict(item) for item in self.data_boundaries],
            "exemptions": dict(self.exemptions),
            "issues": [item.to_dict() for item in self.issues],
        }


class CoverageError(RuntimeError):
    """Raised by :meth:`CoverageManifest.assert_complete` on a coverage gap."""

    def __init__(self, report: CoverageReport) -> None:
        self.report = report
        summary = ", ".join(
            f"{item.code}:{item.operation or item.entrypoint}" for item in report.issues
        )
        super().__init__(f"authorization coverage is incomplete: {summary}")


@dataclass(frozen=True)
class _EnforcementEvidence:
    kind: str
    name: str
    operation: str
    final: bool
    evidence: str

    @property
    def entrypoint(self) -> str:
        return f"{self.kind}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "entrypoint": self.entrypoint,
            "operation": self.operation,
            "final": self.final,
            "evidence": self.evidence,
        }


class CoverageManifest:
    """Track whether catalog entrypoints have a final enforcement guard.

    By default, every operation currently registered in ``catalog`` is
    required to have a mapped entrypoint. A catalog often includes operations
    that are intentionally not deployed by one service; use :meth:`exempt`
    with a reason rather than silently shrinking the catalog.

    Framework adapters can call :meth:`record_enforcement` while they install
    a route/tool guard. Applications may call it directly for task queues,
    custom MCP servers, or other runtime surfaces. ``evidence`` is a stable
    test name, route identifier, or deployment reference for humans; it is not
    a cryptographic proof that arbitrary host code cannot bypass the guard.
    """

    def __init__(
        self,
        catalog: Catalog,
        *,
        required_operations: Iterable[str] | None = None,
    ) -> None:
        if not isinstance(catalog, Catalog):
            raise TypeError("catalog must be a Catalog")
        self.catalog = catalog
        inventory = catalog.inventory()
        known_operations = {
            str(item.get("name") or "").strip()
            for item in inventory["operations"]
            if str(item.get("name") or "").strip()
        }
        selected = known_operations if required_operations is None else {
            str(item or "").strip() for item in required_operations if str(item or "").strip()
        }
        self._required_operations = frozenset(selected)
        self._lock = RLock()
        self._exemptions: dict[str, str] = {}
        self._enforced: dict[tuple[str, str], _EnforcementEvidence] = {}
        self._data_boundaries: dict[str, tuple[str, str]] = {}
        self._final_operations: set[str] = set()
        self._recording_issues: list[CoverageIssue] = []

    def exempt(self, operation: str, *, reason: str) -> "CoverageManifest":
        """Document why this service intentionally does not cover an operation."""

        operation_name = str(operation or "").strip()
        detail = str(reason or "").strip()
        if not operation_name or not detail:
            raise ValueError("operation and non-empty exemption reason are required")
        with self._lock:
            self._exemptions[operation_name] = detail
        return self

    def require_final_execution(self, operation: str) -> "CoverageManifest":
        """Require at least one final guard for a high-risk operation."""

        operation_name = str(operation or "").strip()
        if not operation_name:
            raise ValueError("operation is required")
        with self._lock:
            self._final_operations.add(operation_name)
        return self

    def require_data_boundary(self, operation: str) -> "CoverageManifest":
        """Require a declared prompt/data boundary for a retrieval operation."""

        operation_name = str(operation or "").strip()
        if not operation_name:
            raise ValueError("operation is required")
        with self._lock:
            self._data_boundaries.setdefault(operation_name, ("", ""))
        return self

    def record_enforcement(
        self,
        kind: str,
        name: str,
        *,
        operation: str = "",
        final: bool = True,
        evidence: str = "",
    ) -> "CoverageManifest":
        """Record a guard installation and validate its catalog mapping.

        Calling this does not execute a policy decision; invoke
        :meth:`assert_complete` after the application has registered routes,
        tools, and tasks. Mismatched/unknown bindings become reportable gaps
        rather than being silently accepted as evidence.
        """

        normalized_kind = str(kind or "").strip()
        normalized_name = str(name or "").strip()
        requested_operation = str(operation or "").strip()
        if not normalized_kind or not normalized_name:
            raise ValueError("entrypoint kind and name are required")
        binding = self.catalog.entrypoint(normalized_kind, normalized_name)
        entrypoint = f"{normalized_kind}:{normalized_name}"
        with self._lock:
            if binding is None:
                self._recording_issues.append(
                    CoverageIssue(
                        "coverage.entrypoint_unregistered",
                        operation=requested_operation,
                        entrypoint=entrypoint,
                        detail="register this entrypoint in Catalog before claiming coverage",
                    )
                )
                return self
            if requested_operation and requested_operation != binding.operation:
                self._recording_issues.append(
                    CoverageIssue(
                        "coverage.entrypoint_operation_mismatch",
                        operation=requested_operation,
                        entrypoint=entrypoint,
                        detail=f"catalog maps this entrypoint to {binding.operation}",
                    )
                )
                return self
            self._enforced[(normalized_kind, normalized_name)] = _EnforcementEvidence(
                kind=normalized_kind,
                name=normalized_name,
                operation=binding.operation,
                final=bool(final),
                evidence=str(evidence or "").strip(),
            )
        return self

    def record_data_boundary(
        self,
        operation: str,
        *,
        entrypoint: str = "rag.retrieve",
        evidence: str = "",
    ) -> "CoverageManifest":
        """Record the prompt/data filter attached to a retrieval operation."""

        operation_name = str(operation or "").strip()
        if not operation_name:
            raise ValueError("operation is required")
        with self._lock:
            self._data_boundaries[operation_name] = (
                str(entrypoint or "rag.retrieve").strip() or "rag.retrieve",
                str(evidence or "").strip(),
            )
        return self

    def report(self) -> CoverageReport:
        """Return all gaps without mutating the application configuration."""

        inventory = self.catalog.inventory()
        known_operations = {
            str(item.get("name") or "").strip()
            for item in inventory["operations"]
            if str(item.get("name") or "").strip()
        }
        entrypoints = tuple(
            item
            for item in inventory["entrypoints"]
            if str(item.get("kind") or "").strip() and str(item.get("name") or "").strip()
        )
        with self._lock:
            required = tuple(sorted(self._required_operations))
            exemptions = dict(self._exemptions)
            enforced = dict(self._enforced)
            data_boundaries = dict(self._data_boundaries)
            final_operations = set(self._final_operations)
            issues = list(self._recording_issues)

        active_operations = set(required) - set(exemptions)
        for operation in sorted(active_operations - known_operations):
            issues.append(
                CoverageIssue(
                    "coverage.operation_unregistered",
                    operation=operation,
                    detail="required operation is not registered in Catalog",
                )
            )

        by_operation: dict[str, list[Mapping[str, Any]]] = {}
        for binding in entrypoints:
            operation = str(binding.get("operation") or "").strip()
            by_operation.setdefault(operation, []).append(binding)
        for operation in sorted(active_operations & known_operations):
            if not by_operation.get(operation):
                issues.append(
                    CoverageIssue(
                        "coverage.operation_entrypoint_missing",
                        operation=operation,
                        detail="register at least one API, Tool, task, MCP, or data entrypoint",
                    )
                )

        for binding in entrypoints:
            operation = str(binding.get("operation") or "").strip()
            if operation not in active_operations:
                continue
            kind = str(binding.get("kind") or "").strip()
            name = str(binding.get("name") or "").strip()
            if (kind, name) not in enforced:
                issues.append(
                    CoverageIssue(
                        "coverage.entrypoint_enforcement_missing",
                        operation=operation,
                        entrypoint=f"{kind}:{name}",
                        detail="no adapter or application guard recorded for this entrypoint",
                    )
                )

        for operation in sorted(final_operations - set(exemptions)):
            final_evidence = [
                item
                for item in enforced.values()
                if item.operation == operation and item.final
            ]
            if not final_evidence:
                issues.append(
                    CoverageIssue(
                        "coverage.final_enforcement_missing",
                        operation=operation,
                        detail="a high-risk operation needs at least one final execution guard",
                    )
                )

        data_report: list[dict[str, str]] = []
        for operation, (entrypoint, evidence) in sorted(data_boundaries.items()):
            if operation not in known_operations:
                issues.append(
                    CoverageIssue(
                        "coverage.data_operation_unregistered",
                        operation=operation,
                        detail="data boundary references an unknown catalog operation",
                    )
                )
                continue
            if not entrypoint and operation not in exemptions:
                issues.append(
                    CoverageIssue(
                        "coverage.data_boundary_missing",
                        operation=operation,
                        detail="declare CandidateFilter/query-pushdown coverage before prompt assembly",
                    )
                )
                continue
            if entrypoint:
                data_report.append(
                    {"operation": operation, "entrypoint": entrypoint, "evidence": evidence}
                )

        # A repeated adapter invocation can produce the same stable issue;
        # collapse it so CI output is useful rather than noisy.
        unique = {
            (item.code, item.operation, item.entrypoint, item.detail): item
            for item in issues
        }
        return CoverageReport(
            required_operations=required,
            enforced_entrypoints=tuple(
                item.to_dict()
                for _, item in sorted(enforced.items(), key=lambda pair: pair[0])
            ),
            data_boundaries=tuple(data_report),
            exemptions=exemptions,
            issues=tuple(sorted(unique.values(), key=lambda item: (item.code, item.operation, item.entrypoint))),
        )

    def assert_complete(self) -> CoverageReport:
        """Return a clean report or raise a compact CI-friendly error."""

        report = self.report()
        if not report.ready:
            raise CoverageError(report)
        return report


__all__ = ["CoverageError", "CoverageIssue", "CoverageManifest", "CoverageReport"]
