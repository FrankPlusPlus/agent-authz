"""Fail-closed data-plane enforcement for retrieval candidates.

This module is deliberately independent of a framework, database, or vector
store.  Use it at the enforcement point between a SQL/vector/MCP adapter that
has returned *raw candidates* and the code that assembles LLM prompt context::

    raw_candidates = vector_store.search(query)
    permitted = candidate_filter.filter(raw_candidates, subject=subject,
                                        operation="knowledge_chunk.read")
    prompt_context = permitted.candidates

``CandidateFilter`` is not an obligation interpreter.  Every candidate is
mapped to a stable :class:`~authz_sdk.models.Resource` and is individually
authorized before it can be returned.  Mapping and authorization errors are
excluded by design.  The returned audit summary contains only stable resource
references and outcome categories; it never stores candidate bodies or raw
authorization messages.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
from typing import Any, Generic, Iterable, Mapping, Protocol, TypeVar

from authz_sdk.models import Decision, Resource


Candidate = TypeVar("Candidate")


def _resource_reference(resource: Resource | None) -> str:
    """Return an opaque audit reference without retaining an application ID.

    Candidate mappers are application code and could accidentally use a
    document body as a resource ID.  Keeping only a deterministic digest in a
    filtering summary preserves correlation while ensuring that mistake does
    not put the body into diagnostics or an audit sink.
    """

    if resource is None or not resource.type or not resource.id:
        return ""
    return "sha256:" + hashlib.sha256(resource.uri.encode("utf-8")).hexdigest()


class CandidateResourceMapper(Protocol[Candidate]):
    """Map one adapter-specific candidate to its authorization resource.

    The mapper receives the candidate, requesting subject, and request context
    and must return a ``Resource`` with both a non-empty type and ID.  The
    resource should identify the protected data object (for example
    ``knowledge_chunk:chunk-42``), not the vector index or the query itself.
    Returning ``None`` means the candidate has no trustworthy authorization
    target and therefore must be excluded.
    """

    def __call__(
        self,
        candidate: Candidate,
        subject: object,
        context: Mapping[str, Any],
    ) -> Resource | None: ...


class CandidateChecker(Protocol):
    """Optional authorization checker for non-native policy backends."""

    def __call__(
        self,
        subject: object,
        *,
        operation: str,
        resource: Resource,
        context: Mapping[str, Any],
        entrypoint: str,
    ) -> Decision | bool: ...


class AuthorizationClient(Protocol):
    """The small portion of ``Authz`` needed at the data-plane boundary."""

    def can(
        self,
        subject: object,
        *,
        operation: str,
        resource: Resource,
        context: Mapping[str, Any] | None = None,
        entrypoint: str = "",
    ) -> Decision: ...


@dataclass(frozen=True)
class CandidateFilterRecord:
    """One body-free audit record for a considered retrieval candidate.

    ``resource_uri`` is retained as a compatibility attribute, but stores an
    opaque SHA-256 reference rather than the original resource URI.
    """

    index: int
    resource_uri: str
    outcome: str
    reason_code: str

    def to_dict(self) -> dict[str, object]:
        """Return only safe audit metadata, never the candidate itself."""

        return {
            "index": self.index,
            "resource_ref": self.resource_uri,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class CandidateFilterSummary:
    """Auditable aggregate of filtering without retaining candidate bodies."""

    operation: str
    entrypoint: str
    input_count: int
    allowed_count: int
    excluded_count: int
    records: tuple[CandidateFilterRecord, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize safe metadata suitable for an audit event or trace."""

        return {
            "operation": self.operation,
            "entrypoint": self.entrypoint,
            "input_count": self.input_count,
            "allowed_count": self.allowed_count,
            "excluded_count": self.excluded_count,
            "records": [record.to_dict() for record in self.records],
        }


@dataclass(frozen=True)
class CandidateFilterResult(Generic[Candidate]):
    """Authorized candidates plus their body-free filtering summary.

    ``candidates`` intentionally has ``repr=False`` so application logs do not
    accidentally print the authorized candidate bodies.  It is the only field
    that holds candidate values, because callers need those values to build
    their already-authorized prompt context.
    """

    candidates: tuple[Candidate, ...] = field(repr=False)
    summary: CandidateFilterSummary


class CandidateFilter(Generic[Candidate]):
    """Enforce per-candidate authorization before prompt-context assembly.

    Exactly one authority is required: pass the SDK's ``Authz`` facade (the
    normal path) or a narrow injected ``checker`` for an external PDP.  There
    is intentionally no fail-open switch: an invalid resource mapping, an
    authorization exception, or an invalid checker result excludes the item.
    """

    def __init__(
        self,
        authz: AuthorizationClient | None = None,
        *,
        resource_mapper: CandidateResourceMapper[Candidate],
        checker: CandidateChecker | None = None,
    ) -> None:
        if not callable(resource_mapper):
            raise TypeError("resource_mapper must be callable")
        if authz is None and checker is None:
            raise ValueError("authz or checker is required")
        if authz is not None and checker is not None:
            raise ValueError("pass authz or checker, not both")
        if authz is not None and not callable(getattr(authz, "can", None)):
            raise TypeError("authz must expose a callable can method")
        if checker is not None and not callable(checker):
            raise TypeError("checker must be callable")
        self._authz = authz
        self._checker = checker
        self._resource_mapper = resource_mapper

    def filter(
        self,
        candidates: Iterable[Candidate],
        *,
        subject: object,
        operation: str,
        entrypoint: str = "rag.retrieve",
        context: Mapping[str, Any] | None = None,
    ) -> CandidateFilterResult[Candidate]:
        """Return only candidates allowed by the configured authority.

        Call this after the storage adapter returns candidate rows/documents,
        but before those values are put in a prompt, tool argument, cache, or
        other caller-visible context.  Each mapper/checker receives a fresh
        deep context copy so a nested mutable value cannot let one
        candidate influence another candidate's authorization context.
        """

        operation_name = str(operation or "").strip()
        entrypoint_name = str(entrypoint or "rag.retrieve").strip() or "rag.retrieve"
        request_context = dict(context or {})
        kept: list[Candidate] = []
        records: list[CandidateFilterRecord] = []

        for index, candidate in enumerate(candidates):
            if not operation_name:
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri="",
                        outcome="excluded",
                        reason_code="request.operation_missing",
                    )
                )
                continue

            try:
                candidate_context = deepcopy(request_context)
            except Exception:
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri="",
                        outcome="excluded",
                        reason_code="candidate.context_copy_failed",
                    )
                )
                continue
            try:
                resource = self._resource_mapper(candidate, subject, candidate_context)
            except Exception:
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri="",
                        outcome="excluded",
                        reason_code="candidate.resource_mapping_failed",
                    )
                )
                continue

            if not isinstance(resource, Resource):
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri="",
                        outcome="excluded",
                        reason_code="candidate.resource_missing",
                    )
                )
                continue
            if not resource.type or not resource.id:
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri=_resource_reference(resource),
                        outcome="excluded",
                        reason_code="candidate.resource_invalid",
                    )
                )
                continue

            try:
                result = self._authorize(
                    subject,
                    operation=operation_name,
                    resource=resource,
                    context=candidate_context,
                    entrypoint=entrypoint_name,
                )
            except Exception:
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri=_resource_reference(resource),
                        outcome="excluded",
                        reason_code="candidate.authorization_failed",
                    )
                )
                continue

            allowed = self._is_allowed(result)
            if allowed is None:
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri=_resource_reference(resource),
                        outcome="excluded",
                        reason_code="candidate.checker_invalid_result",
                    )
                )
                continue
            if not allowed:
                records.append(
                    CandidateFilterRecord(
                        index=index,
                        resource_uri=_resource_reference(resource),
                        outcome="excluded",
                        reason_code="authorization.denied",
                    )
                )
                continue

            kept.append(candidate)
            records.append(
                CandidateFilterRecord(
                    index=index,
                    resource_uri=_resource_reference(resource),
                    outcome="allowed",
                    reason_code="authorization.allowed",
                )
            )

        summary = CandidateFilterSummary(
            operation=operation_name,
            entrypoint=entrypoint_name,
            input_count=len(records),
            allowed_count=len(kept),
            excluded_count=len(records) - len(kept),
            records=tuple(records),
        )
        return CandidateFilterResult(candidates=tuple(kept), summary=summary)

    def _authorize(
        self,
        subject: object,
        *,
        operation: str,
        resource: Resource,
        context: Mapping[str, Any],
        entrypoint: str,
    ) -> Decision | bool:
        if self._checker is not None:
            return self._checker(
                subject,
                operation=operation,
                resource=resource,
                context=context,
                entrypoint=entrypoint,
            )
        assert self._authz is not None
        return self._authz.can(
            subject,
            operation=operation,
            resource=resource,
            context=context,
            entrypoint=entrypoint,
        )

    @staticmethod
    def _is_allowed(result: Decision | bool) -> bool | None:
        if isinstance(result, Decision):
            return result.allowed
        if isinstance(result, bool):
            return result
        return None


# ``AuthorizedCandidateFilter`` reads naturally at call sites while preserving
# one implementation and one fail-closed contract.
AuthorizedCandidateFilter = CandidateFilter


__all__ = [
    "AuthorizationClient",
    "AuthorizedCandidateFilter",
    "CandidateChecker",
    "CandidateFilter",
    "CandidateFilterRecord",
    "CandidateFilterResult",
    "CandidateFilterSummary",
    "CandidateResourceMapper",
]
