"""Deterministic, fail-closed policy engine for the public SDK."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping
from uuid import uuid4

from authz_sdk.catalog import Catalog
from authz_sdk.adapters import ResourceIdentityMismatchError, ResourceRegistry
from authz_sdk.conditions import matches as condition_matches, validate as validate_condition
from authz_sdk.models import (
    AUTHZ_CONTRACT_VERSION,
    AuthorizationRequest,
    Decision,
    Resource,
    Subject,
)
from authz_sdk.evaluator import (
    Evaluator,
    _is_reviewed_production_evaluator,
    _reviewed_production_evaluator_mode,
)


SUPPORTED_TEMPLATES = (
    "authenticated",
    "subject_allowlist",
    "subject_denylist",
    "role_allowlist",
    "deny",
    "creator_only",
    "owner_or_admin",
    "relation",
    "relation_any",
    "deny_non_owner",
    "query.own_rows",
    "query.related_rows",
    "allow",
    "conditional",
)


# This marker is intentionally not part of the public request schema. It keeps
# an AgentRuntime-owned lifecycle fact separate from caller/context data while
# still allowing the ordinary ``can()`` pipeline to build one decision/audit
# envelope. It is an integration guard, not a Python-process sandbox.
_TRUSTED_AGENT_PHASE_KEY = object()
_PRODUCTION_EVALUATOR_METHODS = frozenset(
    {
        "authorize",
        "production_readiness",
        "_encode_payload",
        "_validate_response_binding",
        "_production_configuration_is_intact",
        "_production_decoder_is_reviewed",
    }
)


@dataclass(frozen=True)
class PolicyBinding:
    id: str
    operation: str
    template: str
    priority: int = 1000
    relations: tuple[str, ...] = ()
    roles: tuple[str, ...] = ()
    positions: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    actor_types: tuple[str, ...] = ()
    parameters: Mapping[str, Any] = field(default_factory=dict)
    description: str = ""
    effect: str = "allow"
    when: Mapping[str, Any] = field(default_factory=dict)
    obligations: Mapping[str, Any] = field(default_factory=dict)


class PolicySet:
    """In-memory policy repository for local SDK use and examples."""

    def __init__(
        self,
        bindings: Iterable[PolicyBinding] = (),
        *,
        combining: str = "deny_overrides",
        default_effect: str = "deny",
        version: str = "1",
        operation_defaults: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        if combining not in {"deny_overrides", "allow_overrides", "first_match"}:
            raise ValueError("combining must be deny_overrides, allow_overrides, or first_match")
        if default_effect not in {"deny", "allow"}:
            raise ValueError("default_effect must be deny or allow")
        self._bindings: list[PolicyBinding] = list(bindings)
        self.combining = combining
        self.default_effect = default_effect
        self.version = str(version or "1")
        self.operation_defaults = {}
        for operation, value in (operation_defaults or {}).items():
            name = str(operation).strip()
            if not name or not isinstance(value, Mapping):
                continue
            operation_combining = str(value.get("combining") or combining).strip()
            operation_effect = str(
                value.get("default_effect") or value.get("effect") or default_effect
            ).strip()
            # ``inherit`` is a dashboard/configuration convenience: it means
            # use the policy-set default, not a third runtime decision state.
            if operation_combining == "inherit":
                operation_combining = combining
            if operation_effect == "inherit":
                operation_effect = default_effect
            self.operation_defaults[name] = {
                "combining": operation_combining,
                "default_effect": operation_effect,
            }
        for operation, setting in self.operation_defaults.items():
            if setting["combining"] not in {"deny_overrides", "allow_overrides", "first_match"}:
                raise ValueError(f"unsupported combining mode for operation {operation}")
            if setting["default_effect"] not in {"deny", "allow"}:
                raise ValueError(f"unsupported default effect for operation {operation}")

    def bind(
        self,
        *,
        id: str,
        operation: str,
        template: str,
        priority: int = 1000,
        relations: Iterable[str] = (),
        roles: Iterable[str] = (),
        positions: Iterable[str] = (),
        emails: Iterable[str] = (),
        actor_types: Iterable[str] = (),
        parameters: Mapping[str, Any] | None = None,
        description: str = "",
        effect: str = "allow",
        when: Mapping[str, Any] | None = None,
        obligations: Mapping[str, Any] | None = None,
    ) -> PolicyBinding:
        normalized_effect = str(effect or "allow").strip().lower()
        if normalized_effect not in {"allow", "deny"}:
            raise ValueError("policy effect must be allow or deny")
        binding = PolicyBinding(
            id=str(id).strip(),
            operation=str(operation).strip(),
            template=str(template).strip(),
            priority=int(priority),
            relations=tuple(str(item).strip() for item in relations if str(item).strip()),
            roles=tuple(str(item).strip().lower() for item in roles if str(item).strip()),
            positions=tuple(str(item).strip() for item in positions if str(item).strip()),
            emails=tuple(str(item).strip().lower() for item in emails if str(item).strip()),
            actor_types=tuple(str(item).strip().lower() for item in actor_types if str(item).strip()),
            parameters=dict(parameters or {}),
            description=str(description or "").strip(),
            effect=normalized_effect,
            when=dict(when or {}),
            obligations=dict(obligations or {}),
        )
        if not binding.id or not binding.operation:
            raise ValueError("policy id and operation are required")
        if binding.template not in SUPPORTED_TEMPLATES:
            raise ValueError(f"unsupported policy template: {binding.template}")
        condition_errors = validate_condition(binding.when)
        if condition_errors:
            raise ValueError(f"invalid condition for {binding.id or 'policy'}: {'; '.join(condition_errors)}")
        # Policy identifiers are scoped to an operation. Reusing a readable
        # statement id such as ``resource.owner`` across a reviewed operation
        # group keeps explanations stable without merging two operations.
        if any(item.id == binding.id and item.operation == binding.operation for item in self._bindings):
            raise ValueError(
                f"policy id already exists for operation {binding.operation}: {binding.id}"
            )
        if binding.template in {"subject_allowlist", "subject_denylist", "role_allowlist"} and not any(
            (binding.roles, binding.positions, binding.emails, binding.actor_types)
        ):
            raise ValueError(f"{binding.template} requires at least one subject selector")
        self._bindings.append(binding)
        return binding

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any], *, catalog: Catalog | None = None) -> "PolicySet":
        """Load the stable dashboard/config contract without doing file I/O."""

        if not isinstance(config, Mapping):
            raise TypeError("policy config must be an object")
        raw_bindings = config.get(
            "bindings",
            config.get("policy_bindings", config.get("policies", ())),
        )
        if not isinstance(raw_bindings, (list, tuple)):
            raise TypeError("policy config bindings must be a list")
        result = cls(
            combining=str(config.get("combining") or "deny_overrides"),
            default_effect=str(config.get("default_effect") or "deny"),
            version=str(config.get("version") or "1"),
            operation_defaults=config.get("operation_defaults") or {},
        )
        for index, raw in enumerate(raw_bindings):
            if not isinstance(raw, Mapping):
                raise TypeError(f"bindings[{index}] must be an object")
            subjects = raw.get("subjects") if isinstance(raw.get("subjects"), Mapping) else {}
            operation = str(raw.get("operation") or "").strip()
            if catalog is not None and catalog.operation_definition(operation) is None:
                raise ValueError(f"bindings[{index}] references unknown operation: {operation}")
            result.bind(
                id=str(raw.get("id") or "").strip(),
                operation=operation,
                template=str(raw.get("template") or raw.get("template_id") or "").strip(),
                priority=int(raw.get("priority") or 1000),
                relations=raw.get("relations", ()) or (),
                roles=subjects.get("roles", raw.get("roles", ())) or (),
                positions=subjects.get("positions", raw.get("positions", ())) or (),
                emails=subjects.get("emails", raw.get("emails", ())) or (),
                actor_types=subjects.get("actor_types", raw.get("actor_types", ())) or (),
                parameters=raw.get("parameters") or {},
                description=str(raw.get("description") or "").strip(),
                effect=str(raw.get("effect") or "allow"),
                when=raw.get("when") or raw.get("condition") or {},
                obligations=raw.get("obligations") or {},
            )
        issues = result.validate(catalog=catalog)
        errors = [item for item in issues if item.get("level") == "error"]
        if errors:
            first = errors[0]
            raise ValueError(
                f"invalid policy config for {first.get('policy') or 'policy'}: "
                f"{first.get('message') or first.get('code')}"
            )
        return result

    def for_operation(self, operation: str) -> list[PolicyBinding]:
        return sorted(
            (item for item in self._bindings if item.operation == operation),
            key=lambda item: (item.priority, item.id),
        )

    def inventory(self) -> list[dict[str, Any]]:
        return [
            {
                "id": item.id,
                "operation": item.operation,
                "template": item.template,
                "priority": item.priority,
                "relations": list(item.relations),
                "roles": list(item.roles),
                "positions": list(item.positions),
                "emails": list(item.emails),
                "actor_types": list(item.actor_types),
                "parameters": dict(item.parameters),
                "description": item.description,
                "effect": item.effect,
                "when": dict(item.when),
                "obligations": dict(item.obligations),
                "combining": self.combining,
                "version": self.version,
                "operation_defaults": dict(self.operation_defaults.get(item.operation) or {}),
            }
            for item in self._bindings
        ]

    def to_mapping(self) -> dict[str, Any]:
        """Export the portable policy-set contract without doing file I/O.

        This is deliberately the inverse of :meth:`from_mapping`, so a policy
        bundle, Git-backed control plane, or remote PDP adapter can exchange a
        deterministic configuration rather than Python object state.
        """

        bindings = sorted(
            self._bindings,
            key=lambda item: (item.operation, item.priority, item.id),
        )
        return {
            "version": self.version,
            "combining": self.combining,
            "default_effect": self.default_effect,
            "operation_defaults": {
                name: dict(value)
                for name, value in sorted(self.operation_defaults.items())
            },
            "bindings": [
                {
                    "id": item.id,
                    "operation": item.operation,
                    "template": item.template,
                    "priority": item.priority,
                    "relations": list(item.relations),
                    "subjects": {
                        "roles": list(item.roles),
                        "positions": list(item.positions),
                        "emails": list(item.emails),
                        "actor_types": list(item.actor_types),
                    },
                    "parameters": dict(item.parameters),
                    "description": item.description,
                    "effect": item.effect,
                    "when": dict(item.when),
                    "obligations": dict(item.obligations),
                }
                for item in bindings
            ],
        }

    def fingerprint(self) -> str:
        """Return a stable digest suitable for a decision/audit boundary."""

        try:
            serialized = json.dumps(
                self.to_mapping(),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("policy set must contain JSON-serializable values to be fingerprinted") from exc
        return hashlib.sha256(serialized).hexdigest()

    def validate(self, *, catalog: Catalog | None = None) -> list[dict[str, str]]:
        """Validate a policy set before activation or dashboard publication."""

        issues: list[dict[str, str]] = []
        for binding in self._bindings:
            if catalog is not None and catalog.operation_definition(binding.operation) is None:
                issues.append({"level": "error", "code": "unknown_operation", "policy": binding.id})
            for message in validate_condition(binding.when):
                issues.append({"level": "error", "code": "invalid_condition", "policy": binding.id, "message": message})
            if binding.template in {"relation", "relation_any", "resource.relations"} and not binding.relations and not binding.parameters.get("relations"):
                issues.append({"level": "error", "code": "relation_missing", "policy": binding.id})
        return issues

    def combining_for(self, operation: str) -> str:
        return str((self.operation_defaults.get(str(operation).strip()) or {}).get("combining") or self.combining)

    def default_effect_for(self, operation: str) -> str:
        return str((self.operation_defaults.get(str(operation).strip()) or {}).get("default_effect") or self.default_effect)


class AuthorizationError(PermissionError):
    """Raised by ``Authz.require`` with the complete decision attached."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(decision.reason or f"permission denied: {decision.operation}")


def _matches_subject(binding: PolicyBinding, subject: Subject) -> bool:
    selectors = (
        (binding.roles, set(subject.roles)),
        (binding.positions, set(subject.positions)),
        (binding.emails, {subject.email}),
        (binding.actor_types, {subject.actor_type}),
    )
    # Different selector fields are AND; values in one field are OR.
    return all(not expected or bool(set(expected) & actual) for expected, actual in selectors)


def _relation(resource: Resource | None, names: Iterable[str]) -> bool:
    return bool(resource and any(resource.related(name) for name in names))


class Authz:
    """High-level authorization facade.

    The common path is ``can(subject, resource=..., action=...)``. The
    operation catalog and policy set remain inspectable for dashboards and
    tests, but callers do not need to construct them for every request.
    """

    @classmethod
    def native(
        cls,
        catalog: Catalog,
        policies: PolicySet | None = None,
        resources: ResourceRegistry | None = None,
        *,
        tenant_boundary: bool = True,
        require_tenant_context: bool = False,
        require_trusted_resource: bool = False,
        audit_sink: Any | None = None,
        audit_required: bool = False,
        audit_redactor: Any | None = None,
    ) -> "Authz":
        """Create the simple in-process configuration most applications need."""

        return cls(
            catalog,
            policies,
            resources,
            tenant_boundary=tenant_boundary,
            require_tenant_context=require_tenant_context,
            require_trusted_resource=require_trusted_resource,
            audit_sink=audit_sink,
            audit_required=audit_required,
            audit_redactor=audit_redactor,
        )

    @classmethod
    def connect(
        cls,
        evaluator: Evaluator,
        *,
        catalog: Catalog | None = None,
        policies: PolicySet | None = None,
        resources: ResourceRegistry | None = None,
        catalog_mode: str = "advisory",
        tenant_boundary: bool = True,
        require_tenant_context: bool = False,
        require_trusted_resource: bool = False,
        audit_sink: Any | None = None,
        audit_required: bool = False,
        audit_redactor: Any | None = None,
    ) -> "Authz":
        """Connect an existing Casbin/PDP backend without changing callers."""

        return cls(
            catalog,
            policies,
            resources,
            evaluator=evaluator,
            catalog_mode=catalog_mode,
            tenant_boundary=tenant_boundary,
            require_tenant_context=require_tenant_context,
            require_trusted_resource=require_trusted_resource,
            audit_sink=audit_sink,
            audit_required=audit_required,
            audit_redactor=audit_redactor,
        )

    @classmethod
    def production(
        cls,
        catalog: Catalog,
        policies: PolicySet | None = None,
        resources: ResourceRegistry | None = None,
        *,
        evaluator: Evaluator | None = None,
        audit_sink: Any | None = None,
        audit_required: bool = False,
        audit_redactor: Any | None = None,
    ) -> "Authz":
        """Create the secure-by-default profile for a service boundary.

        The profile is intentionally a small composition of already visible
        switches, rather than a second policy language: registered operations,
        tenant context, and registry-loaded resources are required before the
        policy evaluator receives a request. It does not replace an identity
        provider, durable audit system, or distributed relation service.
        """

        return cls(
            catalog,
            policies,
            resources,
            evaluator=evaluator,
            catalog_mode="strict",
            tenant_boundary=True,
            require_tenant_context=True,
            require_trusted_resource=True,
            audit_sink=audit_sink,
            audit_required=audit_required,
            audit_redactor=audit_redactor,
            profile="production",
        )

    def __init__(
        self,
        catalog: Catalog | None,
        policies: PolicySet | None = None,
        resources: ResourceRegistry | None = None,
        evaluator: Evaluator | None = None,
        catalog_mode: str = "strict",
        tenant_boundary: bool = True,
        require_tenant_context: bool = False,
        require_trusted_resource: bool = False,
        audit_sink: Any | None = None,
        audit_required: bool = False,
        audit_redactor: Any | None = None,
        profile: str = "custom",
    ) -> None:
        normalized_catalog_mode = str(catalog_mode or "strict").strip().lower()
        if normalized_catalog_mode not in {"strict", "advisory", "off"}:
            raise ValueError("catalog_mode must be strict, advisory, or off")
        if catalog is None and normalized_catalog_mode == "strict":
            raise ValueError("a catalog is required when catalog_mode is strict")
        if audit_required and audit_sink is None:
            raise ValueError("audit_required requires an audit_sink")
        if audit_redactor is not None and not callable(getattr(audit_redactor, "redact", None)):
            raise TypeError("audit_redactor must expose a callable redact(field, value)")
        self.catalog = catalog
        self.policies = policies or PolicySet()
        self.resources = resources or ResourceRegistry()
        self.evaluator = evaluator
        self.catalog_mode = normalized_catalog_mode
        self.tenant_boundary = bool(tenant_boundary)
        self.require_tenant_context = bool(require_tenant_context)
        self.require_trusted_resource = bool(require_trusted_resource)
        self.audit_sink = audit_sink
        self.audit_required = bool(audit_required)
        self.audit_redactor = audit_redactor
        self.profile = str(profile or "custom").strip().lower() or "custom"
        # This is deliberately separate from the display/configuration string.
        # A caller can still inspect or even overwrite the public ``profile``
        # attribute for legacy code, but cannot downgrade an instance created
        # by ``Authz.production()`` out of its runtime enforcement profile.
        self._production_profile = self.profile == "production"
        self._production_boundary_configuration = (
            self.catalog,
            self.policies,
            self.resources,
            self.evaluator,
            self.audit_sink,
            self.audit_required,
            self.audit_redactor,
        )
        self._last_audit_error = ""

    @property
    def is_production(self) -> bool:
        """Whether this facade was created with the production boundary."""

        return self._production_profile

    def _reported_profile(self) -> str:
        """Return the immutable effective profile for health/readiness output."""

        return "production" if self.is_production else self.profile

    def _production_boundary_configuration_is_intact(self) -> bool:
        """Return whether production-owned boundary collaborators are intact.

        Replacing a registry or evaluator after a facade has been accepted is
        a configuration change, not an ordinary policy update. Policy/data
        updates inside the configured collaborators retain their normal
        ownership semantics; replacing the boundary object fails closed.
        """

        configured = self._production_boundary_configuration
        return (
            self.catalog is configured[0]
            and self.policies is configured[1]
            and self.resources is configured[2]
            and self.evaluator is configured[3]
            and self.audit_sink is configured[4]
            and self.audit_required == configured[5]
            and self.audit_redactor is configured[6]
        )

    def authorize(self, request: AuthorizationRequest) -> Decision:
        """Evaluate a normalized request through this Authz instance.

        This method makes the built-in engine itself usable anywhere an
        ``Evaluator`` is expected. When an external evaluator is configured,
        :meth:`can` normalizes the request and delegates after catalog and
        trusted-resource validation.
        """

        return self.can(
            request.subject,
            operation=request.operation,
            resource=request.resource,
            context=request.context,
            arguments=request.arguments,
            entrypoint=request.entrypoint,
            request_id=request.request_id,
            trace_id=request.trace_id,
            contract_version=request.contract_version,
            catalog_fingerprint=request.catalog_fingerprint,
        )

    def health(self) -> Mapping[str, object]:
        if self.evaluator is not None:
            return {
                **dict(self.evaluator.health()),
                "catalog_mode": self.catalog_mode,
                "tenant_boundary": self.tenant_boundary,
                "require_tenant_context": self.require_tenant_context,
                "require_trusted_resource": self.require_trusted_resource,
                "profile": self._reported_profile(),
                "production_profile": self.is_production,
                "audit_required": self.audit_required,
                "audit_configured": self.audit_sink is not None,
                "audit_durability": self._audit_durability(),
                "audit_identifier_mode": self._audit_identifier_mode(),
                "trust_boundary": "trusted_host_process",
                "last_audit_error": self._last_audit_error,
            }
        return {
            "status": "ok",
            "backend": "native",
            "policy_version": self.policies.version,
            "catalog_mode": self.catalog_mode,
            "tenant_boundary": self.tenant_boundary,
            "require_tenant_context": self.require_tenant_context,
            "require_trusted_resource": self.require_trusted_resource,
            "profile": self._reported_profile(),
            "production_profile": self.is_production,
            "audit_required": self.audit_required,
            "audit_configured": self.audit_sink is not None,
            "audit_durability": self._audit_durability(),
            "audit_identifier_mode": self._audit_identifier_mode(),
            "trust_boundary": "trusted_host_process",
            "last_audit_error": self._last_audit_error,
        }

    def with_evaluator(
        self,
        evaluator: Evaluator | None,
        *,
        catalog_mode: str | None = None,
        tenant_boundary: bool | None = None,
        require_tenant_context: bool | None = None,
        require_trusted_resource: bool | None = None,
    ) -> "Authz":
        """Return an equivalent facade using another policy evaluator.

        Normal instances default to advisory catalog mode: the catalog remains
        useful metadata for UI and entrypoint discovery, but it cannot reject
        an operation that the selected external engine understands. A
        production facade cannot relax strict catalog, tenant, or trusted
        resource requirements through this convenience method.
        """

        selected_catalog_mode = (
            catalog_mode
            if catalog_mode is not None
            else ("strict" if self.is_production else "advisory")
        )
        selected_tenant_boundary = (
            self.tenant_boundary if tenant_boundary is None else bool(tenant_boundary)
        )
        selected_tenant_context = (
            self.require_tenant_context
            if require_tenant_context is None
            else bool(require_tenant_context)
        )
        selected_trusted_resource = (
            self.require_trusted_resource
            if require_trusted_resource is None
            else bool(require_trusted_resource)
        )
        if self.is_production and (
            str(selected_catalog_mode or "").strip().lower() != "strict"
            or not selected_tenant_boundary
            or not selected_tenant_context
            or not selected_trusted_resource
        ):
            raise ValueError(
                "production profile cannot relax strict catalog, tenant, or trusted-resource requirements"
            )
        return Authz(
            self.catalog,
            self.policies,
            self.resources,
            evaluator=evaluator,
            catalog_mode=selected_catalog_mode,
            tenant_boundary=selected_tenant_boundary,
            require_tenant_context=selected_tenant_context,
            require_trusted_resource=selected_trusted_resource,
            audit_sink=self.audit_sink,
            audit_required=self.audit_required,
            audit_redactor=self.audit_redactor,
            profile=self._reported_profile(),
        )

    def readiness(self) -> dict[str, Any]:
        """Report whether the configured enforcement point meets its profile.

        The SDK cannot prove that a host routed every API, Tool, task, and
        vector query through this object. It can make the local preconditions
        explicit and machine-checkable before an application accepts traffic.
        """

        issues: list[dict[str, str]] = []
        if self.catalog is None:
            issues.append({"level": "error", "code": "catalog.missing"})
        elif self.catalog_mode != "strict":
            issues.append(
                {
                    "level": "error" if self.is_production else "warning",
                    "code": "catalog.not_strict",
                }
            )
        else:
            try:
                self.catalog.fingerprint()
            except Exception:
                issues.append({"level": "error", "code": "catalog.fingerprint_invalid"})
        if self.evaluator is None:
            try:
                self.policies.fingerprint()
            except Exception:
                issues.append({"level": "error", "code": "policy.fingerprint_invalid"})
        elif self.is_production:
            issues.extend(
                {"level": "error", "code": code}
                for code in self._production_backend_issues()
            )
        if self.is_production:
            if self.profile != "production":
                issues.append({"level": "error", "code": "production.profile_mutated"})
            if not Authz._production_boundary_configuration_is_intact(self):
                issues.append(
                    {"level": "error", "code": "production.configuration_mutated"}
                )
            if not self.tenant_boundary:
                issues.append({"level": "error", "code": "tenant.boundary_disabled"})
            if not self.require_tenant_context:
                issues.append({"level": "error", "code": "tenant.context_not_required"})
            if not self.require_trusted_resource:
                issues.append({"level": "error", "code": "resource.trust_not_required"})
            if self.audit_sink is None:
                issues.append({"level": "warning", "code": "audit.not_configured"})
            elif self._audit_durability() != "durable":
                issues.append(
                    {
                        "level": "warning",
                        "code": f"audit.durability_{self._audit_durability()}",
                    }
                )
            if self.audit_sink is not None and self.audit_redactor is None:
                issues.append(
                    {"level": "warning", "code": "audit.identifiers_not_pseudonymized"}
                )
        if self.audit_required and self.audit_sink is None:
            issues.append({"level": "error", "code": "audit.required_but_unconfigured"})
        if self._last_audit_error:
            issues.append({"level": "warning", "code": "audit.last_delivery_failed"})
        boundary_ready = not any(item["level"] == "error" for item in issues)
        return {
            # ``ready`` is retained as the compact compatibility field. It
            # describes only the local SDK boundary, never enterprise-wide
            # operational readiness (deployment, KMS, shared stores, policy
            # rollout, and host coverage are outside this process).
            "ready": boundary_ready,
            "boundary_ready": boundary_ready,
            "operational_ready": None,
            "scope": "local_enforcement_boundary",
            "trust_boundary": "trusted_host_process",
            "profile": self._reported_profile(),
            "production_profile": self.is_production,
            "issues": issues,
            "catalog_fingerprint": self._catalog_fingerprint(),
            "policy_digest": self._policy_digest() if self.evaluator is None else "",
        }

    def _catalog_fingerprint(self) -> str:
        if self.catalog is None:
            return ""
        try:
            return self.catalog.fingerprint()
        except Exception:
            return ""

    def _policy_digest(self) -> str:
        try:
            return self.policies.fingerprint()
        except Exception:
            return ""

    def _audit_durability(self) -> str:
        """Describe the sink's declared durability without overstating it."""

        if self.audit_sink is None:
            return "none"
        value = str(getattr(self.audit_sink, "durability", "unknown") or "unknown").strip()
        return value or "unknown"

    def _audit_identifier_mode(self) -> str:
        """Describe whether fixed audit identifiers are pseudonymized."""

        return "pseudonymized" if self.audit_redactor is not None else "plaintext"

    def _production_backend_issues(self) -> tuple[str, ...]:
        """Check the extra transport/identity guarantees a remote PDP needs.

        An embedded evaluator such as ``CasbinEvaluator`` is in the service
        process and has no network response to bind. A remote evaluator must
        explicitly identify itself and provide a strict preflight report; an
        unknown evaluator is not assumed safe merely because it has an
        ``authorize`` method.
        """

        if self.evaluator is None:
            return ()
        mode = _reviewed_production_evaluator_mode(self.evaluator)
        if mode is None:
            return ("backend.production_evaluator_unreviewed",)
        if self._production_evaluator_methods_are_shadowed():
            return ("backend.production_method_shadowed",)
        readiness = getattr(type(self.evaluator), "production_readiness", None)
        if not callable(readiness):
            return (
                "backend.remote_readiness_missing"
                if mode == "remote"
                else "backend.in_process_readiness_missing",
            )
        try:
            report = readiness(self.evaluator)
        except Exception:
            return (
                "backend.remote_readiness_failed"
                if mode == "remote"
                else "backend.in_process_readiness_failed",
            )
        if not isinstance(report, Mapping):
            return (
                "backend.remote_readiness_invalid"
                if mode == "remote"
                else "backend.in_process_readiness_invalid",
            )
        if bool(report.get("ready")):
            return ()
        raw_issues = report.get("issues") or ()
        if isinstance(raw_issues, str):
            raw_issues = (raw_issues,)
        issues = tuple(
            str(item).strip()
            for item in raw_issues
            if str(item).strip()
        )
        return issues or (
            "backend.remote_not_ready"
            if mode == "remote"
            else "backend.in_process_not_ready",
        )

    def _production_evaluator_methods_are_shadowed(self) -> bool:
        """Reject public instance overrides of reviewed evaluator methods.

        Production resolves reviewed methods from the exact class below.  This
        companion check stops a replacement of a method that a reviewed method
        calls dynamically (for example a protocol-specific payload builder).
        Class-level monkeypatching or private-memory mutation is code already
        inside the documented trusted host boundary.
        """

        if self.evaluator is None:
            return False
        try:
            instance_values = vars(self.evaluator)
        except TypeError:
            return True
        return any(name in instance_values for name in _PRODUCTION_EVALUATOR_METHODS)

    def _production_boundary_issues(self) -> tuple[str, ...]:
        """Return every readiness error that must fail closed at execution.

        ``readiness()`` is not merely an operator dashboard for the production
        profile.  It defines this process's minimum authority boundary, so an
        instance that was constructed or mutated into an unsafe configuration
        must be unable to evaluate a policy successfully.
        """

        try:
            report = self.readiness()
        except Exception:
            return ("production.readiness_failed",)
        if not isinstance(report, Mapping):
            return ("production.readiness_invalid",)
        raw_issues = report.get("issues")
        if not isinstance(raw_issues, (list, tuple)):
            return ("production.readiness_invalid",)
        issues: list[str] = []
        for item in raw_issues:
            if not isinstance(item, Mapping) or item.get("level") != "error":
                continue
            code = str(item.get("code") or "").strip()
            if code:
                issues.append(code)
        return tuple(issues)

    def _remote_response_binding_issue(
        self,
        decision: Decision,
        *,
        request_id: str,
        trace_id: str,
        contract_version: str,
        catalog_fingerprint: str,
    ) -> str:
        """Return a mismatch detail for a production remote PDP response."""

        if not self.is_production or self.evaluator is None:
            return ""
        if _reviewed_production_evaluator_mode(self.evaluator) != "remote":
            return ""
        expected = {
            "request_id": request_id,
            "contract_version": contract_version,
            "catalog_fingerprint": catalog_fingerprint,
            "policy_version": str(
                getattr(self.evaluator, "expected_policy_version", "") or ""
            ).strip(),
            "policy_digest": str(
                getattr(self.evaluator, "expected_policy_digest", "") or ""
            ).strip(),
        }
        if trace_id:
            expected["trace_id"] = trace_id
        observed = {
            "request_id": decision.request_id,
            "trace_id": decision.trace_id,
            "contract_version": decision.contract_version,
            "catalog_fingerprint": decision.catalog_fingerprint,
            "policy_version": decision.policy_version,
            "policy_digest": decision.policy_digest,
        }
        invalid = [
            field_name
            for field_name, expected_value in expected.items()
            if not expected_value or observed.get(field_name, "") != expected_value
        ]
        return ", ".join(sorted(invalid))

    def _finalize_decision(
        self,
        decision: Decision,
        subject: Subject,
        *,
        request_id: str,
        trace_id: str,
        contract_version: str,
        catalog_fingerprint: str,
    ) -> Decision:
        """Attach protocol metadata and emit the optional decision event."""

        finalized = replace(
            decision,
            policy_version=decision.policy_version or self.policies.version,
            request_id=request_id,
            trace_id=trace_id,
            contract_version=contract_version,
            catalog_fingerprint=catalog_fingerprint,
            policy_digest=(
                decision.policy_digest
                or (self._policy_digest() if self.evaluator is None else "")
            ),
        )
        if self.audit_sink is None:
            return finalized
        try:
            from authz_sdk.audit import DecisionEvent

            self.audit_sink.emit(
                DecisionEvent.from_decision(
                    finalized,
                    subject,
                    redactor=self.audit_redactor,
                )
            )
            self._last_audit_error = ""
        except Exception as exc:
            self._last_audit_error = type(exc).__name__
            # A failed audit sink must never turn an otherwise allowed action
            # into an untracked success. A decision already denied for a
            # stronger boundary reason remains denied with its original reason
            # code so operators can still diagnose the real rejection.
            if self.audit_required and finalized.allowed:
                return replace(
                    finalized,
                    allowed=False,
                    reason="authorization audit delivery failed",
                    reason_code="audit.delivery_failed",
                    policy="",
                )
        return finalized

    def can(
        self,
        subject: Subject | object,
        *,
        action: str = "",
        resource: Resource | None = None,
        operation: str = "",
        context: Mapping[str, Any] | None = None,
        arguments: Mapping[str, Any] | None = None,
        entrypoint: str = "",
        resource_type: str = "",
        resource_id: str = "",
        request_id: str = "",
        trace_id: str = "",
        contract_version: str = AUTHZ_CONTRACT_VERSION,
        catalog_fingerprint: str = "",
    ) -> Decision:
        """Make one decision and attach a portable audit/wire envelope.

        Application code only needs ``subject``, ``operation`` and
        ``resource``. ``request_id``, ``trace_id`` and the catalog fingerprint
        are optional propagation fields for a remote PDP, audit sink, or future
        non-Python PEP; callers that do not supply a request ID receive one.
        Generic caller context cannot choose an Agent lifecycle phase.
        """

        actor = subject if isinstance(subject, Subject) else Subject.from_user(subject)
        normalized_contract_version = str(contract_version or AUTHZ_CONTRACT_VERSION).strip()
        normalized_request_id = str(request_id or "").strip() or uuid4().hex
        normalized_trace_id = str(trace_id or "").strip()
        operation_name = str(operation or "").strip()

        if normalized_contract_version != AUTHZ_CONTRACT_VERSION:
            return self._finalize_decision(
                Decision(
                    False,
                    operation_name,
                    reason="unsupported authorization contract version",
                    reason_code="contract.version_unsupported",
                    resource=resource,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                ),
                actor,
                request_id=normalized_request_id,
                trace_id=normalized_trace_id,
                contract_version=normalized_contract_version,
                catalog_fingerprint="",
            )

        try:
            actual_catalog_fingerprint = self.catalog.fingerprint() if self.catalog is not None else ""
        except Exception as exc:
            return self._finalize_decision(
                Decision(
                    False,
                    operation_name,
                    reason=f"catalog fingerprint failed: {type(exc).__name__}",
                    reason_code="catalog.fingerprint_invalid",
                    resource=resource,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                ),
                actor,
                request_id=normalized_request_id,
                trace_id=normalized_trace_id,
                contract_version=normalized_contract_version,
                catalog_fingerprint="",
            )

        supplied_catalog_fingerprint = str(catalog_fingerprint or "").strip()
        if (
            supplied_catalog_fingerprint
            and actual_catalog_fingerprint
            and supplied_catalog_fingerprint != actual_catalog_fingerprint
        ):
            return self._finalize_decision(
                Decision(
                    False,
                    operation_name,
                    reason="authorization catalog fingerprint does not match this enforcement point",
                    reason_code="catalog.fingerprint_mismatch",
                    resource=resource,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                ),
                actor,
                request_id=normalized_request_id,
                trace_id=normalized_trace_id,
                contract_version=normalized_contract_version,
                catalog_fingerprint=actual_catalog_fingerprint,
            )

        if self.is_production:
            boundary_issues = self._production_boundary_issues()
            if boundary_issues:
                if any(code.startswith("backend.") for code in boundary_issues):
                    reason = "authorization backend is not ready for the production profile"
                    reason_code = "backend.not_production_ready"
                elif boundary_issues == ("policy.fingerprint_invalid",):
                    reason = "policy digest failed"
                    reason_code = "policy.fingerprint_invalid"
                else:
                    reason = "authorization production boundary is not ready"
                    reason_code = "production.not_ready"
                return self._finalize_decision(
                    Decision(
                        False,
                        operation_name,
                        reason=reason,
                        reason_code=reason_code,
                        resource=resource,
                        entrypoint=entrypoint,
                        policy_version=self.policies.version,
                    ),
                    actor,
                    request_id=normalized_request_id,
                    trace_id=normalized_trace_id,
                    contract_version=normalized_contract_version,
                    catalog_fingerprint=actual_catalog_fingerprint or supplied_catalog_fingerprint,
                )

        decision = self._can(
            actor,
            action=action,
            resource=resource,
            operation=operation,
            context=context,
            arguments=arguments,
            entrypoint=entrypoint,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=normalized_request_id,
            trace_id=normalized_trace_id,
            contract_version=normalized_contract_version,
            catalog_fingerprint=actual_catalog_fingerprint or supplied_catalog_fingerprint,
        )
        return self._finalize_decision(
            decision,
            actor,
            request_id=normalized_request_id,
            trace_id=normalized_trace_id,
            contract_version=normalized_contract_version,
            catalog_fingerprint=actual_catalog_fingerprint or supplied_catalog_fingerprint,
        )

    def _can_agent(
        self,
        subject: Subject | object,
        *,
        phase: str,
        **kwargs: Any,
    ) -> Decision:
        """Evaluate a lifecycle request with a runtime-owned phase fact.

        This is intentionally an integration hook rather than a normal policy
        parameter. It prevents untrusted request context from selecting a
        policy branch such as ``authz_phase=discover`` while preserving phase
        conditions for an AgentRuntime the host deliberately constructs.
        """

        normalized_phase = str(phase or "").strip().lower()
        if normalized_phase not in {"discover", "mount", "execute"}:
            raise ValueError("agent phase must be discover, mount, or execute")
        raw_context = kwargs.pop("context", None)
        if raw_context is not None and not isinstance(raw_context, Mapping):
            raise TypeError("context must be a mapping")
        runtime_context = dict(raw_context or {})
        runtime_context[_TRUSTED_AGENT_PHASE_KEY] = normalized_phase
        return self.can(
            subject,
            context=runtime_context,
            **kwargs,
        )

    def _can(
        self,
        subject: Subject | object,
        *,
        action: str = "",
        resource: Resource | None = None,
        operation: str = "",
        context: Mapping[str, Any] | None = None,
        arguments: Mapping[str, Any] | None = None,
        entrypoint: str = "",
        resource_type: str = "",
        resource_id: str = "",
        request_id: str = "",
        trace_id: str = "",
        contract_version: str = AUTHZ_CONTRACT_VERSION,
        catalog_fingerprint: str = "",
    ) -> Decision:
        actor = subject if isinstance(subject, Subject) else Subject.from_user(subject)
        request_context = dict(context or {})
        # ``authz_phase`` is a reserved runtime fact. A request body, model
        # output, or direct caller-provided context may not select it. The
        # AgentRuntime calls ``_can_agent`` to inject an internal marker after
        # this sanitization step. The marker is removed before context reaches
        # policy evaluation or a remote PDP.
        trusted_agent_phase = request_context.pop(_TRUSTED_AGENT_PHASE_KEY, "")
        request_context.pop("authz_phase", None)
        if isinstance(trusted_agent_phase, str) and trusted_agent_phase:
            request_context["authz_phase"] = trusted_agent_phase
        target = resource
        operation_name = str(operation or "").strip()
        resolved_type = str(resource_type or (target.type if target else "")).strip()
        if target is not None and resource_type and target.type != str(resource_type).strip():
            return Decision(
                False,
                operation_name,
                reason="resource type does not match the request",
                reason_code="resource.type_mismatch",
                resource=target,
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )
        if target is not None and resource_id and target.id != str(resource_id).strip():
            return Decision(
                False,
                operation_name,
                reason="resource ID does not match the request",
                reason_code="resource.identity_mismatch",
                resource=target,
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )
        if not operation_name:
            if target is None:
                if not resolved_type:
                    return Decision(False, "", reason="resource or operation is required", reason_code="request.missing_target", entrypoint=entrypoint, policy_version=self.policies.version)
                try:
                    operation_name = self.catalog.operation_for(resolved_type, action) if self.catalog else ""
                    if not operation_name:
                        raise KeyError("catalog is required to derive an operation from a resource action")
                except KeyError as exc:
                    return Decision(False, "", reason=str(exc), reason_code="catalog.action_unknown", entrypoint=entrypoint, policy_version=self.policies.version)
            else:
                try:
                    operation_name = self.catalog.operation_for(target.type, action) if self.catalog else ""
                    if not operation_name:
                        raise KeyError("catalog is required to derive an operation from a resource action")
                except KeyError as exc:
                    return Decision(False, "", reason=str(exc), reason_code="catalog.action_unknown", resource=target, entrypoint=entrypoint, policy_version=self.policies.version)
        if target is None and resource_id and resolved_type:
            try:
                target = self.resources.resolve(
                    resolved_type,
                    resource_id,
                    actor,
                    context=request_context,
                )
            except ResourceIdentityMismatchError as exc:
                return Decision(
                    False,
                    operation_name,
                    reason=str(exc),
                    reason_code="resource.identity_mismatch",
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            except Exception as exc:
                return Decision(
                    False,
                    operation_name,
                    reason=f"resource resolution failed: {type(exc).__name__}",
                    reason_code="resource.resolution_failed",
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            if target is None:
                return Decision(
                    False,
                    operation_name,
                    reason="resource was not found",
                    reason_code="resource.not_found",
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )

        definition = self.catalog.operation_definition(operation_name) if self.catalog else None
        if definition is None and self.catalog_mode == "strict":
            return Decision(False, operation_name, reason="operation is not registered", reason_code="catalog.operation_unknown", resource=target, entrypoint=entrypoint, policy_version=self.policies.version)
        if (
            self.catalog_mode == "strict"
            and definition is not None
            and definition.resource_type
            and target is not None
            and target.type != definition.resource_type
        ):
            return Decision(False, operation_name, reason="resource type does not match operation", reason_code="resource.type_mismatch", resource=target, entrypoint=entrypoint, policy_version=self.policies.version)
        if self.require_trusted_resource and target is not None and not self.resources.owns(target):
            return Decision(
                False,
                operation_name,
                reason="resource must be loaded by a trusted ResourceRegistry",
                reason_code="resource.untrusted",
                resource=target,
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )
        subject_tenant = str(actor.tenant_id or "").strip()
        resource_tenant = str(
            (target.attributes.get("tenant_id") if target is not None else "") or ""
        ).strip()
        if self.tenant_boundary and subject_tenant and resource_tenant and subject_tenant != resource_tenant:
            return Decision(
                False,
                operation_name,
                reason="subject and resource belong to different tenants",
                reason_code="resource.tenant_mismatch",
                resource=target,
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )
        tenant_required = bool(definition and getattr(definition, "tenant_required", False))
        if (
            self.tenant_boundary
            and (self.require_tenant_context or tenant_required)
            and not subject_tenant
        ):
            return Decision(
                False,
                operation_name,
                reason="subject tenant is required for a tenant-scoped operation",
                reason_code="subject.tenant_context_missing",
                resource=target,
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )
        if target is not None and self.tenant_boundary and (self.require_tenant_context or tenant_required) and not resource_tenant:
            return Decision(
                False,
                operation_name,
                reason="tenant-scoped operation requires a tenant on the resource",
                reason_code="resource.tenant_context_missing",
                resource=target,
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )
        if (
            self.catalog_mode == "strict"
            and definition is not None
            and definition.requires_resource
            and target is None
        ):
            return Decision(False, operation_name, reason="a trusted resource is required", reason_code="resource.required", resource=None, entrypoint=entrypoint, policy_version=self.policies.version)
        if (
            self.catalog_mode == "strict"
            and definition is not None
            and not actor.authenticated
            and not bool((definition.attributes or {}).get("allow_anonymous"))
        ):
            return Decision(False, operation_name, reason="authentication is required", reason_code="subject.unauthenticated", resource=target, entrypoint=entrypoint, policy_version=self.policies.version)

        # A remote PDP must receive an intentionally provisioned principal
        # coordinate. Never silently substitute a legacy email-only Subject as
        # that network identifier: it leaks PII and makes identity stability
        # ambiguous. Local/native evaluators keep legacy email compatibility.
        if (
            self.is_production
            and self.evaluator is not None
            and _is_reviewed_production_evaluator(self.evaluator)
            and _reviewed_production_evaluator_mode(self.evaluator) == "remote"
            and not actor.id
        ):
            return Decision(
                False,
                operation_name,
                reason="a stable Subject.id is required before a remote PDP request",
                reason_code="subject.remote_principal_required",
                resource=target,
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )

        if self.evaluator is not None:
            request = AuthorizationRequest(
                subject=actor,
                operation=operation_name,
                resource=target,
                context=request_context,
                arguments=dict(arguments or {}),
                entrypoint=entrypoint,
                request_id=request_id,
                trace_id=trace_id,
                contract_version=contract_version,
                catalog_fingerprint=catalog_fingerprint,
            )
            try:
                if self.is_production:
                    authorizer = getattr(type(self.evaluator), "authorize", None)
                    if not callable(authorizer):
                        raise TypeError("reviewed evaluator authorize method is missing")
                    decision = authorizer(self.evaluator, request)
                else:
                    decision = self.evaluator.authorize(request)
            except Exception as exc:
                return Decision(
                    False,
                    operation_name,
                    reason=f"authorization backend failed: {type(exc).__name__}",
                    reason_code="backend.error",
                    resource=target,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            if not isinstance(decision, Decision):
                return Decision(
                    False,
                    operation_name,
                    reason="authorization backend returned an invalid decision",
                    reason_code="backend.contract_error",
                    resource=target,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            if decision.operation and decision.operation != operation_name:
                return Decision(
                    False,
                    operation_name,
                    reason="authorization backend returned a different operation",
                    reason_code="backend.contract_error",
                    resource=target,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            if (
                decision.resource is not None
                and target is not None
                and (
                    decision.resource.type != target.type
                    or decision.resource.id != target.id
                )
            ):
                return Decision(
                    False,
                    operation_name,
                    reason="authorization backend returned a different resource",
                    reason_code="backend.contract_error",
                    resource=target,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            if decision.resource is not None and target is None:
                return Decision(
                    False,
                    operation_name,
                    reason="authorization backend invented a resource",
                    reason_code="backend.contract_error",
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            if decision.entrypoint and decision.entrypoint != entrypoint:
                return Decision(
                    False,
                    operation_name,
                    reason="authorization backend returned a different entrypoint",
                    reason_code="backend.contract_error",
                    resource=target,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            binding_issue = self._remote_response_binding_issue(
                decision,
                request_id=request_id,
                trace_id=trace_id,
                contract_version=contract_version,
                catalog_fingerprint=catalog_fingerprint,
            )
            if binding_issue:
                return Decision(
                    False,
                    operation_name,
                    reason=f"authorization backend response binding mismatch: {binding_issue}",
                    reason_code="backend.response_binding_invalid",
                    resource=target,
                    entrypoint=entrypoint,
                    policy_version=self.policies.version,
                )
            return replace(
                decision,
                operation=operation_name,
                resource=target,
                entrypoint=entrypoint,
                policy_version=decision.policy_version or getattr(self.evaluator, "policy_version", self.policies.version),
            )

        trace: list[dict[str, Any]] = []
        outcomes: list[tuple[bool, PolicyBinding, str, Mapping[str, Any]]] = []
        for binding in self.policies.for_operation(operation_name):
            selected = _matches_subject(binding, actor) and condition_matches(
                binding.when,
                subject=actor,
                resource=target,
                context=request_context,
            )
            trace.append({
                "policy": binding.id,
                "template": binding.template,
                "effect": binding.effect,
                "selected": selected,
            })
            if not selected:
                continue
            allowed, reason, obligations = self._evaluate(binding, actor, target)
            if allowed is None:
                continue
            if binding.effect == "deny":
                allowed = False
            outcomes.append((allowed, binding, reason, {**dict(binding.obligations), **dict(obligations)}))

            if self.policies.combining_for(operation_name) == "first_match":
                break

        selected_outcome: tuple[bool, PolicyBinding, str, Mapping[str, Any]] | None = None
        combining = self.policies.combining_for(operation_name)
        if combining == "allow_overrides":
            selected_outcome = next((item for item in outcomes if item[0]), None) or (outcomes[0] if outcomes else None)
        elif combining == "first_match":
            selected_outcome = outcomes[0] if outcomes else None
        else:
            selected_outcome = next((item for item in outcomes if not item[0]), None) or next((item for item in outcomes if item[0]), None)
        if selected_outcome is not None:
            allowed, binding, reason, obligations = selected_outcome
            return Decision(
                allowed,
                operation_name,
                reason=reason,
                reason_code="policy.allow" if allowed else "policy.deny",
                policy=binding.id,
                resource=target,
                obligations=obligations,
                trace=tuple(trace),
                entrypoint=entrypoint,
                policy_version=self.policies.version,
            )
        return Decision(
            self.policies.default_effect_for(operation_name) == "allow",
            operation_name,
            reason="default policy decision" if self.policies.default_effect_for(operation_name) == "allow" else "no applicable policy allows this operation",
            reason_code="policy.default_allow" if self.policies.default_effect_for(operation_name) == "allow" else "policy.no_match",
            resource=target,
            trace=tuple(trace),
            entrypoint=entrypoint,
            policy_version=self.policies.version,
        )

    def _evaluate(
        self,
        binding: PolicyBinding,
        subject: Subject,
        resource: Resource | None,
    ) -> tuple[bool | None, str, Mapping[str, Any]]:
        template = binding.template
        if template in {"deny", "subject_denylist"}:
            return False, binding.description or "operation is denied by policy", {}
        if template in {"authenticated", "subject_allowlist", "role_allowlist", "allow", "conditional"}:
            return True, binding.description or "subject matches the allow policy", {}
        if template in {"creator_only", "resource.owner_only"}:
            relation_names = binding.relations or ("creator", "owner")
            if _relation(resource, relation_names):
                return True, binding.description or "subject is the creator or owner", {}
            return False, "subject is not the creator or owner", {}
        if template in {"owner_or_admin", "resource.owner_or_admin"}:
            raw_roles = binding.parameters.get("admin_roles", ("admin", "leader"))
            if isinstance(raw_roles, str):
                raw_roles = raw_roles.split(",")
            admin_roles = tuple(str(item).strip().lower() for item in raw_roles)
            is_admin = bool(set(subject.roles) & set(admin_roles))
            if is_admin or _relation(resource, binding.relations or ("creator", "owner")):
                return True, binding.description or "subject is the creator, owner, or administrator", {}
            return False, "subject is neither the creator, owner, nor administrator", {}
        if template in {"relation", "relation_any", "resource.relations"}:
            relations = binding.relations or tuple(binding.parameters.get("relations", ()))
            if _relation(resource, relations):
                return True, binding.description or "subject has a permitted resource relation", {}
            return False, "subject lacks a permitted resource relation", {}
        if template in {"deny_non_owner", "resource.deny_non_owner"}:
            if not _relation(resource, binding.relations or ("creator", "owner")):
                return False, binding.description or "non-owner access is denied", {}
            return None, "owner may continue to the next policy", {}
        if template in {"query.own_rows", "query.related_rows"}:
            relation_names = binding.relations or tuple(binding.parameters.get("relations", ("owner",)))
            if _relation(resource, relation_names) or not resource:
                return True, binding.description or "query is restricted to the permitted relation", {
                    "data_scope": {"mode": "relation", "relations": list(relation_names)}
                }
            return False, "subject is outside the permitted query scope", {}
        return False, f"unsupported policy template: {template}", {}

    def require(self, subject: Subject | object, **kwargs: Any) -> Decision:
        decision = self.can(subject, **kwargs)
        if not decision.allowed:
            raise AuthorizationError(decision)
        return decision

    def can_entrypoint(
        self,
        subject: Subject | object,
        *,
        kind: str,
        name: str,
        resource: Resource | None = None,
        context: Mapping[str, Any] | None = None,
        resource_type: str = "",
        resource_id: str = "",
    ) -> Decision:
        binding = self.catalog.entrypoint(kind, name) if self.catalog else None
        if binding is None:
            return Decision(
                False,
                "",
                reason="entrypoint is not registered",
                entrypoint=f"{kind}:{name}",
            )
        return self.can(
            subject,
            operation=binding.operation,
            resource=resource,
            resource_type=resource_type,
            resource_id=resource_id,
            context=context,
            entrypoint=f"{kind}:{name}",
        )

    def check_many(
        self,
        subject: Subject | object,
        requests: Iterable[Mapping[str, Any] | AuthorizationRequest],
    ) -> list[Decision]:
        """Evaluate multiple checks with one normalized subject.

        This is intentionally an in-process primitive. A remote adapter can
        serialize the same ``AuthorizationRequest`` contract without making
        callers rewrite business code later.
        """

        actor = subject if isinstance(subject, Subject) else Subject.from_user(subject)
        result: list[Decision] = []
        for item in requests:
            if isinstance(item, AuthorizationRequest):
                request = item
            else:
                raw = dict(item)
                request = AuthorizationRequest(
                    subject=actor,
                    operation=str(raw.get("operation") or ""),
                    resource=raw.get("resource"),
                    context=raw.get("context") or {},
                    arguments=raw.get("arguments") or {},
                    entrypoint=str(raw.get("entrypoint") or ""),
                    request_id=str(raw.get("request_id") or ""),
                    trace_id=str(raw.get("trace_id") or ""),
                    contract_version=str(raw.get("contract_version") or AUTHZ_CONTRACT_VERSION),
                    catalog_fingerprint=str(raw.get("catalog_fingerprint") or ""),
                )
            result.append(self.can(
                actor,
                operation=request.operation,
                resource=request.resource,
                context=request.context,
                arguments=request.arguments,
                entrypoint=request.entrypoint,
                resource_type=request.resource.type if request.resource else "",
                request_id=request.request_id,
                trace_id=request.trace_id,
                contract_version=request.contract_version,
                catalog_fingerprint=request.catalog_fingerprint,
            ))
        return result

    def explain(self, subject: Subject | object, **kwargs: Any) -> dict[str, Any]:
        return self.can(subject, **kwargs).to_dict()
