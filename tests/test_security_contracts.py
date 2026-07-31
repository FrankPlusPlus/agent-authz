from __future__ import annotations

from dataclasses import dataclass

import pytest

from authz_sdk import AgentRequest, AgentRuntime, Authz, Catalog, PolicySet, Resource, ResourceRegistry, Subject
from authz_sdk.adapters import ResourceIdentityMismatchError
from authz_sdk.models import AuthorizationRequest, Decision


def _document_authz(*, resources: ResourceRegistry | None = None, **kwargs: object) -> Authz:
    catalog = Catalog()
    catalog.resource("document", actions=("read",), relations=("viewer",))
    policies = PolicySet()
    policies.bind(
        id="document.read.viewer",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    return Authz.native(catalog, policies, resources, **kwargs)


def test_resource_registry_marks_loaded_resources_as_trusted() -> None:
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda resource_id, subject, context: {
            "id": resource_id,
            "relations": {"viewer": subject.email == "alice@example.com"},
        },
    )

    loaded = registry.resolve("document", "doc-1", Subject(email="alice@example.com"))

    assert loaded is not None
    assert loaded.trusted is True
    assert Resource("document", "doc-1", relations={"viewer": True}).trusted is False


def test_public_resource_constructor_cannot_accept_a_provenance_token() -> None:
    with pytest.raises(TypeError, match="_source_token"):
        Resource("document", "doc-1", _source_token=object())  # type: ignore[call-arg]


def test_trusted_resource_mode_rejects_caller_constructed_relations() -> None:
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda resource_id, subject, context: {
            "id": resource_id,
            "relations": {"viewer": True},
        },
    )
    authz = _document_authz(resources=registry, require_trusted_resource=True)
    subject = Subject(email="alice@example.com")

    direct = authz.can(
        subject,
        resource=Resource("document", "doc-1", relations={"viewer": True}),
        action="read",
    )
    loaded = authz.can(subject, resource_type="document", resource_id="doc-1", action="read")

    assert direct.allowed is False
    assert direct.reason_code == "resource.untrusted"
    assert loaded.allowed is True


def test_resource_identity_mismatch_fails_closed_before_policy_evaluation() -> None:
    authz = _document_authz()

    decision = authz.can(
        Subject(email="alice@example.com"),
        resource=Resource("document", "doc-1", relations={"viewer": True}),
        action="read",
        resource_id="doc-2",
    )

    assert decision.allowed is False
    assert decision.reason_code == "resource.identity_mismatch"


def test_registry_rejects_a_loader_that_returns_a_different_requested_resource() -> None:
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda _resource_id, _subject, _context: {
            "id": "doc-other",
            "relations": {"viewer": True},
        },
    )
    authz = _document_authz(resources=registry, require_trusted_resource=True)

    with pytest.raises(ResourceIdentityMismatchError, match="different resource ID"):
        registry.resolve("document", "doc-1", Subject(id="alice"))

    decision = authz.can(
        Subject(id="alice"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "resource.identity_mismatch"


def test_registry_rejects_a_loader_that_returns_a_different_resource_type() -> None:
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda _resource_id, _subject, _context: Resource(
            "project",
            "doc-1",
            relations={"viewer": True},
        ),
    )
    authz = _document_authz(resources=registry, require_trusted_resource=True)

    with pytest.raises(ResourceIdentityMismatchError, match="different resource type"):
        registry.resolve("document", "doc-1", Subject(id="alice"))

    decision = authz.can(
        Subject(id="alice"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "resource.identity_mismatch"


@pytest.mark.parametrize("returned", ({"type": "project", "id": "doc-1"}, {"id": ""}))
def test_registry_does_not_normalize_ambiguous_mapping_coordinates(returned: dict[str, str]) -> None:
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda _resource_id, _subject, _context: {
            **returned,
            "relations": {"viewer": True},
        },
    )

    with pytest.raises(ResourceIdentityMismatchError):
        registry.resolve("document", "doc-1", Subject(id="alice"))


def test_catalog_can_require_tenant_context_per_operation() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",), tenant_required=True)
    policies = PolicySet()
    policies.bind(
        id="document.read.authenticated",
        operation="document.read",
        template="authenticated",
    )
    authz = Authz.native(catalog, policies)

    decision = authz.can(
        Subject(email="alice@example.com"),
        resource=Resource("document", "doc-1", attributes={"tenant_id": "acme"}),
        action="read",
    )

    assert decision.allowed is False
    assert decision.reason_code == "subject.tenant_context_missing"


def test_production_does_not_trust_caller_controlled_lifecycle_context() -> None:
    """A generic context key must never waive a registered resource boundary."""

    catalog = Catalog()
    catalog.resource("document", actions=("delete",), tenant_required=True)
    catalog.register_operation(
        "document.list",
        requires_resource=False,
        tenant_required=True,
    )
    policies = PolicySet()
    policies.bind(id="allow_delete", operation="document.delete", template="allow")
    policies.bind(id="allow_list", operation="document.list", template="allow")
    authz = Authz.production(catalog, policies, ResourceRegistry())

    phase_bypass = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.delete",
        context={"authz_phase": "discover"},
    )
    tenantless_list = authz.can(Subject(id="alice"), operation="document.list")

    assert not phase_bypass.allowed
    assert phase_bypass.reason_code == "resource.required"
    assert not tenantless_list.allowed
    assert tenantless_list.reason_code == "subject.tenant_context_missing"


def test_only_agent_runtime_can_supply_the_reserved_lifecycle_phase_to_policy() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    policies = PolicySet()
    policies.bind(
        id="discover_only",
        operation="document.read",
        template="allow",
        when={"eq": [{"context": "authz_phase"}, "discover"]},
    )
    authz = Authz.native(catalog, policies)
    subject = Subject(id="alice")
    document = Resource("document", "doc-1")

    forged = authz.can(
        subject,
        operation="document.read",
        resource=document,
        context={"authz_phase": "discover"},
    )
    runtime_decision = AgentRuntime(authz).can(
        AgentRequest(
            subject=subject,
            operation="document.read",
            phase="discover",
            resource=document,
        )
    )

    assert not forged.allowed
    assert forged.reason_code == "policy.no_match"
    assert runtime_decision.allowed

    with pytest.raises(TypeError, match="_trusted_agent_phase"):
        authz.can(
            subject,
            operation="document.read",
            resource=document,
            _trusted_agent_phase="discover",  # type: ignore[call-arg]
        )


def test_trusted_resource_provenance_is_scoped_to_the_configured_registry() -> None:
    """A value loaded by another registry is not a resource from this domain."""

    owner = ResourceRegistry()
    foreign = ResourceRegistry()
    for registry in (owner, foreign):
        registry.register(
            "document",
            lambda resource_id, _subject, _context: {
                "id": resource_id,
                "relations": {"viewer": True},
            },
        )
    authz = _document_authz(resources=owner, require_trusted_resource=True)
    subject = Subject(id="alice")
    foreign_resource = foreign.resolve("document", "doc-1", subject)

    decision = authz.can(subject, resource=foreign_resource, action="read")

    assert foreign_resource is not None and foreign_resource.trusted
    assert not owner.owns(foreign_resource)
    assert not decision.allowed
    assert decision.reason_code == "resource.untrusted"


def test_health_and_readiness_explicitly_state_the_trusted_host_boundary() -> None:
    authz = _document_authz()

    assert authz.health()["trust_boundary"] == "trusted_host_process"
    assert authz.readiness()["trust_boundary"] == "trusted_host_process"


@dataclass
class _MismatchedEvaluator:
    response: object
    policy_version: str = "remote-1"

    def authorize(self, request: AuthorizationRequest) -> object:
        return self.response

    def health(self) -> dict[str, object]:
        return {"status": "ok", "backend": "test"}


@dataclass
class _SelfAttestedRemoteEvaluator:
    calls: int = 0
    name: str = "self_attested_remote"
    policy_version: str = "remote-1"
    enforcement_mode: str = "remote"
    expected_policy_version: str = "remote-1"
    expected_policy_digest: str = "digest-1"

    def production_readiness(self) -> dict[str, object]:
        return {"ready": True, "issues": ()}

    def authorize(self, request: AuthorizationRequest) -> Decision:
        self.calls += 1
        return Decision(
            True,
            request.operation,
            resource=request.resource,
            entrypoint=request.entrypoint,
            policy_version=self.expected_policy_version,
            policy_digest=self.expected_policy_digest,
            request_id=request.request_id,
            trace_id=request.trace_id,
            contract_version=request.contract_version,
            catalog_fingerprint=request.catalog_fingerprint,
        )

    def health(self) -> dict[str, object]:
        return {"status": "ok", "backend": self.name}


def test_production_rejects_a_self_attested_custom_evaluator_before_authorization() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",), tenant_required=True)
    policies = PolicySet()
    policies.bind(id="document_read", operation="document.read", template="allow")
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
        },
    )
    evaluator = _SelfAttestedRemoteEvaluator()
    authz = Authz.production(catalog, policies, resources, evaluator=evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert evaluator.calls == 0
    assert {item["code"] for item in authz.readiness()["issues"]} >= {
        "backend.production_evaluator_unreviewed"
    }


def test_external_backend_decision_must_match_the_request() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    request_resource = Resource("document", "doc-1")
    evaluator = _MismatchedEvaluator(
        Decision(True, "document.delete", resource=Resource("document", "doc-1"))
    )
    authz = Authz.connect(evaluator, catalog=catalog)

    decision = authz.can(
        Subject(email="alice@example.com"),
        operation="document.read",
        resource=request_resource,
    )

    assert decision.allowed is False
    assert decision.reason_code == "backend.contract_error"
    assert decision.operation == "document.read"
    assert decision.resource == request_resource


def test_external_backend_resource_binding_compares_structured_coordinates() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    requested = Resource("document", "doc:1")
    returned = Resource("document:doc", "1")
    evaluator = _MismatchedEvaluator(
        Decision(True, "document.read", resource=returned)
    )
    decision = Authz.connect(evaluator, catalog=catalog).can(
        Subject(id="alice"),
        operation="document.read",
        resource=requested,
    )

    assert requested.uri != returned.uri
    assert not decision.allowed
    assert decision.reason_code == "backend.contract_error"


def test_external_backend_malformed_decision_fails_closed() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    authz = Authz.connect(_MismatchedEvaluator({"allowed": True}), catalog=catalog)

    decision = authz.can(
        Subject(email="alice@example.com"),
        operation="document.read",
        resource=Resource("document", "doc-1"),
    )

    assert decision.allowed is False
    assert decision.reason_code == "backend.contract_error"
