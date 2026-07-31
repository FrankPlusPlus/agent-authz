from __future__ import annotations

from pathlib import Path
import runpy

import pytest

from authz_sdk import (
    AgentRequest,
    AgentRuntime,
    Authz,
    AuditRedactor,
    CandidateFilter,
    Catalog,
    Decision,
    ExecutionPermit,
    InMemoryAuditSink,
    InMemoryPermitStore,
    PermitStoreStatus,
    PolicySet,
    Resource,
    ResourceRegistry,
    Subject,
)


def _catalog() -> Catalog:
    catalog = Catalog()
    catalog.resource(
        "document",
        actions=("read", "publish"),
        relations=("viewer",),
        tenant_required=True,
    )
    return catalog


def _policies() -> PolicySet:
    policies = PolicySet(version="bundle-7")
    policies.bind(
        id="document_viewer",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    policies.bind(
        id="document_publish",
        operation="document.publish",
        template="allow",
    )
    return policies


def test_production_profile_requires_a_trusted_tenant_bound_resource() -> None:
    catalog = _catalog()
    policies = _policies()
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda resource_id, subject, context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme", "version": "7"},
            "relations": {"viewer": subject.id == "alice"},
        },
    )
    authz = Authz.production(catalog, policies, registry)
    alice = Subject(id="alice", tenant_id="acme")

    forged = authz.can(
        alice,
        operation="document.read",
        resource=Resource(
            "document",
            "doc-1",
            attributes={"tenant_id": "acme"},
            relations={"viewer": True},
        ),
    )
    allowed = authz.can(
        alice,
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )
    missing_tenant = authz.can(
        Subject(id="alice"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not forged.allowed
    assert forged.reason_code == "resource.untrusted"
    assert allowed.allowed
    assert allowed.resource is not None and allowed.resource.trusted
    assert not missing_tenant.allowed
    assert missing_tenant.reason_code == "subject.tenant_context_missing"
    assert authz.readiness()["ready"]


def test_decisions_carry_a_versioned_request_contract_and_reject_catalog_drift() -> None:
    catalog = _catalog()
    policies = _policies()
    authz = Authz.native(catalog, policies)
    alice = Subject(id="alice", tenant_id="acme")
    document = Resource(
        "document",
        "doc-1",
        attributes={"tenant_id": "acme"},
        relations={"viewer": True},
    )

    decision = authz.can(
        alice,
        operation="document.read",
        resource=document,
        request_id="request-7",
        trace_id="trace-7",
        catalog_fingerprint=catalog.fingerprint(),
    )
    stale = authz.can(
        alice,
        operation="document.read",
        resource=document,
        catalog_fingerprint="stale-catalog",
    )

    assert decision.allowed
    assert decision.request_id == "request-7"
    assert decision.trace_id == "trace-7"
    assert decision.contract_version == "1.0"
    assert decision.catalog_fingerprint == catalog.fingerprint()
    assert decision.policy_digest == policies.fingerprint()
    assert decision.to_dict()["request_id"] == "request-7"
    assert not stale.allowed
    assert stale.reason_code == "catalog.fingerprint_mismatch"


def test_audit_sink_records_only_the_finalized_decision_and_can_fail_closed() -> None:
    catalog = _catalog()
    policies = _policies()
    sink = InMemoryAuditSink()
    authz = Authz.native(catalog, policies, audit_sink=sink)
    alice = Subject(id="alice", tenant_id="acme")
    document = Resource(
        "document",
        "doc-1",
        attributes={"tenant_id": "acme"},
        relations={"viewer": True},
    )

    decision = authz.can(alice, operation="document.read", resource=document, request_id="audit-7")

    assert decision.allowed
    assert sink.events[0].request_id == "audit-7"
    assert sink.events[0].reason_code == "policy.allow"

    class BrokenSink:
        def emit(self, event: object) -> None:
            raise OSError("audit unavailable")

    guarded = Authz.production(catalog, policies, audit_sink=BrokenSink(), audit_required=True)
    denied = guarded.can(
        alice,
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    # This reaches resource loading first, which is the expected secure order
    # for the production profile. Use a trusted loader below to exercise the
    # audit-required fail-closed condition itself.
    assert denied.reason_code == "resource.resolution_failed"

    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda resource_id, subject, context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": True},
        },
    )
    guarded = Authz.production(
        catalog,
        policies,
        registry,
        audit_sink=BrokenSink(),
        audit_required=True,
    )
    denied = guarded.can(
        alice,
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not denied.allowed
    assert denied.reason_code == "audit.delivery_failed"
    assert guarded.health()["last_audit_error"] == "OSError"


def test_required_audit_cannot_be_enabled_without_a_sink() -> None:
    with pytest.raises(ValueError, match="audit_required requires an audit_sink"):
        Authz.production(_catalog(), _policies(), audit_required=True)


def test_production_readiness_does_not_mistake_an_in_memory_sink_for_durable_audit() -> None:
    authz = Authz.production(_catalog(), _policies(), audit_sink=InMemoryAuditSink())

    readiness = authz.readiness()

    assert readiness["ready"]
    assert {item["code"] for item in readiness["issues"]} >= {
        "audit.durability_ephemeral"
    }
    assert authz.health()["audit_durability"] == "ephemeral"


def test_production_audit_redactor_pseudonymizes_identifiers_and_is_observable() -> None:
    sink = InMemoryAuditSink()
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": True},
        },
    )
    authz = Authz.production(
        _catalog(),
        _policies(),
        resources,
        audit_sink=sink,
        audit_redactor=AuditRedactor("audit-secret", key_id="v1"),
    )
    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert decision.allowed
    assert sink.events[0].subject_id.startswith("hmac-sha256:v1:")
    assert sink.events[0].resource_uri.startswith("hmac-sha256:v1:")
    assert authz.health()["audit_identifier_mode"] == "pseudonymized"
    assert "audit.identifiers_not_pseudonymized" not in {
        item["code"] for item in authz.readiness()["issues"]
    }


def test_production_profile_preserves_strict_catalog_with_an_external_evaluator() -> None:
    class AllowEvaluator:
        name = "test"
        policy_version = "remote-1"

        def authorize(self, request):
            return request

        def health(self):
            return {"status": "ok"}

    production = Authz.production(_catalog(), _policies())
    preserved = production.with_evaluator(AllowEvaluator())

    assert preserved.catalog_mode == "strict"
    with pytest.raises(ValueError, match="cannot relax"):
        production.with_evaluator(AllowEvaluator(), catalog_mode="advisory")
    with pytest.raises(ValueError, match="cannot relax"):
        production.with_evaluator(AllowEvaluator(), tenant_boundary=False)


def test_production_runtime_denies_a_relaxed_boundary_before_policy_execution() -> None:
    catalog = _catalog()
    policies = _policies()
    authz = Authz(
        catalog,
        policies,
        catalog_mode="advisory",
        tenant_boundary=False,
        require_tenant_context=False,
        require_trusted_resource=False,
        profile="production",
    )

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.publish",
        resource=Resource("document", "doc-1", attributes={"tenant_id": "other"}),
    )

    assert not decision.allowed
    assert decision.reason_code == "production.not_ready"


def test_production_profile_cannot_be_downgraded_through_public_profile_attribute() -> None:
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
        },
    )
    production = Authz.production(_catalog(), _policies(), resources)
    with pytest.raises(AttributeError, match="immutable"):
        production.profile = "custom"

    decision = production.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.publish",
        resource_type="document",
        resource_id="doc-1",
    )

    assert production.is_production
    assert production.readiness()["profile"] == "production"
    assert production.readiness()["ready"]
    assert decision.allowed


def test_production_profile_requires_the_exact_authz_facade_type() -> None:
    """A subclass cannot inject unchecked helpers into the production path."""

    class BackdoorEvaluateAuthz(Authz):
        def _evaluate(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[bool, str, dict[str, object]]:
            return True, "unreviewed subclass helper", {}

    with pytest.raises(TypeError, match="exact Authz facade"):
        BackdoorEvaluateAuthz.production(_catalog(), _policies(), ResourceRegistry())
    with pytest.raises(TypeError, match="exact Authz facade"):
        BackdoorEvaluateAuthz(
            _catalog(),
            _policies(),
            ResourceRegistry(),
            profile="production",
        )


@pytest.mark.parametrize("mutation", ("instance_dict", "object_setattr"))
def test_production_identity_cannot_be_downgraded_before_can(
    mutation: str,
) -> None:
    """A pre-request low-level profile change must not select native allow."""

    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
        },
    )
    production = Authz.production(
        _catalog(),
        PolicySet(default_effect="allow"),
        resources,
    )
    request = {
        "operation": "document.publish",
        "resource_type": "document",
        "resource_id": "doc-1",
    }
    subject = Subject(id="alice", tenant_id="acme")

    # This establishes that the vulnerable custom/native path would allow the
    # request; the security assertion below is about preserving production
    # identity after a low-level mutation made before ``can()`` starts.
    assert production.can(subject, **request).allowed

    if mutation == "instance_dict":
        production.__dict__["profile"] = "custom"
        production.__dict__["_production_profile"] = False
    else:
        object.__setattr__(production, "profile", "custom")
        object.__setattr__(production, "_production_profile", False)

    decision = production.can(subject, **request)

    assert production.is_production
    assert not decision.allowed
    assert decision.reason_code == "production.not_ready"
    assert "production.profile_mutated" in {
        item["code"] for item in production.readiness()["issues"]
    }


def test_production_identity_rejects_a_low_level_facade_subclass_swap() -> None:
    """`can()` must not dispatch its production mode through an override."""

    class DowngradedAuthz(Authz):
        @property
        def is_production(self) -> bool:
            return False

        def can(self, *_args: object, **_kwargs: object) -> Decision:
            return Decision(True, "document.publish", reason_code="attacker.outer_allow")

    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
        },
    )
    production = Authz.production(
        _catalog(),
        PolicySet(default_effect="allow"),
        resources,
    )
    request = {
        "operation": "document.publish",
        "resource_type": "document",
        "resource_id": "doc-1",
    }
    subject = Subject(id="alice", tenant_id="acme")

    assert production.can(subject, **request).allowed
    object.__setattr__(production, "__class__", DowngradedAuthz)

    # Ordinary public lookup remains pinned to the reviewed base property and
    # method, then detects the changed facade type before evaluation.
    assert production.is_production is True
    decision = production.can(subject, **request)

    assert not decision.allowed
    assert decision.reason_code == "production.not_ready"
    assert "production.facade_type_mutated" in {
        item["code"] for item in production.readiness()["issues"]
    }


def test_production_can_ignores_low_level_internal_method_shadows() -> None:
    """The public production entrypoint must retain its reviewed base path."""

    production = Authz.production(
        _catalog(),
        PolicySet(default_effect="allow"),
        ResourceRegistry(),
    )
    shadow_calls: list[str] = []

    def attacker_allow(*_args, **_kwargs) -> Decision:
        shadow_calls.append("called")
        return Decision(True, "unregistered.delete", reason_code="attacker.inner_allow")

    production.__dict__["_can"] = attacker_allow
    production.__dict__["_finalize_decision"] = attacker_allow
    production.__dict__["can"] = attacker_allow

    decision = production.can(
        Subject(id="alice", tenant_id="acme"),
        operation="unregistered.delete",
    )

    assert not decision.allowed
    assert decision.reason_code == "catalog.operation_unknown"
    assert shadow_calls == []


def test_production_can_ignores_a_low_level_native_policy_evaluator_shadow() -> None:
    """An embedded policy deny cannot be replaced by an instance `_evaluate`."""

    policies = PolicySet()
    policies.bind(
        id="document_publish_denied",
        operation="document.publish",
        template="deny",
    )
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
        },
    )
    production = Authz.production(_catalog(), policies, resources)
    shadow_calls: list[str] = []

    def forged_evaluation(
        *_args: object,
        **_kwargs: object,
    ) -> tuple[bool, str, dict[str, object]]:
        shadow_calls.append("called")
        return True, "forged", {}

    production.__dict__["_evaluate"] = forged_evaluation
    decision = production.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.publish",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "policy.deny"
    assert shadow_calls == []


def test_production_identity_rejects_a_stateful_catalog_mode_subclass() -> None:
    """Primitive production switches must not execute attacker equality code."""

    class StatefulStrict(str):
        def __init__(self, value: str) -> None:
            self.comparisons = 0

        def __eq__(self, other: object) -> bool:
            self.comparisons += 1
            return self.comparisons == 1 and str(other) == "strict"

    production = Authz.production(
        _catalog(),
        PolicySet(default_effect="allow"),
        ResourceRegistry(),
    )
    production.__dict__["catalog_mode"] = StatefulStrict("strict")

    decision = production.can(
        Subject(id="alice", tenant_id="acme"),
        operation="unregistered.delete",
    )

    assert not decision.allowed
    assert decision.reason_code == "production.not_ready"
    assert "production.configuration_mutated" in {
        item["code"] for item in production.readiness()["issues"]
    }


def test_production_runtime_rejects_a_post_construction_registry_swap() -> None:
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": True},
        },
    )
    production = Authz.production(_catalog(), _policies(), resources)
    replacement = ResourceRegistry()
    replacement.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": True},
        },
    )
    with pytest.raises(AttributeError, match="immutable"):
        production.resources = replacement

    decision = production.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.publish",
        resource_type="document",
        resource_id="doc-1",
    )

    assert decision.allowed
    assert production.readiness()["ready"]


@pytest.mark.parametrize(
    ("attribute", "replacement"),
    (
        ("catalog", lambda: _catalog()),
        ("policies", lambda: PolicySet(default_effect="allow")),
        ("resources", ResourceRegistry),
        ("evaluator", lambda: None),
        ("catalog_mode", lambda: "advisory"),
        ("tenant_boundary", lambda: False),
        ("require_tenant_context", lambda: False),
        ("require_trusted_resource", lambda: False),
        ("audit_sink", object),
        ("audit_required", lambda: True),
        ("audit_redactor", object),
        ("profile", lambda: "custom"),
    ),
)
def test_production_boundary_configuration_is_not_publicly_mutable(
    attribute: str,
    replacement,
) -> None:
    production = Authz.production(_catalog(), _policies(), ResourceRegistry())

    with pytest.raises(AttributeError, match="immutable"):
        setattr(production, attribute, replacement())

    assert production.readiness()["ready"]


@pytest.mark.parametrize("method_name", ("readiness", "_production_boundary_issues", "_can"))
def test_production_boundary_methods_are_not_publicly_overridable(
    method_name: str,
) -> None:
    production = Authz.production(_catalog(), _policies(), ResourceRegistry())

    with pytest.raises(AttributeError, match="methods are immutable"):
        setattr(production, method_name, lambda *_args, **_kwargs: None)

    assert production.readiness()["ready"]


def test_production_boundary_seal_rejects_unknown_attributes_and_deletion() -> None:
    production = Authz.production(_catalog(), _policies(), ResourceRegistry())

    with pytest.raises(AttributeError, match="immutable"):
        production.unreviewed_extension = object()
    with pytest.raises(AttributeError, match="immutable"):
        del production.catalog

    assert production.readiness()["ready"]


def test_production_boundary_rejection_precedes_replaced_collaborator_callbacks() -> None:
    class ProbeCatalog:
        def __init__(self) -> None:
            self.calls = 0

        def fingerprint(self) -> str:
            self.calls += 1
            raise AssertionError("a replaced catalog must not be invoked")

    class ProbeSink:
        def __init__(self) -> None:
            self.calls = 0

        def emit(self, _event) -> None:
            self.calls += 1
            raise AssertionError("a replaced audit sink must not be invoked")

    production = Authz.production(_catalog(), _policies(), ResourceRegistry())
    catalog = ProbeCatalog()
    sink = ProbeSink()
    # Exercise defence in depth for objects introduced by a deserializer or
    # other low-level in-process code; public assignment is rejected above.
    object.__setattr__(production, "catalog", catalog)
    object.__setattr__(production, "audit_sink", sink)

    decision = production.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.publish",
        contract_version="unsupported",
    )

    assert not decision.allowed
    assert decision.reason_code == "production.not_ready"
    assert catalog.calls == 0
    assert sink.calls == 0
    assert not production.readiness()["ready"]
    assert catalog.calls == 0
    assert sink.calls == 0


def test_runtime_can_verify_and_consume_a_one_time_permit() -> None:
    catalog = _catalog()
    authz = Authz.native(catalog, _policies())
    runtime = AgentRuntime(authz)
    subject = Subject(id="alice", tenant_id="acme")
    request = AgentRequest(
        subject=subject,
        operation="document.publish",
        phase="execute",
        tool_name="publish_document",
        resource=Resource("document", "doc-1", attributes={"tenant_id": "acme"}),
        arguments={"state": "published"},
    )
    permit = runtime.issue_permit(
        request,
        secret="test-secret",
        resource_version="7",
        now=100.0,
    )
    store = InMemoryPermitStore()

    first = runtime.consume_permit(
        request,
        permit,
        secret="test-secret",
        resource_version="7",
        store=store,
        now=101.0,
    )
    replay = runtime.consume_permit(
        request,
        permit,
        secret="test-secret",
        resource_version="7",
        store=store,
        now=101.0,
    )

    assert first.status is PermitStoreStatus.CONSUMED
    assert replay.status is PermitStoreStatus.REPLAYED


def test_runtime_can_issue_and_verify_a_permit_from_registry_coordinates() -> None:
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": True},
        },
    )
    runtime = AgentRuntime(Authz.production(_catalog(), _policies(), registry))
    request = AgentRequest(
        subject=Subject(id="alice", tenant_id="acme"),
        operation="document.publish",
        phase="execute",
        tool_name="publish_document",
        resource_type="document",
        resource_id="doc-1",
        arguments={"state": "published"},
    )

    permit = runtime.issue_permit(
        request,
        secret="test-secret",
        resource_version="7",
        now=100.0,
    )

    assert permit.resource == "document:doc-1"
    assert permit.resource_type == "document"
    assert permit.resource_id == "doc-1"
    assert runtime.verify_permit(
        request,
        permit,
        secret="test-secret",
        resource_version="7",
        now=101.0,
    )


def test_execution_permit_binds_resource_type_and_id_without_uri_collisions() -> None:
    subject = Subject(id="alice", tenant_id="acme")
    issued_for = Resource("document", "doc:1", attributes={"tenant_id": "acme"})
    colliding_uri = Resource("document:doc", "1", attributes={"tenant_id": "acme"})
    permit = ExecutionPermit.issue(
        Decision(
            True,
            "document.publish",
            resource=issued_for,
            entrypoint="agent.execute:publish_document",
            policy_version="policy-1",
        ),
        subject,
        secret="test-secret",
        resource_version="7",
        now=100.0,
    )

    assert issued_for.uri == "document:doc%3A1"
    assert colliding_uri.uri == "document%3Adoc:1"
    assert issued_for.uri != colliding_uri.uri
    assert permit.resource_type == "document"
    assert permit.resource_id == "doc:1"
    assert not permit.verify(
        subject,
        secret="test-secret",
        operation="document.publish",
        resource=colliding_uri,
        resource_version="7",
        entrypoint="agent.execute:publish_document",
        policy_version="policy-1",
        now=101.0,
    )


def test_coordinate_only_permit_reauthorization_rejects_a_revoked_relationship() -> None:
    state = {"viewer": True, "version": "7"}
    registry = ResourceRegistry()
    registry.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": state["viewer"]},
        },
    )
    runtime = AgentRuntime(Authz.production(_catalog(), _policies(), registry))
    request = AgentRequest(
        subject=Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        phase="execute",
        tool_name="read_document",
        resource_type="document",
        resource_id="doc-1",
    )
    permit = runtime.issue_permit(
        request,
        secret="test-secret",
        resource_version=state["version"],
        now=100.0,
    )
    state["viewer"] = False
    store = InMemoryPermitStore()

    assert not runtime.verify_permit(
        request,
        permit,
        secret="test-secret",
        resource_version=state["version"],
        now=101.0,
    )
    result = runtime.consume_permit(
        request,
        permit,
        secret="test-secret",
        resource_version=state["version"],
        store=store,
        now=101.0,
    )

    assert result.status is PermitStoreStatus.INVALID


def test_production_rag_filter_excludes_a_caller_constructed_relation() -> None:
    authz = Authz.production(_catalog(), _policies(), ResourceRegistry())
    candidate_filter = CandidateFilter(
        authz,
        resource_mapper=lambda candidate, subject, context: Resource(
            "document",
            candidate["id"],
            attributes={"tenant_id": "acme"},
            relations={"viewer": True},
        ),
    )

    result = candidate_filter.filter(
        ({"id": "forged-doc", "text": "must not reach the prompt"},),
        subject=Subject(id="alice", tenant_id="acme"),
        operation="document.read",
    )

    assert result.candidates == ()
    assert result.summary.records[0].reason_code == "authorization.denied"


def test_complete_secure_agent_example_enforces_each_boundary() -> None:
    example = Path(__file__).parents[1] / "examples" / "secure_document_agent.py"
    namespace = runpy.run_path(str(example))

    assert namespace["run_demo"]() == {
        "api_allowed": True,
        "tool_allowed": True,
        "tool_denied": True,
        "cross_tenant_denied": True,
        "permitted_chunk_ids": ["chunk-public"],
        "excluded_candidate_count": 1,
        "permit_status": "consumed",
        "audit_event_count": 8,
        "coverage_ready": True,
    }
