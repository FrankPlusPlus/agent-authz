"""Contract and local end-to-end tests for pluggable policy backends."""

from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from authz_sdk import (
    AgentRequest,
    AgentRuntime,
    Authz,
    AuthzenEvaluator,
    CasbinEvaluator,
    Catalog,
    CerbosEvaluator,
    JsonPdpEvaluator,
    OpaEvaluator,
    OpenFgaEvaluator,
    PdpRequestProjection,
    PolicySet,
    ResourceRegistry,
    Resource,
    SpiceDbEvaluator,
    Subject,
)
from authz_sdk.backends import _urllib_transport, request_payload


def _request(operation: str = "ai_employee.delete"):
    from authz_sdk import AuthorizationRequest

    return AuthorizationRequest(
        subject=Subject(email="alice@example.com", roles=("engineer",), tenant_id="t1"),
        operation=operation,
        resource=Resource("ai_employee", "employee-1", attributes={"tenant_id": "t1"}),
        context={"environment": "test"},
        arguments={"employee_id": "employee-1"},
        entrypoint="tool:ai_employee_delete",
        request_id="request-wire-1",
        trace_id="trace-wire-1",
        catalog_fingerprint="a" * 64,
    )


def test_default_pdp_projection_does_not_send_organizational_subject_data() -> None:
    from authz_sdk import AuthorizationRequest

    request = AuthorizationRequest(
        subject=Subject(
            id="user-7",
            email="alice@example.com",
            roles=("admin",),
            positions=("director",),
            tenant_id="t1",
            organization_ids=("org-1",),
            metadata={"department": "finance"},
        ),
        operation="ai_employee.delete",
        resource=Resource(
            "ai_employee",
            "employee-1",
            attributes={"tenant_id": "t1", "classification": "secret"},
        ),
        context={"prompt": "must not leave the PEP"},
        arguments={"token": "must not leave the PEP"},
    )

    payload = request_payload(request)

    assert payload["subject"] == {"id": "user-7"}
    assert payload["resource"]["attributes"] == {"tenant_id": "t1"}
    assert payload["context"] == {}
    assert payload["arguments"] == {}

    expanded = request_payload(
        request,
        projection=PdpRequestProjection(
            subject_field_keys=("id", "roles", "tenant_id", "organization_ids"),
            subject_metadata_keys=("department",),
        ),
    )
    assert expanded["subject"] == {
        "id": "user-7",
        "roles": ["admin"],
        "tenant_id": "t1",
        "organization_ids": ["org-1"],
        "metadata": {"department": "finance"},
    }


def test_default_pdp_projection_never_uses_email_as_a_hidden_id_fallback() -> None:
    from authz_sdk import AuthorizationRequest

    payload = request_payload(
        AuthorizationRequest(
            subject=Subject(email="alice@example.com"),
            operation="document.read",
        )
    )

    assert payload["subject"] == {}
    assert "alice@example.com" not in json.dumps(payload, sort_keys=True)


def test_production_remote_backend_rejects_even_self_attested_custom_encoder() -> None:
    calls: list[object] = []

    def transport(*_args):
        calls.append(object())
        return {"allowed": True}

    evaluator = JsonPdpEvaluator(
        "https://pdp.example.test/allow",
        transport=transport,
        transport_security="verified",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        encoder=lambda _request: {"unsafe": "caller must review this"},
        projection_enforced=True,
    )
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert calls == []
    assert {
        "backend.remote_custom_encoder_unsupported",
        "backend.remote_custom_transport_unsupported",
    } <= set(evaluator.production_readiness()["issues"])


def test_production_remote_backend_rejects_a_custom_decoder_before_transport() -> None:
    evaluator = JsonPdpEvaluator(
        "https://pdp.example.test/allow",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        decoder=lambda _response: True,
    )
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert "backend.remote_custom_decoder_unsupported" in set(
        evaluator.production_readiness()["issues"]
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda evaluator: setattr(evaluator, "endpoint", "http://attacker.example.test/allow"),
        lambda evaluator: setattr(evaluator, "transport", lambda *_args: {"allowed": True}),
        lambda evaluator: setattr(evaluator, "encoder", lambda _request: {"unsafe": True}),
        lambda evaluator: setattr(evaluator, "decoder", lambda _response: True),
    ),
)
def test_production_remote_backend_rejects_post_construction_configuration_mutation(
    mutate,
) -> None:
    evaluator = JsonPdpEvaluator(
        "https://pdp.example.test/allow",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
    )
    mutate(evaluator)
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert "backend.remote_configuration_mutated" in set(
        evaluator.production_readiness()["issues"]
    )


def test_production_remote_backend_uses_registered_mode_not_a_mutable_attribute() -> None:
    calls: list[object] = []

    def transport(*_args):
        calls.append(object())
        return {"allowed": True}

    evaluator = OpaEvaluator(
        "https://pdp.example.test/allow",
        transport=transport,
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
    )
    evaluator.enforcement_mode = "in_process"
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert calls == []


@pytest.mark.parametrize(
    ("attribute", "replacement"),
    (
        ("production_readiness", lambda *_args: {"ready": True, "issues": ()}),
        ("authorize", lambda *_args: None),
        ("_encode_payload", lambda _request: {"unsafe": True}),
    ),
)
def test_production_remote_backend_rejects_instance_method_shadowing(
    attribute: str,
    replacement,
) -> None:
    evaluator = JsonPdpEvaluator(
        "https://pdp.example.test/allow",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
    )
    setattr(evaluator, attribute, replacement)
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert "backend.production_method_shadowed" in {
        item["code"] for item in authz.readiness()["issues"]
    }


def test_production_openfga_rejects_a_mutated_operation_mapper() -> None:
    evaluator = OpenFgaEvaluator(
        "https://pdp.example.test/allow",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        operation_map={"document.read": "viewer"},
    )
    evaluator.operation_mapper = lambda _request: "owner"
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert "backend.remote_configuration_mutated" in set(
        evaluator.production_readiness()["issues"]
    )


@pytest.mark.parametrize(
    ("factory", "initial_mapping", "mutated_mapping", "readiness_issue"),
    (
        (
            OpenFgaEvaluator,
            "delete",
            "viewer",
            "backend.openfga_production_operation_map_required",
        ),
        (
            SpiceDbEvaluator,
            "delete",
            "viewer",
            "backend.spicedb_production_operation_map_required",
        ),
    ),
)
def test_production_relation_backends_reject_mutable_callable_mappers(
    factory,
    initial_mapping: str,
    mutated_mapping: str,
    readiness_issue: str,
) -> None:
    class MutableMapper:
        def __init__(self, mapping: str) -> None:
            self.mapping = mapping

        def __call__(self, _request) -> str:
            return self.mapping

    mapper = MutableMapper(initial_mapping)
    evaluator = factory(
        "https://pdp.example.test/allow",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        operation_mapper=mapper,
    )
    mapper.mapping = mutated_mapping
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert readiness_issue in {
        item["code"] for item in authz.readiness()["issues"]
    }


@pytest.mark.parametrize(
    ("factory", "expected_mapping"),
    (
        (OpenFgaEvaluator, "viewer"),
        (SpiceDbEvaluator, "read"),
    ),
)
def test_production_relation_backends_freeze_declarative_operation_maps(
    factory,
    expected_mapping: str,
) -> None:
    configured_map = {"document.read": expected_mapping}
    evaluator = factory(
        "https://pdp.example.test/allow",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        operation_map=configured_map,
    )
    configured_map["document.read"] = "owner"

    assert evaluator.production_readiness()["ready"] is True
    assert evaluator.operation_mapper(_request("document.read")) == expected_mapping
    assert _production_remote_authz(evaluator).readiness()["ready"] is True


def test_production_casbin_rejects_a_post_construction_enforcer_swap() -> None:
    class Enforcer:
        def enforce(self, *_args) -> bool:
            return True

    evaluator = CasbinEvaluator(Enforcer(), policy_version="casbin-1")
    evaluator.enforcer = Enforcer()
    authz = _production_remote_authz(evaluator)

    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert "backend.in_process_configuration_mutated" in set(
        evaluator.production_readiness()["issues"]
    )


@pytest.mark.parametrize(
    "evaluator_class",
    (OpaEvaluator, CerbosEvaluator, OpenFgaEvaluator, SpiceDbEvaluator, AuthzenEvaluator),
)
def test_fixed_protocol_adapters_reject_caller_supplied_decoders(evaluator_class) -> None:
    with pytest.raises(TypeError, match="fixed reviewed payload and decision adapters"):
        evaluator_class("https://pdp.example.test/allow", decoder=lambda _response: True)


def test_production_remote_backend_rejects_email_only_subject_before_transport() -> None:
    authz = _production_remote_authz(
        OpaEvaluator(
            "https://pdp.example.test/allow",
            policy_version="remote-revision-7",
            expected_policy_digest="remote-digest-7",
        )
    )

    decision = authz.can(
        Subject(email="alice@example.com", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "subject.remote_principal_required"


def test_casbin_evaluator_is_a_drop_in_backend():
    casbin = pytest.importorskip("casbin")
    model = casbin.Model()
    model.load_model_from_text(
        """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
    )
    enforcer = casbin.Enforcer(model)
    enforcer.add_policy("alice@example.com", "ai_employee:employee-1", "ai_employee.delete")
    evaluator = CasbinEvaluator(enforcer, policy_version="casbin-test-1")

    allowed = evaluator.authorize(_request())
    denied = evaluator.authorize(_request("ai_employee.update"))

    assert allowed.allowed is True
    assert allowed.reason_code == "casbin.allow"
    assert allowed.policy_version == "casbin-test-1"
    assert denied.allowed is False
    assert denied.reason_code == "casbin.deny"


def test_authz_facade_keeps_catalog_and_resource_validation_before_casbin():
    casbin = pytest.importorskip("casbin")
    model = casbin.Model()
    model.load_model_from_text(
        """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
    )
    enforcer = casbin.Enforcer(model)
    enforcer.add_policy("alice@example.com", "ai_employee:employee-1", "ai_employee.delete")
    catalog = Catalog()
    catalog.resource("ai_employee", title="AI Employee", actions=("delete",))
    authz = Authz(
        catalog,
        PolicySet(version="external-policy-1"),
        evaluator=CasbinEvaluator(enforcer),
    )

    allowed = authz.can(
        Subject(email="alice@example.com"),
        resource=Resource("ai_employee", "employee-1"),
        action="delete",
    )
    unknown = authz.can(
        Subject(email="alice@example.com"),
        operation="ai_employee.publish",
    )

    assert allowed.allowed is True
    assert allowed.reason_code == "casbin.allow"
    assert unknown.allowed is False
    assert unknown.reason_code == "catalog.operation_unknown"


def test_agent_runtime_keeps_the_same_call_shape_with_external_evaluator():
    def transport(_endpoint, payload, _headers, _timeout):
        assert payload["input"]["operation"] == "knowledge_base.query"
        assert payload["input"]["context"]["authz_phase"] == "execute"
        return {"allowed": True}

    catalog = Catalog()
    catalog.resource("knowledge_base", title="Knowledge Base", actions=("query",))
    authz = Authz(
        catalog,
        PolicySet(version="remote-policy-2"),
        evaluator=OpaEvaluator(
            "http://pdp.test",
            transport=transport,
            projection=PdpRequestProjection(context_keys=("authz_phase",)),
        ),
    )
    request = AgentRequest(
        subject=Subject(email="alice@example.com"),
        operation="knowledge_base.query",
        phase="execute",
        tool_name="kb_query",
        resource=Resource("knowledge_base", "finance-kb"),
    )

    decision = AgentRuntime(authz).can(request)

    assert decision.allowed is True
    assert decision.reason_code == "opa.allow"
    assert authz.health()["backend"] == "opa"


def test_remote_permit_does_not_compare_response_revision_to_local_placeholder():
    def transport(_endpoint, _payload, _headers, _timeout):
        return {"allowed": True, "policy_version": "remote-revision-7"}

    catalog = Catalog()
    catalog.resource("document", title="Document", actions=("read",))
    authz = Authz(
        catalog,
        PolicySet(version="local-metadata-1"),
        evaluator=OpaEvaluator("http://pdp.test", transport=transport),
    )
    runtime = AgentRuntime(authz)
    request = AgentRequest(
        subject=Subject(email="alice@example.com"),
        operation="document.read",
        phase="execute",
        tool_name="read_document",
        resource=Resource("document", "doc-1"),
        arguments={"document_id": "doc-1"},
    )
    permit = runtime.issue_permit(request, secret="permit-secret", resource_version="7", now=100.0)

    assert permit.policy_version == "remote-revision-7"
    assert runtime.verify_permit(
        request,
        permit,
        secret="permit-secret",
        resource_version="7",
        now=101.0,
    )


def test_external_decision_does_not_claim_a_local_policy_digest_as_remote_truth():
    def transport(_endpoint, _payload, _headers, _timeout):
        return {
            "allowed": True,
            "policy_version": "remote-revision-7",
            "policy_digest": "remote-digest-7",
        }

    catalog = Catalog()
    catalog.resource("document", title="Document", actions=("read",))
    authz = Authz(
        catalog,
        PolicySet(version="local-metadata-1"),
        evaluator=OpaEvaluator("http://pdp.test", transport=transport),
    )

    decision = authz.can(
        Subject(email="alice@example.com"),
        operation="document.read",
        resource=Resource("document", "doc-1"),
    )

    assert decision.allowed
    assert decision.policy_version == "remote-revision-7"
    assert decision.policy_digest == "remote-digest-7"

    no_digest = Authz(
        catalog,
        PolicySet(version="local-metadata-1"),
        evaluator=OpaEvaluator("http://pdp.test", transport=lambda *_: {"allowed": True}),
    ).can(
        Subject(email="alice@example.com"),
        operation="document.read",
        resource=Resource("document", "doc-1"),
    )
    assert no_digest.policy_digest == ""


def _production_remote_authz(evaluator):
    catalog = Catalog()
    catalog.resource("document", title="Document", actions=("read",), tenant_required=True)
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": True},
        },
    )
    return Authz.production(catalog, PolicySet(version="local-metadata-1"), resources, evaluator=evaluator)


def test_production_remote_backend_rejects_insecure_or_unbound_configuration():
    calls: list[object] = []

    def transport(*_args):
        calls.append(object())
        return {"allowed": True}

    authz = _production_remote_authz(
        OpaEvaluator("http://pdp.invalid", transport=transport)
    )
    decision = authz.can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert calls == []
    assert {
        item["code"] for item in authz.readiness()["issues"]
    } >= {
        "backend.remote_https_required",
        "backend.remote_custom_transport_unsupported",
        "backend.remote_policy_version_required",
        "backend.remote_policy_digest_required",
    }


def test_standard_remote_transport_rejects_an_unverified_tls_context() -> None:
    insecure_context = ssl._create_unverified_context()  # noqa: SLF001 - adversarial TLS fixture

    with pytest.raises(ValueError, match="verify both the TLS certificate and hostname"):
        JsonPdpEvaluator("https://pdp.example.test/allow", ssl_context=insecure_context)

    with pytest.raises(ValueError, match="verify both the TLS certificate and hostname"):
        _urllib_transport(
            "https://pdp.example.test/allow",
            {"request": "value"},
            {},
            1.0,
            ssl_context=insecure_context,
        )


@pytest.mark.parametrize(
    "headers",
    (
        {"X-Authz-Request-Id": "forged"},
        {"Content-Type": "text/plain"},
        {"Authorization": "Bearer good\r\nX-Injected: true"},
        {"X-Test": "bad\x00value"},
        {" X-Test": "value"},
        {"X-Test": "one", "x-test": "two"},
    ),
)
def test_remote_pdp_rejects_reserved_or_malformed_configured_headers(
    headers: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="PDP header"):
        OpaEvaluator("https://pdp.example.test/allow", headers=headers)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda context: setattr(context, "check_hostname", False),
        lambda context: (
            setattr(context, "check_hostname", False),
            setattr(context, "verify_mode", ssl.CERT_OPTIONAL),
        ),
    ],
)
def test_standard_remote_transport_rejects_all_unverified_tls_context_variants(mutate) -> None:
    context = ssl.create_default_context()
    mutate(context)

    with pytest.raises(ValueError, match="verify both the TLS certificate and hostname"):
        JsonPdpEvaluator("https://pdp.example.test/allow", ssl_context=context)


def test_production_remote_backend_rejects_a_host_attested_custom_transport() -> None:
    calls: list[object] = []

    def transport(*_args):
        calls.append(object())
        return {"allowed": True}

    evaluator = OpaEvaluator(
        "https://pdp.example.test/allow",
        transport=transport,
        transport_security="host_attested",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
    )
    decision = _production_remote_authz(evaluator).can(
        Subject(id="alice", tenant_id="acme"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    )

    assert not decision.allowed
    assert decision.reason_code == "backend.not_production_ready"
    assert calls == []
    assert "backend.remote_custom_transport_unsupported" in evaluator.production_readiness()["issues"]


def test_remote_backend_requires_response_envelope_binding():
    def drifted_transport(_endpoint, _payload, _headers, _timeout):
        return {
            "allowed": True,
            "request_id": "stale-request",
            "contract_version": "999",
            "catalog_fingerprint": "stale-catalog",
            "policy_version": "remote-revision-7",
            "policy_digest": "remote-digest-7",
        }

    evaluator = OpaEvaluator(
        "https://pdp.example.test/allow",
        transport=drifted_transport,
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        allowed_hosts=("pdp.example.test",),
    )
    decision = evaluator.authorize(_request())

    assert not decision.allowed
    assert decision.reason_code == "opa.response_binding_invalid"


def test_remote_backend_accepts_an_exactly_bound_response_in_development_transport():
    def bound_transport(_endpoint, _payload, headers, _timeout):
        return {
            "allowed": True,
            "request_id": headers["x-authz-request-id"],
            "trace_id": headers.get("x-authz-trace-id", ""),
            "contract_version": headers["x-authz-contract-version"],
            "catalog_fingerprint": headers["x-authz-catalog-fingerprint"],
            "policy_version": headers["x-authz-policy-version"],
            "policy_digest": headers["x-authz-policy-digest"],
        }

    evaluator = OpaEvaluator(
        "https://pdp.example.test/allow",
        transport=bound_transport,
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        allowed_hosts=("pdp.example.test",),
    )
    decision = evaluator.authorize(_request())

    assert decision.allowed
    assert decision.policy_version == "remote-revision-7"
    assert decision.policy_digest == "remote-digest-7"


def test_standard_remote_pdp_configuration_can_be_production_ready() -> None:
    evaluator = OpaEvaluator(
        "https://pdp.example.test/allow",
        policy_version="remote-revision-7",
        expected_policy_digest="remote-digest-7",
        allowed_hosts=("pdp.example.test",),
    )

    assert evaluator.production_readiness()["ready"]


def test_standard_transport_does_not_follow_redirects_or_forward_credentials():
    receiver_headers: list[dict[str, str]] = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib handler API
            receiver_headers.append(
                {str(name).lower(): str(value) for name, value in self.headers.items()}
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            return

    receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    receiver_thread = Thread(target=receiver.serve_forever, daemon=True)
    receiver_thread.start()

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib handler API
            self.send_response(302)
            self.send_header("location", f"http://127.0.0.1:{receiver.server_port}/captured")
            self.end_headers()

        def log_message(self, *_args):
            return

    redirector = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    redirector_thread = Thread(target=redirector.serve_forever, daemon=True)
    redirector_thread.start()
    try:
        with pytest.raises(RuntimeError, match="PDP request failed"):
            _urllib_transport(
                f"http://127.0.0.1:{redirector.server_port}/allow",
                {"request": "value"},
                {"authorization": "Bearer redirect-test"},
                1.0,
            )
    finally:
        redirector.shutdown()
        redirector_thread.join(timeout=2)
        receiver.shutdown()
        receiver_thread.join(timeout=2)

    assert receiver_headers == []


class _PdpHandler(BaseHTTPRequestHandler):
    responses = {
        "/opa": {
            "result": {
                "allow": True,
                "policy": "opa-agent-policy",
                "obligations": {"data_scope": {"mode": "tenant"}},
            }
        },
        "/cerbos": {
            "resourceInstances": {
                "employee-1": {"actions": {"ai_employee.delete": "EFFECT_ALLOW"}}
            }
        },
        "/openfga": {"allowed": True},
        "/spicedb": {"permissionship": "PERMISSIONSHIP_HAS_PERMISSION"},
        "/authzen": {"decision": {"allow": True}},
    }
    received: list[tuple[str, dict, dict[str, str]]] = []

    def do_POST(self):  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.received.append(
            (
                self.path,
                body,
                {str(name).lower(): str(value) for name, value in self.headers.items()},
            )
        )
        # A PDP configured with an expected policy revision must echo the
        # SDK-owned request envelope. This turns the shared local test server
        # into a contract test for every protocol adapter rather than relying
        # on the old decision-only response shape.
        response = dict(self.responses.get(self.path, {"allow": False}))
        response.update(
            {
                "request_id": self.headers.get("x-authz-request-id", ""),
                "trace_id": self.headers.get("x-authz-trace-id", ""),
                "contract_version": self.headers.get("x-authz-contract-version", ""),
                "catalog_fingerprint": self.headers.get("x-authz-catalog-fingerprint", ""),
                "policy_version": self.headers.get("x-authz-policy-version", ""),
            }
        )
        encoded = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


@pytest.fixture()
def pdp_server():
    _PdpHandler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PdpHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _PdpHandler.received
    finally:
        server.shutdown()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    ("path", "factory"),
    [
        ("/opa", OpaEvaluator),
        ("/cerbos", CerbosEvaluator),
        (
            "/openfga",
            lambda endpoint, **kwargs: OpenFgaEvaluator(
                endpoint,
                operation_mapper=lambda _request: "can_delete",
                **kwargs,
            ),
        ),
        (
            "/spicedb",
            lambda endpoint, **kwargs: SpiceDbEvaluator(
                endpoint,
                operation_mapper=lambda _request: "delete",
                **kwargs,
            ),
        ),
        ("/authzen", AuthzenEvaluator),
    ],
)
def test_remote_backend_connectivity_and_wire_contract(pdp_server, path, factory):
    endpoint, received = pdp_server
    evaluator = factory(f"{endpoint}{path}", policy_version="remote-test-1")

    decision = evaluator.authorize(_request())

    assert decision.allowed is True
    assert decision.policy_version == "remote-test-1"
    assert decision.reason_code == f"{evaluator.name}.allow"
    if evaluator.name == "opa":
        assert decision.policy == "opa-agent-policy"
        assert decision.obligations["data_scope"]["mode"] == "tenant"
    request_path, payload, headers = received[-1]
    assert request_path == path
    assert payload
    assert headers["x-authz-contract-version"] == "1.0"
    assert headers["x-authz-request-id"] == "request-wire-1"
    assert headers["x-authz-trace-id"] == "trace-wire-1"
    assert headers["x-authz-catalog-fingerprint"] == "a" * 64
    if evaluator.name == "opa":
        assert payload["input"]["operation"] == "ai_employee.delete"
        assert payload["input"]["arguments"] == {}
        assert payload["input"]["context"] == {}
        assert "email" not in payload["input"]["subject"]
        assert payload["input"]["request_id"] == "request-wire-1"
    elif evaluator.name == "cerbos":
        assert payload["resource"]["kind"] == "ai_employee"
    elif evaluator.name == "openfga":
        assert payload["tuple_key"]["object"] == "ai_employee:employee-1"
        assert payload["tuple_key"]["relation"] == "can_delete"
    elif evaluator.name == "spicedb":
        assert payload["resource"]["objectId"] == "employee-1"
        assert payload["permission"] == "delete"
    else:
        assert payload["action"]["name"] == "ai_employee.delete"


def test_remote_backend_fails_closed_on_malformed_response():
    def broken_transport(_endpoint, _payload, _headers, _timeout):
        return {"unexpected": "shape"}

    evaluator = OpaEvaluator("http://pdp.invalid", transport=broken_transport)
    decision = evaluator.authorize(_request())

    assert decision.allowed is False
    assert decision.reason_code == "opa.error"


@pytest.mark.parametrize(
    ("factory", "readiness_issue"),
    [
        (OpenFgaEvaluator, "backend.openfga_operation_mapper_required"),
        (SpiceDbEvaluator, "backend.spicedb_operation_mapper_required"),
    ],
)
def test_relation_backends_require_an_explicit_operation_mapping(factory, readiness_issue):
    calls: list[object] = []
    evaluator = factory(
        "https://pdp.example.test/check",
        transport=lambda *_args: calls.append(object()) or {"allowed": True},
    )
    decision = evaluator.authorize(_request())

    assert not decision.allowed
    assert decision.reason_code == f"{evaluator.name}.error"
    assert readiness_issue in evaluator.production_readiness()["issues"]
    assert calls == []


@pytest.mark.parametrize(
    ("factory", "invalid_mapping"),
    [
        (OpenFgaEvaluator, "document.read"),
        (SpiceDbEvaluator, "DocumentRead"),
    ],
)
def test_relation_backend_operation_mapping_must_match_its_target_grammar(factory, invalid_mapping):
    evaluator = factory(
        "https://pdp.example.test/check",
        operation_mapper=lambda _request: invalid_mapping,
    )

    decision = evaluator.authorize(_request())

    assert not decision.allowed
    assert decision.reason_code == f"{evaluator.name}.error"


@pytest.mark.parametrize("mapping", ["_", "_a", "trailing_"])
def test_spicedb_operation_mapping_rejects_invalid_identifier_shapes(mapping):
    evaluator = SpiceDbEvaluator(
        "https://pdp.example.test/check",
        operation_mapper=lambda _request: mapping,
    )

    assert not evaluator.authorize(_request()).allowed


def test_spicedb_operation_mapping_accepts_a_valid_private_identifier() -> None:
    evaluator = SpiceDbEvaluator(
        "https://pdp.example.test/check",
        transport=lambda *_args: {"permissionship": "PERMISSIONSHIP_HAS_PERMISSION"},
        operation_mapper=lambda _request: "_ab",
    )

    assert evaluator.authorize(_request()).allowed


def test_remote_protocol_headers_cannot_be_configured_or_overridden():
    observed: dict[str, str] = {}

    def transport(_endpoint, _payload, headers, _timeout):
        observed.update(headers)
        return {"allowed": True}

    with pytest.raises(ValueError, match="reserved"):
        OpaEvaluator(
            "http://pdp.invalid",
            transport=transport,
            headers={"x-authz-request-id": "spoofed"},
        )

    evaluator = OpaEvaluator(
        "http://pdp.invalid",
        transport=transport,
        headers={"authorization": "Bearer trusted-config"},
    )

    decision = evaluator.authorize(_request())

    assert decision.allowed
    assert observed["x-authz-request-id"] == "request-wire-1"
    assert observed["x-authz-trace-id"] == "trace-wire-1"
    assert observed["authorization"] == "Bearer trusted-config"


def test_cerbos_selects_the_requested_action_from_multi_action_response():
    def transport(_endpoint, _payload, _headers, _timeout):
        return {
            "resourceInstances": {
                "employee-1": {
                    "actions": {
                        "ai_employee.delete": "EFFECT_DENY",
                        "ai_employee.update": "EFFECT_ALLOW",
                    }
                }
            }
        }

    evaluator = CerbosEvaluator("http://cerbos.test", transport=transport)

    decision = evaluator.authorize(_request("ai_employee.delete"))

    assert decision.allowed is False
    assert decision.reason_code == "cerbos.deny"
