from __future__ import annotations

import asyncio
from pathlib import Path
import runpy

import pytest

from authz_sdk import (
    AgnoAuthz,
    AgentRuntime,
    Authz,
    Catalog,
    CoverageManifest,
    FastAPIAuthz,
    AuthorizationError,
    LangGraphAuthz,
    PolicySet,
    Resource,
    ResourceRegistry,
    Subject,
)


def _runtime() -> AgentRuntime:
    catalog = Catalog()
    catalog.resource("document", actions=("read",), relations=("viewer",))
    policies = PolicySet()
    policies.bind(
        id="document_viewer",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    return AgentRuntime(Authz(catalog, policies))


def _production_runtime() -> AgentRuntime:
    catalog = Catalog()
    catalog.resource(
        "document",
        actions=("read",),
        relations=("viewer",),
        tenant_required=True,
    )
    policies = PolicySet()
    policies.bind(
        id="document_viewer",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": subject.id == "alice"},
        },
    )
    return AgentRuntime(Authz.production(catalog, policies, resources))


def test_agno_wrapper_authorizes_before_sync_tool_and_preserves_metadata():
    calls: list[str] = []
    subject = Subject(email="alice@example.com")
    resource = Resource("document", "doc-1", relations={"viewer": True})

    def read_document(document_id: str) -> str:
        """Read one document."""

        calls.append(document_id)
        return "content"

    guarded = AgnoAuthz(_runtime(), subject=subject).tool(
        read_document,
        operation="document.read",
        resource=resource,
        arguments=lambda call: {"document_id": call.args[0]},
    )

    assert guarded.__name__ == "read_document"
    assert guarded.__doc__ == "Read one document."
    assert guarded("doc-1") == "content"
    assert calls == ["doc-1"]


def test_agno_wrapper_registers_its_final_guard_in_a_coverage_manifest():
    catalog = Catalog()
    catalog.resource("document", actions=("read",), relations=("viewer",))
    catalog.bind_entrypoint("tool", "read_document", "document.read")
    policies = PolicySet()
    policies.bind(
        id="document_viewer",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    manifest = CoverageManifest(catalog).require_final_execution("document.read")

    def read_document() -> str:
        return "content"

    guarded = AgnoAuthz(
        AgentRuntime(Authz.native(catalog, policies)),
        subject=Subject(id="alice"),
        coverage=manifest,
    ).tool(
        read_document,
        operation="document.read",
        resource=Resource("document", "doc-1", relations={"viewer": True}),
        coverage_evidence="tests/test_framework_integrations.py::test_agno_wrapper_registers_its_final_guard_in_a_coverage_manifest",
    )

    assert guarded() == "content"
    assert manifest.assert_complete().ready


def test_agno_wrapper_denies_before_side_effect():
    calls: list[str] = []
    resource = Resource("document", "doc-1", relations={"viewer": False})

    def delete_document() -> None:
        calls.append("deleted")

    guarded = AgnoAuthz(_runtime(), subject=Subject(email="outsider@example.com")).tool(
        delete_document,
        operation="document.read",
        resource=resource,
    )

    with pytest.raises(AuthorizationError) as error:
        guarded()
    assert error.value.decision.reason_code == "policy.deny"
    assert calls == []


def test_tool_wrapper_resolves_a_trusted_resource_from_tool_arguments_in_production():
    calls: list[str] = []

    def read_document(document_id: str) -> str:
        calls.append(document_id)
        return "content"

    guarded = AgnoAuthz(
        _production_runtime(),
        subject=Subject(id="alice", tenant_id="acme"),
    ).tool(
        read_document,
        operation="document.read",
        resource_type="document",
        resource_id=lambda call: call.args[0],
        arguments=lambda call: {"document_id": call.args[0]},
    )

    assert guarded("doc-1") == "content"
    assert calls == ["doc-1"]


def test_fastapi_dependency_resolves_a_trusted_resource_before_route_execution():
    fastapi = pytest.importorskip("fastapi")
    from fastapi import Depends
    from fastapi.testclient import TestClient

    catalog = Catalog()
    catalog.resource(
        "document",
        actions=("read",),
        relations=("viewer",),
        tenant_required=True,
    )
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    policies = PolicySet()
    policies.bind(
        id="document_viewer",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
            "relations": {"viewer": subject.id == "alice"},
        },
    )
    authz = Authz.production(catalog, policies, resources)
    def client_for(principal: Subject):
        manifest = CoverageManifest(catalog)
        guard = FastAPIAuthz(
            authz,
            subject=lambda request: request.state.authz_subject,
            coverage=manifest,
        )
        app = fastapi.FastAPI()

        @app.middleware("http")
        async def install_verified_identity(request, call_next):
            request.state.authz_subject = principal
            return await call_next(request)

        authorized = guard.dependency(
            entrypoint="GET /documents/{document_id}",
            resource_type="document",
            resource_id=lambda request: request.path_params["document_id"],
        )
        calls: list[str] = []

        @app.get("/documents/{document_id}")
        async def read_document(document_id: str, _decision=Depends(authorized)):
            calls.append(document_id)
            return {"status": "ok"}

        return TestClient(app), manifest, calls

    client, manifest, calls = client_for(Subject(id="alice", tenant_id="acme"))
    assert client.get("/documents/doc-1").json() == {"status": "ok"}
    denied_client, _, denied_calls = client_for(Subject(id="bob", tenant_id="acme"))
    denied = denied_client.get("/documents/doc-1")
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "policy.deny"
    assert manifest.assert_complete().ready
    assert calls == ["doc-1"]
    assert denied_calls == []


def test_fastapi_example_enforces_the_registry_loaded_document_boundary():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    namespace = runpy.run_path(
        str(Path(__file__).parents[1] / "examples" / "fastapi_document_agent.py")
    )
    unauthenticated = TestClient(namespace["app"])
    assert unauthenticated.get("/documents/doc-public").status_code == 401

    app = namespace["create_app"](
        subject_provider=lambda _request: Subject(id="alice", tenant_id="acme")
    )
    client = TestClient(app)

    # Forged request headers do not affect the host-provided identity.
    assert client.get("/documents/doc-public", headers={"x-user-id": "mallory"}).status_code == 200
    assert client.get("/documents/doc-private", headers={"x-user-id": "alice"}).status_code == 403


def test_langgraph_node_can_resolve_authenticated_subject_and_resource_from_state():
    calls: list[dict] = []
    subject = Subject(email="alice@example.com")
    resource = Resource("document", "doc-1", relations={"viewer": True})

    def node(state: dict) -> dict:
        calls.append(state)
        return {**state, "loaded": True}

    guarded = LangGraphAuthz(_runtime(), agent_id="graph-1").node(
        node,
        operation="document.read",
        node_name="load_document",
        subject_from_state=lambda state: state["authz_subject"],
        resource_from_state=lambda state: state["document"],
    )

    state = {"authz_subject": subject, "document": resource}
    result = guarded(state)
    assert result["loaded"] is True
    assert calls == [state]
    assert guarded.authz_operation == "document.read"
    assert guarded.authz_phase == "execute"


def test_langgraph_node_denies_without_calling_node():
    calls: list[bool] = []

    def node(state: dict) -> dict:
        calls.append(True)
        return state

    guarded = LangGraphAuthz(_runtime()).node(
        node,
        operation="document.read",
        subject=Subject(email="alice@example.com"),
        resource=Resource("document", "doc-1", relations={"viewer": False}),
    )
    with pytest.raises(AuthorizationError):
        guarded({})
    assert calls == []


def test_protect_tool_supports_async_callables():
    async def read_document() -> str:
        return "content"

    guarded = LangGraphAuthz(_runtime(), subject=Subject(email="alice@example.com")).tool(
        read_document,
        operation="document.read",
        resource=Resource("document", "doc-1", relations={"viewer": True}),
    )
    assert asyncio.run(guarded()) == "content"
