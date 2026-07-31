from __future__ import annotations

import asyncio

import pytest

from authz_sdk import (
    AgentRuntime,
    Authz,
    AuthorizationError,
    Catalog,
    CoverageManifest,
    MCPAuthz,
    PolicySet,
    ResourceRegistry,
    Subject,
)


def _runtime() -> tuple[AgentRuntime, CoverageManifest]:
    catalog = Catalog()
    catalog.resource(
        "document",
        actions=("read",),
        relations=("viewer",),
        tenant_required=True,
    )
    catalog.bind_entrypoint("mcp.tool", "read_document", "document.read")
    policies = PolicySet()
    policies.bind(
        id="document_read_viewer",
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
    return (
        AgentRuntime(Authz.production(catalog, policies, resources)),
        CoverageManifest(catalog).require_final_execution("document.read"),
    )


def test_mcp_adapter_registers_a_real_v2_tool_with_final_production_guard() -> None:
    pytest.importorskip("mcp")
    from mcp import Client
    from mcp.server import MCPServer

    runtime, coverage = _runtime()
    calls: list[str] = []
    server = MCPServer("Document test")
    guard = MCPAuthz(
        runtime,
        subject=Subject(id="alice", tenant_id="acme"),
        coverage=coverage,
    )

    @guard.tool(
        server,
        name="read_document",
        resource_type="document",
        resource_id=lambda call: call.kwargs["document_id"],
        coverage_evidence="tests/test_mcp_integration.py::test_mcp_adapter_registers_a_real_v2_tool_with_final_production_guard",
    )
    def read_document(document_id: str) -> dict[str, str]:
        calls.append(document_id)
        return {"document_id": document_id, "body": "permitted"}

    async def invoke() -> tuple[object, object]:
        async with Client(server) as client:
            tools = await client.list_tools()
            result = await client.call_tool("read_document", {"document_id": "doc-1"})
            return tools, result

    tools, result = asyncio.run(invoke())

    assert [tool.name for tool in tools.tools] == ["read_document"]
    assert not result.is_error
    assert calls == ["doc-1"]
    assert read_document.authz_operation == "document.read"
    assert read_document.authz_phase == "execute"
    assert coverage.assert_complete().ready


def test_mcp_adapter_denies_before_tool_side_effect() -> None:
    runtime, _coverage = _runtime()
    calls: list[bool] = []

    class DecoratorOnlyMcpServer:
        def tool(self, **_options):
            return lambda function: function

    guard = MCPAuthz(
        runtime,
        subject=Subject(id="bob", tenant_id="acme"),
    )

    @guard.tool(
        DecoratorOnlyMcpServer(),
        name="read_document",
        resource_type="document",
        resource_id=lambda call: call.kwargs["document_id"],
    )
    def read_document(document_id: str) -> str:
        calls.append(True)
        return document_id

    with pytest.raises(AuthorizationError):
        read_document(document_id="doc-1")
    assert calls == []


def test_mcp_adapter_returns_a_real_client_error_before_tool_side_effect() -> None:
    pytest.importorskip("mcp")
    from mcp import Client
    from mcp.server import MCPServer

    runtime, _coverage = _runtime()
    calls: list[str] = []
    server = MCPServer("Denied document test")
    guard = MCPAuthz(runtime, subject=Subject(id="bob", tenant_id="acme"))

    @guard.tool(
        server,
        name="read_document",
        resource_type="document",
        resource_id=lambda call: call.kwargs["document_id"],
    )
    def read_document(document_id: str) -> str:
        calls.append(document_id)
        return document_id

    async def invoke() -> object:
        async with Client(server) as client:
            return await client.call_tool("read_document", {"document_id": "doc-1"})

    result = asyncio.run(invoke())

    assert result.is_error
    assert calls == []


def test_mcp_adapter_derives_a_catalog_operation_and_rejects_a_mismatch() -> None:
    runtime, _coverage = _runtime()

    class DecoratorOnlyMcpServer:
        def tool(self, **_options):
            return lambda function: function

    guard = MCPAuthz(runtime, subject=Subject(id="alice", tenant_id="acme"))

    @guard.tool(
        DecoratorOnlyMcpServer(),
        name="read_document",
        resource_type="document",
        resource_id=lambda call: call.kwargs["document_id"],
    )
    def derived(document_id: str) -> str:
        return document_id

    assert derived.authz_operation == "document.read"

    with pytest.raises(ValueError, match="is mapped to"):

        @guard.tool(
            DecoratorOnlyMcpServer(),
            name="read_document",
            operation="document.delete",
        )
        def mismatched() -> None:
            return None


def test_production_mcp_adapter_requires_a_catalog_binding_by_default() -> None:
    runtime, _coverage = _runtime()

    class DecoratorOnlyMcpServer:
        def tool(self, **_options):
            return lambda function: function

    server = DecoratorOnlyMcpServer()
    production_guard = MCPAuthz(runtime, subject=Subject(id="alice", tenant_id="acme"))

    with pytest.raises(ValueError, match="requires Catalog.bind_entrypoint"):

        @production_guard.tool(server, name="legacy_read", operation="document.read")
        def missing_catalog_binding() -> None:
            return None

    migration_guard = MCPAuthz(
        runtime,
        subject=Subject(id="alice", tenant_id="acme"),
        require_catalog_binding=False,
    )

    @migration_guard.tool(server, name="legacy_read", operation="document.read")
    def explicit_migration_operation() -> None:
        return None

    assert explicit_migration_operation.authz_operation == "document.read"
