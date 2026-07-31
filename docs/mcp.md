# MCP v2 Tool execution boundary

`MCPAuthz` integrates with the official MCP Python SDK v2
`MCPServer.tool()` decorator. It performs the final authorization check
immediately before the registered Python Tool executes, while keeping MCP
optional from the SDK's core dependency graph.

```bash
python -m pip install "agent-authz-sdk[mcp] @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b2"
```

The optional extra is currently constrained to `mcp>=2,<3`; the integration is
contract-tested with an in-memory MCP v2 server/client pair. It uses the public
decorator API and does not couple the core package to MCP transports.

## Bind a Tool to a business operation once

Register the MCP Tool in the catalog, then let the adapter derive the operation
from that binding. The Tool name is an execution surface; the policy remains
about `document.read`.

```python
from contextvars import ContextVar

from mcp.server import MCPServer

from authz_sdk import AgentRuntime, CoverageManifest, MCPAuthz, Subject

mcp = MCPServer("documents")
catalog.bind_entrypoint("mcp.tool", "read_document", "document.read")
coverage = CoverageManifest(catalog).require_final_execution("document.read")
trusted_request_principal: ContextVar[Subject] = ContextVar("trusted_request_principal")


def subject_from_verified_mcp_context(_call):
    # Read a request-local principal only after the MCP server's OAuth/token
    # verifier or host middleware has validated it. Never read a Tool argument
    # such as {"user_id": "..."} here.
    return trusted_request_principal.get()


guard = MCPAuthz(
    AgentRuntime(authz),  # Authz.production(catalog, policies, resources)
    subject=subject_from_verified_mcp_context,
    coverage=coverage,
)


@guard.tool(
    mcp,
    name="read_document",
    # Authz.production resolves this coordinate through ResourceRegistry.
    resource_type="document",
    resource_id=lambda call: call.kwargs["document_id"],
    # Send no Tool arguments to a PDP unless policy genuinely needs one.
    coverage_evidence="tests/test_documents_mcp.py::test_read_document_denied",
)
def read_document(document_id: str) -> dict[str, str]:
    return repository.read(document_id)


coverage.assert_complete()
```

For an `Authz.production(...)` runtime, this catalog binding is mandatory by
default: a Tool cannot be registered merely by passing an explicit operation
string. That makes MCP execution surfaces visible to the catalog and
`CoverageManifest` inventory. An incremental migration may explicitly set
`MCPAuthz(..., require_catalog_binding=False)` and pass
`operation="document.read"`; treat that as a time-bounded exception, not a
way to bypass production coverage governance. If a catalog already binds the
same `mcp.tool` entrypoint, an operation mismatch always fails during server
assembly instead of waiting for a request.

## What the adapter protects

```text
verified MCP identity + Tool arguments
               |
               v
  MCPAuthz / AgentRuntime execute check
               |
               v
 ResourceRegistry loads tenant + relations
               |
               v
 policy decision -> Tool callable side effect
```

- A denied call never invokes the Tool callable.
- In the production profile, Tool arguments supply only resource coordinates;
  tenant and relation facts come from `ResourceRegistry`.
- A `CoverageManifest` records the `mcp.tool` final guard, so missing/mismapped
  registered capability surfaces can fail CI.
- The adapter preserves sync/async callable metadata for MCP schema generation.

## Boundaries MCPAuthz does not pretend to solve

MCP server authentication, token validation, consent, dynamic `tools/list`
filtering, client registration, transport configuration, and rate limits stay
with the MCP server and host application. In particular, a shared static MCP
server may list a Tool to a user who will later be denied at execution; use a
host-owned discovery policy/list filter if visibility itself is sensitive.

For a multi-tenant server, the `subject` provider must read an identity from a
request-local value established by verified MCP authentication or host
middleware. It must never derive identity from Tool arguments. `MCPAuthz`
cannot cryptographically prove that a provider is verified; it is the host's
identity boundary.

This is deliberate: visibility is not the final security boundary. The Tool
must still be checked after the real resource coordinate is known and just
before it reads data or causes a side effect.
