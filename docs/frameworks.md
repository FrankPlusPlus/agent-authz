# Agent Framework Integrations

Authz does not replace LangGraph or Agno. It wraps the places where those
frameworks expose or execute a Tool, so the framework keeps doing orchestration
and Authz keeps doing authorization.

```text
authenticated request
        |
        v
LangGraph / Agno decides what to call
        |
        v
Authz guard builds AgentRequest
        |
        v
policy backend -> Decision
        |
   allow | deny
        v
tool or node side effect
```

The LangGraph/Agno adapters have no framework dependency. Install the framework
in your application as usual; the SDK only needs Python callables. MCP has a
separate optional, contract-tested v2 adapter because an MCP Tool is a public
server capability rather than just an in-process callable.

## FastAPI

For a real HTTP boundary, install the optional extra:

```bash
python -m pip install "agent-authz-sdk[fastapi] @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b6"
```

`FastAPIAuthz` turns a registered API entrypoint into a dependency. The
authenticated subject comes from the application's auth layer, while the path
parameter is only a coordinate for `ResourceRegistry` to resolve:

```python
from fastapi import Depends, FastAPI, HTTPException, Request, status
from authz_sdk import FastAPIAuthz, Subject

app = FastAPI()

def subject_from_auth_middleware(request: Request) -> Subject:
    principal = getattr(request.state, "authz_subject", None)
    if not isinstance(principal, Subject) or not principal.authenticated:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return principal

api_authz = FastAPIAuthz(
    authz,  # Authz.production(catalog, policies, resources)
    subject=subject_from_auth_middleware,
)
read_document = api_authz.dependency(
    entrypoint="GET /documents/{document_id}",
    resource_type="document",
    resource_id=lambda request: request.path_params["document_id"],
)

@app.get("/documents/{document_id}")
async def get_document(document_id: str, _decision=Depends(read_document)):
    return repository.read(document_id)
```

Missing or invalid identity returns `401`; an authenticated but unauthorized
request returns a `403` containing only a stable decision code and operation,
not relationship facts or a policy explanation. See the secure integration
template [`fastapi_document_agent.py`](../examples/fastapi_document_agent.py).

## MCP v2

Install the optional official MCP v2 SDK integration:

```bash
python -m pip install "agent-authz-sdk[mcp] @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b6"
```

Bind the public MCP Tool name in `Catalog`, then register the Tool through
`MCPAuthz`. The adapter derives the shared operation from that catalog binding
and checks it immediately before the callable runs:

```python
from mcp.server import MCPServer
from authz_sdk import MCPAuthz

mcp = MCPServer("documents")
catalog.bind_entrypoint("mcp.tool", "read_document", "document.read")

guard = MCPAuthz(
    AgentRuntime(authz),
    # A provider that reads an already verified request-local MCP principal.
    subject=subject_from_verified_mcp_context,
)

@guard.tool(
    mcp,
    name="read_document",
    resource_type="document",
    resource_id=lambda call: call.kwargs["document_id"],
)
def read_document(document_id: str):
    return repository.read(document_id)
```

Do not derive `subject` from `document_id` or any other Tool argument. MCP
OAuth/token validation and per-client `tools/list` filtering remain the MCP
server's responsibility; this adapter guarantees the final execute guard, not
dynamic discovery. In an `Authz.production(...)` runtime, the catalog binding
above is required by default; use an explicit operation without it only as a
short-lived, reviewed migration exception. See the full [MCP integration
guide](mcp.md).

In production, `subject` must also be a request-local provider. A static
`Subject` requires the explicit `allow_static_subject=True` exception and is
only suitable for a process dedicated to one principal.

## Agno

Agno accepts Python functions in `Agent(tools=[...])`. Wrap each tool once when
the Agent is assembled:

```python
from agno.agent import Agent
from authz_sdk import AgnoAuthz, AgentRuntime, Subject

subject = Subject(id="user-1", email="alice@example.com", tenant_id="acme")
guard = AgnoAuthz(
    AgentRuntime(authz),
    subject=subject,
    agent_id="research-agent",
    session_id="session-42",
)

def search_finance(query: str) -> str:
    return vector_store.search(query, tenant_id="acme")

finance_search = guard.tool(
    search_finance,
    operation="knowledge_base.query",
    # Authz.production resolves these through its ResourceRegistry.
    resource_type="knowledge_base",
    resource_id="finance",
    tool_name="finance_search",
    pack_name="finance_research",
)

agent = Agent(tools=[finance_search])
```

For a resource ID that comes from the tool arguments, pass its coordinates and
let `Authz.production` resolve them through its trusted `ResourceRegistry`.
Do not construct `owner=True`/`viewer=True` from model output:

```python
guarded = guard.tool(
    read_document,
    operation="document.read",
    resource_type="document",
    resource_id=lambda call: call.kwargs.get("document_id") or call.args[0],
)
```

The wrapper preserves the function name, docstring, signature metadata, and
async behavior that Agno uses to build its tool schema.

If a policy needs a tool parameter, pass a deliberately selected JSON mapping
with `arguments=lambda call: {"document_id": call.kwargs["document_id"]}`.
Do not forward secrets, prompts, or arbitrary model output to a remote PDP.

## LangGraph

LangGraph graph nodes normally receive a state mapping. Put the authenticated
subject into state in the host layer, then protect the node:

```python
from authz_sdk import LangGraphAuthz

graph_authz = LangGraphAuthz(
    AgentRuntime(authz),
    agent_id="research-graph",
    session_id="session-42",
)

def retrieve(state):
    return {**state, "documents": search(state["query"])}

protected_retrieve = graph_authz.node(
    retrieve,
    operation="knowledge_base.query",
    node_name="retrieve",
    subject_from_state=lambda state: state["authz_subject"],
    resource_type="knowledge_base",
    resource_id=lambda call: call.args[0]["knowledge_base_id"],
)

builder.add_node("retrieve", protected_retrieve)
```

For a LangGraph tool node, use the same `graph_authz.tool(...)` method. The
business operation is the important part; the graph node name is only an
entrypoint for audit and explanation.

## Discover, mount, execute

Wrapping execution is mandatory, but it is not the only useful check:

```python
visible = graph_authz.filter_tools(subject, [
    {"name": "finance_search", "operation": "knowledge_base.query"},
])
```

- `discover`: hide tools the subject should not see.
- `mount`: prevent a Pack or tool bundle from being attached to an Agent.
- `execute`: the final check immediately before reading data or causing a side
  effect. This wrapper protects this boundary.

Discovery is a usability optimization, not a security boundary. A caller can
always bypass a filtered list, so the execute guard must remain in place.

For a resource-scoped operation, every phase still needs its concrete resource.
`context["authz_phase"]` is never allowed to waive `requires_resource`; a
model or HTTP caller can write ordinary context. If a visibility decision is
truly resource-free, register a separate, explicit operation such as
`agent.tool.discover` with `requires_resource=False`, then continue to enforce
the resource-scoped business operation at execution.

## Framework responsibilities versus Authz responsibilities

| Layer | Owns |
| --- | --- |
| LangGraph / Agno | graph transitions, model calls, retries, streaming, tool schema, session lifecycle |
| Authz | subject normalization, operation mapping, trusted resource context, policy decision, denial, permit and audit fields |
| Application | authentication, resource lookup, SQL/vector filtering, side effects, audit storage |
| External backend | Casbin matcher, OPA/Cerbos policy, OpenFGA/SpiceDB relationship graph and consistency |

Authz cannot make a vector store filter rows just because a PDP returned
`allowed=true`. The application must apply any returned `Decision.obligations`
at the data boundary.
