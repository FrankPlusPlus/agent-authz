# Enforcement coverage manifest

`CoverageManifest` turns `Entrypoint` from an audit label into a CI-checkable
contract:

```text
catalog operation
    -> declared API / Tool / Agent / task / RAG entrypoint
    -> framework-observed or explicitly host-attested final Authz guard
    -> optional test/deployment evidence
```

It is an application integration inventory, not a magical source-code scanner.
It can prove that every operation *you put in the catalog* has a mapped and
recorded guard; it cannot find an unregistered route or hostile code that
bypasses your process's enforcement point. Keep normal code review, route
inventory, and integration tests.

Coverage is governance evidence, not a process-security boundary: code that
can deliberately modify/import private objects in the same Python process can
bypass an embedded PEP as well as its evidence. Strict reports are designed to
prevent ordinary integration mistakes from being mislabeled as adapter-observed
coverage, not to sandbox hostile host code.

## Make gaps fail CI

Create the manifest next to the catalog, hand it to adapters while registering
the application, and assert it after route/Tool/task registration. For
FastAPI, perform the assertion only after the app has assembled its routes:

```python
from authz_sdk import (
    CoverageManifest,
    FastAPIAuthz,
    record_fastapi_inventory,
    record_tool_inventory,
)

coverage = CoverageManifest(catalog)
coverage.require_final_execution("document.publish")
coverage.require_data_boundary("knowledge_chunk.read")

api_authz = FastAPIAuthz(
    authz,
    subject=current_subject,
    coverage=coverage,
)
read_document = api_authz.dependency(
    entrypoint="GET /documents/{document_id}",
    resource_type="document",
    resource_id=lambda request: request.path_params["document_id"],
)

# First create guarded callables with AgnoAuthz/LangGraphAuthz/protect_tool.
# Then verify the exact list handed to the Agent or custom Tool registry:
record_tool_inventory(coverage, agent_tools)
coverage.record_data_boundary(
    "knowledge_chunk.read",
    entrypoint="rag:knowledge_search",
    evidence="tests/test_retrieval.py::test_unauthorized_candidate_is_excluded",
)

# After @app.get(..., dependencies=[Depends(read_document)]) and every router
# is mounted, inspect FastAPI's actual dependency graph:
record_fastapi_inventory(coverage, app)
# Tool/MCP assembly is host-attested unless its framework exposes an
# inspectable registry. This report is explicitly labeled "attested".
coverage.assert_attested_complete()
```

`CoverageManifest(catalog)` requires every catalog operation by default. If a
shared catalog contains an operation deliberately absent from one service,
record the reason instead of muting it:

```python
coverage.exempt(
    "document.delete",
    reason="the document-reader service is intentionally read-only",
)
```

## What it checks

| Check | Gap code | Why it matters |
| --- | --- | --- |
| Required operation is absent from the catalog | `coverage.operation_unregistered` | Stops a hand-written string from becoming unaudited policy surface |
| Catalog operation has no entrypoint | `coverage.operation_entrypoint_missing` | Makes a new capability declare where it is reached |
| Catalog entrypoint has no recorded guard | `coverage.entrypoint_enforcement_missing` | Catches a route/Tool mapping that was never wired through an adapter |
| Guard is only host-attested | `coverage.entrypoint_enforcement_attested_only` | Strict coverage never confuses an application claim with framework-observed evidence |
| Runtime inventory is only host-attested | `coverage.entrypoint_inventory_attested_only` | Strict coverage requires the adapter itself to observe an assembled framework inventory |
| Adapter records an unknown/mismatched entrypoint | `coverage.entrypoint_unregistered` / `coverage.entrypoint_operation_mismatch` | Prevents a guard from claiming the wrong business operation |
| High-risk operation has no final guard | `coverage.final_enforcement_missing` | Ensures discovery-only visibility is not the last check |
| Required retrieval operation lacks a data boundary declaration | `coverage.data_boundary_missing` | Makes prompt-boundary filtering/pushdown a conscious deployment decision |

The `evidence` field is intentionally plain text: use a stable test name,
route inventory ID, or deployment reference. It helps reviewers link a
manifest entry to a real allow/deny test, but does not replace executing that
test.

## Recommended workflow

1. Register all resource actions and explicit operations in `Catalog`.
2. Bind every API, Tool, Agent phase, task, MCP handler, and RAG surface to a
   business operation.
3. For FastAPI, call `record_fastapi_inventory()` after all routes are mounted;
   it finds matching SDK guards in the assembled dependency graph, and
   `assert_complete()` is strict. For Python Agent tools, call
   `record_tool_inventory()` with the exact callable list passed to the
   framework; for MCP and custom queues use explicit host attestations and
   `assert_attested_complete()` unless you add a framework-specific verifier.
4. Mark destructive actions with `require_final_execution()`.
5. Mark retrieval operations with `require_data_boundary()` and record the
   `CandidateFilter`/pushdown boundary.
6. Call strict `assert_complete()` at an observable framework boundary. Where
   that is impossible, call the explicitly weaker `assert_attested_complete()`
   and keep a real allow/deny integration test next to the assembly code.

This is the core governance advantage of the `Entrypoint` concept: policy
stays about a business operation, while coverage shows where that operation is
actually enforced.

## Discover mounted FastAPI routes

`CoverageManifest` deliberately does not inspect source code, but FastAPI
applications can compare their *mounted* routes with the catalog after all
routers are registered. This turns a forgotten catalog binding or a stale
binding into a CI-visible gap:

```python
from authz_sdk import record_fastapi_inventory

# Run after app.include_router(...) calls. Built-in /docs and /openapi.json
# routes are skipped. A created-but-unmounted dependency does not count.
record_fastapi_inventory(
    coverage,
    app,
    ignored=("/health",),  # explicit non-business endpoints only
)
coverage.assert_complete()
```

The inventory uses the canonical catalog form `"METHOD /path"`, for example
`"POST /documents/{document_id}/publish"`. It reports both of these gaps:

- `coverage.discovered_entrypoint_unregistered`: a live application route has
  no matching `Catalog.bind_entrypoint("api", ...)` mapping;
- `coverage.catalog_entrypoint_not_discovered`: the catalog claims an API
  route that the assembled application did not mount.

For FastAPI routes, the inventory also traverses the assembled dependency graph
and accepts coverage only when it finds a matching SDK-created guard. It does
not prove arbitrary handler code paths, custom callables, process isolation, or
database transaction correctness. It is deliberately scoped between
hand-written manifests and an unreliable claim of universal source-code
discovery.

## Verify an Agent Tool registry

For plain Python Agent frameworks, the SDK cannot reliably inspect every
framework's private registry. Give it the same list you pass to the framework:

```python
from authz_sdk import record_tool_inventory

agent_tools = [
    guarded_read_document,
    guarded_publish_document,
]
agent = Agent(tools=agent_tools)

record_tool_inventory(coverage, agent_tools)
coverage.assert_attested_complete()
```

This records `tool:*` coverage only when a callable in that exact list was
created by `protect_tool`, and detects an unguarded callable or a stale/missing
catalog mapping in the supplied list. It cannot prove that the framework later
used the list, so use `coverage.assert_attested_complete()` for this path; the
report is intentionally labeled `attested`, not verified. Keep registration in
one assembly function and pair it with a real allow/deny execution test.
