# Enforcement coverage manifest

`CoverageManifest` turns `Entrypoint` from an audit label into a CI-checkable
contract:

```text
catalog operation
    -> declared API / Tool / Agent / task / RAG entrypoint
    -> installed final Authz guard
    -> optional test/deployment evidence
```

It is an application integration inventory, not a magical source-code scanner.
It can prove that every operation *you put in the catalog* has a mapped and
recorded guard; it cannot find an unregistered route or hostile code that
bypasses your process's enforcement point. Keep normal code review, route
inventory, and integration tests.

## Make gaps fail CI

Create the manifest next to the catalog, hand it to adapters while registering
the application, and assert it after route/Tool/task registration:

```python
from authz_sdk import CoverageManifest, FastAPIAuthz

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

# AgnoAuthz(..., coverage=coverage).tool(...) and
# LangGraphAuthz(..., coverage=coverage).node(...) record their execute guard
# when the wrapper is assembled.
coverage.record_data_boundary(
    "knowledge_chunk.read",
    entrypoint="rag:knowledge_search",
    evidence="tests/test_retrieval.py::test_unauthorized_candidate_is_excluded",
)

coverage.assert_complete()  # raises CoverageError with stable gap codes
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
3. Let `FastAPIAuthz`, `AgnoAuthz`, or `LangGraphAuthz` record guards while
   they are assembled; call `record_enforcement()` directly for custom
   frameworks and job queues.
4. Mark destructive actions with `require_final_execution()`.
5. Mark retrieval operations with `require_data_boundary()` and record the
   `CandidateFilter`/pushdown boundary.
6. Call `assert_complete()` at startup or in an integration test.

This is the core governance advantage of the `Entrypoint` concept: policy
stays about a business operation, while coverage shows where that operation is
actually enforced.
