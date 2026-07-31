# Production Boundary Guide

`Authz.production(...)` is the short, safe starting point for a service boundary. It is not a hosted control plane and cannot secure a path that bypasses it.

```text
registered operation + tenant context + trusted resource
                              |
                              v
                     policy decision / audit
                              |
                              v
          candidate filter or one-time side-effect permit
```

## Start with the production profile

```python
from authz_sdk import Authz, Catalog, PolicySet, ResourceRegistry, Subject

catalog = Catalog()
catalog.resource(
    "document",
    actions=("read", "publish"),
    relations=("viewer", "editor"),
    tenant_required=True,
)
policies = PolicySet(version="2026.08.01")
policies.bind(
    id="document_read_viewer",
    operation="document.read",
    template="relation",
    relations=("viewer",),
)
resources = ResourceRegistry()
resources.register("document", load_document_from_your_database)

authz = Authz.production(catalog, policies, resources)
decision = authz.can(
    Subject(id="alice", tenant_id="acme"),
    operation="document.read",
    resource_type="document",
    resource_id="doc-42",
)
```

The profile enables strict catalog mode, required subject tenant context, and
`ResourceRegistry` provenance. An unknown operation, a caller-created relation,
a resource without a tenant, a tenantless subject, or a cross-tenant request is
denied before the evaluator is called. A resource requirement cannot be waived
by writing `authz_phase=discover` into context. Run `authz.readiness()` at
startup to assess the local configuration it can prove. Its `boundary_ready`
value is deliberately only a local enforcement-boundary result;
`operational_ready` is `None` because the SDK cannot certify your KMS, shared
stores, rollout, audit retention, or host-path coverage.

## Prove declared Agent entrypoints are guarded

Use `CoverageManifest` once the catalog has more than a single route. It
checks that every declared operation has an entrypoint and that each declared
entrypoint has a recorded final guard; it can also require an explicit final
execution guard for destructive actions and a prompt/data boundary declaration
for retrieval. Call `coverage.assert_complete()` at startup or in CI after
routes, Tools, tasks, and graph nodes are registered. See the
[coverage guide](coverage.md). This is a governance check over your declared
inventory, not a source-code scanner for unregistered host paths.

## Make the wire contract observable

`Authz.can()` accepts optional `request_id`, `trace_id`, and `catalog_fingerprint`. Decisions return those fields plus `contract_version`, `catalog_fingerprint`, and `policy_version`. Native decisions also include the embedded `PolicySet` digest; a remote PDP may return its own `policy_digest`, but an SDK-side digest never claims to prove a remote policy snapshot. A mismatched catalog fingerprint fails closed, catching a gateway or PDP talking about a stale operation catalog.

## Record a privacy-safe decision trail

```python
from authz_sdk import AuditRedactor, Authz, JsonlAuditSink

# JsonlAuditSink is useful locally; fsync improves local crash durability but
# does not make the file immutable. Production normally uses a durable,
# monitored delivery pipeline behind the same AuditSink protocol.
audit = JsonlAuditSink("/var/log/my-service/authz.jsonl", fsync=True)
# Load a rotation-aware HMAC key from your secret manager, not source control.
audit_redactor = AuditRedactor(audit_hmac_key, key_id="2026-q3")
authz = Authz.production(
    catalog,
    policies,
    resources,
    audit_sink=audit,
    audit_redactor=audit_redactor,
)
```

`DecisionEvent` uses a fixed allow-list: timestamp, stable subject identifier, operation, resource URI, entrypoint, allow/deny, reason code, policy/version, and request/trace IDs. It deliberately excludes context, tool arguments, resource attributes, subject metadata, obligations, trace details, and human-readable reasons. The fixed schema alone does **not** know whether your IDs or an entrypoint name contain PII: pass `AuditRedactor` to HMAC-pseudonymize subject/resource/entrypoint/request/trace identifiers while keeping them correlatable within the audit stream. `readiness()` warns when a production audit sink has no pseudonymizer and labels built-in in-memory/local-file sinks as non-durable. With `audit_required=True`, a failed audit delivery changes an otherwise allowed decision to `audit.delivery_failed`; an existing denial retains its stronger original reason.

## Keep remote PDP principals opaque

For a remote evaluator under `Authz.production(...)`, `Subject.id` is required
before any network call. It should be a stable, application-provisioned,
non-email principal coordinate; `Subject.email` remains useful for local legacy
policy but is never used as the default remote `id` fallback. Convert an OAuth
claim, directory ID, or tenant-scoped opaque key in your authentication layer
before constructing `Subject`. Built-in remote PDP adapters have reviewed
sparse encoders; `JsonPdpEvaluator(encoder=...)` is intentionally
development-only because arbitrary serialization cannot be verified by a flag.

## Use versioned policy artifacts

```python
from authz_sdk import PolicyBundle, PolicyBundleStore

bundle = PolicyBundle.from_policy_set(
    policies,
    revision=17,
    catalog=catalog,
).sign("load-this-secret-from-your-KMS")
store = PolicyBundleStore(catalog, signing_key="load-this-secret-from-your-KMS")
store.activate(bundle)
active_policies = store.get_active().to_policy_set(catalog=catalog)
# Construct/reload the Authz instance under the host application's deployment
# discipline. PolicyBundleStore does not mutate a running Authz instance.
authz = Authz.production(catalog, active_policies, resources)
```

A bundle carries deterministic canonical JSON, SHA-256 digest, schema/contract versions, revision, and a bound catalog fingerprint. `PolicyBundleStore` atomically activates or rolls back known revisions in one process. It deliberately does not provide durable review, approval, key rotation, distribution, or multi-worker convergence. HMAC is a shared-secret MAC, not an asymmetric signature or non-repudiation proof.

## Protect retrieved data before it reaches a model

```python
from authz_sdk import CandidateFilter

candidate_filter = CandidateFilter(
    authz,
    resource_mapper=lambda row, subject, context: resources.resolve(
        "knowledge_chunk", row["chunk_id"], subject, context=context
    ),
)
authorized = candidate_filter.filter(
    vector_search_results,
    subject=subject,
    operation="knowledge_chunk.read",
)
prompt_context = authorized.candidates  # never use the unfiltered result
```

`CandidateFilter` checks every candidate after a SQL/vector/MCP adapter returns it and before prompt assembly. A missing identity, loader failure, bad checker result, or denial excludes that item. Its summary contains opaque resource references and outcome categories only, never candidate bodies or raw resource IDs. Push equivalent filters into SQL/vector queries where possible, and retain the prompt-boundary check as defense in depth.

## Close the high-risk Tool replay window

```python
from authz_sdk import AgentRuntime, InMemoryPermitStore

runtime = AgentRuntime(authz)
# Create once during application startup and inject it into each request path.
# This in-memory variant is only safe for one process.
permit_store = InMemoryPermitStore()
permit = runtime.issue_permit(
    execute_request,
    secret=permit_secret,
    resource_version=current_version,
)
result = runtime.consume_permit(
    execute_request,
    permit,
    secret=permit_secret,
    resource_version=current_version,
    store=permit_store,
)
assert result.status.value == "consumed"
```

`consume_permit()` verifies the signed resource-version-bound permit, then reserves its nonce through `PermitStore`. Reuse yields `replayed`. `InMemoryPermitStore` is a one-process reference implementation; multi-worker deployments need an atomic Redis or database implementation. The final write must still verify the resource version in its own transaction.

## What this release can and cannot prove

This SDK gives small teams an embedded, secure-by-default Agent PEP and larger teams portable primitives for a PDP/control plane. It does not replace identity/SSO, a distributed relationship database, a general policy engine, durable policy review/rollout, shared PermitStore/key rotation, immutable audit storage, native SQL/vector query pushdown, or coverage proof for every host path.

That boundary is deliberate. The product promise is not another general authorization engine: it is one enforceable Agent operation contract from API and Tool execution through RAG context and background side effects.
