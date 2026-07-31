# Threat model and responsibility boundary

Agent Authz is a **host-side policy enforcement point (PEP)**. It makes the
authorization decision at an API, Tool, graph-node, retrieval, task, or
side-effect boundary easier to express consistently. It cannot make a host
application trustworthy when the host supplies untrusted identity or resource
facts, bypasses the boundary, or runs hostile code in the same Python process.

This document states the boundary deliberately so a team can review an
integration without assuming the SDK is an identity provider, a sandbox, or a
complete authorization platform.

## Assets and trust sources

| Asset | Trust source | SDK role |
| --- | --- | --- |
| Subject identity, tenant, roles | Authentication/session layer | Normalize it into `Subject`; do not authenticate it |
| Resource identity, tenant, relations | Server-side loader / system of record | Require a registry-loaded resource in the production profile |
| Operation and entrypoint mapping | Application-owned `Catalog` | Validate unknown operations/entrypoints fail closed |
| Policy decision | Native `PolicySet` or configured PDP | Bind decision to operation/resource; bind remote response in production |
| Prompt candidates | Retrieval/data adapter | Filter every mapped candidate before prompt assembly |
| Side-effect permit | Application secret/key service plus shared store | Verify a short-lived, resource-version-bound permit and support one-time consumption |
| Audit evidence | Application audit infrastructure | Emit privacy-safe events; expose sink failure for fail-closed handling |

## Threats, controls, and owner

| Threat | SDK control | What the host must still do |
| --- | --- | --- |
| A request body/model output claims `owner=true` | `Authz.production()` rejects resources not loaded by its `ResourceRegistry` | Make the loader query the right system of record and tenant |
| A caller omits tenant data or crosses tenants | Strict tenant/resource checks deny missing or mismatched context | Authenticate tenant membership and correctly populate resource tenant facts |
| A model calls a hidden Tool directly | Tool/node execution wrappers check again; discovery is never the only boundary | Wrap every side-effecting Tool and do not expose an unwrapped equivalent |
| An MCP caller supplies another user's identity in Tool arguments | `MCPAuthz` authorizes the actual registered Tool before its callable executes and production defaults to catalog-bound Tool registration | Authenticate the MCP session, put its verified principal in request-local host state, and never derive `Subject` from Tool arguments |
| A caller sets `context["authz_phase"]` to weaken a check | Caller context cannot select an Agent lifecycle phase | Use `AgentRuntime` for lifecycle checks; do not call private SDK internals from untrusted plugin code |
| A remote PDP sees excessive identity/context data | Built-in PDP payloads send only `Subject.id` by default; email is never a hidden fallback, other subject fields and all free-form fields are allowlisted, and production rejects raw custom encoders | Supply a stable opaque `Subject.id`, review every projected field, and request a supported adapter for a nonstandard production PDP schema |
| A remote PDP response belongs to another request/policy | Production remote PDPs require HTTPS through the SDK standard TLS transport, pinned revision/digest, and echoed request/catalog/policy binding | Pin hosts/certificates as appropriate, configure timeouts, and operate the PDP securely |
| A look-alike resource coordinate is returned or a colon appears in an ID | Resource URIs percent-encode each component; evaluator response checks and execution permits compare structured type/ID fields | Preserve raw resource type and ID in external policy/data stores; do not reconstruct identity by splitting a display URI |
| A redirect forwards PDP credentials | The standard transport refuses redirects and no injected transport is production-ready | Put a reviewed gateway behind the standard transport; do not self-attest arbitrary transport code |
| A live process partially swaps or pre-request downgrades a production boundary | `Authz.production()` seals ordinary facade/evaluator assignment and deletion, keeps its construction identity outside the facade instance dictionary, pins ordinary production entrypoint lookup to reviewed `Authz` methods, derives inherited `can()` production mode through that non-virtual identity, captures catalog, policy set, resource registry, evaluator, audit collaborators, and profile switches before resource work, then rechecks that full snapshot before evaluation and before an allow returns | Build and atomically install a new facade for a configuration/policy-system migration; do not mutate a live PEP |
| Unauthorized RAG text reaches a prompt | `CandidateFilter` fails closed per candidate and returns body-free diagnostics | Apply it before every prompt/cache/output path, and add database/vector pushdown for scale |
| A permit is replayed | Permit is time/resource-version bound; `PermitStore` supports atomic one-time consumption | Use a shared atomic store, rotate keys, and make the final version check part of the side-effect transaction |
| Audit identifiers leak PII | Fixed event schema excludes rich request data; `AuditRedactor` HMAC-pseudonymizes subject/resource/entrypoint/request/trace values | Keep the redaction key in a secret manager, plan key rotation, and use durable monitored storage/retention |
| Audit delivery fails | `audit_required=True` turns an otherwise allowed result into a deny | Use durable monitored storage, retention, alerting, and a compliance export if needed |

## Explicit non-goals

The SDK does not by itself provide:

- authentication, session security, identity lifecycle, or delegated OAuth
  credentials;
- a process sandbox against malicious same-process Python plugins or a model
  that can execute arbitrary host code;
- a Zanzibar-compatible relationship database, tuple write API, or globally
  consistent revision service;
- a hosted policy control plane, approval workflow, immutable audit system,
  or distributed permit revocation service;
- proof that the host routed every route, Tool, task, or retrieval path through
  the SDK.

`ResourceRegistry` provenance is specifically an application-integration guard:
it prevents ordinary request/model values and resources from another registry
from being accepted as trusted by this `Authz` instance. It is not an isolation
boundary against code that can inspect and call arbitrary objects in the same
process. The production sidecar/snapshot protections likewise apply when the
reviewed SDK entrypoint is invoked; they cannot stop code that directly bypasses
Python attribute dispatch (including a forged `__class__` with its own
`__getattribute__`), replaces class/module state, or performs the side effect
itself. `health()` and `readiness()` expose
`trust_boundary="trusted_host_process"` so deployment checks do not mistake
this SDK boundary for a plugin sandbox.

## Integration review questions

Before production, answer these questions for each high-risk operation:

1. Which authenticated principal creates the `Subject`, and how is tenant
   membership established?
2. Which server-side loader supplies resource identity, tenant, and relation
   facts? Does it enforce tenant scoping in its query?
3. Which API/Tool/node/task is the final pre-side-effect boundary? Is it
   tested for both allow and deny paths?
4. If it is a data operation, where is candidate filtering or query pushdown
   applied before a prompt or response is constructed?
5. Which policy revision, PDP timeout/failure behavior, permit store, and
   audit sink apply to the operation?
6. Can a deployment/CI coverage check show that each registered high-risk
   operation has a mapped, enforced entrypoint?

Use this together with the [production guide](production.md) and the upcoming
coverage manifest rather than treating a green unit-test suite as an entire
security review.
