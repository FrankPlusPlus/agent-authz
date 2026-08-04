# Positioning Against Established Projects

The project is intentionally not a new general-purpose policy language. The
policy engine is replaceable; the Agent integration contract is the product.

This project should not claim to replace every authorization system. The
useful distinction is where each project starts and what it owns.

| Project | Core model | Deployment shape | What Agent Authz borrows | What Agent Authz deliberately adds |
| --- | --- | --- | --- | --- |
| [Casbin](https://casbin.apache.org/docs/category/access-control-models/) | Configurable ACL/RBAC/ABAC/ReBAC models and effectors | Embedded library with adapters | Full policy engine through `CasbinEvaluator` | A catalog that maps one business operation to API, Tool, Pack, RAG, and task entrypoints |
| [Oso](https://www.osohq.com/docs/modeling-in-polar/reference/resource-blocks) | Polar rules plus resource blocks, roles, permissions, and relations | Embedded policy engine | Resource-oriented relations and readable policy concepts | JSON-safe conditions and Agent lifecycle guidance without requiring a policy language first |
| [OpenFGA](https://openfga.dev/docs/concepts) | Typed relationship graph and authorization models | Dedicated relationship authorization service | Typed resources, relations, contextual checks, and model/version thinking | A low-dependency in-process API and host-owned resource adapters for small teams |
| [SpiceDB](https://authzed.com/docs/spicedb/concepts/schema) | Zanzibar-style relationship database and permissions | Distributed authorization service | Relationship graph as the scale-out direction | Agent-specific discover/mount/execute and business-operation vocabulary |
| [OPA](https://www.openpolicyagent.org/docs/policy-language) | General policy engine with Rego, bundles, and decision logs | Embedded or PDP service | Rego evaluation through `OpaEvaluator` | A smaller typed surface for application developers and Agent gateway integrations |
| [Cerbos](https://docs.cerbos.dev/cerbos/latest/policies/resource_policies.html) | Resource policies, roles, derived roles, conditions | Language-agnostic PDP | Resource checks through `CerbosEvaluator` | A Python-first SDK that treats Agent Tools, Packs, RAG, and tasks as first-class entrypoints |

## Where the SDK is deliberately opinionated

It standardizes the runtime boundary around five concepts:

1. **Operation:** the business meaning, such as `ai_employee.delete`.
2. **Resource:** the trusted object and subject-relative relations.
3. **Entrypoint:** API, Tool, Pack, RAG, or task that invokes the operation;
   this is coverage/audit metadata, not a second permission language.
4. **Phase:** discover, mount, or execute for Agent runtime checks; it never
   waives a resource requirement from caller-controlled context.
5. **Decision:** allow/deny plus explanation, obligations, and policy version.

Casbin, OPA, Cerbos, OpenFGA, and SpiceDB remain free to express their own
models. Authz does not translate every advanced policy into a reduced local
template; it passes a normalized request to the selected backend.

## Agent authorization reality

These projects increasingly provide Agent, MCP, or RAG integration patterns.
Even with those primitives, the host still has to register a business
operation, load trusted resources, map a Tool and Pack, filter RAG candidates,
and enforce the final decision before side effects. Agent Authz focuses on
making that host-side execution contract backend-neutral and testable.

| Agent concern | What the Authz SDK provides | What the host still owns |
| --- | --- | --- |
| Tool discovery | catalog-bound explicit discovery operation, or a resource-aware check | Tool registry and response filtering |
| Pack mounting | catalog-bound explicit mount operation with Pack identity | Pack membership and version resolution |
| Tool / MCP Tool execution | execution request contract, optional permit, and an MCP v2 final Tool guard | Argument validation, transaction, replay protection, MCP authentication/discovery |
| RAG | fail-closed candidate filter and scope obligation | Vector-store query adapter and query pushdown |
| Delegation | Agent subject/phase/session fields | Authentication, delegation proof, tenant identity |

This is the product distinction: the SDK makes the cross-entrypoint contract
small and typed; it does not pretend that a policy engine can replace an Agent
runtime or a data store.

## The v0.7 enforcement kit

The practical reason to add Authz on top of an established engine is not a
claim that those projects cannot implement Agent authorization. It is that the
Agent PEP work otherwise gets rebuilt, differently, in every API gateway,
Tool registry, retriever, and task worker. This release makes that layer
concrete and backend-neutral:

| Agent adoption problem | Agent Authz v0.7 primitive | What remains with the selected backend/host |
| --- | --- | --- |
| A developer must remember several safety switches | `Authz.production()` requires strict catalog, tenant context, and trusted resources together | Identity, tenant lifecycle, and correct domain loaders |
| API, Tool, Pack, RAG, and task drift into separate checks | `Subject -> Operation -> Resource -> Decision`, catalog entrypoint mapping, and Agent lifecycle request | Route/tool inventory and coverage enforcement in the host |
| Workers disagree about the operation/policy contract | request/trace IDs, contract version, catalog fingerprint, policy version, native/remote-supplied digest; production remote response binding | Cross-language SDKs, remote consistency tokens, fleet deployment |
| Policy JSON is changed without a verifiable artifact | immutable `PolicyBundle`, digest, catalog binding, HMAC proof, atomic in-process activate/rollback | Durable review/approval, KMS, canary, distribution, multi-worker rollout |
| RAG authorization is only an ignored obligation | fail-closed `CandidateFilter` before prompt assembly, body-free filtering summary | SQL/vector pushdown and adapters for each data store |
| A high-risk Tool can replay an allow | short-lived `ExecutionPermit`, atomic shared `RedisPermitStore` consumption, and one-process reference | key rotation and transaction binding |
| Auditing copies prompts or secrets by accident | fixed-field `DecisionEvent` and `AuditSink` | Durable delivery, retention, alerting, compliance export |

For a small Python Agent team, this means an embedded path with very few new
concepts. For an enterprise, it is a PEP and contract layer that can sit in
front of Casbin/OPA/Cerbos/OpenFGA/SpiceDB while the selected backend keeps its
own policy language, relationship model, and control plane.

## The honest product boundary

Agent Authz is not a new relationship database, identity provider, vector
store, Tool executor, or model router. It is a portable authorization kernel
and integration contract:

```text
identity facts + trusted resource facts + policy
                    |
                    v
       subject -> operation -> resource
                    |
                    v
             decision + obligations
```

The host owns authentication, organization data, resource loading, query
pushdown, durable audit storage, and side effects. This is important: a
permission SDK cannot make a caller-provided `owner=true` trustworthy, and an
obligation cannot protect a vector query if the vector adapter ignores it.

## What is available in 0.7

- JSON-safe conditions with `all`, `any`, `not`, relation checks, attribute
  comparisons, collection checks, and numeric comparisons.
- Explicit `allow`/`deny` effects with `deny_overrides`, `allow_overrides`, or
  `first_match` combining. The default is fail-closed `deny_overrides`.
- Policy `version`, stable decision `reason_code`, explainable trace data, and
  a versioned request/decision contract with request/trace IDs and catalog/
  policy fingerprints.
- Reusable relation resolvers in addition to full resource loaders.
- `check_many()` and a normalized `AuthorizationRequest` wire-shaped object.
- `AgentRequest` and `AgentRuntime` for discover, mount, and execute. A Pack
  grant never silently grants future Tool members; execution must be checked.
- `Authz.production()` for strict catalog, tenant-context, and trusted-resource
  defaults without making every team assemble safety switches.
- A short-lived HMAC-signed `ExecutionPermit` contract plus one-time
  `PermitStore` implementations: `InMemoryPermitStore` for one process and
  `RedisPermitStore` for shared worker/pod consumption. The host still owns
  key rotation and transaction enforcement.
- `PolicyBundle` / `PolicyBundleStore` as catalog-bound, HMAC-verified,
  in-process policy artifact and activation primitives, not a control plane.
- Fixed-field `DecisionEvent` / `AuditSink` primitives and fail-closed
  `CandidateFilter` for prompt-boundary retrieval filtering.
- A stable `Evaluator` contract and optional Casbin adapter.
- Experimental JSON starter adapters for OPA, Cerbos, OpenFGA, SpiceDB, and
  AuthZEN-style endpoints, with fail-closed response handling, minimal default
  projection, redirect refusal, and a strict production remote envelope. They
  are not official or feature-complete backend clients.
- Dependency-free LangGraph and Agno adapters for Tool and Node execution
  guards, including sync/async callables and registry-resolved resource
  coordinates.
- An optional MCP v2 `MCPAuthz` decorator that protects the actual registered
  server Tool execution and records an `mcp.tool` coverage entrypoint; MCP
  OAuth/token validation and dynamic Tool discovery remain host-owned.

## What is intentionally still future work

The following are not silently claimed as complete:

- a Zanzibar-compatible tuple store, revision consistency, watch stream, or
  `ListObjects` service;
- transaction adapters for fully closing TOCTOU windows;
- a full policy control plane, bundle distribution, approvals, asymmetric
  signing, durable rollback history, hot reload, and non-Python clients;
- official vector-store adapters and query pushdown that mechanically cover
  every retrieval path.

Those are product milestones, not things a few more policy templates can
solve. The SDK's public contracts are designed so they can be added without
changing the business vocabulary.
