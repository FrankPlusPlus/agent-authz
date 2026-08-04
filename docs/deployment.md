# Deployment patterns

Agent Authz is an embedded Policy Enforcement Point (PEP). Keep it in the
service that executes a business action; choose a policy backend and shared
state only when the deployment needs them. The SDK is not a central
authorization service and does not replace the business transaction that
performs the final write.

## 1. One process: the simplest safe start

Use this for local development, a single-worker service, or low-risk internal
read paths:

```text
HTTP route / Agent Tool / RAG assembly
                 |
                 v
   Agent Authz + trusted resource loader + native or Casbin evaluator
                 |
                 v
             business callable
```

Use `Authz.production(...)` for tenant-sensitive resources. An in-memory
permit store is only suitable for a single process; it is not replay protection
across workers.

## 2. Multiple workers: share only high-risk permit state

Ordinary authorization decisions do not require Redis. Each worker can embed
the same PEP and use the same policy backend. A shared store is needed only
when a high-risk approval or execution permit must be consumed once across
workers, pods, or retries:

```text
worker A ─┐
worker B ─┼─> Agent Authz final guard ─> RedisPermitStore ─> consume once
worker C ─┘                                      |
                                                v
                             database transaction: idempotency + version check
```

At startup, require `runtime.permit_readiness(store, require_shared=True)` for
those high-risk paths. Redis prevents a permit nonce from being reused; it does
not make a database write exactly-once. The owning business transaction must
still enforce an idempotency key, current resource version, and state-machine
transition.

The repository includes a Redis 7 cross-process E2E job for permit consumption
and revocation. Its key layout uses one Redis hash tag for both nonce keys, so
it is designed for Redis Cluster scripting. A deployment using Redis Cluster
should still run its own topology and failover test before treating that
environment as operationally attested.

## 3. Microservices: distributed PEPs, optional central PDP

Use this when several services need one policy source, independent policy
rollout, or non-Python clients:

```text
                         ┌──────────── policy decision point ────────────┐
service API/Tool ─> local Agent Authz PEP ─> Casbin / OPA / OpenFGA / Cerbos │
                         └───────────────────────────────────────────────┘
                   |                         |
                   v                         v
          trusted service-owned         decision revision / audit receipt
          resource loader
                   |
                   v
       service-owned transaction and side effect
```

Every service keeps a local final guard because only that service knows whether
its Tool, job, or write transaction is actually about to execute. A gateway can
apply coarse protocol-level policy and an external PDP can decide policy, but
neither replaces the service-local trusted resource load and final check.

Use the same stable business operation names across services, but let each
service own its resource loader and database transaction. Send the remote PDP
only the reviewed, minimal decision projection needed by its model; do not use
the PDP as an unbounded dump of Tool arguments or resource bodies.

## Responsibility matrix

| Concern | Owner |
| --- | --- |
| Authentication, user/session validation, delegation identity | Host identity system |
| Tenant, owner, relation, resource version facts | Service-owned trusted loader / database |
| Policy model and relationship tuples | Casbin, OPA, OpenFGA, Cerbos, or another selected PDP |
| Mapping operation to API/Tool/MCP/task boundaries | Agent Authz catalog and service integration |
| Final allow/deny immediately before execution | Agent Authz PEP in the executing service |
| Cross-worker one-time approval/replay state | `RedisPermitStore` or another shared `PermitStore` |
| Exactly-once write, idempotency, state transition | Owning business transaction |
| Policy rollout, audit retention, SSO, key management | Host platform / dedicated control plane |

## Production acceptance checklist

Before calling a deployment production-ready, demonstrate all applicable
items:

1. Every high-risk registered execution boundary has a final guard and passes
   `CoverageManifest` checks; framework inventories expose live unregistered
   routes or stale mappings.
2. A direct Tool invocation, a cross-tenant resource coordinate, and a missing
   trusted resource loader are denied before the side effect.
3. Retrieval candidates are filtered before prompt assembly, with a test that
   the unfiltered collection is never used as model context.
4. Multi-worker high-risk actions use a shared permit store, are tested across
   processes, and retain a transaction-level idempotency/version check.
5. A remote PDP timeout, contract mismatch, or policy/catalog revision mismatch
   produces the explicitly configured safe outcome; the default is deny.
6. Audit events correlate operation, entrypoint, policy revision, request/trace
   identifiers, and outcome without exporting prompt or resource bodies.

These are deployment responsibilities, not claims the SDK can infer by itself.
