# Changelog

All notable changes to this project will be documented here.

## 0.7.0b6 - 2026-08-03

- Disabled implicit HTTP(S) proxy discovery in the SDK-owned remote PDP
  transport. Decision payloads now go only to the configured PDP endpoint;
  deployments that need egress mediation must make that gateway the explicit
  endpoint.
- Made the MCP beta adapter reject a static `Subject` in production by
  default. Shared MCP servers must provide request-local verified identity;
  a dedicated single-principal process must explicitly opt in with
  `allow_static_subject=True`.
- Declared the v0.7 core request and enforcement contracts stable through the
  Beta line so future adapter/observability work does not force business-call
  site rewrites.

## 0.7.0b5 - 2026-08-03

- Made coverage evidence materially stronger at framework boundaries. FastAPI
  coverage now inspects the assembled dependency graph and accepts only an
  attached SDK guard for the exact HTTP method/path; constructing an unused
  dependency or adding a manual record cannot claim verified route coverage.
- Added `record_tool_inventory()` for the exact callable list handed to a
  Python Agent/runtime. It reports an unguarded callable, stale Catalog
  binding, or a protected wrapper that was not supplied to that list. Because
  a generic framework registry is not inspectable, this is an explicitly
  labeled host attestation, not strict deployment evidence.
- Made `MCPAuthz` record an attested `mcp.tool` guard only after the MCP
  server's `tool()` decorator accepts the guarded callable; direct MCP server
  registration remains explicitly out of the adapter's inventory scope.
- Added a runnable FastAPI + Casbin reference showing the intended division of
  responsibility: Casbin decides policy while Agent Authz maps the HTTP
  execution boundary, resolves trusted resources, and checks coverage.

## 0.7.0b4 - 2026-08-02

- Added FastAPI runtime registration inventory to `CoverageManifest`. It
  compares live application routes, including mounted sub-applications, with
  catalog mappings and reports unregistered or stale API entrypoints without
  claiming universal source-code discovery.
- Added opt-in real Redis cross-process permit E2E tests and a Redis 7 GitHub
  Actions job for one-time consumption, cross-process revocation, and
  fail-closed shared-store behavior.
- Added deployment guidance for single-process, multi-worker, and distributed
  PEP / remote-PDP deployments, and clarified that Redis Cluster/failover
  attestation remains environment-specific.

## 0.7.0b3 - 2026-07-31

- Added `RedisPermitStore`, an optional-dependency, shared Redis implementation
  of the existing `PermitStore` contract. It uses TTL-backed atomic Lua
  consumption/revocation and returns an explicit fail-closed `unavailable`
  status when the shared store cannot be reached; `InMemoryPermitStore` remains
  the documented single-process reference implementation.
- Closed final independent-review production races: an accepted evaluator now
  rejects every ordinary attribute write/deletion (including a new field or
  `__class__`), and each request snapshots catalog, policies, resource
  registry, evaluator, audit collaborators, and boundary switches. The SDK
  rechecks that complete snapshot after resource work, before evaluation, and
  before an allow returns, so a low-level registry/type swap fails closed
  instead of influencing a later stage of the same request.
- Hardened Casbin adapter output handling: production accepts only a boolean
  decision (or a tuple headed by one); truthy strings, mappings, lists, and
  other nonstandard values now fail closed as `casbin.error`.

## 0.7.0b2 - 2026-07-31

- Fixed the GitHub Linux release lock by explicitly pinning the conditional
  `SecretStorage` / `jeepney` dependency pulled through `twine` and `keyring`.
  CI now verifies the hash-locked release environment on Linux before a tag can
  be created.

## 0.7.0b1 - 2026-07-31

- Closed production-boundary bypasses found in independent pre-release review:
  only exact reviewed SDK evaluator classes can act as a production backend,
  remote PDP header configuration is injection/collision checked, response
  resource identity compares structured coordinates, and execution permits
  sign resource type and ID independently. Resource URI coordinates now
  percent-encode components to remove delimiter collisions. Production also
  rejects caller-supplied PDP decision decoders, refuses configuration
  downgrades through `with_evaluator()`, and fails closed on every production
  readiness error before policy evaluation. It also detects post-construction
  remote-PDP configuration drift, and permits now preserve case-sensitive
  opaque subject IDs. Public profile or evaluator-mode mutations cannot
  downgrade production enforcement; per-instance evaluator method shadowing
  and supported adapter swaps/remaps are denied as configuration drift. A
  production facade also rejects replacement of its boundary collaborators.
- Hardened release isolation: the read-only build/test job uses a
  hash-locked dependency set and passes an immutable artifact to the
  protected write-capable attestation/release job. The release process also
  tests its documented wheel-only checksum command, and artifact verification
  now validates every wheel RECORD hash and size.
- Added optional `MCPAuthz` support for the official MCP Python SDK v2:
  catalog-derived `mcp.tool` operations, registry-resolved resource
  coordinates, final execution guards, coverage evidence, and an in-memory
  MCP server/client contract test. Production MCP registration now requires a
  catalog binding by default, and the contract suite covers a real denied
  client call with no Tool side effect.
- Strengthened remote-PDP data minimization: the sparse default uses only
  `Subject.id`, never an implicit email fallback; production rejects a remote
  call without a stable principal before transport.
- Made raw `JsonPdpEvaluator(encoder=...)` and `decoder=...` development-only.
  Custom payload or decision code cannot self-attest through
  `projection_enforced=True`; production accepts only reviewed built-in
  adapters until an audited extension contract exists.
- Extended `AuditRedactor` to pseudonymize entrypoint identifiers as well as
  subject/resource/request/trace identifiers, and made the trusted-host-process
  scope machine-readable in health/readiness.
- Hardened public release verification: public-export scanning now rejects
  symlinks/non-text payloads, GitHub Actions are SHA-pinned with credentials
  disabled at checkout, wheel and sdist each receive an SBOM/provenance
  attestation, and release governance requirements are documented.
- Made the public beta boundary explicit: unsafe TLS contexts are rejected,
  trusted resource loaders must return the requested coordinate, registry-based
  Agent permit issuance is supported, and the FastAPI example consumes only a
  verified request-local Subject.
- OpenFGA and SpiceDB starter adapters now require an explicit operation-to-
  relation/permission mapping instead of treating a dotted business operation
  as a backend identifier. Production accepts only a declarative, immutable
  `operation_map`, preventing mutable mapper closures or dictionaries from
  silently changing a relation/permission after the PEP starts.
- Production facades now freeze normal public boundary and method replacement,
  exact evaluator classes retain their import-time production call surface,
  and accepted remote/in-process evaluators seal their public wire/configuration
  attributes. Casbin production accepts the reviewed default request or an
  immutable declarative `request_fields` / `CasbinRequestTemplate`; mutable
  `request_builder` callbacks remain development-only. Remote PDP evaluators
  also copy caller-owned projections and fail closed if an evaluator-owned
  projection or supplied TLS context's security state drifts after sealing.

## 0.6.0 - 2026-07-31

- Added `Authz.production(...)` and a machine-readable readiness report for a
  strict catalog, tenant context, and trusted-resource service boundary.
- Added the `1.0` request/decision contract metadata: request/trace IDs,
  catalog fingerprint, policy digest, and backend propagation headers.
- Added immutable, catalog-bound `PolicyBundle` artifacts with deterministic
  digest, HMAC verification, validation, in-memory atomic activation, and
  explicit rollback.
- Added privacy-safe `DecisionEvent` / `AuditSink` primitives, memory and
  JSONL sinks, and optional audit-required fail-closed behavior.
- Added optional HMAC `AuditRedactor` pseudonymization for subject/resource/
  request/trace identifiers, plus production readiness visibility when a sink
  is configured without it.
- Added a fail-closed `CandidateFilter` that prevents unauthorized retrieval
  candidates from reaching prompt context, with body-free summaries.
- Added the optional `FastAPIAuthz` route dependency and runnable FastAPI
  document-agent example; LangGraph/Agno adapters can now resolve resources
  through a trusted registry by type and ID.
- Added `CoverageManifest`: a CI/startup-checkable catalog → entrypoint →
  final-guard inventory, including high-risk execution and RAG data-boundary
  declarations; FastAPI, Agno, and LangGraph wrappers can record their guard.
- Added `PermitStore` and a thread-safe in-memory reference implementation;
  `AgentRuntime.consume_permit()` now verifies and reserves a one-time permit
  at the side-effect boundary.
- Hardened lifecycle, tenant, resource-provenance, and permit-time validation:
  caller-provided context can no longer select an Agent lifecycle phase,
  registry provenance is per-registry, and non-finite permit timestamps fail
  closed.
- Hardened remote PDP use for production: explicit sparse field projection,
  HTTPS/verified transport readiness checks, redirect refusal, policy
  version/digest pinning, and request/catalog/policy response binding.
- Added the complete dependency-free `secure_document_agent.py` example and
  production deployment guidance, public roadmap, and release-isolation
  verification.
- Added a tag-gated GitHub release workflow with package verification, SPDX
  SBOM generation, artifact attestation, issue/PR templates, and a documented
  no-implicit-PyPI supply-chain policy.
- Improved release packaging metadata and CI verification of distribution
  contents.

## 0.5.1 - 2026-07-30

- Added opt-in trusted-resource enforcement backed by an internal registry
  provenance marker.
- Added resource identity mismatch checks and request/response identity
  validation for external evaluators; mismatches fail closed.
- Added per-resource `tenant_required` catalog metadata and exposed the
  global tenant-context guard in health and documentation.
- Fixed Cerbos multi-action responses to select the requested action instead of
  the first action returned by the backend.
- Added regression tests for the security boundaries above.

## 0.5.0 - 2026-07-30

- Added dependency-free `LangGraphAuthz` and `AgnoAuthz` adapters for wrapping
  tools and graph nodes at the execution boundary.
- Added one sync/async `protect_tool()` primitive that preserves callable
  metadata and uses the same `AgentRequest -> Decision` contract everywhere.
- Added framework integration tests and documentation without requiring either
  framework as a core SDK dependency.

## 0.4.0 - 2026-07-30

- Added `strict`, `advisory`, and `off` Catalog modes.
- External evaluators can now use operations and resource shapes not present in
  the local Catalog, removing the accidental policy ceiling.
- Added regression coverage for transparent Casbin operation evaluation.
- Reframed the README and architecture docs around the no-lock-in Agent
  authorization integration layer.

## 0.3.0 - 2026-07-30

- Added the stable `Evaluator` contract for pluggable policy decision
  backends.
- Added optional Casbin integration without making Casbin a core dependency.
- Added JSON PDP adapters for OPA, Cerbos, OpenFGA, SpiceDB, and AuthZEN-style
  endpoints.
- Added fail-closed remote evaluation and local wire-contract end-to-end tests.
- Repositioned the project as an Agent authorization integration layer rather
  than a replacement for general-purpose policy engines.

## 0.2.0 - 2026-07-29

- Added a safe JSON condition dialect with logical composition and attribute,
  relation, collection, and numeric operators.
- Added explicit allow/deny effects, policy combining modes, default-deny
  behavior, policy versions, validation, stable reason codes, and trace data.
- Added reusable relation resolvers and batch checks.
- Added typed Agent runtime requests for discover, mount, and execute phases.
- Added short-lived signed execution permits bound to resource versions.
- Added a native host-application migration reference; historical permission
  names can be retained in an application-owned audit inventory.
- Added independent evaluation and competitive positioning documentation.

## 0.1.0 - 2026-07-29

- Initial public release of the framework-independent Authz SDK.
- Added catalog-driven resources, actions, operations, and entrypoints.
- Added policy templates for authentication, selectors, relations, ownership,
  deny rules, and query scopes.
- Added trusted `ResourceRegistry` adapters and explainable decisions.
- Added API, Tool, Pack, RAG, and task integration guidance.
