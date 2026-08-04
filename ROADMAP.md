# Agent Authz Roadmap

## Product boundary

Agent Authz is the host-side authorization enforcement layer for Agent-facing
applications. It is designed to reuse an application's identity system and
its policy engine, while making the same business operation enforceable at an
HTTP route, tool, graph node, RAG boundary, background task, and high-risk
side effect.

It is intentionally **not** a replacement for an identity provider, a
relationship-tuple database, a hosted policy control plane, or a vector
database. Those systems remain excellent choices behind the SDK's evaluator
contract. The differentiator is consistent, observable enforcement at the
places an Agent application actually executes work.

## What is available in 0.7

- A typed `subject -> operation -> resource` contract, strict catalog, and a
  trusted resource registry for Python services.
- One decision boundary for API dependencies, Python tools, MCP v2 Tools,
  LangGraph-style nodes, Agno-style tools, packs, RAG candidate filtering, and
  tasks.
- Secure production defaults: default deny, tenant and trusted-resource
  requirements, request/catalog/policy binding, permit verification, and
  explicit lifecycle phases.
- Backend portability for the embedded policy evaluator and Casbin/remote
  PDP integrations, with a sparse request projection and fail-closed response
  binding for remote production PDPs.
- Audit events, signed immutable policy-bundle primitives, local reference
  sinks, a shared Redis `PermitStore`, tests, a FastAPI example, and
  distribution checks.
- A published [threat model](docs/threat-model.md) separating SDK guarantees
  from identity, data, and operations owned by the host application.

## Near-term: make adoption boring (0.8)

The next release should make the safe path the shortest path:

- Production-grade integration recipes for FastAPI, LangGraph, and Agno, plus
  MCP authentication/discovery recipes beyond the current final Tool guard.
- Add framework-specific inventory for any registry that cannot hand the SDK
  its assembled callable list, and keep coverage evidence scoped to what each
  adapter can actually observe.
- First-class OpenTelemetry spans/metrics and a structured audit exporter;
  retain privacy-safe defaults and never export prompt bodies by accident.
- Configurable error mapping and an explicit policy for fail-open versus
  fail-closed *operational* outages. The library default remains fail closed.
- Key-rotation/verification-key interfaces, documented as reference
  infrastructure rather than magic enterprise compliance.

**Exit criterion:** a new Python service can protect a route and tool using a
trusted resource loader, pass an integration test, and see a correlated,
redacted audit event in under 30 minutes.

## Release operations before broad adoption

These are release-management tasks, not SDK feature claims. Complete them in
the standalone GitHub repository before presenting the project as a broadly
installable public package:

- Enable GitHub private vulnerability reporting, secret scanning, Dependabot,
  a protected `main` ruleset, `v*` tag protection, and the approved `release`
  environment described in [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).
- Run the Redis cross-process E2E job and MCP SDK 2.x contract suite on the
  exact release commit; record any environment-specific exclusions.
- Register the `agent-authz-sdk` project name on PyPI and configure PyPI
  Trusted Publishing for this GitHub repository. Do not store a long-lived
  upload token in GitHub Secrets.
- Add a separate, approval-gated PyPI publishing job only after TestPyPI/PyPI
  Trusted Publishing, package ownership, and release rollback procedures have
  been exercised.
- Publish a signed, human-reviewed release note with supported Python versions,
  public Beta limitations, upgrade notes, and SBOM/attestation verification
  instructions.

## Enterprise integration: distributed enforcement (0.9)

This milestone focuses on operationally credible building blocks, without
pretending the SDK itself is a complete authorization platform:

- Supported backend conformance suites and tested production adapters for OPA,
  Cerbos, OpenFGA, SpiceDB, and Casbin integration patterns.
- Explicit revision/decision-cache semantics, timeout budgets, circuit-breaker
  hooks, and a transparent degraded-mode decision record.
- PostgreSQL permit consumption and audit outbox delivery reference
  implementations, with retry, retention, and observability guidance.
- Pushdown interfaces for SQL/vector filtering, plus a contract test proving
  that unauthorized candidates never reach prompt assembly.
- Tenant isolation, impersonation/delegation, approval/obligation, and
  resource-version examples for destructive side effects.

**Exit criterion:** teams can independently validate that a remote policy
backend, data filter, audit trail, and final side-effect permit use the same
request and policy revision.

## Control plane: only when it is earned (1.0+)

If users demonstrate a need for a shared policy-management surface, the
project can add an optional control-plane reference implementation:

- signed bundle publishing with version promotion, rollback, approval, and
  provenance;
- multi-service catalog/version governance and compatibility checks;
- policy simulation, decision replay, drift detection, and coverage reports;
- a separate relationship-store integration rather than a partial clone of
  OpenFGA or SpiceDB.

The control plane must stay optional. A small service should be able to use
the same core contract without deploying it.

## What success looks like

The project should be judged by evidence rather than stars:

1. A small team can adopt it quickly with fewer duplicated checks.
2. A security reviewer can trace every Agent execution to a business
   operation, trusted resource, policy version, and audit record.
3. A company that already uses Casbin, OPA, Cerbos, OpenFGA, or SpiceDB can
   adopt the SDK without replacing its policy investment.
4. Framework integrations converge on one enforcement contract instead of
   creating framework-specific authorization semantics.

See [the production guide](docs/production.md) for current limitations and
deployment responsibilities.
