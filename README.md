# Agent Authz

> **Public beta — GitHub Release · Python 3.11+ · Apache-2.0**

## One business operation, guarded where it executes

Protect the same SaaS operation before a FastAPI route, Python Agent Tool, MCP
v2 Tool, retrieval boundary, or task runs.

Agent Authz is an embedded Python authorization PEP. Your service supplies a
verified identity and trusted tenant/resource facts; Authz maps registered
entrypoints to one business operation and performs the final allow/deny check.
Use the native evaluator or retain an existing policy backend.

It is **not** a PDP, relationship database, identity provider, vector database,
Agent framework, or hosted control plane. It protects the boundaries you
explicitly register and route through it; it cannot discover an unwrapped path.

**Use it when** one business operation crosses API, Agent Tool, MCP, RAG, or
task boundaries and you need the same final decision over a trusted resource.
**Use a dedicated PDP or relationship database alongside it** when you need
policy distribution, tuple writes, global consistency, or a hosted control plane.

~~~
verified subject  →  business operation  →  trusted resource  →  decision
~~~

## Install and prove it

Until PyPI publishing is explicitly enabled, use the checked GitHub Release
wheel—not an unverified package name. Download its checksum alongside it:

~~~bash
gh release download v0.7.0b3 --repo FrankPlusPlus/agent-authz \
  --pattern 'agent_authz_sdk-0.7.0b3-py3-none-any.whl' --pattern WHEEL-SHA256SUMS
shasum -a 256 -c WHEEL-SHA256SUMS
gh attestation verify agent_authz_sdk-0.7.0b3-py3-none-any.whl \
  -R FrankPlusPlus/agent-authz
python -m pip install --no-deps agent_authz_sdk-0.7.0b3-py3-none-any.whl
~~~

For a transparent integration checkout and executable proof, use the release
tag for development and source review. A Git tag is not a content-addressed
release proof; verify the release wheel above for a deployed artifact:

~~~bash
git clone --branch v0.7.0b3 https://github.com/FrankPlusPlus/agent-authz.git
cd agent-authz
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python examples/secure_document_agent.py
~~~

The dependency-free demo asserts that an API and Tool allow the same authorized
operation, a direct Tool call is denied, a cross-tenant request is denied, an
unauthorized retrieval candidate stays out of the prompt, and a final permit is
consumed once.

For a reviewed source-tag dependency during development or source review (not
as a release-integrity proof):

~~~bash
python -m pip install "agent-authz-sdk @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b3"
~~~

**Start here:** [Protect an MCP Tool](docs/mcp.md) ·
[Add a FastAPI route](docs/frameworks.md#fastapi) ·
[Support matrix](#support-matrix) · [Beta scope](#beta-scope) ·
[中文](docs/zh-CN/README.md)

## Why it exists

"document.publish" may be reached through an HTTP route, a Tool, an MCP server,
a background task, or a retrieval workflow. Framework hooks make it easy to add
one check; they do not guarantee each entrypoint asks the same business question
about the same trusted resource.
An **entrypoint** is simply that execution surface: a route, callable Tool, MCP
Tool, retrieval boundary, or task.

~~~
POST /documents/{id}/publish ─┐
tool: publish_document         ├─ document.publish ─ trusted document ─ decision
mcp: publish_document          │
task: publish_scheduled        ┘
~~~

Agent Authz provides the contract around that drift:

- A typed Catalog maps one business operation to declared entrypoints.
- ResourceRegistry loads tenant and relationship facts from host-owned data,
  rather than trusting model output, request JSON, or Tool arguments.
- API, callable Tool, MCP, RAG, and task integrations share an
  AgentRequest → Decision contract.
- CoverageManifest makes **declared** final guards and data boundaries testable
  in CI. It is governance inventory, not automatic bypass discovery.
- Permits, audit events, and candidate filtering provide explicit high-risk
  primitives without pretending to be a distributed control plane.

## A safe five-minute integration

The request supplies a resource coordinate. Your loader owns tenant and
relationship facts. This is the recommended production-shaped path.

~~~python
from authz_sdk import Authz, Catalog, PolicySet, ResourceRegistry, Subject

catalog = Catalog()
catalog.resource(
    "document",
    actions=("read",),
    relations=("viewer",),
    tenant_required=True,
)
policies = PolicySet()
policies.bind(
    id="document_viewers_read",
    operation="document.read",
    template="relation",
    relations=("viewer",),
)

documents = {
    "doc-1": {
        "tenant_id": "acme",
        "viewers": {"alice"},
        "body": "Quarterly plan",
    }
}
resources = ResourceRegistry()
resources.register(
    "document",
    lambda document_id, subject, _context: (
        {
            "id": document_id,
            "attributes": {"tenant_id": documents[document_id]["tenant_id"]},
            "relations": {"viewer": subject.id in documents[document_id]["viewers"]},
        }
        if document_id in documents
        else None
    ),
)

authz = Authz.production(catalog, policies, resources)
decision = authz.can(
    Subject(id="alice", tenant_id="acme"),
    operation="document.read",
    resource_type="document",
    resource_id="doc-1",
)
assert decision.allowed
~~~

Then attach the operation to a final execution guard:

~~~python
from authz_sdk import AgentRuntime, protect_tool

runtime = AgentRuntime(authz)

@protect_tool(
    runtime=runtime,
    operation="document.read",
    subject=lambda call: call.kwargs["subject"],
    resource_type="document",
    resource_id=lambda call: call.kwargs["document_id"],
)
def read_document(*, subject, document_id):
    return documents[document_id]["body"]
~~~

## Support matrix

| Surface | Status | What users can rely on | Explicit boundary |
| --- | --- | --- | --- |
| Native core + Authz.production | Available | Embedded decisions, strict catalog, trusted-resource and tenant checks | Host owns authentication and data lookup correctness |
| FastAPI | Available, optional extra | Dependency guard before a route handler | Host provides a verified request identity |
| MCP Python SDK v2 | Beta, optional extra | Final guard immediately before a registered Tool callable | No MCP OAuth, consent, rate limiting, or dynamic tools/list filtering |
| Agno / LangGraph | Foundation callable wrappers | Guard Python tools/nodes before execution | Not native framework plugins; no checkpoint, handoff, or streaming coverage |
| Casbin | Available, optional extra | Use an existing Casbin enforcer behind the common contract; production supports the default or static request template | Casbin owns model and policy storage |
| OPA / Cerbos | Experimental starter transports | Proof-of-concept remote evaluation | Not official/full clients; no async pool, retry, or control plane |
| OpenFGA / SpiceDB | Experimental; static mapping required in production | Proof-of-concept remote relation/permission check | Host maps a business operation to a valid backend relation/permission and owns model/version semantics |
| RAG CandidateFilter | Available primitive | Filters candidates before prompt assembly | No automatic SQL/vector pushdown or proof every query path is wired |
| Packs and tasks | Manual contract | Host can map/check the same operation | SDK does not execute, discover, or automatically cover them |
| Hosted PDP / relationship graph / control plane | Not provided | — | Use an external system |

~~~mermaid
flowchart LR
    I["Verified identity<br/>(host authentication)"] --> G["Agent Authz guard<br/>entrypoint → operation"]
    E["FastAPI route · Agent Tool · MCP Tool"] --> G
    G --> R["ResourceRegistry<br/>(host data: tenant + relations)"]
    R --> P["Native policy<br/>or existing PDP"]
    P -->|allow| S["Business API or Tool side effect"]
    P -->|deny| D["403 or Tool error"]
~~~

## Beta scope

Agent Authz is fail-closed where it makes a decision, but the host application
still must:

- Authenticate the caller and pass a verified, request-local Subject; never
  derive identity from Tool arguments or untrusted headers.
- Load ownership, membership, and tenant facts from a trusted store through
  ResourceRegistry.
- Place a final guard immediately before a side effect and re-check current
  resource version/transaction state where the domain requires it.
- Route every relevant API, Tool, MCP, retrieval, and task path through a
  guard; unregistered paths are outside the SDK's visibility.
- Treat code that can execute arbitrary Python in the service process as
  trusted. This SDK is not a plugin sandbox; isolate untrusted extensions and
  put a remote PDP/PEP boundary around them when that threat matters.
- Use a durable audit sink, shared atomic permit store, query pushdown, key
  management, and an outage policy when the application needs them.

See the [threat model](docs/threat-model.md), [production guide](docs/production.md),
and [security policy](SECURITY.md) before a security-sensitive rollout.

## More documentation

- [Quickstart](docs/quickstart.md) — Catalog, policy bindings, and trusted loaders
- [Architecture](docs/architecture.md) — execution contract and trust boundaries
- [Agent runtime](docs/agent-runtime.md) — discover, mount, execute, and permits
- [Framework integrations](docs/frameworks.md) — FastAPI, LangGraph, and Agno-style guards
- [MCP v2](docs/mcp.md) — verified identity and Tool integration
- [Policy backends](docs/backends.md) — remote-PDP boundary and mapping requirements
- [Coverage manifest](docs/coverage.md) — CI evidence for declared entrypoints
- [Migration guide](docs/migration.md) — incremental adoption without a rewrite
- [Comparison](docs/comparison.md) — how this PEP complements established systems
- [中文说明](docs/zh-CN/README.md)

## Roadmap and contribution

The next milestone is not a larger policy language. It is making the safe path
boring: framework inventories, observable remote-PDP contracts, durable
reference stores, query-pushdown interfaces, and backend conformance suites.
See [ROADMAP.md](ROADMAP.md).

Please read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) before opening a pull request or using a
release artifact.

## License

Apache-2.0. See [LICENSE](LICENSE).
