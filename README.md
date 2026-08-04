<h1 align="center">Agent Authz</h1>

<p align="center">
  <strong>Authorization integrity at the moment an Agent action executes.</strong><br>
  One business operation · every registered path · one final decision before work happens.
</p>

<p align="center">
  <a href="docs/architecture.md"><img src="https://img.shields.io/badge/boundary-execution%20PEP-7c5cff?style=flat-square" alt="Execution PEP"></a>
  <a href="https://github.com/FrankPlusPlus/agent-authz/actions/workflows/ci.yml"><img src="https://github.com/FrankPlusPlus/agent-authz/actions/workflows/ci.yml/badge.svg?branch=main&style=flat-square" alt="CI status"></a>
  <img src="https://img.shields.io/badge/status-public%20beta-f59e0b?style=flat-square" alt="Public beta">
  <img src="https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.11 or newer">
  <img src="https://img.shields.io/badge/license-Apache--2.0-2f80ed?style=flat-square" alt="Apache 2.0 license">
</p>

<p align="center">
  <a href="#start-here"><img src="https://img.shields.io/badge/START-Quickstart-1e3a8a?style=flat-square" alt="Quickstart"></a>
  <a href="#why-agent-authz"><img src="https://img.shields.io/badge/WHY-Execution%20integrity-312e81?style=flat-square" alt="Why Agent Authz"></a>
  <a href="#proof-not-promises"><img src="https://img.shields.io/badge/PROOF-Coverage%20evidence-0f766e?style=flat-square" alt="Coverage evidence"></a>
  <a href="docs/quickstart.md"><img src="https://img.shields.io/badge/DOCS-Read%20the%20guide-334155?style=flat-square" alt="Documentation"></a>
  <a href="docs/zh-CN/README.md"><img src="https://img.shields.io/badge/语言-中文-334155?style=flat-square" alt="中文说明"></a>
</p>

<p align="center">
  <img src="assets/agent-authz-hero.svg" alt="API, Agent Tool, MCP Tool, worker, and retrieval paths converge on one business operation before an allow or deny decision" width="960">
</p>

Agent Authz is an embedded Python **Policy Enforcement Point (PEP)** for the
moment an agent action actually runs. It maps a registered API route, Agent
Tool, MCP Tool, retrieval boundary, or worker to a business operation; loads
trusted tenant and resource facts; then allows or denies before protected data
is returned or a side effect begins.

It works beside the policy system you already use. Your application continues
to own identity, business data, transactions, and policy distribution.

## The execution-integrity loop

| 1. Name the action | 2. Guard the execution | 3. Prove the coverage |
| --- | --- | --- |
| Map `document.publish` once, rather than inventing a check per surface. | Put the guard immediately before the route handler, Tool callable, MCP callable, retrieval result, or worker side effect. | Compare registered paths, Catalog bindings, and final guards in CI. |

```text
API route ─┐
Agent Tool ├──> document.publish ──> trusted facts ──> allow / deny ──> side effect
MCP Tool  ─┤
worker    ─┤
retrieval ─┘
```

## Start here

Clone the public Beta and run the dependency-free end-to-end example:

```bash
git clone https://github.com/FrankPlusPlus/agent-authz.git
cd agent-authz
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python examples/secure_document_agent.py
```

It exercises the real model of the SDK—not a toy allow-list:

```text
api_allowed=True          tool_allowed=True
tool_denied=True          cross_tenant_denied=True
permitted_chunk_ids=['chunk-public']
permit_status='consumed'  coverage_ready=True
```

Then follow the [five-minute quickstart](docs/quickstart.md), or jump straight
to [FastAPI, Tool, MCP, and framework integrations](docs/frameworks.md).

## Why Agent Authz

An agent can reach the same business action through far more than an HTTP
endpoint. A route guard alone does not protect a Tool called directly; a policy
engine alone cannot show whether every executable path applied that policy.

| Keep using | Agent Authz adds |
| --- | --- |
| **Casbin, OPA, Cerbos, OpenFGA, SpiceDB** | A common execution contract and a final guard at Python application boundaries. |
| **FastAPI, MCP, agent frameworks** | A way to map their heterogeneous entrypoints to one operation vocabulary. |
| **Your database and identity provider** | Trusted resource loading: tenant, ownership, and relations come from host-owned data, never model output. |
| **Your CI and audit stack** | Coverage evidence, decision metadata, and privacy-safe audit primitives. |

That is the product boundary: **Agent Authz is not a PDP, IAM system,
relationship database, vector database, agent framework, gateway, or hosted
control plane.** It is the thin runtime layer that keeps authorization from
drifting at the execution boundary.

## A minimal production-shaped guard

Define the resource and policy once. The loader is owned by the host service,
so the model cannot assert tenant or relationship facts for itself.

```python
from authz_sdk import Authz, Catalog, PolicySet, ResourceRegistry, Subject

catalog = Catalog()
catalog.resource("document", actions=("read",), relations=("viewer",), tenant_required=True)

policies = PolicySet()
policies.bind(
    id="document_viewers_read",
    operation="document.read",
    template="relation",
    relations=("viewer",),
)

documents = {
    "doc-1": {"tenant_id": "acme", "viewers": {"alice"}, "body": "Private launch plan"}
}
resources = ResourceRegistry()

def load_document(document_id, subject, context):
    row = documents.get(document_id)
    if row is None or row["tenant_id"] != subject.tenant_id:
        return None
    return {
        "id": document_id,
        "attributes": {"tenant_id": row["tenant_id"]},
        "relations": {"viewer": subject.id in row["viewers"]},
    }

resources.register("document", load_document)
authz = Authz.production(catalog, policies, resources)

decision = authz.can(
    Subject(id="alice", tenant_id="acme"),
    operation="document.read",
    resource_type="document",
    resource_id="doc-1",
)
assert decision.allowed
```

Put the same operation immediately around the callable that returns data or
causes the effect:

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

## Proof, not promises

Most authorization libraries can answer a policy question. Agent Authz also
helps answer an operational question: **did the application attach the final
check everywhere it claims to?**

| Capability | What it catches |
| --- | --- |
| `CoverageManifest` | Missing final guards, missing declared data boundaries, and unmapped Catalog operations. |
| FastAPI route inventory | Live registered routes, mounted sub-applications, and matching Authz guards in FastAPI's assembled dependency graph. |
| `CandidateFilter` | Retrieval candidates that must not enter an LLM prompt. |
| `ExecutionPermit` + `RedisPermitStore` | Replay of high-risk approvals across workers; shared-store outages fail closed. |

Coverage evidence is intentionally scoped: FastAPI has strict evidence from
its assembled dependency graph; generic Python Agent tools, MCP, and task
registries are explicit host attestations unless their framework exposes an
inspectable registry. The report labels these levels rather than pretending to
scan arbitrary Python code or protect an unintegrated service. Read [Coverage
evidence](docs/coverage.md) for the exact contract.

## Fits around your stack

| Surface | Availability | Execution boundary |
| --- | --- | --- |
| Native core + `Authz.production()` | Available | Catalog, trusted resources, policy, final decision |
| FastAPI | Available extra | Dependency guard before the handler |
| Python Agent Tools | Available | Sync/async callable guard before execution |
| MCP Python SDK 2.x | Beta extra | Registered MCP Tool callable; host owns MCP authentication |
| Agno / LangGraph | Foundation wrappers | Tool and node execution guards |
| Casbin | Available extra | Existing enforcer behind the common request/decision contract |
| OPA / Cerbos / OpenFGA / SpiceDB | Experimental transports | Fail-closed starter adapters, not complete vendor clients |
| RAG | Available primitive | Filter candidates before prompt assembly |

See the [integration matrix](docs/frameworks.md), [policy backend boundaries](docs/backends.md), and [deployment patterns](docs/deployment.md).

## Production boundary

Agent Authz can fail closed for its own decision and permit store. The host
application is still responsible for:

- authenticating the caller and supplying a verified, request-local `Subject`;
- loading tenant, ownership, and relationship facts from a trusted source;
- placing the final guard immediately before a side effect;
- routing each relevant execution path through a registered guard;
- durable audit storage, query pushdown, key management, and outage policy.

For the exact threat model and multi-worker/microservice guidance, read the
[production guide](docs/production.md), [deployment patterns](docs/deployment.md),
and [threat model](docs/threat-model.md).

## Learn, evaluate, contribute

| Start with | Then evaluate | Before production |
| --- | --- | --- |
| [Quickstart](docs/quickstart.md) | [Architecture](docs/architecture.md) · [Comparison](docs/comparison.md) | [Production](docs/production.md) · [Security](SECURITY.md) |
| [Agent runtime](docs/agent-runtime.md) | [MCP](docs/mcp.md) · [Coverage](docs/coverage.md) | [Supply chain](SUPPLY_CHAIN.md) · [Deployment](docs/deployment.md) |

The public roadmap is in [ROADMAP.md](ROADMAP.md). Please read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

Apache-2.0. See [LICENSE](LICENSE).
