# Policy Backends

Agent Authz separates the **Agent integration contract** from the **policy
decision backend**. The application keeps calling `Authz.can()`,
`AgentRuntime.can()`, and `ExecutionPermit`; only the evaluator changes.

## No lock-in by design

The SDK has three catalog modes:

- `strict`: the local Catalog is the allowed operation universe. Use it with
  Native and a dashboard that should reject unknown names.
- `advisory`: the Catalog drives UI and documentation, but an external engine
  may evaluate additional operations and resource shapes.
- `off`: the external engine owns the policy vocabulary. Authz normalizes the
  request and returns a common `Decision`; explicit safety guardrails such as
  tenant boundaries remain available and can be disabled deliberately.

Calling `with_evaluator()` defaults to `advisory` for a normal instance, so
adding Casbin or a remote PDP does not silently reduce its model to the local
template list. A production-profile instance preserves `strict` mode unless
the caller explicitly changes it.

## Choose a backend

| Backend | Best for | What it owns | What Authz still owns |
| --- | --- | --- | --- |
| Native | Small Python services and local development | In-process policy matching | Catalog, resources, Agent phases, scopes, permits |
| Casbin | Existing Casbin deployments or advanced custom matchers | Model, matcher, grouping, policy storage | Request normalization and Agent entrypoints |
| OPA | Rego teams and centralized policy bundles | Rego evaluation and bundle lifecycle | Agent contract, resource context, decision normalization |
| Cerbos | Language-neutral enterprise PDP | Resource policies and contextual decisions | Agent lifecycle and host resource adapters |
| OpenFGA | Relationship-heavy authorization | Typed relationship graph | Tool/Pack/RAG operation mapping and execution controls |
| SpiceDB | Distributed Zanzibar-style relationship checks | Relationship database and consistency | Agent gateway contract and data-scope enforcement |

Authz is not a replacement database for OpenFGA/SpiceDB, and it does not
pretend that a generic JSON response can automatically enforce a SQL or vector
query. The host still has to apply returned obligations at the data boundary.

## Native is still the default

```python
from authz_sdk import Authz, Catalog, PolicySet

authz = Authz(Catalog(), PolicySet())
```

This path has no runtime dependency beyond Python. It is the right starting
point for examples and tests. A service boundary should normally use
`Authz.production(catalog, policies, resources)` so tenant/trusted-resource
checks are not assembled manually.

## Casbin without changing Agent code

Install the optional dependency:

```bash
python -m pip install "agent-authz-sdk[casbin] @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b3"
```

Create a normal Casbin enforcer and put it behind the same Authz facade:

```python
import casbin

from authz_sdk import Authz, CasbinEvaluator, Catalog, PolicySet, Resource, Subject

model = casbin.Model()
model.load_model_from_text('''
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
''')
enforcer = casbin.Enforcer(model)
enforcer.add_policy("alice@example.com", "ai_employee:employee-1", "ai_employee.delete")

catalog = Catalog()
catalog.resource("ai_employee", actions=("delete",))
authz = Authz(
    catalog,
    PolicySet(version="casbin-policy-7"),
    evaluator=CasbinEvaluator(enforcer),
)

decision = authz.can(
    Subject(email="alice@example.com"),
    resource=Resource("ai_employee", "employee-1"),
    action="delete",
)
assert decision.allowed
```

When an external evaluator is supplied, it **replaces** local `PolicySet`
matching. The local policy object still carries the SDK configuration version
and catalog-facing metadata, while the selected backend is the policy source
of truth. Structural checks such as unknown operations, tenant mismatches, and
trusted resource loading remain in the Authz gateway.

The default Casbin request is:

```text
sub = subject.id or subject.email
obj = resource.uri (a canonical percent-encoded type:id coordinate)
act = Authz operation, for example ai_employee.delete
```

For ordinary identifiers this remains the familiar `document:doc-1`. A colon,
percent sign, or reserved URI character in either component is encoded
independently, so `Resource("document", "doc:1")` cannot collide with
`Resource("document:doc", "1")`. Their canonical coordinates are
`document:doc%3A1` and `document%3Adoc:1`, respectively. If an existing Casbin model persisted a raw colon-joined
object key, pass a deliberate `request_builder` during migration and test the
old/new mapping; do not parse `resource.uri` back into business fields. For a
custom matcher, use a static field template in production instead of an
arbitrary Python callback:

```python
evaluator = CasbinEvaluator(
    enforcer,
    # Example four-argument model: subject, canonical resource, action, domain.
    request_fields=(
        "subject.id",
        "resource.uri",
        "operation",
        "subject.tenant_id",
    ),
)
```

`request_fields=` builds an immutable `CasbinRequestTemplate`; it supports the
named fields above plus explicit `context.<key>`, `arguments.<key>`,
`subject.metadata.<key>`, `resource.attributes.<key>`,
`resource.relations.<key>`, and `literal:<value>` selectors. The default
three-field request and these templates are production-ready. A callable
`request_builder=` remains a development/migration escape hatch, but
`Authz.production()` rejects it because mutable closure or object state can
change a live matcher request without changing callable identity.

At evaluation time, `CasbinEvaluator` accepts only a boolean decision (or a
tuple whose first item is a boolean). A truthy string, mapping, list, or other
nonstandard adapter result is treated as a backend error and denied rather
than being coerced into an allow.

## Remote PDPs

The SDK includes **experimental starter wire adapters** for OPA, Cerbos,
OpenFGA, SpiceDB, and an AuthZEN-style endpoint. They use the standard library
by default and accept an injected transport for tests; they are not official,
feature-complete clients. A starter adapter is useful for a local proof of
concept, not evidence of compatibility with every feature of that backend.

`CerbosEvaluator` currently targets the legacy single-resource Check response
shape (`resourceInstances`), not the newer
[`CheckResources`](https://docs.cerbos.dev/cerbos/latest/api/reference.html)
result-list API.
Keep it behind a compatible gateway or contribute a reviewed current-API
adapter before treating it as a production Cerbos integration.

```python
from authz_sdk import Authz, OpaEvaluator

evaluator = OpaEvaluator(
    "https://opa.internal/v1/data/agent_authz/allow",
    headers={"authorization": "Bearer ..."},
    timeout=2.0,
    # Required when this evaluator is used by Authz.production(...).
    policy_version="bundle-2026-08-01",
    expected_policy_digest="sha256-of-the-reviewed-pdp-policy",
    allowed_hosts=("opa.internal",),
)
authz = Authz.production(catalog, policies, resources, evaluator=evaluator)
```

The default remote payload sends only `Subject.id` as a stable subject
identifier,
resource coordinates, and the resource `tenant_id`. It does **not** forward
roles, tenant/organization data from the subject, email as a separate field,
subject metadata, arbitrary resource metadata, request context, or Tool
arguments. It never falls back from `Subject.id` to `Subject.email`. A
production remote call without a non-empty application-provisioned ID is
denied before transport; map an authenticated identity to an opaque, stable ID
at the host boundary. If a development PDP intentionally uses email, project
the `email` field explicitly and treat it as PII:

```python
from authz_sdk import PdpRequestProjection

evaluator = OpaEvaluator(
    "https://opa.internal/v1/data/agent_authz/allow",
    projection=PdpRequestProjection(
        subject_field_keys=("id", "roles", "tenant_id"),
        resource_attribute_keys=("tenant_id", "classification"),
        context_keys=("environment",),
        argument_keys=("document_id",),
    ),
)
```

All remote adapters have the following baseline guarantees:

- network errors and malformed responses fail closed;
- a caller-supplied standard TLS context must verify both the peer certificate
  and hostname; an unverified context is rejected at construction time;
- the standard transport rejects all HTTP redirects before a second origin can
  receive an `Authorization` header;
- the public result is always an Authz `Decision`;
- the original operation, trusted resource, entrypoint, request/trace IDs,
  contract version, catalog fingerprint, and policy version are preserved;
- the adapter does not silently turn a policy-engine decision into a data
  query or side effect.

For the Cerbos starter adapter, the decision must additionally bind to the
requested coordinate inside `resourceInstances`: Agent Authz reads only
`resourceInstances[resource.id].actions[operation]`. An allow for another
resource, another action, or a generic top-level `allow` is not reused for the
current request and fails closed. This is intentionally narrower than a generic
JSON boolean decoder because a Cerbos response can contain several decisions.

The response parser accepts the common `allow`, `allowed`, `authorized`,
`permitted`, `result`, and backend-specific permission-status shapes. A normal
development adapter may return only one of those fields. A production-profile
remote evaluator is stricter: it must use HTTPS with the SDK's standard
verified TLS transport, pin a policy version and digest, and return this bound
envelope with every decision:

```json
{
  "allowed": true,
  "request_id": "same value received by the PDP",
  "trace_id": "same value when supplied",
  "contract_version": "1.0",
  "catalog_fingerprint": "same value received by the PDP",
  "policy_version": "bundle-2026-08-01",
  "policy_digest": "sha256-of-the-reviewed-pdp-policy"
}
```

Missing or mismatched fields deny before the final decision is returned. This
is deliberate: a stock backend endpoint that does not emit the envelope stays
usable for development, but is not silently promoted to a production execution
authority. Pin the remote service API version and add a contract test against
the exact gateway/sidecar you deploy.

The built-in adapters use reviewed, fixed payload encoders and decision
decoders on top of this projection. A custom
`JsonPdpEvaluator(encoder=...)` can serialize arbitrary data, and a custom
`JsonPdpEvaluator(decoder=...)` can reinterpret a PDP denial. Both are
development-only and are always rejected by `Authz.production(...)`—including
when an application passes the legacy `projection_enforced=True` argument.
Request a supported adapter or keep the custom gateway outside the production
authority path until it has reviewed, contract-tested payload and decision
adapters.

Production readiness also detects post-construction changes to the PDP endpoint,
transport, payload encoder, decision decoder, headers, timeout, projection,
custom TLS-context security state, or policy binding. Projection instances and
mapping inputs are copied into SDK-owned immutable values, so mutating the
configuration object that was passed to an evaluator cannot silently change a
live production request. If any configured value drifts, the production boundary
denies before opening a PDP connection; create a new reviewed evaluator instead
of mutating a live one.

Production accepts only the exact evaluator types that ship in this SDK
release; a subclass or arbitrary `Evaluator` cannot opt itself in by returning
`enforcement_mode="remote"` or a ready-looking health report. This prevents
configuration-shaped self-attestation from turning unreviewed transport,
encoder, or decoder code into the final authority. It is still not a sandbox against code
that is already trusted to run in the same Python process.

A custom injected transport is useful for tests and development gateways, but
is never production-ready in v0.7—even if a caller marks it `host_attested`
(or uses the legacy `verified` spelling). The SDK cannot independently prove
arbitrary transport code validates certificates, resists redirect leakage, or
preserves response binding. Put a reviewed gateway behind the standard
transport instead.

Configured PDP headers are validated at construction. SDK protocol headers
(`x-authz-*`) and `Content-Type` are reserved, header names are
case-insensitively unique, and control characters are rejected. Put bearer
tokens only in a normal `Authorization` header supplied by the application.

### OpenFGA and SpiceDB require an explicit operation mapping

Authz business operations intentionally use names such as `document.read`.
Those names are not automatically valid OpenFGA relations or SpiceDB
permissions, and the SDK cannot infer the meaning of your relationship model.
The two starter adapters therefore fail closed until the host supplies an
explicit mapping. Use the small declarative `operation_map` in production:
the SDK copies it into an immutable snapshot, so mutating the source
dictionary later cannot change an authorization authority already accepted by
the PEP.

```python
from authz_sdk import OpenFgaEvaluator, SpiceDbEvaluator

openfga = OpenFgaEvaluator(
    "https://openfga.internal/check",
    operation_map={
        "document.read": "can_read",
    },
)
spicedb = SpiceDbEvaluator(
    "https://spicedb.internal/check",
    operation_map={
        "document.read": "read",
    },
)
```

`operation_mapper=` still accepts a callable for local development and
advanced prototypes. It is intentionally rejected by `Authz.production()`:
an arbitrary Python callable can change through captured mutable state even
when its object identity stays the same. Pass a mapping (to either
`operation_map=` or the source-compatible `operation_mapper=`) for a
production-ready, static operation-to-relation/permission contract.

The OpenFGA mapping must return a relation made only of letters, digits,
underscores, or hyphens. The SpiceDB mapping must return a 3–64 character
lowercase identifier that starts with a letter or underscore, ends
alphanumeric, and otherwise uses letters, digits, or underscores. A malformed
declarative `operation_map` is rejected while the evaluator is constructed,
before production readiness can report ready. This validates naming only; your
model, tuple schema, consistency semantics, and official client compatibility
remain the host's responsibility.

## Agent code does not change

The same runtime code works with every evaluator:

```python
from authz_sdk import AgentRequest, AgentRuntime

runtime = AgentRuntime(authz)
decision = runtime.can(AgentRequest(
    subject=subject,
    operation="knowledge_base.query",
    phase="execute",
    tool_name="kb_query",
    resource=finance_kb,
))
```

The evaluator decides **whether** the operation is allowed. Authz continues to
describe **where and when** the decision is enforced: discovery, Pack mount,
Tool execution, RAG retrieval, or a background task.

## Production boundary

The adapters intentionally do not claim to provide:

- policy distribution, approval, rollback, or watch streams;
- relationship data loading or organization synchronization;
- SQL row filtering or vector-store filtering by themselves;
- replay storage or permit revocation;
- a universal translation of every third-party policy language.

Those responsibilities belong to the selected backend and the host service.
The value of this package is that changing one of those choices does not force
the Agent runtime to learn a new authorization API.
