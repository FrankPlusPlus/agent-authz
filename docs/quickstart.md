# Quickstart

This guide builds a complete policy without a web framework or database. It
uses the same three concepts that a production integration uses: subject,
operation, and resource.

Install a checked GitHub Release wheel while PyPI publishing is not enabled.
Verify the downloaded bytes and GitHub provenance before installation:

```bash
gh release download v0.7.0b3 --repo FrankPlusPlus/agent-authz \
  --pattern 'agent_authz_sdk-0.7.0b3-py3-none-any.whl' --pattern WHEEL-SHA256SUMS
shasum -a 256 -c WHEEL-SHA256SUMS
gh attestation verify agent_authz_sdk-0.7.0b3-py3-none-any.whl \
  -R FrankPlusPlus/agent-authz
python -m pip install --no-deps agent_authz_sdk-0.7.0b3-py3-none-any.whl
```

For development or source review, you may install from a reviewed tag, but a
Git tag is not a release-integrity proof:

```bash
python -m pip install "agent-authz-sdk @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b3"
```

See the complete [supply-chain policy](../SUPPLY_CHAIN.md) before using a
security-sensitive release.

## Recommended service boundary

For a service, start with `Authz.production(...)`, a stable `Subject.id`, and
a `ResourceRegistry` loader. The caller supplies only a resource coordinate;
the loader supplies tenant and relationship facts. The root
[README](../README.md#a-safe-five-minute-integration) has the complete safe
first example. The direct `Resource(...)` example below is deliberately kept
as a compact unit-test illustration, not as a production request boundary.

## 1. Register a resource

```python
from authz_sdk import Authz, Catalog, PolicySet, Resource, Subject

catalog = Catalog()
catalog.resource(
    "document",
    title="Document",
    actions=("read", "publish"),
    relations=("viewer", "editor", "owner"),
    tenant_required=True,
)
```

`actions` becomes the list of valid business operations:

```text
document.read
document.publish
```

The SDK does not assume that every resource has CRUD. A knowledge base may
have `query`, a deployment may have `rollback`, and an Agent Pack may have
`mount` and `unmount`.

## 2. Add policy bindings

```python
policies = PolicySet()
policies.bind(
    id="document_read_viewers",
    operation="document.read",
    template="relation",
    relations=("viewer", "editor", "owner"),
)
policies.bind(
    id="document_publish_editors",
    operation="document.publish",
    template="relation",
    relations=("editor", "owner"),
)
```

Policy bindings are reusable rules. They are not rows in a per-document ACL
table. The domain adapter decides whether Alice is a viewer of document 123.

## 3. Make a decision

```python
authz = Authz(catalog, policies)
alice = Subject(id="alice", roles=("member",), tenant_id="acme")
document = Resource(
    "document",
    "123",
    attributes={"tenant_id": "acme"},
    relations={"viewer": True, "editor": False, "owner": False},
)

read = authz.can(alice, resource=document, action="read")
publish = authz.can(alice, resource=document, action="publish")

assert read.allowed
assert not publish.allowed
```

The direct `Resource` above is convenient for a unit test. For a service
boundary, prefer a registry loader and the secure-by-default profile:

```python
authz = Authz.production(catalog, policies, resources)
```

With that profile, a resource must have been resolved by `ResourceRegistry`,
and tenant context plus a strict Catalog are required. A caller cannot grant
itself `owner` or `viewer` by constructing a mapping. See the
[production guide](production.md) for audit, policy-bundle, RAG, and Permit
boundaries.

At a hard enforcement point, use `require()`. It raises on this deliberately
denied `publish` request:

```python
from authz_sdk import AuthorizationError

try:
    authz.require(alice, resource=document, action="publish")
except AuthorizationError as error:
    assert error.decision.reason_code == "policy.deny"
```

`AuthorizationError` includes the complete `Decision` object.

## 4. Load resource facts from the business database

Never trust a caller-provided `creator=True` or `owner=True` flag. Register a
loader owned by the service that owns the data:

```python
from authz_sdk import ResourceRegistry

resources = ResourceRegistry()

documents = {
    "123": {
        "id": "123",
        "tenant_id": "acme",
        "viewers": {"alice"},
        "editors": set(),
        "owner_email": "owner@example.com",
    }
}

def load_document(document_id, subject, context):
    row = documents.get(document_id)
    if row is None:
        return None
    return {
        "id": row["id"],
        "attributes": {"tenant_id": row["tenant_id"]},
        "relations": {
            "viewer": subject.id in row["viewers"],
            "editor": subject.id in row["editors"],
            "owner": row["owner_email"] == subject.id,
        },
    }

resources.register("document", load_document)
authz = Authz.production(catalog, policies, resources)
authz.require(
    alice,
    operation="document.publish",
    resource_type="document",
    resource_id="123",
)
```

In a real application, the loader should also enforce tenant boundaries in its
query.

## 5. Use configuration files or a dashboard

The policy engine accepts a parsed mapping and validates it against the
catalog:

```python
policies = PolicySet.from_mapping(
    {
        "bindings": [
            {
                "id": "document_read_viewers",
                "operation": "document.read",
                "template": "relation",
                "relations": ["viewer", "editor", "owner"],
            }
        ]
    },
    catalog=catalog,
)
```

The SDK intentionally leaves YAML/JSON/database loading to the host. This
keeps the core dependency-free and lets a dashboard use `catalog.inventory()`
to render only valid resources, operations, relations, and entrypoints.

## 6. Bind Agent entrypoints

```python
catalog.bind_entrypoint("api", "GET /documents/{id}", "document.read")
catalog.bind_entrypoint("tool", "document_read", "document.read")

api_decision = authz.can_entrypoint(
    alice,
    kind="api",
    name="GET /documents/{id}",
    resource_type="document",
    resource_id="123",
)
tool_decision = authz.can_entrypoint(
    alice,
    kind="tool",
    name="document_read",
    resource_type="document",
    resource_id="123",
)
```

Both calls evaluate `document.read`. This is the key invariant for Agent
systems: discovery, mounting, and execution may add runtime checks, but they
must not silently invent a second business permission.
