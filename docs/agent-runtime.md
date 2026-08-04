# Agent Runtime Guide

Agent permissions are easiest to reason about when the runtime is split into
three stages:

```text
discover -> mount -> execute
```

These stages are runtime entrypoints that can all point to one or more catalog
operations. They are not a bypass mechanism: a resource-scoped operation still
needs a trusted concrete resource in `discover`, `mount`, and `execute`.

`AgentRequest` is the typed envelope for these checks. It carries the subject,
operation, phase, Tool/Pack identity, session, delegation context, approval,
resource, and arguments. `AgentRuntime.issue_permit()` and
`consume_permit()` bind that envelope to a short-lived, one-time execution
permit. The final executor must still perform the resource-version check in its
transaction; multi-worker deployments must supply a shared `PermitStore`.

## API routes

An API route should bind to the operation it performs:

```python
catalog.bind_entrypoint(
    "api",
    "POST /knowledge-bases/{id}/query",
    "knowledge_base.query",
    methods=("POST",),
)
```

The handler still has to load the knowledge base and pass a trusted `Resource`
or `resource_id` to `can_entrypoint()`. Hiding a resource ID in a URL does not
make it trusted.

## Tools

A Tool is an executable program or function. Register its public name as an
entrypoint and map it to the business operation:

```python
catalog.bind_entrypoint(
    "tool",
    "kb_openai_chat_completions",
    "knowledge_base.query",
)
```

The Agent gateway should check the Tool before execution, then check the
resource-aware operation immediately before reading or writing data. The same
operation can therefore protect a direct API call and an indirect Tool call.

For an actually resource-free visibility decision, model it explicitly rather
than relying on the phase in caller-controlled context:

```python
catalog.register_operation(
    "agent.tool.discover",
    requires_resource=False,
    tenant_required=True,
)
catalog.bind_agent_entrypoint("discover", "finance_search", "agent.tool.discover")
```

The execution entrypoint can still map to `knowledge_base.query`, which
requires and resolves the real knowledge-base resource. This makes the
visibility rule reviewable without creating a path that can waive a destructive
operation's resource check.

## Packs

A Pack is a named bundle of Tools. Pack-level policy answers whether a subject
may discover or mount the bundle. Each Tool still needs its own operation
check at execution time:

```python
catalog.bind_entrypoint("pack", "finance_research", "knowledge_base.query")
```

If a Pack contains multiple business operations, register each Tool or Pack
member explicitly. A Pack grant is not a blanket grant to every future Tool;
the gateway should fail closed when a member has no catalog binding.

## RAG and documents

Use different resource types when the business semantics differ:

```python
catalog.resource(
    "knowledge_base",
    title="Knowledge Base",
    actions=("query", "publish"),
    relations=("viewer", "editor", "owner"),
)
catalog.resource(
    "knowledge_document",
    title="Knowledge Document",
    actions=("read", "update", "delete"),
    relations=("viewer", "editor", "owner"),
)
```

A RAG query can require both a knowledge-base relation and a document-level
filter. `CandidateFilter` can take rows/documents returned by the vector or SQL
adapter, map each to a trusted resource, and fail closed before model prompt
assembly. The host should also apply equivalent query pushdown for performance;
an allow on a knowledge-base query alone is not document authorization.

## Models and tasks

Model selection, token budgets, and cost controls are usually separate
resources or attributes:

```python
catalog.resource(
    "model_route",
    title="Model Route",
    actions=("invoke",),
    relations=("viewer", "operator"),
)
```

An asynchronous task should carry the original subject or an explicit service
identity. Do not silently turn a human request into an administrator task.
When a task performs a destructive operation, evaluate the same resource-aware
operation again at execution time rather than trusting the enqueue-time check.

## Runtime checklist

- Authenticate once and build one subject per request.
- Keep Tool names and Pack names as entrypoint metadata.
- Map them to business operations in the catalog.
- Load relations from the data owner, not from request JSON.
- Give resource-free discovery/mount decisions their own explicit operation;
  never use caller context to waive a resource requirement.
- Check resource-aware operations before discovery when visibility itself is
  resource-specific.
- Check again before mounting or executing when side effects matter.
- Filter every RAG candidate before it becomes prompt context.
- Consume a destructive-operation permit immediately before the side effect. Use
  `RedisPermitStore` (not `InMemoryPermitStore`) whenever more than one worker,
  pod, or host can execute the action; proceed only on `consumed`.
- Fail closed when a Tool, Pack member, or operation is unknown.
- Record operation, resource URI, policy ID, entrypoint, and outcome.
- Do not log secrets, prompts, retrieved document contents, or Tool arguments
  unless the host has an explicit data policy.
