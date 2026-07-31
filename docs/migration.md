# Migration Guide

The safest migration is not a rewrite of every old check. Keep existing
behavior while introducing one public vocabulary.

## Phase 1: inventory

List current checks and group them by business operation:

| Existing check | New operation |
| --- | --- |
| `DELETE /ai-employees/{id}` | `ai_employee.delete` |
| `kb_openai_chat_completions` Tool | `knowledge_base.query` |
| `finance_research` Pack mount | `knowledge_base.query` or its declared member operations |
| product list page | `product.list` |

Do not make the URL or Tool name the permission itself. They are entrypoints.

## Phase 2: add the catalog

Register resources, actions, and entrypoints in code. Generate a catalog
inventory for the dashboard. At this point, no access behavior has to change.

## Phase 3: add an adapter

Wrap the existing user and resource loaders:

```python
def subject_from_existing_user(user):
    return Subject(
        id=user.id,
        email=user.email,
        roles=(user.role,),
        positions=(user.position,),
        tenant_id=user.tenant_id,
    )
```

For each resource type, compute the old ownership or visibility facts in a
`ResourceRegistry` loader. The adapter is where compatibility lives; the
policy engine should not know the application's ORM or tables.

## Phase 4: overlap mode

Run the new decision beside the old decision and record differences without
changing the response. Review every difference:

- Is the old behavior intentional?
- Is the new resource relation incomplete?
- Is a route mapped to the wrong operation?
- Is the old check relying on a hidden administrator bypass?

Only activate the new result for a small operation or tenant after the
difference report is empty or explicitly accepted.

## Phase 5: enforce and remove duplication

Replace the old call at one enforcement point with `require()` or
`decision.allowed`. Keep response shaping and business validation in the
handler. After all callers use the new contract, remove the old check only
after a regression window and audit review.

## Compatibility rule

The SDK cannot automatically infer a business relation that the old code never
exposed. For example, “only the creator can delete” requires a trusted creator
fact. A CRUD menu entry alone cannot express that rule. The migration must
register the resource relation and add the policy binding.

## Dashboard contract

A dashboard should be generated from:

- `catalog.inventory()` for valid resources, actions, operations, and
  entrypoints;
- `PolicySet.inventory()` for current bindings;
- `SUPPORTED_TEMPLATES` for guided policy choices;
- `Authz.explain()` for test and audit previews.

It should ask the user for the smallest useful form: operation first, then
subject selectors or resource relation, then effect and description. Advanced
parameters should be hidden until a template needs them.
