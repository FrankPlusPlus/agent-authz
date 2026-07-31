"""One business operation shared by an API and an Agent Tool."""

from authz_sdk import Authz, Catalog, PolicySet, Resource, Subject


catalog = Catalog()
catalog.resource("knowledge_base", title="Knowledge Base", actions=("query",), relations=("viewer",))
catalog.bind_entrypoint("api", "POST /knowledge-bases/{id}/query", "knowledge_base.query")
catalog.bind_entrypoint("tool", "kb_openai_chat_completions", "knowledge_base.query")

policies = PolicySet()
policies.bind(
    id="knowledge_base_query_viewer",
    operation="knowledge_base.query",
    template="relation",
    relations=("viewer",),
)

authz = Authz(catalog, policies)
subject = Subject(email="reader@example.com")
resource = Resource("knowledge_base", "finance-kb", relations={"viewer": True})

for kind, name in (
    ("api", "POST /knowledge-bases/{id}/query"),
    ("tool", "kb_openai_chat_completions"),
):
    decision = authz.can_entrypoint(subject, kind=kind, name=name, resource=resource)
    print(kind, decision.allowed, decision.operation, decision.entrypoint)
