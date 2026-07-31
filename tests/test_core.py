from authz_sdk import Authz, Catalog, PolicySet, Resource, ResourceRegistry, Subject


def test_catalog_derives_actions_and_operation_names():
    catalog = Catalog()
    catalog.resource("document", title="Document", actions=("read", "publish"))

    assert catalog.operation_for("document", "read") == "document.read"
    assert [item["name"] for item in catalog.actions_for("document")] == ["read", "publish"]


def test_owner_or_admin_covers_creator_and_admin_without_object_rules():
    catalog = Catalog()
    catalog.resource("ai_employee", title="AI Employee", crud=True, relations=("creator", "owner"))
    policies = PolicySet()
    policies.bind(
        id="delete_creator_or_admin",
        operation="ai_employee.delete",
        template="owner_or_admin",
        relations=("creator",),
        parameters={"admin_roles": ["admin"]},
    )
    authz = Authz(catalog, policies)
    resource = Resource("ai_employee", "employee-1", relations={"creator": False})

    assert authz.can(Subject(email="admin@example.com", roles=("admin",)), resource=resource, action="delete")
    assert not authz.can(Subject(email="member@example.com"), resource=resource, action="delete")


def test_registry_computes_subject_relative_relations():
    catalog = Catalog()
    catalog.resource("document", title="Document", actions=("read",), relations=("viewer",))
    policies = PolicySet()
    policies.bind(
        id="read_viewer",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, subject, context: {
            "relations": {"viewer": subject.email == "alice@example.com"}
        },
    )
    authz = Authz(catalog, policies, resources)

    assert authz.can(
        Subject(email="alice@example.com"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    ).allowed
    assert not authz.can(
        Subject(email="bob@example.com"),
        operation="document.read",
        resource_type="document",
        resource_id="doc-1",
    ).allowed


def test_api_and_tool_entrypoints_share_one_operation():
    catalog = Catalog()
    catalog.resource("knowledge_base", title="Knowledge Base", actions=("query",))
    catalog.bind_entrypoint("api", "POST /kb/{id}/query", "knowledge_base.query")
    catalog.bind_entrypoint("tool", "kb_query", "knowledge_base.query")
    policies = PolicySet()
    policies.bind(id="query_authenticated", operation="knowledge_base.query", template="authenticated")
    authz = Authz(catalog, policies)
    subject = Subject(email="reader@example.com")
    resource = Resource("knowledge_base", "finance")

    api = authz.can_entrypoint(subject, kind="api", name="POST /kb/{id}/query", resource=resource)
    tool = authz.can_entrypoint(subject, kind="tool", name="kb_query", resource=resource)
    assert api.allowed and tool.allowed
    assert api.operation == tool.operation == "knowledge_base.query"
