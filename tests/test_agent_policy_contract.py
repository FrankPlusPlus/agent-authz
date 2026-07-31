from authz_sdk import AgentRequest, AgentRuntime, Authz, Catalog, ExecutionPermit, PolicySet, Resource, Subject


def make_authz() -> Authz:
    catalog = Catalog()
    catalog.resource(
        "document",
        title="Document",
        actions=("read", "publish"),
        relations=("viewer", "editor", "owner"),
    )
    policies = PolicySet(version="2026.07.29")
    policies.bind(
        id="document_read_same_tenant",
        operation="document.read",
        template="conditional",
        when={
            "all": [
                {"relation": "viewer"},
                {"eq": [{"subject": "tenant_id"}, {"resource": "tenant_id"}]},
            ]
        },
    )
    policies.bind(
        id="document_publish_editor",
        operation="document.publish",
        template="relation",
        relations=("editor", "owner"),
        when={
            "any": [
                {"eq": [{"context": "authz_phase"}, "mount"]},
                {"eq": [{"context": "authz_phase"}, "execute"]},
                {"not": {"exists": [{"context": "authz_phase"}, True]}},
            ]
        },
    )
    policies.bind(
        id="document_publish_discover",
        operation="document.publish",
        template="authenticated",
        when={"eq": [{"context": "authz_phase"}, "discover"]},
        priority=50,
        description="A signed-in user may discover the tool; execution is checked separately.",
    )
    policies.bind(
        id="document_publish_deny_after_hours",
        operation="document.publish",
        template="allow",
        effect="deny",
        when={"eq": [{"context": "business_hours"}, False]},
        priority=1,
        description="Publishing is disabled outside business hours.",
    )
    return Authz(catalog, policies)


def test_conditions_and_deny_overrides_are_explicit_and_explainable():
    authz = make_authz()
    subject = Subject(email="alice@example.com", tenant_id="tenant-a")
    document = Resource(
        "document",
        "doc-1",
        attributes={"tenant_id": "tenant-a"},
        relations={"viewer": True, "editor": True},
    )

    allowed = authz.can(subject, resource=document, action="read")
    assert allowed.allowed
    assert allowed.reason_code == "policy.allow"
    assert allowed.policy_version == "2026.07.29"

    denied = authz.can(
        subject,
        resource=document,
        action="publish",
        context={"business_hours": False},
    )
    assert not denied.allowed
    assert denied.policy == "document_publish_deny_after_hours"
    assert denied.reason_code == "policy.deny"


def test_policy_validation_rejects_unknown_operation_and_bad_condition():
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    try:
        PolicySet.from_mapping(
            {
                "version": "test",
                "bindings": [
                    {
                        "id": "bad-operation",
                        "operation": "document.read",
                        "template": "allow",
                        "when": {"operator": "mystery", "left": 1, "right": 2},
                    }
                ],
            },
            catalog=catalog,
        )
    except ValueError as exc:
        assert "invalid condition" in str(exc)
    else:
        raise AssertionError("invalid policy configuration must be rejected before activation")


def test_agent_runtime_requires_a_resource_at_each_resource_scoped_phase():
    authz = make_authz()
    runtime = AgentRuntime(authz)
    subject = Subject(email="alice@example.com", tenant_id="tenant-a")
    document = Resource(
        "document",
        "doc-1",
        attributes={"tenant_id": "tenant-a"},
        relations={"viewer": True, "editor": True},
    )
    discover = runtime.can(
        AgentRequest(
            subject=subject,
            operation="document.publish",
            phase="discover",
            tool_name="document_publish",
        )
    )
    execute = runtime.can(
        AgentRequest(
            subject=subject,
            operation="document.publish",
            phase="execute",
            tool_name="document_publish",
            resource=document,
            context={"business_hours": True},
        )
    )
    assert not discover.allowed
    assert discover.reason_code == "resource.required"
    assert execute.allowed
    assert discover.operation == execute.operation == "document.publish"
    assert discover.entrypoint.startswith("agent.discover:")
    assert execute.entrypoint.startswith("agent.execute:")


def test_catalog_agent_entrypoint_is_phase_validated():
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_agent_entrypoint("execute", "document_read", "document.read")
    assert catalog.entrypoint("agent.execute", "document_read").operation == "document.read"
    try:
        catalog.bind_agent_entrypoint("inspect", "document_read", "document.read")
    except ValueError as exc:
        assert "agent phase" in str(exc)
    else:
        raise AssertionError("unknown Agent phases must be rejected")


def test_batch_checks_reuse_one_subject_and_fail_closed_for_unknown_operation():
    authz = make_authz()
    subject = Subject(email="alice@example.com", tenant_id="tenant-a")
    document = Resource("document", "doc-1", attributes={"tenant_id": "tenant-a"}, relations={"viewer": True})
    results = authz.check_many(subject, [
        {"operation": "document.read", "resource": document},
        {"operation": "missing.operation", "resource": document},
    ])
    assert [item.allowed for item in results] == [True, False]
    assert results[1].reason_code == "catalog.operation_unknown"


def test_string_false_relation_fact_cannot_become_an_allow():
    resource = Resource("document", "doc-1", relations={"viewer": "false"})
    assert resource.related("viewer") is False


def test_attribute_false_relation_fact_cannot_become_an_allow():
    resource = Resource("document", "doc-1", attributes={"viewer": "false"})
    assert resource.related("viewer") is False


def test_tenant_scoped_resource_requires_subject_tenant():
    base = make_authz()
    authz = Authz(base.catalog, base.policies, require_tenant_context=True)
    decision = authz.can(
        Subject(email="alice@example.com"),
        resource=Resource("document", "doc-1", attributes={"tenant_id": "tenant-a"}, relations={"viewer": True}),
        action="read",
    )
    assert not decision.allowed
    assert decision.reason_code == "subject.tenant_context_missing"


def test_negating_a_missing_fact_fails_closed():
    from authz_sdk.conditions import matches

    subject = Subject(email="alice@example.com")
    resource = Resource("document", "doc-1")
    assert not matches(
        {"not": {"relation": "owner"}},
        subject=subject,
        resource=resource,
        context={},
    )


def test_execution_permit_binds_allow_to_identity_resource_version_and_expiry():
    authz = make_authz()
    subject = Subject(id="user-1", email="alice@example.com", tenant_id="tenant-a")
    resource = Resource("document", "doc-1", attributes={"tenant_id": "tenant-a", "version": "7"}, relations={"editor": True})
    decision = AgentRuntime(authz).can(
        AgentRequest(
            subject=subject,
            operation="document.publish",
            phase="execute",
            tool_name="document_publish",
            resource=resource,
            context={"business_hours": True},
        )
    )
    permit = ExecutionPermit.issue(
        decision,
        subject,
        secret="test-secret",
        resource_version="7",
        now=100.0,
        runtime_context={"agent_id": "agent-1", "session_id": "session-1", "tool_name": "document_publish"},
        arguments={"document_id": "doc-1"},
    )
    restored = ExecutionPermit.from_token(permit.to_token())
    verification = {
        "secret": "test-secret",
        "operation": "document.publish",
            "resource": resource,
            "resource_version": "7",
            "entrypoint": "agent.execute:document_publish",
            "policy_version": "2026.07.29",
        "runtime_context": {"agent_id": "agent-1", "session_id": "session-1", "tool_name": "document_publish"},
        "arguments": {"document_id": "doc-1"},
    }
    assert restored.verify(subject, now=101.0, **verification)
    assert not restored.verify(subject, resource=None, now=101.0, **{key: value for key, value in verification.items() if key != "resource"})
    assert not restored.verify(subject, resource_version="8", now=101.0, **{key: value for key, value in verification.items() if key != "resource_version"})
    assert not restored.verify(subject, now=131.0, **verification)


def test_agent_runtime_binds_permit_to_the_exact_request_envelope():
    authz = make_authz()
    runtime = AgentRuntime(authz)
    subject = Subject(id="user-1", email="alice@example.com", tenant_id="tenant-a")
    resource = Resource("document", "doc-1", attributes={"tenant_id": "tenant-a"}, relations={"editor": True})
    request = AgentRequest(
        subject=subject,
        operation="document.publish",
        phase="execute",
        tool_name="document_publish",
        session_id="session-1",
        resource=resource,
        arguments={"document_id": "doc-1"},
        context={"business_hours": True},
    )
    permit = runtime.issue_permit(request, secret="test-secret", resource_version="7", now=100.0)
    assert runtime.verify_permit(request, permit, secret="test-secret", resource_version="7", now=101.0)
    authz.policies.version = "2026.07.30"
    assert not runtime.verify_permit(request, permit, secret="test-secret", resource_version="7", now=101.0)
    changed_request = AgentRequest(
        subject=subject,
        operation=request.operation,
        phase=request.phase,
        tool_name=request.tool_name,
        session_id="other-session",
        resource=resource,
        arguments=request.arguments,
        context=request.context,
    )
    assert not runtime.verify_permit(changed_request, permit, secret="test-secret", resource_version="7", now=101.0)


def test_empty_permit_secret_is_rejected():
    authz = make_authz()
    subject = Subject(email="alice@example.com", tenant_id="tenant-a")
    decision = authz.can(
        subject,
        resource=Resource("document", "doc-1", attributes={"tenant_id": "tenant-a"}, relations={"viewer": True}),
        action="read",
    )
    try:
        ExecutionPermit.issue(decision, subject, secret=b"")
    except ValueError as exc:
        assert "secret" in str(exc)
    else:
        raise AssertionError("empty permit secrets must be rejected")
