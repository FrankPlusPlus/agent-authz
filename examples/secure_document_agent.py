"""A complete, dependency-free Agent authorization path.

Run from a source checkout with::

    python -m pip install -e .
    python examples/secure_document_agent.py

The example proves one business operation can cross an API, an Agent Tool,
candidate-level RAG filtering, and a one-time destructive execution permit.
It is intentionally in-memory so the security boundaries are visible; replace
the loaders and PermitStore with the application's database/Redis adapters in
a production deployment.
"""

from __future__ import annotations

from typing import Any

from authz_sdk import (
    AgentRequest,
    AgentRuntime,
    AuditRedactor,
    Authz,
    CandidateFilter,
    Catalog,
    CoverageManifest,
    InMemoryAuditSink,
    InMemoryPermitStore,
    PermitStoreStatus,
    PolicySet,
    ResourceRegistry,
    Subject,
)


def build_authz() -> tuple[Authz, ResourceRegistry, InMemoryAuditSink, CoverageManifest]:
    """Build the secure-by-default boundary and trusted data adapters."""

    catalog = Catalog()
    catalog.resource(
        "document",
        actions=("read", "publish"),
        relations=("viewer", "editor"),
        tenant_required=True,
    )
    catalog.resource(
        "knowledge_chunk",
        actions=("read",),
        relations=("viewer",),
        tenant_required=True,
    )
    catalog.bind_entrypoint("api", "GET /documents/{id}", "document.read")
    catalog.bind_entrypoint("tool", "document_read", "document.read")
    catalog.bind_agent_entrypoint("execute", "document_publish", "document.publish")
    catalog.bind_entrypoint("rag", "document_search", "knowledge_chunk.read")

    policies = PolicySet(version="demo-bundle-1")
    policies.bind(
        id="document_viewers_read",
        operation="document.read",
        template="relation",
        relations=("viewer",),
    )
    policies.bind(
        id="document_editors_publish",
        operation="document.publish",
        template="relation",
        relations=("editor",),
    )
    policies.bind(
        id="visible_chunks_read",
        operation="knowledge_chunk.read",
        template="relation",
        relations=("viewer",),
    )

    documents = {
        "doc-acme": {"tenant_id": "acme", "viewers": {"alice"}, "editors": {"alice"}, "version": "7"},
    }
    chunks = {
        "chunk-public": {"tenant_id": "acme", "viewers": {"alice"}, "text": "approved context"},
        "chunk-private": {"tenant_id": "acme", "viewers": {"bob"}, "text": "must never reach Alice"},
    }
    resources = ResourceRegistry()

    def load_document(resource_id: str, subject: Subject, context: dict[str, Any]) -> dict[str, Any] | None:
        row = documents.get(resource_id)
        if row is None:
            return None
        return {
            "id": resource_id,
            "attributes": {"tenant_id": row["tenant_id"], "version": row["version"]},
            "relations": {
                "viewer": subject.id in row["viewers"],
                "editor": subject.id in row["editors"],
            },
        }

    def load_chunk(resource_id: str, subject: Subject, context: dict[str, Any]) -> dict[str, Any] | None:
        row = chunks.get(resource_id)
        if row is None:
            return None
        return {
            "id": resource_id,
            "attributes": {"tenant_id": row["tenant_id"]},
            "relations": {"viewer": subject.id in row["viewers"]},
        }

    resources.register("document", load_document)
    resources.register("knowledge_chunk", load_chunk)
    audit = InMemoryAuditSink()
    coverage = CoverageManifest(catalog)
    coverage.require_final_execution("document.publish")
    coverage.require_data_boundary("knowledge_chunk.read")
    coverage.record_enforcement(
        "api",
        "GET /documents/{id}",
        evidence="examples/secure_document_agent.py::run_demo",
    )
    coverage.record_enforcement(
        "tool",
        "document_read",
        evidence="examples/secure_document_agent.py::run_demo",
    )
    coverage.record_enforcement(
        "agent.execute",
        "document_publish",
        evidence="examples/secure_document_agent.py::run_demo",
    )
    coverage.record_enforcement(
        "rag",
        "document_search",
        evidence="examples/secure_document_agent.py::run_demo",
    )
    coverage.record_data_boundary(
        "knowledge_chunk.read",
        entrypoint="rag:document_search",
        evidence="examples/secure_document_agent.py::run_demo",
    )
    return (
        Authz.production(
            catalog,
            policies,
            resources,
            audit_sink=audit,
            # Demo-only key. A deployment loads and rotates this through its
            # secret manager, then writes only pseudonymous identifiers.
            audit_redactor=AuditRedactor("demo-audit-secret", key_id="demo"),
        ),
        resources,
        audit,
        coverage,
    )


def run_demo() -> dict[str, Any]:
    """Run all boundaries and return only safe, inspectable outcomes."""

    authz, resources, audit, coverage = build_authz()
    alice = Subject(id="alice", tenant_id="acme")

    api = authz.can_entrypoint(
        alice,
        kind="api",
        name="GET /documents/{id}",
        resource_type="document",
        resource_id="doc-acme",
    )
    tool = authz.can_entrypoint(
        alice,
        kind="tool",
        name="document_read",
        resource_type="document",
        resource_id="doc-acme",
    )
    tool_denied = authz.can_entrypoint(
        Subject(id="bob", tenant_id="acme"),
        kind="tool",
        name="document_read",
        resource_type="document",
        resource_id="doc-acme",
    )
    cross_tenant = authz.can_entrypoint(
        Subject(id="alice", tenant_id="other-tenant"),
        kind="api",
        name="GET /documents/{id}",
        resource_type="document",
        resource_id="doc-acme",
    )

    raw_candidates = (
        {"id": "chunk-public", "text": "approved context"},
        {"id": "chunk-private", "text": "must never reach Alice"},
    )
    candidate_filter = CandidateFilter(
        authz,
        resource_mapper=lambda candidate, subject, context: resources.resolve(
            "knowledge_chunk",
            candidate["id"],
            subject,
            context=context,
        ),
    )
    retrieval = candidate_filter.filter(
        raw_candidates,
        subject=alice,
        operation="knowledge_chunk.read",
        entrypoint="rag:document_search",
    )

    runtime = AgentRuntime(authz)
    # This store belongs to the process/application lifetime. Never create a
    # fresh store at each destructive request: that would forget consumed
    # nonces and make replay protection meaningless.
    permit_store = InMemoryPermitStore()
    document = resources.resolve("document", "doc-acme", alice)
    assert document is not None
    publish = AgentRequest(
        subject=alice,
        operation="document.publish",
        phase="execute",
        tool_name="document_publish",
        resource=document,
        arguments={"state": "published"},
    )
    permit = runtime.issue_permit(
        publish,
        secret="demo-secret-not-for-production",
        resource_version="7",
        now=100.0,
    )
    permit_result = runtime.consume_permit(
        publish,
        permit,
        secret="demo-secret-not-for-production",
        resource_version="7",
        store=permit_store,
        now=101.0,
    )
    coverage_report = coverage.assert_complete()

    return {
        "api_allowed": api.allowed,
        "tool_allowed": tool.allowed,
        "tool_denied": not tool_denied.allowed,
        "cross_tenant_denied": not cross_tenant.allowed,
        "permitted_chunk_ids": [candidate["id"] for candidate in retrieval.candidates],
        "excluded_candidate_count": retrieval.summary.excluded_count,
        "permit_status": permit_result.status.value,
        "audit_event_count": len(audit.events),
        "coverage_ready": coverage_report.ready,
    }


if __name__ == "__main__":
    summary = run_demo()
    assert summary["permit_status"] == PermitStoreStatus.CONSUMED.value
    assert summary["tool_denied"]
    assert summary["cross_tenant_denied"]
    assert summary["coverage_ready"]
    print(summary)
