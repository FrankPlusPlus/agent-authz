from __future__ import annotations

import pytest

from authz_sdk import (
    AgentRuntime,
    Authz,
    Catalog,
    CoverageError,
    CoverageManifest,
    FastAPIAuthz,
    PolicySet,
    Resource,
    Subject,
    protect_tool,
    record_fastapi_inventory,
    record_tool_inventory,
)


def _catalog() -> Catalog:
    catalog = Catalog()
    catalog.resource("document", actions=("read", "publish"))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    catalog.bind_entrypoint("tool", "document_publish", "document.publish")
    return catalog


def test_manifest_reports_missing_guard_and_high_risk_final_execution() -> None:
    manifest = CoverageManifest(_catalog()).require_final_execution("document.publish")
    manifest.record_enforcement(
        "api",
        "GET /documents/{document_id}",
        operation="document.read",
        evidence="tests/test_documents_api.py::test_read_denied",
    )
    manifest.record_enforcement(
        "tool",
        "document_publish",
        operation="document.publish",
        final=False,
        evidence="discovery-only guard",
    )

    report = manifest.report()

    assert not report.ready
    assert {item.code for item in report.issues} >= {
        "coverage.final_enforcement_missing",
    }

    manifest.record_enforcement(
        "tool",
        "document_publish",
        operation="document.publish",
        final=True,
        evidence="tests/test_publish_tool.py::test_publish_denied",
    )
    assert manifest.assert_attested_complete().ready


def test_manifest_requires_catalog_entrypoint_or_explicit_exemption() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read", "delete"))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    manifest = CoverageManifest(catalog)
    manifest.record_enforcement("api", "GET /documents/{document_id}")

    report = manifest.report()
    assert any(
        item.code == "coverage.operation_entrypoint_missing" and item.operation == "document.delete"
        for item in report.issues
    )

    manifest.exempt("document.delete", reason="this read-only service cannot delete documents")
    assert manifest.assert_attested_complete().ready


def test_manifest_rejects_unregistered_or_mismatched_evidence() -> None:
    manifest = CoverageManifest(_catalog())
    manifest.record_enforcement("api", "missing-route", operation="document.read")
    manifest.record_enforcement(
        "tool",
        "document_publish",
        operation="document.read",
    )

    codes = {item.code for item in manifest.report().issues}
    assert codes >= {
        "coverage.entrypoint_unregistered",
        "coverage.entrypoint_operation_mismatch",
    }
    with pytest.raises(CoverageError, match="authorization coverage is incomplete"):
        manifest.assert_complete()


def test_manifest_distinguishes_strict_evidence_from_a_host_attestation() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("task", "refresh_document", "document.read")
    manifest = CoverageManifest(catalog)
    manifest.record_enforcement("task", "refresh_document", final=True)

    strict = manifest.report()

    assert not strict.ready
    assert strict.verification_level == "strict"
    assert any(item.code == "coverage.entrypoint_enforcement_attested_only" for item in strict.issues)
    with pytest.raises(CoverageError):
        manifest.assert_complete()
    assert manifest.assert_attested_complete().verification_level == "attested"


def test_manifest_refuses_a_direct_framework_evidence_claim_without_adapter_capability() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    manifest = CoverageManifest(catalog)

    with pytest.raises(TypeError):
        manifest._record_framework_enforcement("api", "GET /documents/{document_id}")


def test_manifest_requires_a_declared_data_boundary_when_requested() -> None:
    catalog = Catalog()
    catalog.resource("knowledge_chunk", actions=("read",))
    catalog.bind_entrypoint("rag", "knowledge_search", "knowledge_chunk.read")
    manifest = CoverageManifest(catalog).require_data_boundary("knowledge_chunk.read")
    manifest.record_enforcement("rag", "knowledge_search", final=True)

    assert any(item.code == "coverage.data_boundary_missing" for item in manifest.report().issues)

    manifest.record_data_boundary(
        "knowledge_chunk.read",
        entrypoint="rag:knowledge_search",
        evidence="tests/test_retrieval.py::test_unauthorized_chunk_excluded",
    )
    assert manifest.assert_attested_complete().ready


def test_fastapi_inventory_reports_live_unregistered_and_stale_catalog_routes() -> None:
    fastapi = pytest.importorskip("fastapi")
    catalog = Catalog()
    catalog.resource("document", actions=("read", "delete"))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    catalog.bind_entrypoint("api", "DELETE /documents/{document_id}", "document.delete")
    manifest = CoverageManifest(catalog)
    manifest.record_enforcement("api", "GET /documents/{document_id}")
    manifest.record_enforcement("api", "DELETE /documents/{document_id}")
    app = fastapi.FastAPI()

    @app.get("/documents/{document_id}")
    async def read_document(document_id: str) -> dict[str, str]:
        return {"id": document_id}

    @app.post("/documents/{document_id}/preview")
    async def preview_document(document_id: str) -> dict[str, str]:
        return {"id": document_id}

    report = record_fastapi_inventory(manifest, app)
    issues = {(item.code, item.entrypoint) for item in report.issues}

    assert ("coverage.discovered_entrypoint_unregistered", "api:POST /documents/{document_id}/preview") in issues
    assert ("coverage.catalog_entrypoint_not_discovered", "api:DELETE /documents/{document_id}") in issues
    assert {item["name"] for item in report.discovered_entrypoints} == {
        "GET /documents/{document_id}",
        "POST /documents/{document_id}/preview",
    }


def test_fastapi_inventory_requires_explicit_ignores_and_skips_builtin_docs_routes() -> None:
    fastapi = pytest.importorskip("fastapi")
    catalog = Catalog()
    catalog.resource("health", actions=({"name": "read", "requires_resource": False},))
    manifest = CoverageManifest(catalog).exempt(
        "health.read",
        reason="health endpoint has no protected business action",
    )
    app = fastapi.FastAPI()

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    report = record_fastapi_inventory(manifest, app, ignored=("/health",))

    assert report.ready
    assert not report.discovered_entrypoints


def test_fastapi_inventory_walks_mounted_subapplication_routes() -> None:
    fastapi = pytest.importorskip("fastapi")
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("api", "GET /v1/documents/{document_id}", "document.read")
    manifest = CoverageManifest(catalog)
    guard = FastAPIAuthz(
        _UnusedAuthz(),
        subject=lambda _request: object(),
        coverage=manifest,
    ).dependency(entrypoint="GET /v1/documents/{document_id}")
    child = fastapi.FastAPI()

    @child.get("/documents/{document_id}", dependencies=[fastapi.Depends(guard)])
    async def read_document(document_id: str) -> dict[str, str]:
        return {"id": document_id}

    app = fastapi.FastAPI()
    app.mount("/v1", child)

    report = record_fastapi_inventory(manifest, app)

    assert report.ready
    assert report.discovered_entrypoints == (
        {
            "kind": "api",
            "name": "GET /v1/documents/{document_id}",
            "source": "FastAPI route registration",
        },
    )


class _UnusedAuthz:
    """Satisfy FastAPIAuthz construction without executing a route guard."""

    def can(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("the inventory test must not execute this guard")

    def can_entrypoint(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("the inventory test must not execute this guard")


def test_fastapi_inventory_requires_a_guard_attached_to_the_real_route() -> None:
    fastapi = pytest.importorskip("fastapi")
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    manifest = CoverageManifest(catalog)
    guard = FastAPIAuthz(
        _UnusedAuthz(),
        subject=lambda _request: object(),
        coverage=manifest,
    ).dependency(entrypoint="GET /documents/{document_id}")
    app = fastapi.FastAPI()

    @app.get("/documents/{document_id}")
    async def read_document(document_id: str) -> dict[str, str]:
        return {"id": document_id}

    report = record_fastapi_inventory(manifest, app)

    assert any(
        item.code == "coverage.entrypoint_enforcement_missing"
        and item.entrypoint == "api:GET /documents/{document_id}"
        for item in report.issues
    )
    assert guard is not None


def test_fastapi_inventory_verifies_a_guard_in_the_assembled_dependency_tree() -> None:
    fastapi = pytest.importorskip("fastapi")
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    manifest = CoverageManifest(catalog)
    guard = FastAPIAuthz(
        _UnusedAuthz(),
        subject=lambda _request: object(),
        coverage=manifest,
    ).dependency(entrypoint="GET /documents/{document_id}")
    app = fastapi.FastAPI()

    @app.get("/documents/{document_id}", dependencies=[fastapi.Depends(guard)])
    async def read_document(document_id: str) -> dict[str, str]:
        return {"id": document_id}

    report = record_fastapi_inventory(manifest, app)

    assert report.ready
    assert report.enforced_entrypoints == (
        {
            "kind": "api",
            "name": "GET /documents/{document_id}",
            "entrypoint": "api:GET /documents/{document_id}",
            "operation": "document.read",
            "final": True,
            "evidence": "FastAPI route registration: read_document",
            "verified": True,
        },
    )


def test_fastapi_inventory_rejects_a_manual_route_coverage_assertion() -> None:
    fastapi = pytest.importorskip("fastapi")
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    manifest = CoverageManifest(catalog)
    manifest.record_enforcement("api", "GET /documents/{document_id}")
    app = fastapi.FastAPI()

    @app.get("/documents/{document_id}")
    async def read_document(document_id: str) -> dict[str, str]:
        return {"id": document_id}

    report = record_fastapi_inventory(manifest, app)

    assert any(
        item.code == "coverage.entrypoint_enforcement_attested_only"
        and item.entrypoint == "api:GET /documents/{document_id}"
        for item in report.issues
    )


def test_fastapi_inventory_rejects_a_public_marker_spoof() -> None:
    fastapi = pytest.importorskip("fastapi")
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")
    manifest = CoverageManifest(catalog)

    async def unguarded_dependency() -> None:
        return None

    setattr(
        unguarded_dependency,
        "__agent_authz_fastapi_entrypoint__",
        "GET /documents/{document_id}",
    )
    app = fastapi.FastAPI()

    @app.get("/documents/{document_id}", dependencies=[fastapi.Depends(unguarded_dependency)])
    async def read_document(document_id: str) -> dict[str, str]:
        return {"id": document_id}

    report = record_fastapi_inventory(manifest, app)

    assert any(
        item.code == "coverage.entrypoint_enforcement_missing"
        and item.entrypoint == "api:GET /documents/{document_id}"
        for item in report.issues
    )


def test_tool_inventory_verifies_the_assembled_protected_tool_list() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("tool", "read_document", "document.read")
    manifest = CoverageManifest(catalog)

    def read_document() -> str:
        return "content"

    guarded = protect_tool(
        read_document,
        runtime=AgentRuntime(Authz.native(catalog, PolicySet())),
        operation="document.read",
        subject=Subject(id="alice"),
        resource=Resource("document", "doc-1"),
    )

    report = record_tool_inventory(manifest, [guarded])

    assert not report.ready
    assert report.enforced_entrypoints[0]["verified"] is False
    assert any(item.code == "coverage.entrypoint_enforcement_attested_only" for item in report.issues)
    assert manifest.assert_attested_complete().verification_level == "attested"


def test_tool_inventory_rejects_an_unprotected_callable() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("tool", "read_document", "document.read")
    manifest = CoverageManifest(catalog)

    def read_document() -> str:
        return "content"

    report = record_tool_inventory(manifest, [read_document])

    assert any(
        item.code == "coverage.entrypoint_enforcement_missing"
        and item.entrypoint == "tool:read_document"
        for item in report.issues
    )


def test_tool_inventory_rejects_a_public_marker_spoof() -> None:
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    catalog.bind_entrypoint("tool", "read_document", "document.read")
    manifest = CoverageManifest(catalog)

    def unguarded() -> str:
        return "content"

    unguarded.__name__ = "read_document"
    setattr(unguarded, "authz_protected", True)
    setattr(unguarded, "authz_phase", "execute")
    setattr(unguarded, "authz_entrypoint_kind", "tool")
    setattr(unguarded, "authz_entrypoint_name", "read_document")
    setattr(unguarded, "authz_operation", "document.read")

    report = record_tool_inventory(manifest, [unguarded])

    assert any(
        item.code == "coverage.entrypoint_enforcement_missing"
        and item.entrypoint == "tool:read_document"
        for item in report.issues
    )
