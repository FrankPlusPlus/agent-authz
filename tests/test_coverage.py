from __future__ import annotations

import pytest

from authz_sdk import Catalog, CoverageError, CoverageManifest


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
    assert manifest.assert_complete().ready


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
    assert manifest.assert_complete().ready


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
    assert manifest.assert_complete().ready
