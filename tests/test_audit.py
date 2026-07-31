from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from authz_sdk.audit import AuditRedactor, AuditWriteError, DecisionEvent, InMemoryAuditSink, JsonlAuditSink
from authz_sdk.models import Decision, Resource, Subject


def _decision(*, entrypoint: str = "tool.documents.read") -> Decision:
    return Decision(
        True,
        "document.read",
        reason="matched policy; internal detail must not be audited",
        policy="document.read.viewer",
        resource=Resource(
            "document",
            "doc-42",
            attributes={"classification": "secret", "owner_email": "owner@example.com"},
            metadata={"database_key": "resource-secret"},
        ),
        obligations={"arguments": {"access_token": "obligation-secret"}},
        trace=({"context": {"session_token": "trace-secret"}},),
        entrypoint=entrypoint,
        reason_code="policy.allow",
        policy_version="bundle-42",
        request_id="request-123",
        trace_id="trace-456",
    )


def test_decision_event_uses_a_fixed_safe_schema_without_sensitive_inputs() -> None:
    subject = Subject(
        id="user-42",
        email="alice@example.com",
        metadata={"api_key": "subject-secret", "organization_path_ids": ["org-secret"]},
    )

    event = DecisionEvent.from_decision(
        _decision(),
        subject,
        timestamp=datetime(2026, 7, 31, 9, 30, tzinfo=timezone.utc),
    )
    encoded = json.dumps(event.to_dict(), sort_keys=True)

    assert event.timestamp == "2026-07-31T09:30:00Z"
    assert event.subject_id == "user-42"
    assert event.resource_uri == "document:doc-42"
    assert event.request_id == "request-123"
    assert event.trace_id == "trace-456"
    assert set(event.to_dict()) == {
        "timestamp",
        "subject_id",
        "operation",
        "resource_uri",
        "entrypoint",
        "allowed",
        "reason_code",
        "policy",
        "policy_version",
        "request_id",
        "trace_id",
    }
    for secret in (
        "alice@example.com",
        "subject-secret",
        "org-secret",
        "owner@example.com",
        "resource-secret",
        "obligation-secret",
        "trace-secret",
        "internal detail",
    ):
        assert secret not in encoded


def test_email_only_subject_uses_a_stable_non_email_fallback() -> None:
    event = DecisionEvent.from_decision(_decision(), Subject(email="Alice@example.com"))

    assert event.subject_id.startswith("sha256:")
    assert "alice@example.com" not in event.subject_id


def test_audit_redactor_pseudonymizes_all_correlatable_identifiers() -> None:
    redactor = AuditRedactor("audit-secret", key_id="2026-q3")
    event = DecisionEvent.from_decision(
        _decision(),
        Subject(id="user-42"),
        redactor=redactor,
    )
    repeated = DecisionEvent.from_decision(
        _decision(),
        Subject(id="user-42"),
        redactor=redactor,
    )

    assert event.subject_id.startswith("hmac-sha256:2026-q3:")
    assert event.resource_uri.startswith("hmac-sha256:2026-q3:")
    assert event.entrypoint.startswith("hmac-sha256:2026-q3:")
    assert event.request_id.startswith("hmac-sha256:2026-q3:")
    assert event.trace_id.startswith("hmac-sha256:2026-q3:")
    assert event.subject_id == repeated.subject_id
    assert event.subject_id != event.resource_uri
    encoded = json.dumps(event.to_dict())
    for raw in (
        "user-42",
        "document:doc-42",
        "tool.documents.read",
        "request-123",
        "trace-456",
    ):
        assert raw not in encoded


def test_audit_redactor_requires_a_nonempty_secret() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        AuditRedactor("")


def test_in_memory_sink_exposes_an_immutable_snapshot() -> None:
    sink = InMemoryAuditSink()
    event = DecisionEvent.from_decision(_decision(), Subject(id="user-42"))

    sink.emit(event)

    assert sink.events == (event,)
    assert sink.snapshot() == (event,)
    with pytest.raises(AttributeError):
        sink.events.append(event)  # type: ignore[attr-defined]
    assert sink.durability == "ephemeral"


def test_jsonl_sink_appends_valid_single_line_json_without_log_injection(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    sink = JsonlAuditSink(path, fsync=True)
    first = DecisionEvent.from_decision(
        _decision(entrypoint="tool.documents.read\nforged-record"),
        Subject(id="user-42"),
        timestamp="2026-07-31T09:30:00Z",
    )
    second = DecisionEvent.from_decision(
        _decision(),
        Subject(id="user-43"),
        timestamp="2026-07-31T09:31:00Z",
    )

    sink.emit(first)
    sink.emit(second)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line) for line in lines] == [first.to_dict(), second.to_dict()]
    assert "\n" not in first.entrypoint
    assert "\\u000a" in first.entrypoint
    assert sink.durability == "local_append_only"


def test_jsonl_sink_raises_a_clear_error_when_append_fails(tmp_path) -> None:
    sink = JsonlAuditSink(tmp_path / "missing-parent" / "audit.jsonl")

    with pytest.raises(AuditWriteError, match="unable to append audit event") as error:
        sink.emit(DecisionEvent.from_decision(_decision(), Subject(id="user-42")))

    assert isinstance(error.value.__cause__, FileNotFoundError)
