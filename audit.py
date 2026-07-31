"""Fixed-schema audit primitives with optional identifier pseudonymization.

This module deliberately records a small, fixed decision envelope.  It does
not accept an ``AuthorizationRequest`` and never serializes a ``Decision`` via
``Decision.to_dict()``, because those objects can contain runtime context,
tool arguments, resource attributes, obligations, or explanatory text that is
not appropriate for a durable audit log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Protocol, runtime_checkable

from authz_sdk.models import Decision, Subject


def _safe_text(value: object) -> str:
    """Return a single-line, JSON-safe representation of an audit field.

    JSON encoding would escape newlines too, but normalizing control
    characters at the event boundary also keeps in-memory and custom sinks
    safe from line-oriented log injection.
    """

    text = "" if value is None else str(value).strip()
    return "".join(
        character if ord(character) >= 0x20 and character != "\x7f" else f"\\u{ord(character):04x}"
        for character in text
    )


def _timestamp(value: datetime | str | None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, datetime):
        utc_value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return utc_value.isoformat().replace("+00:00", "Z")
    return _safe_text(value)


def _subject_id(subject: Subject) -> str:
    """Use an application subject ID, or a non-email fallback identifier.

    Applications should provide ``Subject.id``.  If a legacy integration only
    supplies an email address, the audit record contains its SHA-256 digest
    instead of the email itself.  Subject metadata is never consulted.
    """

    subject_id = _safe_text(subject.id)
    if subject_id:
        return subject_id
    email = str(subject.email or "").strip().lower()
    if not email:
        return ""
    return f"sha256:{hashlib.sha256(email.encode('utf-8')).hexdigest()}"


class AuditRedactor:
    """HMAC-pseudonymize identifiers in a fixed decision-event envelope.

    The SDK cannot know whether an application's subject/resource/request IDs
    contain personal or regulated data. Supplying this redactor keeps values
    correlatable inside the audit stream without writing their raw form to that
    stream. Store ``secret`` in a secret manager; changing it changes the
    pseudonyms, so use ``key_id`` to make planned rotation visible.
    """

    def __init__(self, secret: str | bytes, *, key_id: str = "") -> None:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("audit redaction secret must be non-empty str or bytes")
        self._secret = secret
        self.key_id = _safe_text(key_id)

    def redact(self, field: str, value: object) -> str:
        """Return a domain-separated stable pseudonym for one event field."""

        normalized_field = _safe_text(field)
        normalized_value = _safe_text(value)
        if not normalized_value:
            return ""
        payload = f"{normalized_field}\x00{normalized_value}".encode("utf-8")
        digest = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        key_component = f":{self.key_id}" if self.key_id else ""
        return f"hmac-sha256{key_component}:{digest}"


@dataclass(frozen=True)
class DecisionEvent:
    """A fixed, JSON-serializable audit envelope for one authorization result.

    The schema intentionally excludes subject metadata, email (when a stable
    ID is available), resource attributes, request context, arguments,
    obligations, traces, and human-readable decision reasons. IDs and the
    entrypoint remain raw unless the caller supplies :class:`AuditRedactor`.
    """

    timestamp: str
    subject_id: str
    operation: str
    resource_uri: str
    entrypoint: str
    allowed: bool
    reason_code: str
    policy: str
    policy_version: str
    request_id: str = ""
    trace_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be a bool")
        for field_name in (
            "timestamp",
            "subject_id",
            "operation",
            "resource_uri",
            "entrypoint",
            "reason_code",
            "policy",
            "policy_version",
            "request_id",
            "trace_id",
        ):
            object.__setattr__(self, field_name, _safe_text(getattr(self, field_name)))

    @classmethod
    def from_decision(
        cls,
        decision: Decision,
        subject: Subject,
        *,
        timestamp: datetime | str | None = None,
        redactor: AuditRedactor | None = None,
    ) -> "DecisionEvent":
        """Create a safe audit event from SDK value objects only."""

        if not isinstance(decision, Decision):
            raise TypeError("decision must be a Decision")
        if not isinstance(subject, Subject):
            raise TypeError("subject must be a Subject")
        subject_id = _subject_id(subject)
        resource_uri = decision.resource.uri if decision.resource else ""
        entrypoint = decision.entrypoint
        request_id = decision.request_id
        trace_id = decision.trace_id
        if redactor is not None:
            if not callable(getattr(redactor, "redact", None)):
                raise TypeError("redactor must expose a callable redact(field, value)")
            subject_id = redactor.redact("subject_id", subject_id)
            resource_uri = redactor.redact("resource_uri", resource_uri)
            entrypoint = redactor.redact("entrypoint", entrypoint)
            request_id = redactor.redact("request_id", request_id)
            trace_id = redactor.redact("trace_id", trace_id)
        return cls(
            timestamp=_timestamp(timestamp),
            subject_id=subject_id,
            operation=decision.operation,
            resource_uri=resource_uri,
            entrypoint=entrypoint,
            allowed=decision.allowed,
            reason_code=decision.reason_code,
            policy=decision.policy,
            policy_version=decision.policy_version,
            request_id=request_id,
            trace_id=trace_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return only primitive values suitable for JSON serialization."""

        return {
            "timestamp": self.timestamp,
            "subject_id": self.subject_id,
            "operation": self.operation,
            "resource_uri": self.resource_uri,
            "entrypoint": self.entrypoint,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "policy": self.policy,
            "policy_version": self.policy_version,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
        }


@runtime_checkable
class AuditSink(Protocol):
    """A destination for :class:`DecisionEvent` values."""

    def emit(self, event: DecisionEvent) -> None:
        """Persist or forward one audit event, raising on a failed emission."""


class AuditWriteError(RuntimeError):
    """Raised when an audit event cannot be appended to a sink."""


class InMemoryAuditSink:
    """Thread-safe audit sink intended for tests and short-lived processes."""

    durability = "ephemeral"

    def __init__(self) -> None:
        self._events: list[DecisionEvent] = []
        self._lock = Lock()

    def emit(self, event: DecisionEvent) -> None:
        if not isinstance(event, DecisionEvent):
            raise TypeError("event must be a DecisionEvent")
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> tuple[DecisionEvent, ...]:
        """Return an immutable snapshot of emitted events."""

        return self.snapshot()

    def snapshot(self) -> tuple[DecisionEvent, ...]:
        """Return an immutable snapshot of emitted events."""

        with self._lock:
            return tuple(self._events)


class JsonlAuditSink:
    """Append each safe audit event as one JSON object per line.

    Failures are not swallowed: callers receive :class:`AuditWriteError` and
    can choose whether their enforcement point should fail closed or queue a
    retry.  The sink does not create parent directories implicitly, which
    prevents a misspelled production path from silently changing where audit
    data is written.
    """

    # A local append-only file is useful for development and a small service,
    # but it is not immutable or a replacement for a retained event pipeline.
    durability = "local_append_only"

    def __init__(self, path: str | Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.fsync = bool(fsync)
        self._lock = Lock()

    def emit(self, event: DecisionEvent) -> None:
        if not isinstance(event, DecisionEvent):
            raise TypeError("event must be a DecisionEvent")
        try:
            line = json.dumps(
                event.to_dict(),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        except (TypeError, ValueError) as exc:
            raise AuditWriteError("audit event could not be serialized") from exc

        try:
            with self._lock:
                with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(f"{line}\n")
                    stream.flush()
                    if self.fsync:
                        os.fsync(stream.fileno())
        except OSError as exc:
            raise AuditWriteError(f"unable to append audit event to {self.path!r}") from exc


__all__ = [
    "AuditRedactor",
    "AuditSink",
    "AuditWriteError",
    "DecisionEvent",
    "InMemoryAuditSink",
    "JsonlAuditSink",
]
