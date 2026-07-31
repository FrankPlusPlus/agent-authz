"""Short-lived, signed execution permits for side-effecting Agent actions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import uuid4

from authz_sdk.models import Decision, Resource, Subject


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _identity(subject: Subject) -> str:
    """Return the signed principal coordinate without weakening opaque IDs.

    ``Subject.id`` is an application-owned opaque identifier and may be
    case-sensitive. Email remains a legacy fallback and is compared
    case-insensitively when it is the only identity coordinate.
    """

    subject_id = str(subject.id or "").strip()
    if subject_id:
        return subject_id
    return str(subject.email or "").strip().lower()


def _payload(data: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(data),
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _finite_timestamp(value: float | None, *, name: str) -> float:
    """Normalize a security-relevant timestamp without accepting NaN/inf."""

    try:
        normalized = float(time.time() if value is None else value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite timestamp") from exc
    if not math.isfinite(normalized):
        raise ValueError(f"{name} must be a finite timestamp")
    return normalized


@dataclass(frozen=True)
class ExecutionPermit:
    """A permit bound to one authorization decision and one resource version.

    The SDK does not persist or revoke permits. The host must keep the signing
    secret private, reject replayed IDs when replay protection is required, and
    check its current resource version at the side-effect boundary.
    """

    operation: str
    subject: str
    resource: str = ""
    resource_type: str = ""
    resource_id: str = ""
    resource_version: str = ""
    entrypoint: str = ""
    policy_version: str = ""
    issued_at: float = 0.0
    expires_at: float = 0.0
    nonce: str = ""
    agent_id: str = ""
    session_id: str = ""
    tool_name: str = ""
    pack_name: str = ""
    approval: str = ""
    context_digest: str = ""
    arguments_digest: str = ""
    signature: str = ""

    @classmethod
    def issue(
        cls,
        decision: Decision,
        subject: Subject,
        *,
        secret: str | bytes,
        resource_version: str = "",
        ttl_seconds: float = 30.0,
        now: float | None = None,
        runtime_context: Mapping[str, Any] | None = None,
        arguments: Mapping[str, Any] | None = None,
    ) -> "ExecutionPermit":
        if not decision.allowed:
            raise PermissionError("an execution permit requires an allowed decision")
        key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if not key:
            raise ValueError("permit signing secret is required")
        if not _identity(subject):
            raise ValueError("permit subject must be authenticated")
        if decision.resource is not None and not str(resource_version or "").strip():
            raise ValueError("resource_version is required for resource-scoped permits")
        try:
            ttl = float(ttl_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("permit ttl_seconds must be greater than zero and at most 300") from exc
        if not math.isfinite(ttl) or ttl <= 0 or ttl > 300:
            raise ValueError("permit ttl_seconds must be greater than zero and at most 300")
        issued_at = _finite_timestamp(now, name="permit now")
        runtime = dict(runtime_context or {})
        try:
            context_digest = _b64(hashlib.sha256(_payload(runtime)).digest()) if runtime_context is not None else ""
        except (TypeError, ValueError) as exc:
            raise ValueError("runtime_context must be JSON serializable") from exc
        try:
            argument_digest = _b64(hashlib.sha256(_payload(arguments or {})).digest()) if arguments is not None else ""
        except (TypeError, ValueError) as exc:
            raise ValueError("arguments must be JSON serializable") from exc
        permit = cls(
            operation=decision.operation,
            subject=_identity(subject),
            resource=decision.resource.uri if decision.resource else "",
            resource_type=decision.resource.type if decision.resource else "",
            resource_id=decision.resource.id if decision.resource else "",
            resource_version=str(resource_version or ""),
            entrypoint=decision.entrypoint,
            policy_version=decision.policy_version,
            issued_at=issued_at,
            expires_at=issued_at + ttl,
            nonce=uuid4().hex,
            agent_id=str(runtime.get("agent_id") or ""),
            session_id=str(runtime.get("session_id") or ""),
            tool_name=str(runtime.get("tool_name") or ""),
            pack_name=str(runtime.get("pack_name") or ""),
            approval=str(runtime.get("approval") or ""),
            context_digest=context_digest,
            arguments_digest=argument_digest,
        )
        return permit._signed(secret)

    def _unsigned_payload(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "subject": self.subject,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_version": self.resource_version,
            "entrypoint": self.entrypoint,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "pack_name": self.pack_name,
            "approval": self.approval,
            "context_digest": self.context_digest,
            "arguments_digest": self.arguments_digest,
        }

    def _signed(self, secret: str | bytes) -> "ExecutionPermit":
        key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        signature = _b64(hmac.new(key, _payload(self._unsigned_payload()), hashlib.sha256).digest())
        return ExecutionPermit(**self._unsigned_payload(), signature=signature)

    def to_token(self) -> str:
        body = _b64(_payload({**self._unsigned_payload(), "signature": self.signature}))
        return f"ap1.{body}"

    @classmethod
    def from_token(cls, token: str) -> "ExecutionPermit":
        prefix, separator, body = str(token or "").partition(".")
        if prefix != "ap1" or not separator or not body:
            raise ValueError("invalid execution permit token")
        try:
            raw = json.loads(_unb64(body).decode("utf-8"))
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise ValueError("invalid execution permit payload") from exc
        if not isinstance(raw, dict) or not raw.get("signature"):
            raise ValueError("execution permit signature is missing")
        signature = str(raw.pop("signature"))
        return cls(**raw, signature=signature)

    def verify(
        self,
        subject: Subject,
        *,
        secret: str | bytes,
        operation: str,
        resource: Resource | None = None,
        resource_version: str = "",
        now: float | None = None,
        entrypoint: str | None = None,
        policy_version: str | None = None,
        runtime_context: Mapping[str, Any] | None = None,
        arguments: Mapping[str, Any] | None = None,
    ) -> bool:
        """Verify signature, expiry, identity, operation, resource, and version."""

        key = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
        if not key:
            return False
        try:
            expected = _b64(
                hmac.new(key, _payload(self._unsigned_payload()), hashlib.sha256).digest()
            )
        except (TypeError, ValueError):
            return False
        try:
            current = _finite_timestamp(now, name="permit now")
            issued_at = _finite_timestamp(self.issued_at, name="permit issued_at")
            expires_at = _finite_timestamp(self.expires_at, name="permit expires_at")
        except ValueError:
            return False
        if not hmac.compare_digest(expected, self.signature):
            return False
        if expires_at <= issued_at or current < issued_at or current >= expires_at:
            return False
        if self.operation != str(operation or "").strip() or self.subject != _identity(subject):
            return False
        if bool(self.resource) != bool(resource):
            return False
        if self.resource:
            if (
                self.resource_type != resource.type
                or self.resource_id != resource.id
                or self.resource_version != str(resource_version or "")
            ):
                return False
        if self.entrypoint and entrypoint != self.entrypoint:
            return False
        if self.policy_version and policy_version is not None and policy_version != self.policy_version:
            return False
        runtime = dict(runtime_context or {})
        if self.context_digest:
            if runtime_context is None:
                return False
            try:
                actual_context_digest = _b64(hashlib.sha256(_payload(runtime)).digest())
            except (TypeError, ValueError):
                return False
            if actual_context_digest != self.context_digest:
                return False
        for field_name in ("agent_id", "session_id", "tool_name", "pack_name", "approval"):
            expected = getattr(self, field_name)
            if expected and str(runtime.get(field_name) or "") != expected:
                return False
        if self.arguments_digest:
            if arguments is None:
                return False
            try:
                actual_digest = _b64(hashlib.sha256(_payload(arguments)).digest())
            except (TypeError, ValueError):
                return False
            if actual_digest != self.arguments_digest:
                return False
        return True


__all__ = ["ExecutionPermit"]
