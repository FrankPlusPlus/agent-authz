"""Replay and revocation state for :class:`ExecutionPermit` instances.

``InMemoryPermitStore`` is a process-local reference implementation. It makes
single-process consumption atomic, but it cannot prevent a replay sent to a
different worker or host. Multi-process deployments must implement
``PermitStore`` with a shared, atomic backend such as Redis or a database.

This module deliberately does not verify permit signatures or request binding.
Call ``ExecutionPermit.verify(...)`` at the side-effect boundary before
consuming a permit. The store only owns the nonce lifecycle.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Any, Protocol, runtime_checkable

from authz_sdk.permit import ExecutionPermit


class PermitStoreStatus(str, Enum):
    """Outcome of a permit lifecycle operation."""

    CONSUMED = "consumed"
    REPLAYED = "replayed"
    REVOKED = "revoked"
    NOT_REVOKED = "not_revoked"
    EXPIRED = "expired"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"
    CLEANED = "cleaned"


@dataclass(frozen=True, slots=True)
class PermitStoreResult:
    """Structured result of consuming, revoking, or checking one permit."""

    status: PermitStoreStatus
    nonce: str = ""
    expires_at: float | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class PermitStoreCleanupResult:
    """Structured result of removing state whose permit lifetime has ended."""

    consumed_removed: int = 0
    revoked_removed: int = 0
    status: PermitStoreStatus = PermitStoreStatus.CLEANED

    @property
    def removed(self) -> int:
        """Total number of nonce records removed by this cleanup."""

        return self.consumed_removed + self.revoked_removed


@runtime_checkable
class PermitStore(Protocol):
    """Shared-store contract for one-time execution permit lifecycle state.

    Implementations must make ``consume`` atomic for a nonce. A successful
    ``CONSUMED`` result reserves that nonce until its ``expires_at``; concurrent
    or later attempts must report ``REPLAYED`` unless a revocation wins first.
    """

    def consume(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Atomically reserve a valid permit nonce for one side effect."""

    def revoke(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Mark a currently valid permit nonce as revoked until expiry."""

    def is_revoked(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Report revocation state without reducing it to a boolean."""

    def cleanup_expired(self, *, now: float | None = None) -> PermitStoreCleanupResult:
        """Remove consumed and revoked nonce records at or after expiry."""


class InMemoryPermitStore:
    """Thread-safe, process-local ``PermitStore`` implementation.

    This is appropriate for a single-process development deployment or tests.
    It is not a distributed replay-protection system: separate processes have
    separate memory. Use a Redis or database implementation of ``PermitStore``
    for any deployment with multiple workers, pods, or hosts.
    """

    durability = "process_local"

    def __init__(self) -> None:
        self._lock = RLock()
        self._consumed: dict[str, float] = {}
        self._revoked: dict[str, float] = {}

    def consume(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Atomically consume ``permit.nonce`` once while it remains valid."""

        nonce, expires_at, current, error = _permit_state(permit, now)
        if error:
            return _invalid_result(nonce, expires_at, error)
        assert expires_at is not None and current is not None

        with self._lock:
            self._cleanup_locked(current)
            if current >= expires_at:
                return _result(PermitStoreStatus.EXPIRED, nonce, expires_at, "permit has expired")
            if nonce in self._revoked:
                return _result(PermitStoreStatus.REVOKED, nonce, expires_at, "permit nonce is revoked")
            if nonce in self._consumed:
                return _result(PermitStoreStatus.REPLAYED, nonce, expires_at, "permit nonce was already consumed")
            self._consumed[nonce] = expires_at
            return _result(PermitStoreStatus.CONSUMED, nonce, expires_at, "permit nonce was consumed")

    def revoke(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Revoke ``permit.nonce`` until expiry; revocation is idempotent."""

        nonce, expires_at, current, error = _permit_state(permit, now)
        if error:
            return _invalid_result(nonce, expires_at, error)
        assert expires_at is not None and current is not None

        with self._lock:
            self._cleanup_locked(current)
            if current >= expires_at:
                return _result(PermitStoreStatus.EXPIRED, nonce, expires_at, "permit has expired")
            already_revoked = nonce in self._revoked
            self._revoked[nonce] = expires_at
            detail = "permit nonce was already revoked" if already_revoked else "permit nonce was revoked"
            return _result(PermitStoreStatus.REVOKED, nonce, expires_at, detail)

    def is_revoked(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Return a structured revocation status for ``permit``."""

        nonce, expires_at, current, error = _permit_state(permit, now)
        if error:
            return _invalid_result(nonce, expires_at, error)
        assert expires_at is not None and current is not None

        with self._lock:
            self._cleanup_locked(current)
            if current >= expires_at:
                return _result(PermitStoreStatus.EXPIRED, nonce, expires_at, "permit has expired")
            if nonce in self._revoked:
                return _result(PermitStoreStatus.REVOKED, nonce, expires_at, "permit nonce is revoked")
            return _result(PermitStoreStatus.NOT_REVOKED, nonce, expires_at, "permit nonce is not revoked")

    def cleanup_expired(self, *, now: float | None = None) -> PermitStoreCleanupResult:
        """Remove any replay or revocation record whose expiry has passed."""

        current = _current_time(now)
        with self._lock:
            consumed_removed, revoked_removed = self._cleanup_locked(current)
        return PermitStoreCleanupResult(
            consumed_removed=consumed_removed,
            revoked_removed=revoked_removed,
        )

    def _cleanup_locked(self, now: float) -> tuple[int, int]:
        consumed_removed = _discard_expired(self._consumed, now)
        revoked_removed = _discard_expired(self._revoked, now)
        return consumed_removed, revoked_removed

    def readiness(self) -> dict[str, object]:
        """Describe this store without falsely claiming multi-worker safety."""

        return {
            "ready": True,
            "shared": False,
            "durability": self.durability,
            "issues": ("permit_store.process_local",),
        }


class RedisPermitStore:
    """A shared, atomic ``PermitStore`` for Redis-compatible clients.

    The store uses short-lived Redis keys and Lua scripts so a nonce cannot be
    consumed twice across workers, pods, or hosts.  It accepts a synchronous
    client exposing ``eval`` and ``exists`` (for example ``redis.Redis``), so
    importing this module never makes Redis a required dependency.  Use
    :meth:`from_url` after installing the ``redis`` extra when a client is not
    already managed by the host application.

    Redis availability is security-relevant at a high-risk side-effect
    boundary. Client failures deliberately become ``UNAVAILABLE`` rather than
    falling back to process memory; callers must proceed only on ``CONSUMED``.
    Permit signature verification and the final resource-version check remain
    the responsibility of :meth:`AgentRuntime.consume_permit` and the host
    transaction respectively.
    """

    durability = "shared"

    _CONSUME_SCRIPT = """
-- agent-authz-permit:consume
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 2
end
if redis.call('SET', KEYS[2], '1', 'NX', 'PX', ARGV[1]) then
    return 1
end
return 3
"""
    _REVOKE_SCRIPT = """
-- agent-authz-permit:revoke
local was_revoked = redis.call('EXISTS', KEYS[1])
redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])
return was_revoked
"""

    def __init__(self, client: Any, *, prefix: str = "agent-authz:permit") -> None:
        if (
            not callable(getattr(client, "eval", None))
            or not callable(getattr(client, "exists", None))
            or not callable(getattr(client, "ping", None))
        ):
            raise TypeError("RedisPermitStore client must expose callable eval, exists, and ping methods")
        normalized_prefix = str(prefix or "").strip().strip(":")
        if not normalized_prefix:
            raise ValueError("RedisPermitStore prefix is required")
        if "{" in normalized_prefix or "}" in normalized_prefix:
            raise ValueError("RedisPermitStore prefix must not contain Redis hash-tag braces")
        self._client = client
        self.prefix = normalized_prefix

    @classmethod
    def from_url(cls, url: str, *, prefix: str = "agent-authz:permit", **kwargs: Any) -> "RedisPermitStore":
        """Create a store from a Redis URL using the optional ``redis`` extra."""

        try:
            from redis import Redis
        except ImportError as exc:  # pragma: no cover - depends on optional dependency
            raise ImportError(
                "RedisPermitStore.from_url requires the redis extra; install agent-authz[redis]"
            ) from exc
        return cls(Redis.from_url(url, **kwargs), prefix=prefix)

    def consume(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Atomically reserve a nonce once across all clients sharing Redis."""

        nonce, expires_at, current, error = _permit_state(permit, now)
        if error:
            return _invalid_result(nonce, expires_at, error)
        assert expires_at is not None and current is not None
        if current >= expires_at:
            return _result(PermitStoreStatus.EXPIRED, nonce, expires_at, "permit has expired")
        try:
            result = int(
                self._client.eval(
                    self._CONSUME_SCRIPT,
                    2,
                    self._key("revoked", nonce),
                    self._key("consumed", nonce),
                    self._ttl_milliseconds(expires_at, current),
                )
            )
        except Exception as exc:
            return self._unavailable(nonce, expires_at, "consume", exc)
        if result == 1:
            return _result(PermitStoreStatus.CONSUMED, nonce, expires_at, "permit nonce was consumed")
        if result == 2:
            return _result(PermitStoreStatus.REVOKED, nonce, expires_at, "permit nonce is revoked")
        if result == 3:
            return _result(PermitStoreStatus.REPLAYED, nonce, expires_at, "permit nonce was already consumed")
        return self._unexpected_result(nonce, expires_at, "consume", result)

    def revoke(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Atomically mark a nonce revoked until its permit expires."""

        nonce, expires_at, current, error = _permit_state(permit, now)
        if error:
            return _invalid_result(nonce, expires_at, error)
        assert expires_at is not None and current is not None
        if current >= expires_at:
            return _result(PermitStoreStatus.EXPIRED, nonce, expires_at, "permit has expired")
        try:
            already_revoked = int(
                self._client.eval(
                    self._REVOKE_SCRIPT,
                    1,
                    self._key("revoked", nonce),
                    self._ttl_milliseconds(expires_at, current),
                )
            )
        except Exception as exc:
            return self._unavailable(nonce, expires_at, "revoke", exc)
        detail = "permit nonce was already revoked" if already_revoked else "permit nonce was revoked"
        return _result(PermitStoreStatus.REVOKED, nonce, expires_at, detail)

    def is_revoked(self, permit: ExecutionPermit, *, now: float | None = None) -> PermitStoreResult:
        """Read revocation state from the shared store without consuming it."""

        nonce, expires_at, current, error = _permit_state(permit, now)
        if error:
            return _invalid_result(nonce, expires_at, error)
        assert expires_at is not None and current is not None
        if current >= expires_at:
            return _result(PermitStoreStatus.EXPIRED, nonce, expires_at, "permit has expired")
        try:
            revoked = bool(self._client.exists(self._key("revoked", nonce)))
        except Exception as exc:
            return self._unavailable(nonce, expires_at, "read revocation", exc)
        if revoked:
            return _result(PermitStoreStatus.REVOKED, nonce, expires_at, "permit nonce is revoked")
        return _result(PermitStoreStatus.NOT_REVOKED, nonce, expires_at, "permit nonce is not revoked")

    def cleanup_expired(self, *, now: float | None = None) -> PermitStoreCleanupResult:
        """Return a no-op cleanup result because Redis expires nonce keys itself."""

        _current_time(now)
        return PermitStoreCleanupResult()

    def readiness(self) -> dict[str, object]:
        """Check the shared store before a worker accepts high-risk traffic.

        A successful ``PING`` is intentionally only a connectivity check. It
        does not certify Redis persistence, topology, or the host's final
        database transaction; those remain deployment responsibilities.
        """

        try:
            healthy = bool(self._client.ping())
        except Exception as exc:
            return {
                "ready": False,
                "shared": True,
                "durability": self.durability,
                "issues": (f"permit_store.unavailable:{type(exc).__name__}",),
            }
        return {
            "ready": healthy,
            "shared": True,
            "durability": self.durability,
            "issues": () if healthy else ("permit_store.ping_failed",),
        }

    def _key(self, state: str, nonce: str) -> str:
        # Keep opaque permit nonces out of operational key scans and avoid key
        # syntax surprises if a custom permit implementation supplies one.
        # Both Lua-script keys must use the same Redis Cluster hash tag; without
        # it a healthy cluster rejects EVAL with CROSSSLOT before replay
        # protection can run.
        digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        return f"{self.prefix}:{{{digest}}}:{state}"

    @staticmethod
    def _ttl_milliseconds(expires_at: float, current: float) -> int:
        # Verification still enforces the exact timestamp. Rounding up only
        # retains a replay/revocation marker slightly longer, never a permit.
        return max(1, math.ceil((expires_at - current) * 1000))

    @staticmethod
    def _unavailable(
        nonce: str,
        expires_at: float,
        operation: str,
        error: Exception,
    ) -> PermitStoreResult:
        return _result(
            PermitStoreStatus.UNAVAILABLE,
            nonce,
            expires_at,
            f"shared permit store unavailable during {operation}: {type(error).__name__}",
        )

    def _unexpected_result(
        self,
        nonce: str,
        expires_at: float,
        operation: str,
        result: object,
    ) -> PermitStoreResult:
        return _result(
            PermitStoreStatus.UNAVAILABLE,
            nonce,
            expires_at,
            f"shared permit store returned an invalid {operation} result: {result!r}",
        )


def _permit_state(
    permit: ExecutionPermit,
    now: float | None,
) -> tuple[str, float | None, float | None, str]:
    nonce = getattr(permit, "nonce", "")
    if not isinstance(nonce, str) or not nonce.strip():
        return "", None, None, "permit nonce is required"
    nonce = nonce.strip()

    raw_expiry = getattr(permit, "expires_at", None)
    try:
        expires_at = float(raw_expiry)
    except (TypeError, ValueError):
        return nonce, None, None, "permit expires_at must be a timestamp"
    if not math.isfinite(expires_at):
        return nonce, None, None, "permit expires_at must be finite"

    try:
        current = _current_time(now)
    except ValueError as exc:
        return nonce, expires_at, None, str(exc)
    return nonce, expires_at, current, ""


def _current_time(now: float | None) -> float:
    try:
        current = float(time.time() if now is None else now)
    except (TypeError, ValueError) as exc:
        raise ValueError("now must be a finite timestamp") from exc
    if not math.isfinite(current):
        raise ValueError("now must be a finite timestamp")
    return current


def _discard_expired(records: dict[str, float], now: float) -> int:
    expired = [nonce for nonce, expires_at in records.items() if now >= expires_at]
    for nonce in expired:
        del records[nonce]
    return len(expired)


def _invalid_result(nonce: str, expires_at: float | None, detail: str) -> PermitStoreResult:
    return _result(PermitStoreStatus.INVALID, nonce, expires_at, detail)


def _result(
    status: PermitStoreStatus,
    nonce: str,
    expires_at: float | None,
    detail: str,
) -> PermitStoreResult:
    return PermitStoreResult(status=status, nonce=nonce, expires_at=expires_at, detail=detail)


def permit_store_readiness(
    store: PermitStore,
    *,
    require_shared: bool = False,
) -> dict[str, object]:
    """Normalize operational readiness for a permit store.

    The lifecycle protocol deliberately stays small, so applications may use
    their own Redis/database adapter.  This helper lets a startup check reject
    a process-local store when a deployment has multiple workers, while still
    accepting compatible custom stores that report the same small schema.
    """

    readiness = getattr(store, "readiness", None)
    if callable(readiness):
        try:
            raw = readiness()
        except Exception as exc:
            raw = {
                "ready": False,
                "shared": False,
                "durability": "unknown",
                "issues": (f"permit_store.readiness_failed:{type(exc).__name__}",),
            }
    else:
        raw = {
            "ready": False,
            "shared": False,
            "durability": str(getattr(store, "durability", "unknown") or "unknown"),
            "issues": ("permit_store.readiness_unavailable",),
        }
    if not isinstance(raw, dict):
        raw = {
            "ready": False,
            "shared": False,
            "durability": "unknown",
            "issues": ("permit_store.readiness_invalid",),
        }
    issues = tuple(str(item) for item in raw.get("issues", ()) if str(item))
    ready = bool(raw.get("ready"))
    shared = bool(raw.get("shared"))
    if require_shared and not shared:
        issues = (*issues, "permit_store.shared_required")
        ready = False
    return {
        "ready": ready,
        "shared": shared,
        "durability": str(raw.get("durability", "unknown") or "unknown"),
        "issues": issues,
    }


__all__ = [
    "InMemoryPermitStore",
    "PermitStore",
    "PermitStoreCleanupResult",
    "PermitStoreResult",
    "PermitStoreStatus",
    "RedisPermitStore",
    "permit_store_readiness",
]
