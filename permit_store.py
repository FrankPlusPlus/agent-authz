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

import math
import time
from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Protocol, runtime_checkable

from authz_sdk.permit import ExecutionPermit


class PermitStoreStatus(str, Enum):
    """Outcome of a permit lifecycle operation."""

    CONSUMED = "consumed"
    REPLAYED = "replayed"
    REVOKED = "revoked"
    NOT_REVOKED = "not_revoked"
    EXPIRED = "expired"
    INVALID = "invalid"
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


__all__ = [
    "InMemoryPermitStore",
    "PermitStore",
    "PermitStoreCleanupResult",
    "PermitStoreResult",
    "PermitStoreStatus",
]
