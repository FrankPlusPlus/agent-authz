from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from authz_sdk.permit import ExecutionPermit
from authz_sdk.models import Decision, Subject
from authz_sdk.permit_store import InMemoryPermitStore, PermitStoreStatus


def _permit(*, nonce: str = "permit-nonce", expires_at: float = 200.0) -> ExecutionPermit:
    return ExecutionPermit(
        operation="document.publish",
        subject="user-1",
        nonce=nonce,
        expires_at=expires_at,
    )


def test_consume_is_atomic_when_workers_race_for_one_nonce() -> None:
    store = InMemoryPermitStore()
    permit = _permit()
    workers = 16
    start = Barrier(workers)

    def consume_once() -> PermitStoreStatus:
        start.wait()
        return store.consume(permit, now=100.0).status

    with ThreadPoolExecutor(max_workers=workers) as executor:
        statuses = list(executor.map(lambda _: consume_once(), range(workers)))

    assert statuses.count(PermitStoreStatus.CONSUMED) == 1
    assert statuses.count(PermitStoreStatus.REPLAYED) == workers - 1


def test_revoke_is_structured_idempotent_and_blocks_consumption() -> None:
    store = InMemoryPermitStore()
    permit = _permit()

    assert store.is_revoked(permit, now=100.0).status is PermitStoreStatus.NOT_REVOKED
    assert store.revoke(permit, now=100.0).status is PermitStoreStatus.REVOKED
    assert store.revoke(permit, now=100.0).status is PermitStoreStatus.REVOKED
    assert store.is_revoked(permit, now=100.0).status is PermitStoreStatus.REVOKED
    assert store.consume(permit, now=100.0).status is PermitStoreStatus.REVOKED


def test_expiry_is_reported_and_expired_state_is_cleaned() -> None:
    store = InMemoryPermitStore()
    expired = _permit(nonce="expired", expires_at=100.0)
    consumed = _permit(nonce="consumed", expires_at=200.0)
    revoked = _permit(nonce="revoked", expires_at=200.0)

    assert store.consume(expired, now=100.0).status is PermitStoreStatus.EXPIRED
    assert store.consume(consumed, now=101.0).status is PermitStoreStatus.CONSUMED
    assert store.revoke(revoked, now=101.0).status is PermitStoreStatus.REVOKED

    cleanup = store.cleanup_expired(now=200.0)

    assert cleanup.status is PermitStoreStatus.CLEANED
    assert cleanup.consumed_removed == 1
    assert cleanup.revoked_removed == 1
    assert cleanup.removed == 2
    assert store.is_revoked(revoked, now=200.0).status is PermitStoreStatus.EXPIRED


def test_malformed_permit_fields_return_invalid_status() -> None:
    store = InMemoryPermitStore()
    missing_nonce = _permit(nonce="")
    invalid_expiry = _permit(nonce="bad-expiry", expires_at=float("nan"))

    assert store.consume(missing_nonce, now=100.0).status is PermitStoreStatus.INVALID
    assert store.revoke(invalid_expiry, now=100.0).status is PermitStoreStatus.INVALID


def test_permit_rejects_non_finite_timestamps_and_ttl() -> None:
    decision = Decision(True, "document.publish")
    subject = Subject(id="user-1")

    for ttl in (float("nan"), float("inf"), float("-inf")):
        try:
            ExecutionPermit.issue(decision, subject, secret="permit-secret", ttl_seconds=ttl)
        except ValueError:
            pass
        else:  # pragma: no cover - protects the explicit security invariant
            raise AssertionError("non-finite permit ttl was accepted")

    permit = ExecutionPermit.issue(
        decision,
        subject,
        secret="permit-secret",
        now=100.0,
    )
    malformed_expiry = ExecutionPermit(
        **{**permit._unsigned_payload(), "expires_at": float("nan")},
        signature=permit.signature,
    )

    assert not permit.verify(
        subject,
        secret="permit-secret",
        operation="document.publish",
        now=float("nan"),
    )
    assert not malformed_expiry.verify(
        subject,
        secret="permit-secret",
        operation="document.publish",
        now=101.0,
    )


def test_permit_preserves_case_sensitive_subject_ids() -> None:
    decision = Decision(True, "document.publish")
    permit = ExecutionPermit.issue(
        decision,
        Subject(id="Alice"),
        secret="permit-secret",
        now=100.0,
    )

    assert permit.subject == "Alice"
    assert permit.verify(
        Subject(id="Alice"),
        secret="permit-secret",
        operation="document.publish",
        now=101.0,
    )
    assert not permit.verify(
        Subject(id="alice"),
        secret="permit-secret",
        operation="document.publish",
        now=101.0,
    )
