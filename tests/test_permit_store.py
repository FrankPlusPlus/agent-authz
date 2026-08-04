from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

from authz_sdk.permit import ExecutionPermit
from authz_sdk.models import Decision, Subject
from authz_sdk.permit_store import (
    InMemoryPermitStore,
    PermitStoreStatus,
    RedisPermitStore,
    permit_store_readiness,
)


class _FakeRedis:
    """Small atomic Redis-script test double; no Redis server is required."""

    def __init__(self) -> None:
        self._values: set[str] = set()
        self._lock = Lock()
        self.calls: list[tuple[object, ...]] = []
        self.failure: Exception | None = None
        self.ping_result = True

    def eval(self, script: str, key_count: int, *args: object) -> int:
        if self.failure is not None:
            raise self.failure
        self.calls.append((script, key_count, *args))
        with self._lock:
            if "agent-authz-permit:consume" in script:
                revoked_key, consumed_key, _ttl = args
                if str(revoked_key) in self._values:
                    return 2
                if str(consumed_key) in self._values:
                    return 3
                self._values.add(str(consumed_key))
                return 1
            if "agent-authz-permit:revoke" in script:
                revoked_key, _ttl = args
                already_revoked = str(revoked_key) in self._values
                self._values.add(str(revoked_key))
                return int(already_revoked)
        raise AssertionError("unexpected Redis script")

    def exists(self, key: str) -> int:
        if self.failure is not None:
            raise self.failure
        with self._lock:
            return int(key in self._values)

    def ping(self) -> bool:
        if self.failure is not None:
            raise self.failure
        return self.ping_result


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


def test_redis_store_consumes_one_nonce_once_across_independent_store_instances() -> None:
    client = _FakeRedis()
    first = RedisPermitStore(client, prefix="test-permit")
    second = RedisPermitStore(client, prefix="test-permit")
    permit = _permit()
    workers = 16
    start = Barrier(workers)

    def consume_once(index: int) -> PermitStoreStatus:
        start.wait()
        store = first if index % 2 else second
        return store.consume(permit, now=100.0).status

    with ThreadPoolExecutor(max_workers=workers) as executor:
        statuses = list(executor.map(consume_once, range(workers)))

    assert statuses.count(PermitStoreStatus.CONSUMED) == 1
    assert statuses.count(PermitStoreStatus.REPLAYED) == workers - 1
    consumed_key = first._key("consumed", permit.nonce)
    assert permit.nonce not in consumed_key
    assert consumed_key.startswith("test-permit:{")
    assert consumed_key.endswith("}:consumed")
    revoked_key = first._key("revoked", permit.nonce)
    assert consumed_key.split("{", 1)[1].split("}", 1)[0] == revoked_key.split("{", 1)[1].split("}", 1)[0]


def test_redis_store_revocation_and_expiry_follow_the_permit_store_contract() -> None:
    client = _FakeRedis()
    store = RedisPermitStore(client)
    permit = _permit()

    assert store.is_revoked(permit, now=100.0).status is PermitStoreStatus.NOT_REVOKED
    assert store.revoke(permit, now=100.0).status is PermitStoreStatus.REVOKED
    assert store.revoke(permit, now=100.0).detail == "permit nonce was already revoked"
    assert store.consume(permit, now=100.0).status is PermitStoreStatus.REVOKED
    assert store.cleanup_expired(now=100.0).removed == 0
    assert store.consume(_permit(expires_at=100.0), now=100.0).status is PermitStoreStatus.EXPIRED


def test_redis_store_fails_closed_when_the_shared_backend_is_unavailable() -> None:
    client = _FakeRedis()
    store = RedisPermitStore(client)
    client.failure = ConnectionError("redis unavailable")

    result = store.consume(_permit(), now=100.0)

    assert result.status is PermitStoreStatus.UNAVAILABLE
    assert "ConnectionError" in result.detail


def test_permit_store_readiness_rejects_process_local_store_for_multi_worker_use() -> None:
    local = permit_store_readiness(InMemoryPermitStore(), require_shared=True)
    client = _FakeRedis()
    shared = permit_store_readiness(RedisPermitStore(client), require_shared=True)
    client.ping_result = False
    unhealthy = permit_store_readiness(RedisPermitStore(client), require_shared=True)

    assert not local["ready"]
    assert "permit_store.shared_required" in local["issues"]
    assert shared == {
        "ready": True,
        "shared": True,
        "durability": "shared",
        "issues": (),
    }
    assert not unhealthy["ready"]
    assert "permit_store.ping_failed" in unhealthy["issues"]


def test_redis_store_validates_client_and_prefix_without_importing_redis() -> None:
    try:
        RedisPermitStore(object())
    except TypeError as error:
        assert "eval" in str(error)
    else:  # pragma: no cover - protects the public constructor contract
        raise AssertionError("invalid Redis client was accepted")

    try:
        RedisPermitStore(_FakeRedis(), prefix="::")
    except ValueError as error:
        assert "prefix" in str(error)
    else:  # pragma: no cover - protects the public constructor contract
        raise AssertionError("empty Redis prefix was accepted")
