"""Production-shaped Redis permit tests.

These tests intentionally require an explicitly supplied Redis URL.  Unit
tests keep the regular suite dependency-free with a small script-compatible
fake; this module proves the shared-store behavior against a real Redis server
and independent Python processes.  CI supplies the URL through its Redis
service container.
"""

from __future__ import annotations

import multiprocessing
import os
import time
from importlib.util import find_spec
from queue import Empty
from uuid import uuid4

import pytest

from authz_sdk import ExecutionPermit, PermitStoreStatus, RedisPermitStore


pytestmark = pytest.mark.redis_e2e


def _redis_url() -> str:
    """Return the opt-in test endpoint without embedding deployment defaults."""

    url = str(os.environ.get("AUTHZ_REDIS_URL") or "").strip()
    if not url:
        pytest.skip("set AUTHZ_REDIS_URL to run real Redis permit E2E tests")
    if find_spec("redis") is None:
        pytest.skip("install agent-authz[redis] to run real Redis permit E2E tests")
    return url


def _permit(*, nonce: str) -> ExecutionPermit:
    """Create a valid nonce record; signature validation belongs to runtime tests."""

    current = time.time()
    return ExecutionPermit(
        operation="document.publish",
        subject="user-1",
        issued_at=current,
        expires_at=current + 60,
        nonce=nonce,
    )


def _consume_in_child(
    url: str,
    prefix: str,
    permit: ExecutionPermit,
    start: multiprocessing.synchronize.Event,
    outcomes: multiprocessing.queues.Queue,
) -> None:
    """Consume from a fresh interpreter process after the parent releases it."""

    start.wait(timeout=10)
    status = RedisPermitStore.from_url(url, prefix=prefix).consume(permit).status.value
    outcomes.put(status)


def _delete_test_keys(url: str, prefix: str) -> None:
    """Remove only this test's opaque prefix rather than relying on database flushes."""

    try:
        from redis import Redis

        client = Redis.from_url(url)
        keys = list(client.scan_iter(match=f"{prefix}:*"))
        if keys:
            client.delete(*keys)
    except Exception:
        # The test assertion must report a connectivity/atomicity failure; a
        # best-effort cleanup error is not a reason to hide that result.
        return


def test_real_redis_consumes_a_permit_once_across_independent_processes() -> None:
    """Exactly one worker receives CONSUMED for a shared permit nonce."""

    url = _redis_url()
    prefix = f"agent-authz:e2e:{uuid4().hex}"
    permit = _permit(nonce=uuid4().hex)
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    outcomes = context.Queue()
    workers = [
        context.Process(
            target=_consume_in_child,
            args=(url, prefix, permit, start, outcomes),
        )
        for _ in range(2)
    ]

    try:
        for worker in workers:
            worker.start()
        start.set()
        received: list[str] = []
        for _ in workers:
            try:
                received.append(outcomes.get(timeout=15))
            except Empty as exc:
                raise AssertionError("a Redis permit worker did not report an outcome") from exc
        for worker in workers:
            worker.join(timeout=10)
            assert worker.exitcode == 0

        assert sorted(received) == [
            PermitStoreStatus.CONSUMED.value,
            PermitStoreStatus.REPLAYED.value,
        ]
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(timeout=5)
        _delete_test_keys(url, prefix)


def test_real_redis_revocation_is_visible_to_another_process() -> None:
    """A permit revoked by one worker is denied by a freshly started worker."""

    url = _redis_url()
    prefix = f"agent-authz:e2e:{uuid4().hex}"
    permit = _permit(nonce=uuid4().hex)
    store = RedisPermitStore.from_url(url, prefix=prefix)
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    outcomes = context.Queue()
    worker = context.Process(
        target=_consume_in_child,
        args=(url, prefix, permit, start, outcomes),
    )

    try:
        assert store.revoke(permit).status is PermitStoreStatus.REVOKED
        worker.start()
        start.set()
        try:
            outcome = outcomes.get(timeout=15)
        except Empty as exc:
            raise AssertionError("the Redis revocation worker did not report an outcome") from exc
        worker.join(timeout=10)
        assert worker.exitcode == 0
        assert outcome == PermitStoreStatus.REVOKED.value
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=5)
        _delete_test_keys(url, prefix)
