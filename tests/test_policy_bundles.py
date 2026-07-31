"""Tests for the portable, fail-closed policy bundle primitive."""

from __future__ import annotations

from dataclasses import replace

import pytest

from authz_sdk.bundle import (
    POLICY_BUNDLE_SIGNATURE_ALGORITHM,
    PolicyBundle,
    PolicyBundleStore,
    PolicyBundleValidationError,
    canonical_json,
    policy_set_from_mapping,
)
from authz_sdk.catalog import Catalog
from authz_sdk.engine import PolicySet


def _catalog() -> Catalog:
    catalog = Catalog()
    catalog.resource("document", actions=("read", "publish"))
    return catalog


def _policies(*, version: str = "2026.07.31") -> PolicySet:
    policies = PolicySet(version=version)
    policies.bind(
        id="document_reader",
        operation="document.read",
        template="role_allowlist",
        roles=("reader",),
    )
    policies.bind(
        id="document_publisher",
        operation="document.publish",
        template="role_allowlist",
        roles=("editor",),
    )
    return policies


def _bundle(catalog: Catalog, revision: int, *, version: str = "2026.07.31") -> PolicyBundle:
    return PolicyBundle.from_policy_set(
        _policies(version=version),
        revision=revision,
        catalog=catalog,
    )


def test_bundle_uses_stable_canonical_json_and_round_trips_policy_set():
    catalog = _catalog()
    first = _bundle(catalog, 7)
    second = PolicyBundle.from_mapping(first.to_mapping())

    assert canonical_json({"z": [2, 1], "a": {"b": True}}) == '{"a":{"b":true},"z":[2,1]}'
    assert first.canonical_json() == second.canonical_json()
    assert first.digest == second.digest
    assert second.catalog_fingerprint == catalog.fingerprint()
    restored = policy_set_from_mapping(second.policy, catalog=catalog)
    assert restored.version == "2026.07.31"
    assert [item.id for item in restored.for_operation("document.read")] == ["document_reader"]


def test_hmac_proof_detects_tampering_and_is_not_an_asymmetric_signature():
    catalog = _catalog()
    signed = _bundle(catalog, 1).sign(b"shared-secret")
    tampered = replace(
        signed,
        policy={
            **signed.to_mapping()["policy"],
            "version": "attacker-rewrite",
        },
    )

    assert signed.signature_algorithm == POLICY_BUNDLE_SIGNATURE_ALGORITHM == "hmac-sha256"
    assert signed.verify("shared-secret")
    assert not signed.verify("wrong-secret")
    assert not tampered.verify("shared-secret")

    store = PolicyBundleStore(catalog, signing_key="shared-secret")
    with pytest.raises(PolicyBundleValidationError) as exc_info:
        store.activate(tampered)

    assert {issue.code for issue in exc_info.value.issues} == {"signature_invalid"}
    assert store.get_active() is None
    assert store.history() == ()


def test_store_rejects_catalog_mismatch_and_invalid_policy_without_mutation():
    catalog = _catalog()
    other_catalog = Catalog()
    other_catalog.resource("document", actions=("read", "publish"))
    other_catalog.resource("invoice", actions=("read",))
    key = b"shared-secret"
    store = PolicyBundleStore(catalog, signing_key=key)

    wrong_catalog_bundle = _bundle(other_catalog, 1).sign(key)
    with pytest.raises(PolicyBundleValidationError) as mismatch:
        store.activate(wrong_catalog_bundle)
    assert "catalog_mismatch" in {issue.code for issue in mismatch.value.issues}

    invalid = PolicyBundle(
        revision=2,
        catalog_fingerprint=catalog.fingerprint(),
        policy={
            "version": "invalid",
            "bindings": [
                {
                    "id": "unknown_operation",
                    "operation": "invoice.read",
                    "template": "allow",
                }
            ],
        },
    ).sign(key)
    with pytest.raises(PolicyBundleValidationError) as invalid_policy:
        store.activate(invalid)

    assert "policy_invalid" in {issue.code for issue in invalid_policy.value.issues}
    assert store.get_active() is None
    assert store.history() == ()


def test_store_activates_monotonically_and_rolls_back_only_to_verified_history():
    catalog = _catalog()
    key = "shared-secret"
    first = _bundle(catalog, 1, version="one").sign(key)
    second = _bundle(catalog, 2, version="two").sign(key)
    store = PolicyBundleStore(catalog, signing_key=key)

    assert store.activate(first).digest == first.digest
    assert store.activate(second).revision == 2
    assert store.get_active() == second
    assert [bundle.revision for bundle in store.history()] == [1, 2]

    rolled_back = store.rollback(1)
    assert rolled_back == first
    assert store.get_active() == first
    assert [bundle.revision for bundle in store.history()] == [1, 2, 1]

    with pytest.raises(LookupError):
        store.rollback(99)
    with pytest.raises(ValueError, match="must increase"):
        store.activate(first)
