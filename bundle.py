"""Versioned, signed policy bundles for embedded and remote policy delivery.

This module deliberately owns only a portable policy *artifact* and a small
in-memory activation store.  It does not perform I/O, persistence, network
transport, policy review, or key management.  A control plane can therefore
serialize the same artifact for a remote PDP, while an embedded application can
activate it locally with the identical validation rules.

``hmac-sha256`` is a shared-secret message authentication code.  It proves that
an actor with the shared HMAC key produced the payload, but it is **not** an
asymmetric/public-key signature and does not provide non-repudiation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import math
import re
from threading import RLock
from types import MappingProxyType
from typing import Any, Mapping, Self, Sequence

from authz_sdk.catalog import Catalog
from authz_sdk.engine import PolicySet
from authz_sdk.models import AUTHZ_CONTRACT_VERSION


POLICY_BUNDLE_SCHEMA_VERSION = "1.0"
"""Schema understood by this policy-bundle implementation."""

POLICY_BUNDLE_SIGNATURE_ALGORITHM = "hmac-sha256"
"""Shared-secret HMAC algorithm; this is not an asymmetric signature."""

_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{64}\Z")
_BINDING_FIELDS = (
    "id",
    "operation",
    "template",
    "priority",
    "relations",
    "roles",
    "positions",
    "emails",
    "actor_types",
    "parameters",
    "description",
    "effect",
    "when",
    "obligations",
)

HmacKey = str | bytes | bytearray


@dataclass(frozen=True)
class BundleValidationIssue:
    """One fail-closed validation finding for a policy bundle."""

    code: str
    message: str
    field: str = ""


class PolicyBundleValidationError(ValueError):
    """Raised when a bundle cannot safely become active."""

    def __init__(self, issues: Sequence[BundleValidationIssue]) -> None:
        self.issues = tuple(issues)
        detail = "; ".join(f"{item.code}: {item.message}" for item in self.issues)
        super().__init__(f"policy bundle validation failed: {detail or 'unknown error'}")


def _json_value(value: Any, *, path: str = "$") -> Any:
    """Return a JSON-only copy and reject lossy or ambiguous Python values."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must not contain NaN or infinity")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} object keys must be strings")
            result[key] = _json_value(item, path=f"{path}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [_json_value(item, path=f"{path}[{index}]") for index, item in enumerate(value)]
    raise TypeError(f"{path} must contain only JSON values, not {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize JSON data deterministically for digests and wire transport.

    Mapping keys are sorted, whitespace is removed, Unicode is escaped, and
    non-JSON values (including non-finite floats) are rejected instead of being
    coerced with ``str``.  The latter is important: a digest must never hide a
    lossy conversion.
    """

    return json.dumps(
        _json_value(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _freeze_json(value: Any) -> Any:
    normalized = _json_value(value)
    if isinstance(normalized, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in normalized.items()})
    if isinstance(normalized, list):
        return tuple(_freeze_json(item) for item in normalized)
    return normalized


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    if isinstance(value, list):
        return [_thaw_json(item) for item in value]
    return value


def _text(value: object, field_name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized and not allow_empty:
        raise ValueError(f"{field_name} is required")
    return normalized


def _fingerprint(value: object, field_name: str = "catalog_fingerprint") -> str:
    normalized = _text(value, field_name).lower()
    if not _FINGERPRINT_RE.fullmatch(normalized):
        raise ValueError(f"{field_name} must be a SHA-256 hexadecimal digest")
    return normalized


def _hmac_key(value: HmacKey) -> bytes:
    if isinstance(value, str):
        key = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        key = bytes(value)
    else:
        raise TypeError("HMAC key must be str, bytes, or bytearray")
    if not key:
        raise ValueError("HMAC key must not be empty")
    return key


def _canonical_policy(policy: Mapping[str, Any]) -> Mapping[str, Any]:
    """Freeze policy JSON and remove non-semantic binding insertion order."""

    normalized = _thaw_json(_freeze_json(policy))
    bindings = normalized.get("bindings")
    if isinstance(bindings, list):
        normalized["bindings"] = sorted(bindings, key=canonical_json)
    return _freeze_json(normalized)


def _catalog_fingerprint(
    *,
    catalog: Catalog | None,
    catalog_fingerprint: str | None,
) -> str:
    explicit = _fingerprint(catalog_fingerprint) if catalog_fingerprint is not None else ""
    if catalog is None:
        if not explicit:
            raise ValueError("catalog or catalog_fingerprint is required")
        return explicit
    discovered = _fingerprint(catalog.fingerprint())
    if explicit and not hmac.compare_digest(explicit, discovered):
        raise ValueError("catalog and catalog_fingerprint do not match")
    return discovered


def policy_set_to_mapping(policies: PolicySet) -> dict[str, Any]:
    """Export ``PolicySet`` to the stable bundle policy mapping.

    The exported form is deliberately the same JSON-shaped contract accepted by
    ``PolicySet.from_mapping``.  It avoids private ``PolicySet`` fields so a
    remote PDP can use this mapping without importing the embedded runtime.
    """

    if not isinstance(policies, PolicySet):
        raise TypeError("policies must be a PolicySet")
    bindings: list[dict[str, Any]] = []
    for binding in policies.inventory():
        bindings.append({key: _thaw_json(binding.get(key)) for key in _BINDING_FIELDS})
    bindings.sort(key=canonical_json)
    return {
        "version": policies.version,
        "combining": policies.combining,
        "default_effect": policies.default_effect,
        "operation_defaults": _thaw_json(policies.operation_defaults),
        "bindings": bindings,
    }


def policy_set_from_mapping(
    mapping: Mapping[str, Any],
    *,
    catalog: Catalog | None = None,
) -> PolicySet:
    """Import a policy mapping using the native engine's semantic validator."""

    if not isinstance(mapping, Mapping):
        raise TypeError("policy mapping must be an object")
    return PolicySet.from_mapping(_thaw_json(_freeze_json(mapping)), catalog=catalog)


@dataclass(frozen=True)
class PolicyBundle:
    """Immutable, versioned policy payload independent of a transport layer."""

    revision: int
    catalog_fingerprint: str
    policy: Mapping[str, Any]
    schema_version: str = POLICY_BUNDLE_SCHEMA_VERSION
    contract_version: str = AUTHZ_CONTRACT_VERSION
    signature_algorithm: str = ""
    signature: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.revision, bool) or not isinstance(self.revision, int):
            raise TypeError("revision must be an integer")
        if not isinstance(self.policy, Mapping):
            raise TypeError("policy must be an object")
        object.__setattr__(self, "catalog_fingerprint", _fingerprint(self.catalog_fingerprint))
        object.__setattr__(self, "schema_version", _text(self.schema_version, "schema_version"))
        object.__setattr__(self, "contract_version", _text(self.contract_version, "contract_version"))
        object.__setattr__(
            self,
            "signature_algorithm",
            _text(self.signature_algorithm, "signature_algorithm", allow_empty=True).lower(),
        )
        object.__setattr__(
            self,
            "signature",
            _text(self.signature, "signature", allow_empty=True).lower(),
        )
        object.__setattr__(self, "policy", _canonical_policy(self.policy))

    @classmethod
    def from_policy_set(
        cls,
        policies: PolicySet,
        *,
        revision: int,
        catalog: Catalog | None = None,
        catalog_fingerprint: str | None = None,
        schema_version: str = POLICY_BUNDLE_SCHEMA_VERSION,
        contract_version: str = AUTHZ_CONTRACT_VERSION,
    ) -> Self:
        """Build a validated unsigned bundle from the native policy model."""

        fingerprint = _catalog_fingerprint(
            catalog=catalog,
            catalog_fingerprint=catalog_fingerprint,
        )
        bundle = cls(
            revision=revision,
            catalog_fingerprint=fingerprint,
            policy=policy_set_to_mapping(policies),
            schema_version=schema_version,
            contract_version=contract_version,
        )
        issues = bundle.validate(catalog=catalog)
        if issues:
            raise PolicyBundleValidationError(issues)
        return bundle

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> Self:
        """Parse a serialized bundle and reject a mismatched advertised digest."""

        if not isinstance(mapping, Mapping):
            raise TypeError("policy bundle must be an object")
        if "policy" not in mapping:
            raise ValueError("policy bundle policy is required")
        bundle = cls(
            revision=mapping.get("revision"),
            catalog_fingerprint=mapping.get("catalog_fingerprint"),
            policy=mapping.get("policy"),
            schema_version=mapping.get("schema_version", POLICY_BUNDLE_SCHEMA_VERSION),
            contract_version=mapping.get("contract_version", AUTHZ_CONTRACT_VERSION),
            signature_algorithm=mapping.get("signature_algorithm", ""),
            signature=mapping.get("signature", ""),
        )
        if "digest" in mapping:
            advertised = _text(mapping["digest"], "digest").lower()
            if not _FINGERPRINT_RE.fullmatch(advertised):
                raise ValueError("digest must be a SHA-256 hexadecimal digest")
            if not hmac.compare_digest(advertised, bundle.digest):
                raise ValueError("policy bundle digest does not match its payload")
        return bundle

    @property
    def digest(self) -> str:
        """SHA-256 digest of decision-bearing bundle fields, excluding proof."""

        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def canonical_payload(self) -> dict[str, Any]:
        """Return the signed/digested content without the digest or HMAC proof."""

        return {
            "schema_version": self.schema_version,
            "contract_version": self.contract_version,
            "revision": self.revision,
            "catalog_fingerprint": self.catalog_fingerprint,
            "policy": _thaw_json(self.policy),
        }

    def canonical_json(self) -> str:
        """Return canonical JSON for the decision-bearing bundle content."""

        return canonical_json(self.canonical_payload())

    def to_mapping(self) -> dict[str, Any]:
        """Export the complete wire representation, including optional proof."""

        return {
            **self.canonical_payload(),
            "digest": self.digest,
            "signature_algorithm": self.signature_algorithm,
            "signature": self.signature,
        }

    def to_policy_set(self, *, catalog: Catalog | None = None) -> PolicySet:
        """Import the policy content through the native semantic validator."""

        return policy_set_from_mapping(self.policy, catalog=catalog)

    def sign(self, key: HmacKey) -> Self:
        """Return a new bundle authenticated with a shared HMAC-SHA-256 key.

        This is intentionally not a public-key signature.  Both signers and
        verifiers possess the same secret, so applications needing signer
        identity or non-repudiation must use an external asymmetric mechanism.
        """

        signature = hmac.new(_hmac_key(key), self.canonical_json().encode("utf-8"), hashlib.sha256)
        return replace(
            self,
            signature_algorithm=POLICY_BUNDLE_SIGNATURE_ALGORITHM,
            signature=signature.hexdigest(),
        )

    def verify(self, key: HmacKey) -> bool:
        """Verify the HMAC proof without raising for an invalid proof."""

        if self.signature_algorithm != POLICY_BUNDLE_SIGNATURE_ALGORITHM:
            return False
        if not _SIGNATURE_RE.fullmatch(self.signature):
            return False
        try:
            expected = hmac.new(
                _hmac_key(key),
                self.canonical_json().encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(self.signature, expected)

    def validate(
        self,
        *,
        catalog: Catalog | None = None,
        expected_catalog_fingerprint: str | None = None,
        hmac_key: HmacKey | None = None,
        require_signature: bool = False,
    ) -> tuple[BundleValidationIssue, ...]:
        """Validate compatibility, policy semantics, catalog binding, and proof.

        Validation returns all locally discoverable failures so callers can show
        useful diagnostics.  ``PolicyBundleStore`` turns any finding into an
        exception before changing its active revision.
        """

        issues: list[BundleValidationIssue] = []
        if self.schema_version != POLICY_BUNDLE_SCHEMA_VERSION:
            issues.append(
                BundleValidationIssue(
                    "schema_unsupported",
                    f"schema version {self.schema_version!r} is not supported",
                    "schema_version",
                )
            )
        if self.contract_version != AUTHZ_CONTRACT_VERSION:
            issues.append(
                BundleValidationIssue(
                    "contract_unsupported",
                    f"contract version {self.contract_version!r} is not supported",
                    "contract_version",
                )
            )
        if self.revision < 1:
            issues.append(
                BundleValidationIssue(
                    "revision_invalid",
                    "revision must be greater than zero",
                    "revision",
                )
            )

        expected = ""
        if expected_catalog_fingerprint is not None:
            try:
                expected = _fingerprint(expected_catalog_fingerprint, "expected_catalog_fingerprint")
            except (TypeError, ValueError) as exc:
                issues.append(
                    BundleValidationIssue("catalog_expectation_invalid", str(exc), "catalog_fingerprint")
                )
        if catalog is not None:
            try:
                actual = _fingerprint(catalog.fingerprint(), "catalog.fingerprint")
            except (TypeError, ValueError) as exc:
                issues.append(BundleValidationIssue("catalog_invalid", str(exc), "catalog"))
            else:
                if expected and not hmac.compare_digest(expected, actual):
                    issues.append(
                        BundleValidationIssue(
                            "catalog_expectation_mismatch",
                            "configured catalog fingerprint differs from the current catalog",
                            "catalog_fingerprint",
                        )
                    )
                expected = actual
        if expected and not hmac.compare_digest(self.catalog_fingerprint, expected):
            issues.append(
                BundleValidationIssue(
                    "catalog_mismatch",
                    "bundle catalog fingerprint does not match the evaluating catalog",
                    "catalog_fingerprint",
                )
            )

        try:
            self.to_policy_set(catalog=catalog)
        except (KeyError, TypeError, ValueError) as exc:
            issues.append(BundleValidationIssue("policy_invalid", str(exc), "policy"))

        if self.signature:
            if self.signature_algorithm != POLICY_BUNDLE_SIGNATURE_ALGORITHM:
                issues.append(
                    BundleValidationIssue(
                        "signature_algorithm_unsupported",
                        "only hmac-sha256 bundle proofs are supported",
                        "signature_algorithm",
                    )
                )
            elif not _SIGNATURE_RE.fullmatch(self.signature):
                issues.append(
                    BundleValidationIssue(
                        "signature_invalid",
                        "HMAC-SHA-256 proof must be a hexadecimal digest",
                        "signature",
                    )
                )
            elif hmac_key is None:
                issues.append(
                    BundleValidationIssue(
                        "signature_unverifiable",
                        "a signed bundle requires an HMAC verification key",
                        "signature",
                    )
                )
            elif not self.verify(hmac_key):
                issues.append(
                    BundleValidationIssue(
                        "signature_invalid",
                        "HMAC proof does not match the decision-bearing payload",
                        "signature",
                    )
                )
        elif self.signature_algorithm:
            issues.append(
                BundleValidationIssue(
                    "signature_invalid",
                    "signature_algorithm is present but the bundle has no proof",
                    "signature",
                )
            )
        elif require_signature:
            issues.append(
                BundleValidationIssue(
                    "signature_required",
                    "this store requires a valid HMAC-SHA-256 proof",
                    "signature",
                )
            )

        return tuple(issues)


def sign_bundle(bundle: PolicyBundle, key: HmacKey) -> PolicyBundle:
    """Authenticate a bundle with HMAC-SHA-256 (not a public-key signature)."""

    if not isinstance(bundle, PolicyBundle):
        raise TypeError("bundle must be a PolicyBundle")
    return bundle.sign(key)


def verify_bundle(bundle: PolicyBundle, key: HmacKey) -> bool:
    """Verify a bundle's HMAC proof (not an asymmetric signature)."""

    return isinstance(bundle, PolicyBundle) and bundle.verify(key)


class PolicyBundleStore:
    """Thread-safe in-memory activation point for immutable policy bundles.

    The store is intentionally not a durable control plane.  It holds an
    activation history in process memory and verifies every activation and
    rollback against the currently configured catalog and optional HMAC key.
    This makes it suitable as an embedded PDP primitive or as the final local
    cache behind a future remote bundle delivery client.
    """

    def __init__(
        self,
        catalog: Catalog | None = None,
        *,
        catalog_fingerprint: str | None = None,
        signing_key: HmacKey | None = None,
        require_signature: bool | None = None,
    ) -> None:
        self._catalog = catalog
        self._expected_catalog_fingerprint = _catalog_fingerprint(
            catalog=catalog,
            catalog_fingerprint=catalog_fingerprint,
        )
        self._signing_key = _hmac_key(signing_key) if signing_key is not None else None
        self._require_signature = (
            self._signing_key is not None if require_signature is None else bool(require_signature)
        )
        if self._require_signature and self._signing_key is None:
            raise ValueError("require_signature needs a shared HMAC signing_key")
        self._lock = RLock()
        self._bundles: dict[int, PolicyBundle] = {}
        self._history: list[PolicyBundle] = []
        self._active_revision: int | None = None

    @property
    def expected_catalog_fingerprint(self) -> str:
        """The catalog contract that every bundle must bind to."""

        return self._expected_catalog_fingerprint

    @property
    def require_signature(self) -> bool:
        """Whether unsigned bundles are forbidden at this activation point."""

        return self._require_signature

    def _activation_issues(self, bundle: PolicyBundle) -> tuple[BundleValidationIssue, ...]:
        issues = list(
            bundle.validate(
                catalog=self._catalog,
                expected_catalog_fingerprint=self._expected_catalog_fingerprint,
                hmac_key=self._signing_key,
                require_signature=self._require_signature,
            )
        )
        if self._catalog is not None:
            try:
                current = _fingerprint(self._catalog.fingerprint(), "catalog.fingerprint")
            except (TypeError, ValueError) as exc:
                issues.append(BundleValidationIssue("catalog_invalid", str(exc), "catalog"))
            else:
                if not hmac.compare_digest(current, self._expected_catalog_fingerprint):
                    issues.append(
                        BundleValidationIssue(
                            "catalog_changed",
                            "the store's catalog changed after the store was configured",
                            "catalog_fingerprint",
                        )
                    )
        return tuple(issues)

    def _require_activatable(self, bundle: PolicyBundle) -> None:
        if not isinstance(bundle, PolicyBundle):
            raise TypeError("bundle must be a PolicyBundle")
        issues = self._activation_issues(bundle)
        if issues:
            raise PolicyBundleValidationError(issues)

    def activate(self, bundle: PolicyBundle) -> PolicyBundle:
        """Atomically make a newer, valid bundle active.

        Revisions are monotonic on the ordinary activation path.  Going back to
        a known revision requires the explicit :meth:`rollback` method.
        """

        with self._lock:
            self._require_activatable(bundle)
            active = self.get_active()
            if active is not None and bundle.revision <= active.revision:
                raise ValueError("policy bundle revision must increase; use rollback for an older revision")
            known = self._bundles.get(bundle.revision)
            if known is not None and not hmac.compare_digest(known.digest, bundle.digest):
                raise ValueError("policy bundle revision is already bound to different content")
            self._bundles[bundle.revision] = bundle
            self._active_revision = bundle.revision
            self._history.append(bundle)
            return bundle

    def get_active(self) -> PolicyBundle | None:
        """Return the active immutable bundle, if an activation has succeeded."""

        with self._lock:
            if self._active_revision is None:
                return None
            return self._bundles.get(self._active_revision)

    def history(self) -> tuple[PolicyBundle, ...]:
        """Return activation events in order, including explicit rollbacks."""

        with self._lock:
            return tuple(self._history)

    def rollback(self, revision: int) -> PolicyBundle:
        """Reactivate a previously activated revision after re-validating it.

        Rollback is intentionally in-memory and does not mint a replacement
        revision or persist an audit event; a durable control plane must do that
        around this primitive.
        """

        if isinstance(revision, bool) or not isinstance(revision, int):
            raise TypeError("revision must be an integer")
        with self._lock:
            bundle = self._bundles.get(revision)
            if bundle is None:
                raise LookupError("rollback target is not in this store's activation history")
            self._require_activatable(bundle)
            self._active_revision = revision
            self._history.append(bundle)
            return bundle


__all__ = [
    "BundleValidationIssue",
    "HmacKey",
    "POLICY_BUNDLE_SCHEMA_VERSION",
    "POLICY_BUNDLE_SIGNATURE_ALGORITHM",
    "PolicyBundle",
    "PolicyBundleStore",
    "PolicyBundleValidationError",
    "canonical_json",
    "policy_set_from_mapping",
    "policy_set_to_mapping",
    "sign_bundle",
    "verify_bundle",
]
