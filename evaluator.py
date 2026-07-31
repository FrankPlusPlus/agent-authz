"""Portable evaluator contract used by Agent Authz backends.

The SDK owns the request and decision vocabulary. A policy engine owns the
actual rule evaluation. Keeping this contract deliberately small lets an
application use the embedded engine today and Casbin, OPA, Cerbos, OpenFGA,
or SpiceDB later without changing Agent/Tool integration code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from authz_sdk.models import AuthorizationRequest, Decision


# Production accepts only exact SDK evaluator classes registered at import
# time. The registry also records every production-relevant class slot across
# the reviewed MRO. That catches an ordinary class-level monkeypatch or a
# newly inserted subclass slot before the PEP calls it. This remains an
# integration guard, not a sandbox against arbitrary code already executing
# inside the trusted host process.
_REVIEWED_PRODUCTION_TOKEN = object()
_MISSING_METHOD = object()
_REVIEWED_PRODUCTION_METHODS = frozenset(
    {
        "__delattr__",
        "__getattribute__",
        "__setattr__",
        "authorize",
        "production_readiness",
        "_encode_payload",
        "_validate_response_binding",
        "_production_configuration_is_intact",
        "_production_decoder_is_reviewed",
        "_seal_for_production",
        "default_request",
    }
)


@dataclass(frozen=True)
class _ReviewedProductionEvaluator:
    token: object
    mode: Literal["in_process", "remote"]
    resolved_methods: tuple[tuple[str, object], ...]
    class_method_slots: tuple[tuple[type[object], str, object], ...]


_REVIEWED_PRODUCTION_TYPES: dict[type[object], _ReviewedProductionEvaluator] = {}


def _register_reviewed_production_evaluator(
    evaluator_type: type[object],
    *,
    mode: Literal["in_process", "remote"],
) -> None:
    """Mark an exact SDK evaluator type and freeze its production call surface."""

    resolved_methods = tuple(
        (name, getattr(evaluator_type, name, _MISSING_METHOD))
        for name in _REVIEWED_PRODUCTION_METHODS
    )
    class_method_slots = tuple(
        (owner, name, vars(owner).get(name, _MISSING_METHOD))
        for owner in evaluator_type.__mro__
        if owner is not object
        for name in _REVIEWED_PRODUCTION_METHODS
    )
    _REVIEWED_PRODUCTION_TYPES[evaluator_type] = _ReviewedProductionEvaluator(
        _REVIEWED_PRODUCTION_TOKEN,
        mode,
        resolved_methods,
        class_method_slots,
    )


def _reviewed_production_evaluator_registration(
    evaluator: object,
) -> _ReviewedProductionEvaluator | None:
    """Return the import-time registration for an exact evaluator type."""

    registered = _REVIEWED_PRODUCTION_TYPES.get(type(evaluator))
    if registered is None or registered.token is not _REVIEWED_PRODUCTION_TOKEN:
        return None
    return registered


def _is_reviewed_production_evaluator(evaluator: object) -> bool:
    """Return whether an evaluator has the SDK's production capability."""

    return _reviewed_production_evaluator_registration(evaluator) is not None


def _reviewed_production_evaluator_mode(
    evaluator: object,
) -> Literal["in_process", "remote"] | None:
    """Return the reviewed mode for an exact evaluator type, if any.

    The result intentionally comes from import-time SDK registration rather
    than a mutable instance attribute such as ``enforcement_mode``.
    """

    registered = _reviewed_production_evaluator_registration(evaluator)
    if registered is None:
        return None
    return registered.mode


def _reviewed_production_evaluator_methods_are_intact(evaluator: object) -> bool:
    """Return whether the registered class call surface still matches import time."""

    registered = _reviewed_production_evaluator_registration(evaluator)
    if registered is None:
        return False
    return all(
        vars(owner).get(name, _MISSING_METHOD) is expected
        for owner, name, expected in registered.class_method_slots
    )


def _reviewed_production_evaluator_method(
    evaluator: object,
    name: str,
) -> object | None:
    """Return the exact import-time production method for a reviewed evaluator."""

    registered = _reviewed_production_evaluator_registration(evaluator)
    if registered is None:
        return None
    for method_name, method in registered.resolved_methods:
        if method_name == name and method is not _MISSING_METHOD:
            return method
    return None


@runtime_checkable
class Evaluator(Protocol):
    """The minimum contract for a policy decision backend."""

    name: str
    policy_version: str

    def authorize(self, request: AuthorizationRequest) -> Decision:
        """Evaluate one normalized authorization request."""

    def health(self) -> Mapping[str, object]:
        """Return a cheap, side-effect-free backend status snapshot."""


class BackendUnavailableError(RuntimeError):
    """Raised when an optional evaluator dependency is not installed."""


__all__ = ["BackendUnavailableError", "Evaluator"]
