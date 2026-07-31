"""Portable evaluator contract used by Agent Authz backends.

The SDK owns the request and decision vocabulary. A policy engine owns the
actual rule evaluation. Keeping this contract deliberately small lets an
application use the embedded engine today and Casbin, OPA, Cerbos, OpenFGA,
or SpiceDB later without changing Agent/Tool integration code.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal, Protocol, runtime_checkable

from authz_sdk.models import AuthorizationRequest, Decision


# Production accepts only exact SDK evaluator classes registered at import
# time. This is an integration guard, not a sandbox against arbitrary code
# already executing inside the trusted host process.
_REVIEWED_PRODUCTION_TOKEN = object()
_REVIEWED_PRODUCTION_TYPES: dict[type[object], tuple[object, Literal["in_process", "remote"]]] = {}


def _register_reviewed_production_evaluator(
    evaluator_type: type[object],
    *,
    mode: Literal["in_process", "remote"],
) -> None:
    """Mark one exact SDK-owned evaluator type and its reviewed mode."""

    _REVIEWED_PRODUCTION_TYPES[evaluator_type] = (_REVIEWED_PRODUCTION_TOKEN, mode)


def _is_reviewed_production_evaluator(evaluator: object) -> bool:
    """Return whether an evaluator has the SDK's production capability."""

    registered = _REVIEWED_PRODUCTION_TYPES.get(type(evaluator))
    return registered is not None and registered[0] is _REVIEWED_PRODUCTION_TOKEN


def _reviewed_production_evaluator_mode(
    evaluator: object,
) -> Literal["in_process", "remote"] | None:
    """Return the reviewed mode for an exact evaluator type, if any.

    The result intentionally comes from import-time SDK registration rather
    than a mutable instance attribute such as ``enforcement_mode``.
    """

    registered = _REVIEWED_PRODUCTION_TYPES.get(type(evaluator))
    if registered is None or registered[0] is not _REVIEWED_PRODUCTION_TOKEN:
        return None
    return registered[1]


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
