"""Optional FastAPI dependencies for a trusted API authorization boundary.

The module does not import FastAPI at package import time. Install
``agent-authz-sdk[fastapi]`` only in applications that use this adapter.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from typing import Any

from authz_sdk.coverage import CoverageManifest
from authz_sdk.evaluator import BackendUnavailableError
from authz_sdk.models import Decision, Subject


RequestValue = str | Callable[[Any], Any] | None
SubjectProvider = Callable[[Any], Subject | object]
ContextProvider = Mapping[str, Any] | Callable[[Any], Mapping[str, Any] | None] | None


async def _resolve(value: Any, request: Any) -> Any:
    resolved = value(request) if callable(value) else value
    if inspect.isawaitable(resolved):
        return await resolved
    return resolved


def _fastapi_types() -> tuple[Any, Any]:
    try:
        from fastapi import HTTPException, Request
    except ImportError as exc:  # pragma: no cover - depends on application extra
        raise BackendUnavailableError(
            "FastAPI is optional; install agent-authz-sdk[fastapi] first"
        ) from exc
    return HTTPException, Request


class FastAPIAuthz:
    """Create FastAPI dependencies that call the same trusted Authz boundary.

    The adapter deliberately does not infer a resource from request JSON. Give
    it a resource type and ID resolver; the underlying ``Authz.production``
    instance then resolves that pair through its ``ResourceRegistry``. The
    subject provider must be owned by the application's authentication layer.
    """

    def __init__(
        self,
        authz: Any,
        *,
        subject: SubjectProvider,
        coverage: CoverageManifest | None = None,
    ) -> None:
        if not callable(subject):
            raise TypeError("subject must be a callable request identity provider")
        if not callable(getattr(authz, "can", None)):
            raise TypeError("authz must expose a callable can method")
        self.authz = authz
        self.subject = subject
        if coverage is not None and not isinstance(coverage, CoverageManifest):
            raise TypeError("coverage must be a CoverageManifest")
        self.coverage = coverage

    def dependency(
        self,
        *,
        operation: str = "",
        entrypoint: str = "",
        resource_type: RequestValue = "",
        resource_id: RequestValue = "",
        context: ContextProvider = None,
        denied_status_code: int = 403,
    ) -> Callable[[Any], Any]:
        """Return a FastAPI dependency that denies before the route executes.

        Supply either an explicit business ``operation`` or a registered API
        ``entrypoint``. The returned dependency yields the allowed
        :class:`Decision`, which a route may keep for correlation but does not
        need to inspect before performing its work.
        """

        operation_name = str(operation or "").strip()
        entrypoint_name = str(entrypoint or "").strip()
        if bool(operation_name) == bool(entrypoint_name):
            raise ValueError("provide exactly one of operation or entrypoint")
        status_code = int(denied_status_code)
        if status_code < 400 or status_code > 599:
            raise ValueError("denied_status_code must be an HTTP error status")
        if self.coverage is not None and entrypoint_name:
            self.coverage.record_enforcement(
                "api",
                entrypoint_name,
                final=True,
            )
        http_exception, request_type = _fastapi_types()

        async def require_authorized(request: Any) -> Decision:
            raw_subject = await _resolve(self.subject, request)
            actor = raw_subject if isinstance(raw_subject, Subject) else Subject.from_user(raw_subject)
            resolved_type = str(await _resolve(resource_type, request) or "").strip()
            resolved_id = str(await _resolve(resource_id, request) or "").strip()
            raw_context = await _resolve(context, request)
            if raw_context is not None and not isinstance(raw_context, Mapping):
                raise TypeError("context must resolve to a mapping")
            request_context = dict(raw_context or {})
            if entrypoint_name:
                decision = self.authz.can_entrypoint(
                    actor,
                    kind="api",
                    name=entrypoint_name,
                    resource_type=resolved_type,
                    resource_id=resolved_id,
                    context=request_context,
                )
            else:
                decision = self.authz.can(
                    actor,
                    operation=operation_name,
                    resource_type=resolved_type,
                    resource_id=resolved_id,
                    context=request_context,
                    entrypoint=f"api:{operation_name}",
                )
            if not decision.allowed:
                # Deliberately expose stable, non-sensitive machine context
                # rather than a policy reason, resource relation, or prompt.
                raise http_exception(
                    status_code=status_code,
                    detail={
                        "code": decision.reason_code or "authorization.denied",
                        "operation": decision.operation,
                    },
                )
            return decision

        # With postponed annotations enabled, a locally imported FastAPI
        # ``Request`` type would otherwise be stored as an unresolved string.
        # Assign the concrete type so FastAPI injects the request rather than
        # treating it as a query parameter.
        require_authorized.__annotations__["request"] = request_type
        return require_authorized


__all__ = ["FastAPIAuthz"]
