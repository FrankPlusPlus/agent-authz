"""Optional FastAPI dependencies for a trusted API authorization boundary.

The module does not import FastAPI at package import time. Install
``agent-authz[fastapi]`` only in applications that use this adapter.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from threading import RLock
from typing import Any
from weakref import WeakKeyDictionary

from authz_sdk.coverage import (
    CoverageManifest,
    CoverageReport,
    _FRAMEWORK_OBSERVATION_TOKEN,
)
from authz_sdk.evaluator import BackendUnavailableError
from authz_sdk.models import Decision, Subject


RequestValue = str | Callable[[Any], Any] | None
SubjectProvider = Callable[[Any], Subject | object]
ContextProvider = Mapping[str, Any] | Callable[[Any], Mapping[str, Any] | None] | None
_FASTAPI_BUILTIN_ROUTE_NAMES = frozenset(
    {"openapi", "swagger_ui_html", "swagger_ui_redirect", "redoc_html"}
)
_FASTAPI_GUARDS: WeakKeyDictionary[Callable[..., Any], str] = WeakKeyDictionary()
_FASTAPI_GUARDS_LOCK = RLock()


@dataclass(frozen=True)
class FastAPIRouteInventory:
    """One concrete FastAPI route observed during application assembly."""

    entrypoint: str
    method: str
    path: str
    route_name: str

    def to_dict(self) -> dict[str, str]:
        return {
            "entrypoint": self.entrypoint,
            "method": self.method,
            "path": self.path,
            "route_name": self.route_name,
        }


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
            "FastAPI is optional; install agent-authz[fastapi] first"
        ) from exc
    return HTTPException, Request


def discover_fastapi_routes(
    app: Any,
    *,
    ignored: Iterable[str] = (),
) -> tuple[FastAPIRouteInventory, ...]:
    """Return concrete business routes using Catalog's ``"METHOD /path"`` form.

    This is a runtime registration inventory, not a source scanner. It
    deliberately skips FastAPI's own documentation endpoints, ignores implicit
    ``HEAD``/``OPTIONS`` handling, and requires every other ignored route to be
    explicitly named. A caller can pass either a collection of canonical
    entrypoint names or paths (for example ``"GET /health"`` or ``"/health"``).
    """

    routes = getattr(app, "routes", None)
    if routes is None:
        raise TypeError("app must expose a FastAPI-compatible routes collection")
    ignored_values = {str(item or "").strip() for item in ignored if str(item or "").strip()}

    inventory, _attached_guards = _discover_fastapi_routes_and_guards(
        routes,
        prefix="",
        ignored=ignored_values,
    )
    return tuple(sorted(inventory, key=lambda item: item.entrypoint))


def _discover_fastapi_routes_and_guards(
    routes: Iterable[Any],
    *,
    prefix: str,
    ignored: set[str],
) -> tuple[list[FastAPIRouteInventory], dict[str, set[str]]]:
    """Return live routes and the SDK guards attached to each dependency graph."""

    inventory: list[FastAPIRouteInventory] = []
    attached_guards: dict[str, set[str]] = {}
    _collect_fastapi_routes(
        routes,
        prefix=prefix,
        ignored=ignored,
        inventory=inventory,
        attached_guards=attached_guards,
    )
    return inventory, attached_guards


def _collect_fastapi_routes(
    routes: Iterable[Any],
    *,
    prefix: str,
    ignored: set[str],
    inventory: list[FastAPIRouteInventory],
    attached_guards: dict[str, set[str]],
) -> None:
    """Walk FastAPI/Starlette routes, including mounted sub-applications."""

    for route in routes:
        path = str(getattr(route, "path", "") or "").strip()
        methods = getattr(route, "methods", None)
        route_name = str(getattr(route, "name", "") or "").strip()
        child_routes = getattr(route, "routes", None)
        if methods:
            full_path = _join_route_path(prefix, path)
            guard_entrypoints = _fastapi_guard_entrypoints(route)
            if route_name in _FASTAPI_BUILTIN_ROUTE_NAMES:
                continue
            for method in sorted(str(item or "").upper() for item in methods):
                if method in {"HEAD", "OPTIONS"}:
                    continue
                entrypoint = f"{method} {full_path}"
                if entrypoint in ignored or full_path in ignored:
                    continue
                inventory.append(
                    FastAPIRouteInventory(
                        entrypoint=entrypoint,
                        method=method,
                        path=full_path,
                        route_name=route_name,
                    )
                )
                if entrypoint in guard_entrypoints:
                    attached_guards.setdefault(entrypoint, set()).add(route_name)
            continue
        if child_routes is not None:
            _collect_fastapi_routes(
                child_routes,
                prefix=_join_route_path(prefix, path),
                ignored=ignored,
                inventory=inventory,
                attached_guards=attached_guards,
            )


def _fastapi_guard_entrypoints(route: Any) -> set[str]:
    """Find SDK guard markers in FastAPI's assembled dependency tree."""

    root = getattr(route, "dependant", None)
    pending = list(getattr(root, "dependencies", ()) or ())
    seen: set[int] = set()
    entrypoints: set[str] = set()
    while pending:
        dependant = pending.pop()
        identity = id(dependant)
        if identity in seen:
            continue
        seen.add(identity)
        call = getattr(dependant, "call", None)
        with _FASTAPI_GUARDS_LOCK:
            marker = str(_FASTAPI_GUARDS.get(call, "") or "").strip()
        if marker:
            entrypoints.add(marker)
        pending.extend(getattr(dependant, "dependencies", ()) or ())
    return entrypoints


def _join_route_path(prefix: str, path: str) -> str:
    """Compose a mount prefix and route path without leaking double slashes."""

    normalized_prefix = str(prefix or "").strip().rstrip("/")
    normalized_path = str(path or "").strip()
    if not normalized_path or normalized_path == "/":
        return normalized_prefix or "/"
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"
    return f"{normalized_prefix}{normalized_path}" or "/"


def record_fastapi_inventory(
    coverage: CoverageManifest,
    app: Any,
    *,
    ignored: Iterable[str] = (),
    source: str = "FastAPI route registration",
) -> CoverageReport:
    """Compare registered FastAPI routes with Catalog API bindings.

    The returned report includes unregistered live routes, stale Catalog
    mappings, and missing final guards. Call this after every router is
    mounted. The inspection records coverage only when FastAPI's assembled
    dependency graph contains a matching :class:`FastAPIAuthz` guard; creating
    a dependency without attaching it to a route is not evidence of coverage.
    """

    if not isinstance(coverage, CoverageManifest):
        raise TypeError("coverage must be a CoverageManifest")
    app_routes = getattr(app, "routes", None)
    if app_routes is None:
        raise TypeError("app must expose a FastAPI-compatible routes collection")
    ignored_values = {str(item or "").strip() for item in ignored if str(item or "").strip()}
    routes, attached_guards = _discover_fastapi_routes_and_guards(
        app_routes,
        prefix="",
        ignored=ignored_values,
    )
    coverage._record_framework_inventory(
        "api",
        (item.entrypoint for item in routes),
        source=source,
        _token=_FRAMEWORK_OBSERVATION_TOKEN,
    )
    for route in routes:
        if route.entrypoint in attached_guards:
            coverage._record_framework_enforcement(
                "api",
                route.entrypoint,
                final=True,
                evidence=f"{source}: {route.route_name or route.entrypoint}",
                _token=_FRAMEWORK_OBSERVATION_TOKEN,
            )
    return coverage.report()


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
        if entrypoint_name and not callable(getattr(self.authz, "can_entrypoint", None)):
            raise TypeError("authz must expose callable can_entrypoint for an API entrypoint guard")
        status_code = int(denied_status_code)
        if status_code < 400 or status_code > 599:
            raise ValueError("denied_status_code must be an HTTP error status")
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
        if entrypoint_name:
            with _FASTAPI_GUARDS_LOCK:
                _FASTAPI_GUARDS[require_authorized] = entrypoint_name
        return require_authorized


__all__ = [
    "FastAPIAuthz",
    "FastAPIRouteInventory",
    "discover_fastapi_routes",
    "record_fastapi_inventory",
]
