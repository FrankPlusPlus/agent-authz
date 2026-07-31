"""Framework-neutral callable guards used by Agent integrations."""

from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Mapping, TypeVar

from authz_sdk.coverage import CoverageManifest
from authz_sdk.models import Resource, Subject
from authz_sdk.runtime import AgentRequest, AgentRuntime


T = TypeVar("T", bound=Callable[..., Any])
ValueProvider = Any | Callable[["CallInput"], Any]


@dataclass(frozen=True)
class CallInput:
    """The original callable arguments made available to context factories."""

    args: tuple[Any, ...]
    kwargs: Mapping[str, Any]


def _resolve(value: ValueProvider, call: CallInput) -> Any:
    return value(call) if callable(value) else value


def _subject(value: ValueProvider, call: CallInput) -> Subject:
    resolved = _resolve(value, call)
    if resolved is None:
        raise ValueError("an authenticated subject is required")
    return resolved if isinstance(resolved, Subject) else Subject.from_user(resolved)


def _resource(value: ValueProvider, call: CallInput) -> Resource | None:
    resolved = _resolve(value, call)
    if resolved is None or isinstance(resolved, Resource):
        return resolved
    if isinstance(resolved, Mapping):
        return Resource(
            type=str(resolved.get("type") or ""),
            id=str(resolved.get("id") or ""),
            attributes=resolved.get("attributes") or {},
            relations=resolved.get("relations") or {},
            metadata=resolved.get("metadata") or {},
        )
    raise TypeError("resource provider must return Resource, mapping, or None")


def _request(
    call: CallInput,
    *,
    runtime: AgentRuntime,
    operation: str,
    subject: ValueProvider,
    resource: ValueProvider,
    resource_type: ValueProvider,
    resource_id: ValueProvider,
    context: ValueProvider,
    arguments: ValueProvider,
    phase: str,
    tool_name: str,
    pack_name: str,
    agent_id: ValueProvider,
    session_id: ValueProvider,
) -> AgentRequest:
    raw_context = _resolve(context, call) or {}
    if not isinstance(raw_context, Mapping):
        raise TypeError("context provider must return a mapping")
    return AgentRequest(
        subject=_subject(subject, call),
        operation=operation,
        phase=phase,
        tool_name=tool_name,
        pack_name=pack_name,
        agent_id=str(_resolve(agent_id, call) or ""),
        session_id=str(_resolve(session_id, call) or ""),
        resource=_resource(resource, call),
        resource_type=str(_resolve(resource_type, call) or ""),
        resource_id=str(_resolve(resource_id, call) or ""),
        arguments=dict(_resolve(arguments, call) or {}),
        context=dict(raw_context),
    )


def _mark_wrapper(
    wrapper: Callable[..., Any], *, operation: str, phase: str
) -> Callable[..., Any]:
    # Agent frameworks use these attributes while building tool schemas.
    setattr(wrapper, "authz_operation", operation)
    setattr(wrapper, "authz_phase", phase)
    setattr(wrapper, "authz_protected", True)
    return wrapper


def protect_tool(
    tool: T,
    *,
    runtime: AgentRuntime,
    operation: str,
    subject: ValueProvider,
    resource: ValueProvider = None,
    resource_type: ValueProvider = "",
    resource_id: ValueProvider = "",
    context: ValueProvider = None,
    arguments: ValueProvider = None,
    phase: str = "execute",
    tool_name: str = "",
    pack_name: str = "",
    agent_id: ValueProvider = "",
    session_id: ValueProvider = "",
    coverage: CoverageManifest | None = None,
    coverage_kind: str = "tool",
    coverage_evidence: str = "",
) -> T:
    """Return a sync/async callable that authorizes before invoking ``tool``.

    Providers receive ``CallInput(args, kwargs)``. For a production
    ``Authz.production`` boundary, prefer ``resource_type`` plus
    ``resource_id``: the Authz facade will resolve those coordinates through
    its configured ``ResourceRegistry`` instead of accepting a tool/model
    supplied relation mapping. Pass ``resource`` only when the provider itself
    returns a registry-loaded resource.
    """

    if not callable(tool):
        raise TypeError("tool must be callable")
    name = tool_name or str(getattr(tool, "__name__", "tool"))
    if coverage is not None:
        if not isinstance(coverage, CoverageManifest):
            raise TypeError("coverage must be a CoverageManifest")
        coverage.record_enforcement(
            coverage_kind,
            name,
            operation=operation,
            final=phase == "execute",
            evidence=coverage_evidence,
        )

    def authorize(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> None:
        request = _request(
            CallInput(args, kwargs),
            runtime=runtime,
            operation=operation,
            subject=subject,
            resource=resource,
            resource_type=resource_type,
            resource_id=resource_id,
            context=context,
            arguments=arguments,
            phase=phase,
            tool_name=name,
            pack_name=pack_name,
            agent_id=agent_id,
            session_id=session_id,
        )
        runtime.require(request)

    if inspect.iscoroutinefunction(tool):

        @functools.wraps(tool)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            authorize(args, kwargs)
            return await tool(*args, **kwargs)

        return _mark_wrapper(async_wrapper, operation=operation, phase=phase)  # type: ignore[return-value]

    @functools.wraps(tool)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        authorize(args, kwargs)
        return tool(*args, **kwargs)

    return _mark_wrapper(wrapper, operation=operation, phase=phase)  # type: ignore[return-value]


__all__ = ["CallInput", "protect_tool"]
