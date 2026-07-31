"""LangGraph-compatible guards without a LangGraph runtime dependency."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from authz_sdk.coverage import CoverageManifest
from authz_sdk.integrations.common import CallInput, ValueProvider, protect_tool
from authz_sdk.models import Resource, Subject
from authz_sdk.runtime import AgentRuntime


class LangGraphAuthz:
    """Protect LangGraph tools and nodes at their actual execution boundary.

    LangGraph node signatures vary by graph state schema. ``subject_from_state``
    and ``resource_from_state`` keep that schema in the application while the
    authorization request remains stable. The state values must be injected by
    the authenticated host, never by model output.
    """

    def __init__(
        self,
        runtime: AgentRuntime,
        *,
        subject: Subject | object | None = None,
        agent_id: str = "",
        session_id: str = "",
        context: Mapping[str, Any] | None = None,
        coverage: CoverageManifest | None = None,
    ) -> None:
        self.runtime = runtime
        self.subject = subject
        self.agent_id = agent_id
        self.session_id = session_id
        self.context = dict(context or {})
        self.coverage = coverage

    def tool(self, tool: Callable[..., Any], **kwargs: Any) -> Callable[..., Any]:
        """Wrap a LangChain/LangGraph-compatible Python tool function."""

        kwargs.setdefault("subject", self.subject)
        kwargs.setdefault("agent_id", self.agent_id)
        kwargs.setdefault("session_id", self.session_id)
        kwargs.setdefault("context", self.context)
        kwargs.setdefault("coverage", self.coverage)
        kwargs.setdefault("coverage_kind", "tool")
        return protect_tool(tool, runtime=self.runtime, **kwargs)

    def node(
        self,
        node: Callable[..., Any],
        *,
        operation: str,
        node_name: str = "",
        subject: Subject | object | None = None,
        subject_from_state: Callable[[Mapping[str, Any]], Subject | object] | None = None,
        resource: Resource | None = None,
        resource_type: ValueProvider = "",
        resource_id: ValueProvider = "",
        resource_from_state: Callable[[Mapping[str, Any]], Resource | Mapping[str, Any] | None] | None = None,
        context: Mapping[str, Any] | None = None,
        context_from_state: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        arguments: ValueProvider = None,
        phase: str = "execute",
        coverage_evidence: str = "",
    ) -> Callable[..., Any]:
        """Wrap a graph node whose side effect needs an authorization check."""

        def state(call: CallInput) -> Mapping[str, Any]:
            value = call.args[0] if call.args and isinstance(call.args[0], Mapping) else {}
            return value

        subject_provider: ValueProvider = subject
        if subject_from_state is not None:
            subject_provider = lambda call: subject_from_state(state(call))
        elif subject_provider is None:
            subject_provider = self.subject

        resource_provider: ValueProvider = resource
        if resource_from_state is not None:
            resource_provider = lambda call: resource_from_state(state(call))

        def context_provider(call: CallInput) -> Mapping[str, Any]:
            result = dict(self.context)
            result.update(dict(context or {}))
            if context_from_state is not None:
                result.update(dict(context_from_state(state(call)) or {}))
            return result

        return protect_tool(
            node,
            runtime=self.runtime,
            operation=operation,
            subject=subject_provider,
            resource=resource_provider,
            resource_type=resource_type,
            resource_id=resource_id,
            context=context_provider,
            arguments=arguments,
            phase=phase,
            tool_name=node_name or getattr(node, "__name__", "node"),
            agent_id=self.agent_id,
            session_id=self.session_id,
            coverage=self.coverage,
            coverage_kind=f"agent.{phase}",
            coverage_evidence=coverage_evidence,
        )

    protect_node = node

    def filter_tools(
        self,
        subject: Subject | object,
        tools: Iterable[Mapping[str, Any]],
        *,
        context: Mapping[str, Any] | None = None,
    ) -> list[Mapping[str, Any]]:
        """Filter graph tool metadata for discovery; execution still rechecks."""

        normalized = subject if isinstance(subject, Subject) else Subject.from_user(subject)
        return self.runtime.filter_tools(normalized, tools, context=context)


__all__ = ["LangGraphAuthz"]
