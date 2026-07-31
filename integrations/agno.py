"""Agno-compatible callable guards without importing Agno."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

from authz_sdk.coverage import CoverageManifest
from authz_sdk.integrations.common import ValueProvider, protect_tool
from authz_sdk.models import Resource, Subject
from authz_sdk.runtime import AgentRuntime


class AgnoAuthz:
    """Build protected functions for ``Agent(tools=[...])``.

    Agno receives the returned function unchanged from its perspective: the
    wrapper preserves name, docstring, signature metadata, and async behavior.
    """

    def __init__(
        self,
        runtime: AgentRuntime,
        *,
        subject: Subject | object,
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

    def tool(
        self,
        tool: Callable[..., Any],
        *,
        operation: str,
        resource: ValueProvider = None,
        resource_type: ValueProvider = "",
        resource_id: ValueProvider = "",
        context: ValueProvider = None,
        arguments: ValueProvider = None,
        tool_name: str = "",
        pack_name: str = "",
        subject: ValueProvider | None = None,
        coverage_evidence: str = "",
    ) -> Callable[..., Any]:
        """Wrap one Agno tool before passing it to ``Agent``."""

        base_context = self.context
        context_provider: ValueProvider = context
        if context is not None:
            context_provider = lambda call: {
                **base_context,
                **dict(context(call) if callable(context) else context or {}),
            }
        else:
            context_provider = base_context
        return protect_tool(
            tool,
            runtime=self.runtime,
            operation=operation,
            subject=self.subject if subject is None else subject,
            resource=resource,
            resource_type=resource_type,
            resource_id=resource_id,
            context=context_provider,
            arguments=arguments,
            phase="execute",
            tool_name=tool_name,
            pack_name=pack_name,
            agent_id=self.agent_id,
            session_id=self.session_id,
            coverage=self.coverage,
            coverage_kind="tool",
            coverage_evidence=coverage_evidence,
        )

    def filter_tools(
        self,
        tools: Iterable[Mapping[str, Any]],
        *,
        context: Mapping[str, Any] | None = None,
    ) -> list[Mapping[str, Any]]:
        """Filter a metadata list before exposing tools to an Agno Agent."""

        subject = self.subject if isinstance(self.subject, Subject) else Subject.from_user(self.subject)
        return self.runtime.filter_tools(subject, tools, context={**self.context, **dict(context or {})})


__all__ = ["AgnoAuthz"]
