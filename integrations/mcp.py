"""MCP v2 server-tool authorization without importing the optional SDK.

``MCPAuthz`` works with the official MCP Python SDK's ``server.tool()``
decorator, but keeps ``mcp`` out of the core dependency graph. It protects the
actual Tool callable, not merely its discovery metadata. Authentication stays
with the MCP server's OAuth/token-verifier or host middleware: callers must
provide a verified subject, never derive one from model-controlled tool input.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from authz_sdk.coverage import CoverageManifest
from authz_sdk.integrations.common import CallInput, ValueProvider, protect_tool
from authz_sdk.models import Subject
from authz_sdk.runtime import AgentRuntime


T = TypeVar("T", bound=Callable[..., Any])


class MCPAuthz:
    """Register MCP Tools with a final Agent Authz execution guard.

    The integration is tested against the official MCP Python SDK v2
    ``MCPServer.tool()`` decorator. It deliberately does not authenticate an
    MCP client or dynamically filter a shared server's ``tools/list`` result;
    those concerns belong to the server's transport/authentication lifecycle.
    Every registered Tool is nevertheless re-authorized immediately before its
    Python callable executes.
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
        require_catalog_binding: bool | None = None,
        allow_static_subject: bool = False,
    ) -> None:
        if not isinstance(runtime, AgentRuntime):
            raise TypeError("runtime must be an AgentRuntime")
        if coverage is not None and not isinstance(coverage, CoverageManifest):
            raise TypeError("coverage must be a CoverageManifest")
        if not isinstance(allow_static_subject, bool):
            raise TypeError("allow_static_subject must be a bool")
        self.runtime = runtime
        self.subject = subject
        self.agent_id = str(agent_id or "")
        self.session_id = str(session_id or "")
        self.context = dict(context or {})
        self.coverage = coverage
        self.allow_static_subject = allow_static_subject
        self._registered_tools: dict[str, str] = {}
        profile = str(getattr(runtime.authz, "profile", "") or "").strip().lower()
        is_production = bool(
            getattr(runtime.authz, "is_production", profile == "production")
        )
        self.is_production = is_production
        # An explicit operation is useful while migrating a development server,
        # but a production MCP Tool must be visible in the catalog/coverage
        # inventory. Callers can make a deliberate, reviewable exception while
        # incrementally adopting the SDK.
        self.require_catalog_binding = (
            is_production
            if require_catalog_binding is None
            else bool(require_catalog_binding)
        )

    def _operation(self, *, tool_name: str, requested: str) -> str:
        """Prefer a catalog MCP binding without duplicating policy strings."""

        operation = str(requested or "").strip()
        catalog = getattr(self.runtime.authz, "catalog", None)
        binding = catalog.entrypoint("mcp.tool", tool_name) if catalog is not None else None
        if binding is not None:
            if operation and operation != binding.operation:
                raise ValueError(
                    f"MCP Tool {tool_name!r} is mapped to {binding.operation!r}, not {operation!r}"
                )
            return binding.operation
        if self.require_catalog_binding:
            raise ValueError(
                "MCP Tool "
                f"{tool_name!r} requires Catalog.bind_entrypoint('mcp.tool', "
                "tool_name, operation) before it can be registered"
            )
        if not operation:
            raise ValueError(
                "provide operation or register Catalog.bind_entrypoint('mcp.tool', tool_name, operation)"
            )
        return operation

    def tool(
        self,
        server: Any,
        *,
        operation: str = "",
        name: str = "",
        resource: ValueProvider = None,
        resource_type: ValueProvider = "",
        resource_id: ValueProvider = "",
        context: ValueProvider = None,
        arguments: ValueProvider = None,
        subject: ValueProvider | None = None,
        coverage_evidence: str = "",
        **mcp_tool_options: Any,
    ) -> Callable[[T], T]:
        """Return an official MCP ``@server.tool()``-compatible decorator.

        Supply ``resource_type`` plus ``resource_id`` for
        ``Authz.production`` so the SDK resolves server-owned resource facts
        through ``ResourceRegistry``. ``arguments`` is intentionally empty by
        default; explicitly allowlist only the Tool arguments that a policy
        backend needs.

        The `subject` provider receives ``CallInput``. In an HTTP MCP server it
        should read an identity that the MCP authentication layer already
        verified (for example a request-local principal), not an argument
        supplied by the model or MCP client.

        A production ``Authz`` profile requires a matching
        ``Catalog.bind_entrypoint('mcp.tool', tool_name, operation)`` by
        default. Set ``require_catalog_binding=False`` only as an explicit,
        temporary migration exception; doing so weakens catalog and coverage
        governance, not the final execution check.
        """

        register = getattr(server, "tool", None)
        if not callable(register):
            raise TypeError("server must expose an MCP-compatible callable tool() decorator")
        requested_name = str(name or "").strip()

        def decorator(function: T) -> T:
            if not callable(function):
                raise TypeError("MCP Tool must be callable")
            tool_name = requested_name or str(getattr(function, "__name__", "tool") or "tool")
            resolved_operation = self._operation(tool_name=tool_name, requested=operation)
            actor: ValueProvider = self.subject if subject is None else subject
            if actor is None:
                raise ValueError("an authenticated MCP subject is required")
            if self.is_production and not callable(actor) and not self.allow_static_subject:
                raise ValueError(
                    "a production MCP Tool requires a request-local subject provider; "
                    "set allow_static_subject=True only for a dedicated single-principal server"
                )

            base_context = dict(self.context)
            if context is None:
                context_provider: ValueProvider = base_context
            elif callable(context):
                context_provider = lambda call: {
                    **base_context,
                    **dict(context(call) or {}),
                }
            else:
                context_provider = {**base_context, **dict(context or {})}

            protected = protect_tool(
                function,
                runtime=self.runtime,
                operation=resolved_operation,
                subject=actor,
                resource=resource,
                resource_type=resource_type,
                resource_id=resource_id,
                context=context_provider,
                arguments=arguments,
                phase="execute",
                tool_name=tool_name,
                agent_id=self.agent_id,
                session_id=self.session_id,
                # A wrapper is not coverage evidence until the MCP server has
                # accepted it through its real ``tool()`` decorator below.
                coverage=None,
                coverage_kind="mcp.tool",
                coverage_evidence=coverage_evidence,
            )
            options = dict(mcp_tool_options)
            if requested_name:
                options["name"] = requested_name
            registered = register(**options)(protected)
            if self.coverage is not None:
                self._registered_tools[tool_name] = str(coverage_evidence or "").strip()
                self.coverage.record_inventory(
                    "mcp.tool",
                    self._registered_tools,
                    source="MCP server registration",
                )
                self.coverage.record_enforcement(
                    "mcp.tool",
                    tool_name,
                    operation=resolved_operation,
                    final=True,
                    evidence=(
                        str(coverage_evidence or "").strip()
                        or f"MCP server registration: {tool_name}"
                    ),
                )
            return registered

        return decorator


__all__ = ["MCPAuthz"]
