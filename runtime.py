"""Agent runtime authorization primitives.

The runtime model keeps three lifecycle checks explicit while reusing the same
business operation policy: discover, mount, and execute. The SDK does not
execute a Tool or Pack; it returns the decision that the gateway must enforce.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from authz_sdk.models import Decision, Resource, Subject


AGENT_PHASES = ("discover", "mount", "execute")


@dataclass(frozen=True)
class AgentRequest:
    """One authorization request at an Agent runtime enforcement point."""

    subject: Subject
    operation: str
    phase: str
    tool_name: str = ""
    pack_name: str = ""
    agent_id: str = ""
    session_id: str = ""
    resource: Resource | None = None
    resource_type: str = ""
    resource_id: str = ""
    delegation_chain: tuple[str, ...] = ()
    approval: str = ""
    arguments: Mapping[str, Any] = field(default_factory=dict)
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        phase = str(self.phase or "").strip().lower()
        if phase not in AGENT_PHASES:
            raise ValueError(f"unsupported agent phase: {phase or '<empty>'}")
        object.__setattr__(self, "phase", phase)
        object.__setattr__(self, "operation", str(self.operation or "").strip())
        object.__setattr__(self, "tool_name", str(self.tool_name or "").strip())
        object.__setattr__(self, "pack_name", str(self.pack_name or "").strip())
        object.__setattr__(self, "agent_id", str(self.agent_id or "").strip())
        object.__setattr__(self, "session_id", str(self.session_id or "").strip())
        object.__setattr__(self, "resource_type", str(self.resource_type or "").strip())
        object.__setattr__(self, "resource_id", str(self.resource_id or "").strip())
        object.__setattr__(self, "delegation_chain", tuple(str(item) for item in self.delegation_chain if str(item).strip()))
        object.__setattr__(self, "approval", str(self.approval or "").strip())
        object.__setattr__(self, "arguments", dict(self.arguments or {}))
        object.__setattr__(self, "context", dict(self.context or {}))

    @property
    def entrypoint_name(self) -> str:
        return self.tool_name or self.pack_name or self.operation

    def context_payload(self) -> dict[str, Any]:
        return {
            **dict(self.context),
            "authz_phase": self.phase,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "pack_name": self.pack_name,
            "delegation_chain": list(self.delegation_chain),
            "approval": self.approval,
        }


class AgentRuntime:
    """Thin runtime adapter around an :class:`authz_sdk.Authz` instance."""

    def __init__(self, authz: Any) -> None:
        self.authz = authz

    def can(self, request: AgentRequest) -> Decision:
        if not request.operation:
            return Decision(
                False,
                "",
                reason="agent operation is required",
                reason_code="agent.operation_required",
                entrypoint=f"agent.{request.phase}:{request.entrypoint_name}",
                policy_version=self.authz.policies.version,
            )
        request_kwargs = {
            "operation": request.operation,
            "resource": request.resource,
            "resource_type": request.resource_type,
            "resource_id": request.resource_id,
            "context": request.context_payload(),
            "arguments": request.arguments,
            "entrypoint": f"agent.{request.phase}:{request.entrypoint_name}",
        }
        trusted_runtime_check = getattr(self.authz, "_can_agent", None)
        if callable(trusted_runtime_check):
            return trusted_runtime_check(
                request.subject,
                phase=request.phase,
                **request_kwargs,
            )
        # Compatibility for a narrow custom Authz facade. Such a facade owns
        # its own runtime trust boundary; Authz itself always uses _can_agent.
        return self.authz.can(request.subject, **request_kwargs)

    def require(self, request: AgentRequest) -> Decision:
        decision = self.can(request)
        if not decision.allowed:
            from authz_sdk.engine import AuthorizationError

            raise AuthorizationError(decision)
        return decision

    def issue_permit(
        self,
        request: AgentRequest,
        *,
        secret: str | bytes,
        resource_version: str = "",
        ttl_seconds: float = 30.0,
        now: float | None = None,
    ):
        """Authorize and issue a permit bound to this exact Agent request."""

        from authz_sdk.permit import ExecutionPermit

        decision = self.require(request)
        return ExecutionPermit.issue(
            decision,
            request.subject,
            secret=secret,
            resource_version=resource_version,
            ttl_seconds=ttl_seconds,
            now=now,
            runtime_context=request.context_payload(),
            arguments=request.arguments,
        )

    def verify_permit(
        self,
        request: AgentRequest,
        permit: Any,
        *,
        secret: str | bytes,
        resource_version: str = "",
        now: float | None = None,
    ) -> bool:
        """Verify a permit at the final side-effect boundary."""

        # A coordinate-only request must resolve the current trusted resource
        # again at the side-effect boundary. Re-authorizing here also prevents
        # a permit from outliving an intervening policy or tenant change.
        decision = self.can(request)
        if not decision.allowed:
            return False
        resource = decision.resource if decision.resource is not None else request.resource
        policy_version = decision.policy_version or None
        return bool(permit.verify(
            request.subject,
            secret=secret,
            operation=request.operation,
            resource=resource,
            resource_version=resource_version,
            entrypoint=f"agent.{request.phase}:{request.entrypoint_name}",
            policy_version=policy_version,
            runtime_context=request.context_payload(),
            arguments=request.arguments,
            now=now,
        ))

    def consume_permit(
        self,
        request: AgentRequest,
        permit: Any,
        *,
        secret: str | bytes,
        resource_version: str = "",
        store: Any,
        now: float | None = None,
    ) -> Any:
        """Verify and atomically reserve a one-time permit at execution time.

        Call this immediately before the side effect. ``store`` must implement
        :class:`authz_sdk.permit_store.PermitStore`; the built-in in-memory
        store is only safe for one process, while multi-worker deployments need
        a shared atomic Redis or database implementation.
        """

        from authz_sdk.permit_store import PermitStoreResult, PermitStoreStatus

        if not self.verify_permit(
            request,
            permit,
            secret=secret,
            resource_version=resource_version,
            now=now,
        ):
            return PermitStoreResult(
                status=PermitStoreStatus.INVALID,
                nonce=str(getattr(permit, "nonce", "") or ""),
                expires_at=getattr(permit, "expires_at", None),
                detail="execution permit verification failed",
            )
        return store.consume(permit, now=now)

    def filter_tools(
        self,
        subject: Subject,
        tools: Iterable[Mapping[str, Any]],
        *,
        operation_key: str = "operation",
        context: Mapping[str, Any] | None = None,
    ) -> list[Mapping[str, Any]]:
        """Filter tool metadata for discovery; execution must check again."""

        visible: list[Mapping[str, Any]] = []
        for tool in tools:
            raw = dict(tool)
            try:
                request = AgentRequest(
                    subject=subject,
                    operation=str(raw.get(operation_key) or ""),
                    phase="discover",
                    tool_name=str(raw.get("name") or ""),
                    pack_name=str(raw.get("pack") or ""),
                    agent_id=str(raw.get("agent_id") or ""),
                    context={**dict(context or {}), **dict(raw.get("context") or {})},
                )
            except ValueError:
                continue
            if self.can(request).allowed:
                visible.append(tool)
        return visible


__all__ = ["AGENT_PHASES", "AgentRequest", "AgentRuntime"]
