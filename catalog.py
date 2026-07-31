"""Resource and operation catalog used by code, UI, and integrations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from threading import RLock
from typing import Any, Iterable, Mapping


CRUD_ACTIONS = ("list", "read", "create", "update", "delete")
_DEFAULT_RESOURCE_ACTIONS = {
    "list": False,
    "read": True,
    "create": False,
    "update": True,
    "delete": True,
}


@dataclass(frozen=True)
class ActionDefinition:
    name: str
    title: str
    description: str = ""
    requires_resource: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _action_items(value: Iterable[str | Mapping[str, Any]] | None) -> tuple[ActionDefinition, ...]:
    items: list[ActionDefinition] = []
    for item in value or ():
        if isinstance(item, Mapping):
            name = str(item.get("name") or "").strip()
            title = str(item.get("title") or name).strip()
            requires_resource = bool(item.get("requires_resource", True))
            description = str(item.get("description") or "").strip()
        else:
            name = str(item or "").strip()
            title = name
            requires_resource = _DEFAULT_RESOURCE_ACTIONS.get(name, True)
            description = ""
        if name:
            items.append(ActionDefinition(name, title, description, requires_resource))
    return tuple(dict((item.name, item) for item in items).values())


@dataclass(frozen=True)
class ResourceDefinition:
    name: str
    title: str
    description: str = ""
    actions: tuple[ActionDefinition, ...] = ()
    relations: tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)
    tenant_required: bool = False

    def action(self, name: str) -> ActionDefinition | None:
        return next((item for item in self.actions if item.name == str(name).strip()), None)

    def operation(self, action: str) -> str:
        item = self.action(action)
        if item is None:
            raise KeyError(f"unsupported action {action!r} for resource {self.name!r}")
        return f"{self.name}.{item.name}"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["actions"] = [item.to_dict() for item in self.actions]
        value["relations"] = list(self.relations)
        value["attributes"] = dict(self.attributes)
        return value


@dataclass(frozen=True)
class OperationDefinition:
    name: str
    title: str
    resource_type: str = ""
    action: str = ""
    description: str = ""
    requires_resource: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)
    tenant_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["attributes"] = dict(self.attributes)
        return value


@dataclass(frozen=True)
class EntrypointDefinition:
    kind: str
    name: str
    operation: str
    methods: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["methods"] = list(self.methods)
        return value


class Catalog:
    """Thread-safe catalog that drives both runtime validation and UI choices."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._resources: dict[str, ResourceDefinition] = {}
        self._operations: dict[str, OperationDefinition] = {}
        self._entrypoints: dict[tuple[str, str], EntrypointDefinition] = {}

    def resource(
        self,
        name: str,
        *,
        title: str | None = None,
        description: str = "",
        crud: bool = False,
        actions: Iterable[str | Mapping[str, Any]] = (),
        relations: Iterable[str] = (),
        attributes: Mapping[str, Any] | None = None,
        tenant_required: bool = False,
    ) -> ResourceDefinition:
        resource_name = str(name or "").strip()
        if not resource_name:
            raise ValueError("resource name is required")
        action_defs = _action_items(tuple(CRUD_ACTIONS if crud else ()) + tuple(actions))
        definition = ResourceDefinition(
            name=resource_name,
            title=str(title or resource_name).strip(),
            description=str(description or "").strip(),
            actions=action_defs,
            relations=tuple(dict.fromkeys(str(item).strip() for item in relations if str(item).strip())),
            attributes=dict(attributes or {}),
            tenant_required=bool(tenant_required),
        )
        with self._lock:
            if resource_name in self._resources:
                raise ValueError(f"resource already registered: {resource_name}")
            self._resources[resource_name] = definition
            for action in action_defs:
                self._operations[f"{resource_name}.{action.name}"] = OperationDefinition(
                    name=f"{resource_name}.{action.name}",
                    title=f"{definition.title} · {action.title}",
                    resource_type=resource_name,
                    action=action.name,
                    description=action.description,
                    requires_resource=action.requires_resource,
                    tenant_required=bool(tenant_required),
                )
        return definition

    def register_operation(
        self,
        name: str,
        *,
        title: str | None = None,
        resource_type: str = "",
        action: str = "",
        description: str = "",
        requires_resource: bool = False,
        attributes: Mapping[str, Any] | None = None,
        tenant_required: bool = False,
        replace: bool = False,
    ) -> OperationDefinition:
        operation_name = str(name or "").strip()
        if not operation_name:
            raise ValueError("operation name is required")
        definition = OperationDefinition(
            name=operation_name,
            title=str(title or operation_name).strip(),
            resource_type=str(resource_type or "").strip(),
            action=str(action or "").strip(),
            description=str(description or "").strip(),
            requires_resource=bool(requires_resource),
            attributes=dict(attributes or {}),
            tenant_required=bool(tenant_required),
        )
        with self._lock:
            if operation_name in self._operations and not replace:
                raise ValueError(f"operation already registered: {operation_name}")
            self._operations[operation_name] = definition
        return definition

    def bind_entrypoint(
        self,
        kind: str,
        name: str,
        operation: str,
        *,
        methods: Iterable[str] = (),
    ) -> EntrypointDefinition:
        key = (str(kind or "").strip(), str(name or "").strip())
        operation_name = str(operation or "").strip()
        with self._lock:
            if not all(key) or not operation_name:
                raise ValueError("entrypoint kind, name, and operation are required")
            if operation_name not in self._operations:
                raise KeyError(f"unknown operation: {operation_name}")
            definition = EntrypointDefinition(key[0], key[1], operation_name, tuple(methods))
            self._entrypoints[key] = definition
            return definition

    def bind_agent_entrypoint(
        self,
        phase: str,
        name: str,
        operation: str,
        *,
        methods: Iterable[str] = (),
    ) -> EntrypointDefinition:
        """Bind a discover/mount/execute Agent surface to one operation."""

        normalized_phase = str(phase or "").strip().lower()
        if normalized_phase not in {"discover", "mount", "execute"}:
            raise ValueError("agent phase must be discover, mount, or execute")
        return self.bind_entrypoint(
            f"agent.{normalized_phase}",
            name,
            operation,
            methods=methods,
        )

    def resource_definition(self, name: str) -> ResourceDefinition | None:
        with self._lock:
            return self._resources.get(str(name or "").strip())

    def operation_definition(self, name: str) -> OperationDefinition | None:
        with self._lock:
            return self._operations.get(str(name or "").strip())

    def entrypoint(self, kind: str, name: str) -> EntrypointDefinition | None:
        with self._lock:
            return self._entrypoints.get((str(kind or "").strip(), str(name or "").strip()))

    def operation_for(self, resource_type: str, action: str) -> str:
        resource = self.resource_definition(resource_type)
        if resource is None:
            raise KeyError(f"unknown resource: {resource_type}")
        return resource.operation(action)

    def actions_for(self, resource_type: str) -> list[dict[str, Any]]:
        resource = self.resource_definition(resource_type)
        return [item.to_dict() for item in resource.actions] if resource else []

    def inventory(self) -> dict[str, Any]:
        with self._lock:
            return {
                "resources": [item.to_dict() for item in self._resources.values()],
                "operations": [item.to_dict() for item in self._operations.values()],
                "entrypoints": [item.to_dict() for item in self._entrypoints.values()],
            }

    def fingerprint(self) -> str:
        """Return a stable SHA-256 fingerprint of the authorization catalog.

        The fingerprint intentionally covers only the public catalog contract,
        not registration order or in-process object identity. It can travel in
        a decision request, policy bundle, audit event, or readiness report to
        make a catalog/policy mismatch visible across service boundaries.
        """

        snapshot = self.inventory()
        snapshot["resources"].sort(key=lambda item: str(item.get("name") or ""))
        snapshot["operations"].sort(key=lambda item: str(item.get("name") or ""))
        snapshot["entrypoints"].sort(
            key=lambda item: (str(item.get("kind") or ""), str(item.get("name") or ""))
        )
        try:
            serialized = json.dumps(
                snapshot,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("catalog must contain JSON-serializable values to be fingerprinted") from exc
        return hashlib.sha256(serialized).hexdigest()
