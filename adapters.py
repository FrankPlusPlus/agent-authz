"""Business-owned resource loading without framework or database coupling."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from threading import RLock
from typing import Any

from authz_sdk.models import Resource, Subject


ResourceLoader = Callable[
    [str, Subject, Mapping[str, Any]],
    Resource | Mapping[str, Any] | None,
]
RelationResolver = Callable[[Subject, Resource, Mapping[str, Any]], bool]


class ResourceIdentityMismatchError(ValueError):
    """A trusted loader returned a different resource than was requested.

    A registry is the source of relationship and tenant facts, but it is not
    allowed to silently turn a request for one resource into a decision about
    another. Keeping this as a dedicated exception lets the enforcement layer
    fail closed with an actionable, non-ambiguous reason code.
    """


def _resource_from_mapping(
    resource_type: str,
    resource_id: str,
    value: Mapping[str, Any],
    *,
    source_token: object,
) -> Resource:
    mapped_type = (
        str(value.get("type") or "").strip()
        if "type" in value
        else resource_type
    )
    mapped_id = (
        str(value.get("id") or "").strip()
        if "id" in value
        else resource_id
    )
    attributes = dict(value.get("attributes") or value)
    return Resource._from_trusted_loader(
        type=mapped_type,
        id=mapped_id,
        attributes=attributes,
        relations=dict(value.get("relations") or {}),
        metadata=dict(value.get("metadata") or {}),
        source_token=source_token,
    )


class ResourceRegistry:
    """Registry for adapters owned by the domain that owns the data."""

    def __init__(self) -> None:
        self._lock = RLock()
        # The provenance token is per registry, rather than a module-global
        # sentinel.  A resource loaded by one domain adapter cannot be passed
        # off as a resource loaded by another application's registry.
        self._trust_token = object()
        self._loaders: dict[str, ResourceLoader] = {}
        self._relations: dict[tuple[str, str], RelationResolver] = {}

    def register(self, resource_type: str, loader: ResourceLoader, *, replace: bool = False) -> None:
        name = str(resource_type or "").strip()
        if not name or not callable(loader):
            raise ValueError("resource type and callable loader are required")
        with self._lock:
            if name in self._loaders and not replace:
                raise ValueError(f"resource loader already exists: {name}")
            self._loaders[name] = loader

    def register_relation(
        self,
        resource_type: str,
        relation: str,
        resolver: RelationResolver,
        *,
        replace: bool = False,
    ) -> None:
        """Register one reusable subject/resource relationship resolver.

        A loader may still return a relation directly. This hook is useful when
        a service has a shared relation implementation such as ``tenant`` or
        ``organization_member`` and should keep policy declarations free of
        database details.
        """

        key = (str(resource_type or "").strip(), str(relation or "").strip())
        if not all(key) or not callable(resolver):
            raise ValueError("resource type, relation, and callable resolver are required")
        with self._lock:
            if key in self._relations and not replace:
                raise ValueError(f"relation resolver already exists: {key[0]}:{key[1]}")
            self._relations[key] = resolver

    def resolve(
        self,
        resource_type: str,
        resource_id: str,
        subject: Subject,
        *,
        context: Mapping[str, Any] | None = None,
        required: bool = True,
    ) -> Resource | None:
        name = str(resource_type or "").strip()
        identifier = str(resource_id or "").strip()
        with self._lock:
            loader = self._loaders.get(name)
            relation_resolvers = {
                relation: resolver
                for (resource_name, relation), resolver in self._relations.items()
                if resource_name == name
            }
        if loader is None:
            if required:
                raise LookupError(f"no resource loader registered for {name}")
            return Resource(name, identifier)
        value = loader(identifier, subject, dict(context or {}))
        if value is None:
            return None
        if isinstance(value, Resource):
            resource = Resource._from_trusted_loader(
                type=value.type,
                id=value.id,
                attributes=value.attributes,
                relations=value.relations,
                metadata=value.metadata,
                source_token=self._trust_token,
            )
        else:
            resource = _resource_from_mapping(
                name,
                identifier,
                value,
                source_token=self._trust_token,
            )
        if resource.type != name:
            raise ResourceIdentityMismatchError(
                "resource loader returned a different resource type than was requested"
            )
        if resource.id != identifier:
            raise ResourceIdentityMismatchError(
                "resource loader returned a different resource ID than was requested"
            )
        if not relation_resolvers:
            return resource
        relations = dict(resource.relations)
        request_context = dict(context or {})
        for relation, resolver in relation_resolvers.items():
            if relation in relations:
                continue
            try:
                relations[relation] = bool(resolver(subject, resource, request_context))
            except Exception:
                # A missing/failed relationship must never become an allow.
                relations[relation] = False
        return Resource._from_trusted_loader(
            type=resource.type,
            id=resource.id,
            attributes=resource.attributes,
            relations=relations,
            metadata=resource.metadata,
            source_token=self._trust_token,
        )

    def owns(self, resource: Resource | None) -> bool:
        """Return whether ``resource`` was loaded by this exact registry.

        This rejects caller-constructed values and values produced by a
        different registry.  It prevents accidental provenance confusion; it
        is not a sandbox against arbitrary Python code running in the same
        process as the application.
        """

        return isinstance(resource, Resource) and resource._source_token is self._trust_token

    def inventory(self) -> list[str]:
        with self._lock:
            return sorted(self._loaders)


__all__ = [
    "RelationResolver",
    "ResourceIdentityMismatchError",
    "ResourceLoader",
    "ResourceRegistry",
]
