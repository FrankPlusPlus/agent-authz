"""Framework-independent authorization value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import quote


# The protocol is deliberately independent from the Python package version.
# A policy decision service and a future non-Python PEP can therefore negotiate
# the request/decision shape without treating every SDK patch release as a
# wire-contract change.
AUTHZ_CONTRACT_VERSION = "1.0"

def _values(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, (list, tuple, set, frozenset)):
        value = (value,)
    return tuple(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))


def _relation_value(value: Any) -> bool:
    """Normalize relation facts without treating ``"false"`` as true."""

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off", ""}:
            return False
    return False


@dataclass(frozen=True)
class Subject:
    """The actor making a request.

    Roles and positions are attributes supplied by the application's identity
    provider. Authz does not own the employee directory.
    """

    id: str = ""
    email: str = ""
    roles: tuple[str, ...] = ()
    positions: tuple[str, ...] = ()
    actor_type: str = "human"
    tenant_id: str = ""
    organization_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", str(self.id or "").strip())
        object.__setattr__(self, "email", str(self.email or "").strip().lower())
        object.__setattr__(self, "roles", tuple(item.lower() for item in _values(self.roles)))
        object.__setattr__(self, "positions", _values(self.positions))
        object.__setattr__(self, "actor_type", str(self.actor_type or "human").strip().lower())
        object.__setattr__(self, "tenant_id", str(self.tenant_id or "").strip())
        object.__setattr__(self, "organization_ids", _values(self.organization_ids))
        object.__setattr__(self, "metadata", dict(self.metadata or {}))

    @property
    def authenticated(self) -> bool:
        return bool(self.id or self.email)

    # These singular aliases keep framework adapters readable while the
    # portable SDK still stores multi-valued roles/positions canonically.
    @property
    def user_id(self) -> str:
        return self.id

    @property
    def role(self) -> str:
        return self.roles[0] if self.roles else ""

    @property
    def position(self) -> str:
        return self.positions[0] if self.positions else ""

    @property
    def organization_path_ids(self) -> tuple[str, ...]:
        return tuple(self.metadata.get("organization_path_ids") or ())

    @property
    def managed_organization_ids(self) -> tuple[str, ...]:
        return tuple(self.metadata.get("managed_organization_ids") or ())

    @classmethod
    def from_user(cls, user: object) -> "Subject":
        """Build a subject from the most common user object shapes."""

        if isinstance(user, cls):
            return user
        role = getattr(user, "role", "")
        roles = getattr(user, "roles", None) or role
        position = getattr(user, "position", "")
        positions = getattr(user, "positions", None) or position
        metadata = dict(getattr(user, "metadata", {}) or {})
        if hasattr(user, "is_admin"):
            metadata.setdefault("is_admin", bool(getattr(user, "is_admin", False)))
        if hasattr(user, "user_type"):
            metadata.setdefault("user_type", str(getattr(user, "user_type", "") or ""))
        if hasattr(user, "is_active"):
            metadata.setdefault("is_active", bool(getattr(user, "is_active", True)))
        return cls(
            id=getattr(user, "id", "") or getattr(user, "user_id", ""),
            email=getattr(user, "email", ""),
            roles=roles,
            positions=positions,
            actor_type=getattr(user, "actor_type", "human"),
            tenant_id=getattr(user, "tenant_id", ""),
            metadata=metadata,
        )


@dataclass(frozen=True)
class Resource:
    """A trusted business object, not a caller-controlled URL string."""

    type: str
    id: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    relations: Mapping[str, bool] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    _source_token: object | None = field(
        default=None,
        repr=False,
        compare=False,
        init=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "type", str(self.type or "").strip())
        object.__setattr__(self, "id", str(self.id or "").strip())
        object.__setattr__(self, "attributes", dict(self.attributes or {}))
        object.__setattr__(self, "relations", {str(k): _relation_value(v) for k, v in dict(self.relations or {}).items()})
        object.__setattr__(self, "metadata", dict(self.metadata or {}))

    @classmethod
    def _from_trusted_loader(
        cls,
        *,
        source_token: object,
        type: str,
        id: str = "",
        attributes: Mapping[str, Any] | None = None,
        relations: Mapping[str, bool] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "Resource":
        """Create a registry-marked value without exposing a public token kwarg.

        This remains an application integration guard, not an isolation
        mechanism against arbitrary code in the same Python process. The
        private factory primarily prevents an ordinary request/model mapping
        from accidentally populating the provenance marker through the public
        ``Resource(...)`` constructor.
        """

        resource = cls(
            type=type,
            id=id,
            attributes=attributes or {},
            relations=relations or {},
            metadata=metadata or {},
        )
        object.__setattr__(resource, "_source_token", source_token)
        return resource

    @property
    def uri(self) -> str:
        """Return the canonical, unambiguous external resource coordinate.

        type:id remains easy to read for ordinary identifiers. Each component
        is percent-encoded independently, however, so a colon in an
        application ID cannot make two different coordinates look the same.
        Authorization-sensitive code should still preserve the structured
        type and id fields rather than attempting to parse this value.
        """

        resource_type = quote(self.type, safe="-._~")
        return f"{resource_type}:{quote(self.id, safe='-._~')}" if self.id else resource_type

    @property
    def trusted(self) -> bool:
        """Whether a registry loader attached a private provenance token.

        This is deliberately only an integration guard.  A Python plugin that
        can execute arbitrary code in the host process is already inside the
        application's trust boundary and must not be treated as an untrusted
        sandbox.  :class:`~authz_sdk.adapters.ResourceRegistry` performs the
        stronger, registry-instance-specific provenance check used by the
        production profile.
        """

        return self._source_token is not None

    def related(self, relation: str) -> bool:
        name = str(relation or "").strip()
        if name in self.relations:
            return bool(self.relations[name])
        return _relation_value(self.attributes.get(name, False))


@dataclass(frozen=True)
class AuthorizationRequest:
    """Normalized request shared by embedded and remote decision backends."""

    subject: Subject
    operation: str
    resource: Resource | None = None
    context: Mapping[str, Any] = field(default_factory=dict)
    entrypoint: str = ""
    arguments: Mapping[str, Any] = field(default_factory=dict)
    request_id: str = ""
    trace_id: str = ""
    contract_version: str = AUTHZ_CONTRACT_VERSION
    catalog_fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", str(self.operation or "").strip())
        object.__setattr__(self, "context", dict(self.context or {}))
        object.__setattr__(self, "arguments", dict(self.arguments or {}))
        object.__setattr__(self, "entrypoint", str(self.entrypoint or "").strip())
        object.__setattr__(self, "request_id", str(self.request_id or "").strip())
        object.__setattr__(self, "trace_id", str(self.trace_id or "").strip())
        object.__setattr__(
            self,
            "contract_version",
            str(self.contract_version or AUTHZ_CONTRACT_VERSION).strip(),
        )
        object.__setattr__(
            self,
            "catalog_fingerprint",
            str(self.catalog_fingerprint or "").strip(),
        )


@dataclass(frozen=True)
class Decision:
    """Stable result returned by every SDK integration."""

    allowed: bool
    operation: str
    reason: str = ""
    policy: str = ""
    resource: Resource | None = None
    obligations: Mapping[str, Any] = field(default_factory=dict)
    trace: tuple[Mapping[str, Any], ...] = ()
    entrypoint: str = ""
    reason_code: str = ""
    policy_version: str = ""
    request_id: str = ""
    trace_id: str = ""
    contract_version: str = AUTHZ_CONTRACT_VERSION
    catalog_fingerprint: str = ""
    policy_digest: str = ""

    def __bool__(self) -> bool:
        return self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "operation": self.operation,
            "reason": self.reason,
            "policy": self.policy,
            "resource": self.resource.uri if self.resource else "",
            "obligations": dict(self.obligations),
            "trace": [dict(item) for item in self.trace],
            "entrypoint": self.entrypoint,
            "reason_code": self.reason_code,
            "policy_version": self.policy_version,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "contract_version": self.contract_version,
            "catalog_fingerprint": self.catalog_fingerprint,
            "policy_digest": self.policy_digest,
        }
