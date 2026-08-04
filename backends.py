"""Optional policy engine and PDP adapters.

The adapters deliberately do not make third-party engines mandatory. Agent
Authz is useful as a small embedded SDK, while teams with an existing policy
stack can keep that stack and use the same ``AuthorizationRequest`` and
``Decision`` contract.
"""

from __future__ import annotations

import inspect
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from authz_sdk.evaluator import (
    BackendUnavailableError,
    _REVIEWED_PRODUCTION_METHODS,
    _register_reviewed_production_evaluator,
)
from authz_sdk.models import AuthorizationRequest, Decision, Resource


RequestBuilder = Callable[[AuthorizationRequest], tuple[Any, ...]]
Transport = Callable[[str, Mapping[str, Any], Mapping[str, str], float], Mapping[str, Any]]
Decoder = Callable[..., bool | None]
OperationMapper = Callable[[AuthorizationRequest], str]


@dataclass(frozen=True, init=False)
class OperationMap:
    """Immutable mapping from catalog operations to relation-backend names.

    OpenFGA and SpiceDB must not infer relationship-model semantics from a
    dotted business operation such as ``document.delete``.  This small
    declarative form is therefore the production-safe choice: the SDK copies
    it into immutable entries at construction, so a later mutation of the
    caller's dictionary cannot change the authority sent to the PDP.

    Callable ``operation_mapper`` functions remain available for local
    development and advanced prototypes. They are deliberately not
    production-ready because Python cannot establish that an arbitrary
    callable (including its closures and mutable object state) will keep the
    same mapping after the PEP has started.
    """

    _entries: tuple[tuple[str, str], ...]

    def __init__(self, values: "OperationMap | Mapping[str, str]") -> None:
        if type(values) is _REVIEWED_OPERATION_MAP_TYPE:
            entries = _operation_map_entries(values)
            if entries is None:
                raise ValueError("operation_map has an invalid immutable snapshot")
        else:
            if not isinstance(values, Mapping):
                raise TypeError("operation_map must be a mapping of operation names to backend names")
            normalized: dict[str, str] = {}
            for raw_operation, raw_target in values.items():
                if raw_operation is None or raw_target is None:
                    raise ValueError("operation_map entries require a non-empty operation and backend name")
                operation = str(raw_operation).strip()
                target = str(raw_target).strip()
                if not operation or not target:
                    raise ValueError("operation_map entries require a non-empty operation and backend name")
                if operation in normalized:
                    raise ValueError(f"duplicate operation_map entry: {operation}")
                normalized[operation] = target
            if not normalized:
                raise ValueError("operation_map must include at least one operation")
            entries = tuple(sorted(normalized.items()))
        object.__setattr__(self, "_entries", entries)

    @property
    def entries(self) -> tuple[tuple[str, str], ...]:
        """Return immutable, normalized operation-to-backend entries."""

        return self._entries

    def __call__(self, request: AuthorizationRequest) -> str:
        for operation, target in self._entries:
            if request.operation == operation:
                return target
        raise KeyError(f"operation_map has no entry for {request.operation!r}")


_OPERATION_MAP_MISSING = object()
_REVIEWED_OPERATION_MAP_TYPE = OperationMap
_REVIEWED_OPERATION_MAP_CLASS_SLOTS = tuple(
    (name, vars(OperationMap).get(name, _OPERATION_MAP_MISSING))
    for name in ("__call__", "__getattribute__")
)


def _operation_map_entries(mapper: object) -> tuple[tuple[str, str], ...] | None:
    """Read a static map's actual immutable entries without a public property."""

    if type(mapper) is not _REVIEWED_OPERATION_MAP_TYPE:
        return None
    try:
        entries = vars(mapper).get("_entries")
    except TypeError:
        return None
    if not isinstance(entries, tuple):
        return None
    return entries


def _is_reviewed_operation_map(mapper: object) -> bool:
    """Return whether the frozen map and its executable class surface match import time."""

    return (
        type(mapper) is _REVIEWED_OPERATION_MAP_TYPE
        and all(
            vars(_REVIEWED_OPERATION_MAP_TYPE).get(name, _OPERATION_MAP_MISSING)
            is expected
            for name, expected in _REVIEWED_OPERATION_MAP_CLASS_SLOTS
        )
    )


def _coerce_operation_mapper(
    operation_mapper: OperationMapper | Mapping[str, str] | None,
    operation_map: OperationMap | Mapping[str, str] | None,
) -> OperationMapper | OperationMap | None:
    """Normalize the ergonomic declarative map and legacy callable escape hatch."""

    if operation_mapper is not None and operation_map is not None:
        raise TypeError("pass either operation_mapper or operation_map, not both")
    configured = operation_map if operation_map is not None else operation_mapper
    if configured is None:
        return None
    if type(configured) is _REVIEWED_OPERATION_MAP_TYPE:
        # Copy even an existing map so this evaluator owns the frozen snapshot.
        return _REVIEWED_OPERATION_MAP_TYPE(configured)
    if isinstance(configured, Mapping):
        return _REVIEWED_OPERATION_MAP_TYPE(configured)
    if callable(configured):
        return configured
    raise TypeError("operation_mapper must be callable and operation_map must be a mapping")

_AUTHZ_PROTOCOL_HEADERS = frozenset(
    {
        "x-authz-contract-version",
        "x-authz-request-id",
        "x-authz-trace-id",
        "x-authz-catalog-fingerprint",
        "x-authz-policy-version",
        "x-authz-policy-digest",
    }
)
_SUBJECT_PROJECTION_FIELDS = frozenset(
    {
        "id",
        "email",
        "roles",
        "positions",
        "actor_type",
        "tenant_id",
        "organization_ids",
    }
)
_OPENFGA_RELATION = re.compile(r"^[A-Za-z0-9_-]+$")
_SPICEDB_PERMISSION = re.compile(r"^[a-z_][a-z0-9_]{1,62}[a-z0-9]$")
_HEADER_NAME = re.compile("^[!#$%&'*+\\-.^_" + chr(96) + "|~0-9A-Za-z]+$")


def _verified_tls_context(context: ssl.SSLContext) -> bool:
    """Return whether a caller-supplied TLS context verifies peer and host."""

    try:
        return bool(context.check_hostname) and context.verify_mode == ssl.CERT_REQUIRED
    except (AttributeError, TypeError):
        return False


def _tls_context_security_snapshot(
    context: ssl.SSLContext | None,
) -> tuple[object, ...] | None:
    """Capture the security-relevant state of a caller-supplied TLS context.

    ``SSLContext`` is mutable through ordinary public methods such as
    ``load_verify_locations`` and ``set_ciphers``. Its identity alone is not a
    production seal: adding a new trust root after construction can change who
    may impersonate a PDP while ``CERT_REQUIRED`` still appears intact. The
    standard transport is owned by the SDK, but a supplied context needs this
    structural drift check before each production decision.
    """

    if context is None:
        return ()
    if not isinstance(context, ssl.SSLContext):
        return None
    try:
        certificates = tuple(sorted(bytes(item) for item in context.get_ca_certs(binary_form=True)))
        ciphers = tuple(
            sorted(
                (
                    str(cipher.get("name") or ""),
                    str(cipher.get("protocol") or ""),
                    int(cipher.get("strength_bits") or 0),
                    int(cipher.get("alg_bits") or 0),
                )
                for cipher in context.get_ciphers()
            )
        )
        return (
            bool(context.check_hostname),
            int(context.verify_mode),
            int(context.verify_flags),
            int(context.options),
            int(context.minimum_version),
            int(context.maximum_version),
            bool(getattr(context, "hostname_checks_common_name", False)),
            bool(getattr(context, "post_handshake_auth", False)),
            str(getattr(context, "keylog_filename", "") or ""),
            certificates,
            ciphers,
        )
    except (AttributeError, TypeError, ValueError):
        return None


def _principal(request: AuthorizationRequest) -> str:
    return request.subject.id or request.subject.email or request.subject.actor_type


def _remote_principal(request: AuthorizationRequest) -> str:
    """Return the only default principal coordinate allowed to leave the PEP.

    Remote PDPs must not silently turn an email-only legacy subject into a
    network principal.  A production ``Authz`` boundary additionally rejects
    a remote request without ``Subject.id`` before transport.  Development
    users who deliberately need email-based policy can opt in with
    ``subject_field_keys=("email",)`` instead of relying on a hidden fallback.
    """

    return request.subject.id


def _field_names(values: object, *, name: str) -> tuple[str, ...]:
    """Normalize an explicit remote-PDP projection field list."""

    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise TypeError(f"{name} must be an iterable of field names")
    result: list[str] = []
    for value in values:
        field_name = str(value or "").strip()
        if not field_name:
            continue
        if field_name not in result:
            result.append(field_name)
    return tuple(result)


def _project_fields(values: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Copy only allowlisted PDP fields; unspecified fields never leave the PEP."""

    return {field_name: values[field_name] for field_name in fields if field_name in values}


@dataclass(frozen=True)
class PdpRequestProjection:
    """Explicit allowlist for optional fields sent to a remote PDP.

    The default deliberately transmits only one stable subject identifier,
    resource coordinates, and a resource's ``tenant_id``. It does *not*
    forward roles, organization data, subject/resource metadata, prompt
    context, or Tool arguments. Add each field deliberately after deciding
    that the PDP needs it and that it is safe to transmit to that service.
    """

    subject_field_keys: tuple[str, ...] = ("id",)
    subject_metadata_keys: tuple[str, ...] = ()
    resource_attribute_keys: tuple[str, ...] = ("tenant_id",)
    resource_relation_keys: tuple[str, ...] = ()
    resource_metadata_keys: tuple[str, ...] = ()
    context_keys: tuple[str, ...] = ()
    argument_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "subject_field_keys",
            "subject_metadata_keys",
            "resource_attribute_keys",
            "resource_relation_keys",
            "resource_metadata_keys",
            "context_keys",
            "argument_keys",
        ):
            object.__setattr__(
                self,
                field_name,
                _field_names(getattr(self, field_name), name=field_name),
            )
        unknown_subject_fields = set(self.subject_field_keys) - _SUBJECT_PROJECTION_FIELDS
        if unknown_subject_fields:
            raise ValueError(
                "unknown subject projection fields: "
                + ", ".join(sorted(unknown_subject_fields))
            )

    @classmethod
    def coerce(cls, value: "PdpRequestProjection | Mapping[str, Any] | None") -> "PdpRequestProjection":
        if value is None:
            return cls()
        if isinstance(value, cls):
            # Do not retain a caller-owned instance, even though the base
            # value object is frozen. A subclass or low-level mutation of a
            # shared instance must not alter the fields sent by a production
            # PDP after the evaluator has been accepted at the PEP boundary.
            # Reconstructing the exact reviewed value type also normalizes
            # every field into the immutable tuples used by the wire encoder.
            return cls(
                subject_field_keys=value.subject_field_keys,
                subject_metadata_keys=value.subject_metadata_keys,
                resource_attribute_keys=value.resource_attribute_keys,
                resource_relation_keys=value.resource_relation_keys,
                resource_metadata_keys=value.resource_metadata_keys,
                context_keys=value.context_keys,
                argument_keys=value.argument_keys,
            )
        if not isinstance(value, Mapping):
            raise TypeError("projection must be a PdpRequestProjection or mapping")
        allowed = {
            "subject_field_keys",
            "subject_metadata_keys",
            "resource_attribute_keys",
            "resource_relation_keys",
            "resource_metadata_keys",
            "context_keys",
            "argument_keys",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown PDP projection fields: {', '.join(sorted(map(str, unknown)))}")
        return cls(**dict(value))


_PROJECTION_FIELD_NAMES = (
    "subject_field_keys",
    "subject_metadata_keys",
    "resource_attribute_keys",
    "resource_relation_keys",
    "resource_metadata_keys",
    "context_keys",
    "argument_keys",
)
_PROJECTION_MISSING = object()
_REVIEWED_PROJECTION_TYPE = PdpRequestProjection
_REVIEWED_PROJECTION_CLASS_SLOTS = tuple(
    (name, vars(PdpRequestProjection).get(name, _PROJECTION_MISSING))
    for name in ("__getattribute__",)
)


def _projection_snapshot(
    projection: object,
) -> tuple[tuple[str, ...], ...] | None:
    """Return the exact immutable projection fields without dynamic lookup.

    Production must not trust a subclass override or a mutable value returned
    by an object's public properties. Reading the reviewed dataclass storage
    directly gives the production configuration check a structural snapshot
    that can detect a later low-level object-state change.
    """

    if type(projection) is not _REVIEWED_PROJECTION_TYPE:
        return None
    try:
        values = vars(projection)
    except TypeError:
        return None
    snapshot: list[tuple[str, ...]] = []
    for field_name in _PROJECTION_FIELD_NAMES:
        value = values.get(field_name)
        if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
            return None
        snapshot.append(value)
    return tuple(snapshot)


def _is_reviewed_projection(projection: object) -> bool:
    """Return whether a projection retains its reviewed class surface."""

    return (
        type(projection) is _REVIEWED_PROJECTION_TYPE
        and all(
            vars(_REVIEWED_PROJECTION_TYPE).get(name, _PROJECTION_MISSING)
            is expected
            for name, expected in _REVIEWED_PROJECTION_CLASS_SLOTS
        )
    )


def _resource_payload(
    resource: Resource | None,
    *,
    projection: PdpRequestProjection,
) -> dict[str, Any] | None:
    if resource is None:
        return None
    return {
        "type": resource.type,
        "id": resource.id,
        "uri": resource.uri,
        "attributes": _project_fields(resource.attributes, projection.resource_attribute_keys),
        "relations": _project_fields(resource.relations, projection.resource_relation_keys),
        "metadata": _project_fields(resource.metadata, projection.resource_metadata_keys),
    }


def _subject_payload(
    request: AuthorizationRequest,
    *,
    projection: PdpRequestProjection,
) -> dict[str, Any]:
    """Project identity fields separately from free-form subject metadata."""

    subject = request.subject
    available = {
        "email": subject.email,
        "roles": list(subject.roles),
        "positions": list(subject.positions),
        "actor_type": subject.actor_type,
        "tenant_id": subject.tenant_id,
        "organization_ids": list(subject.organization_ids),
    }
    # Do not use ``email`` as a concealed fallback for the ``id`` field. A
    # remote PDP needs an intentionally supplied stable principal; otherwise
    # the default payload contains no subject coordinate at all.
    if subject.id:
        available["id"] = subject.id
    payload = _project_fields(available, projection.subject_field_keys)
    if projection.subject_metadata_keys:
        payload["metadata"] = _project_fields(
            subject.metadata,
            projection.subject_metadata_keys,
        )
    return payload


def request_payload(
    request: AuthorizationRequest,
    *,
    projection: PdpRequestProjection | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize an explicitly projected SDK request for a remote PDP.

    The safe default is intentionally sparse.  Use
    :class:`PdpRequestProjection` instead of relying on a broad implicit
    forwarding rule when a remote policy needs context, arguments, or selected
    domain attributes.
    """

    selected = PdpRequestProjection.coerce(projection)
    return {
        "subject": _subject_payload(request, projection=selected),
        "operation": request.operation,
        "resource": _resource_payload(request.resource, projection=selected),
        "context": _project_fields(request.context, selected.context_keys),
        "arguments": _project_fields(request.arguments, selected.argument_keys),
        "entrypoint": request.entrypoint,
        "request_id": request.request_id,
        "trace_id": request.trace_id,
        "contract_version": request.contract_version,
        "catalog_fingerprint": request.catalog_fingerprint,
    }


def _decision(
    request: AuthorizationRequest,
    allowed: bool,
    *,
    backend: str,
    reason: str = "",
    reason_code: str = "",
    policy: str = "",
    obligations: Mapping[str, Any] | None = None,
    trace: tuple[Mapping[str, Any], ...] = (),
    policy_version: str = "",
    policy_digest: str = "",
    request_id: str | None = None,
    trace_id: str | None = None,
    contract_version: str | None = None,
    catalog_fingerprint: str | None = None,
) -> Decision:
    return Decision(
        bool(allowed),
        request.operation,
        reason=reason or ("allowed by backend" if allowed else "denied by backend"),
        reason_code=reason_code or f"{backend}.{'allow' if allowed else 'deny'}",
        policy=policy,
        resource=request.resource,
        obligations=dict(obligations or {}),
        trace=trace,
        entrypoint=request.entrypoint,
        policy_version=policy_version,
        request_id=request.request_id if request_id is None else str(request_id or ""),
        trace_id=request.trace_id if trace_id is None else str(trace_id or ""),
        contract_version=(
            request.contract_version
            if contract_version is None
            else str(contract_version or "")
        ),
        catalog_fingerprint=(
            request.catalog_fingerprint
            if catalog_fingerprint is None
            else str(catalog_fingerprint or "")
        ),
        policy_digest=policy_digest,
    )


def _bool_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in {"ALLOW", "ALLOWED", "PERMIT", "PERMITTED", "EFFECT_ALLOW", "PERMISSIONSHIP_HAS_PERMISSION", "HAS_PERMISSION"}:
            return True
        if normalized in {"DENY", "DENIED", "EFFECT_DENY", "PERMISSIONSHIP_NO_PERMISSION", "NO_PERMISSION"}:
            return False
    return None


def _find_allowed(payload: Any) -> bool | None:
    """Read common PDP response shapes, keeping each adapter fail-closed."""

    direct = _bool_value(payload)
    if direct is not None:
        return direct
    if not isinstance(payload, Mapping):
        return None
    for key in ("allowed", "allow", "authorized", "permitted"):
        if key in payload:
            direct = _bool_value(payload[key])
            if direct is not None:
                return direct
    if "permissionship" in payload:
        direct = _bool_value(payload["permissionship"])
        if direct is not None:
            return direct
    if "result" in payload:
        direct = _find_allowed(payload["result"])
        if direct is not None:
            return direct
    if "decision" in payload:
        direct = _find_allowed(payload["decision"])
        if direct is not None:
            return direct
    return None


def _decision_details(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract optional explainability fields without requiring them."""

    for key in ("result", "decision"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            return value
    return payload


def _decode(decoder: Decoder, payload: Mapping[str, Any], request: AuthorizationRequest) -> bool | None:
    """Support legacy one-argument decoders and request-aware decoders."""

    try:
        parameters = list(inspect.signature(decoder).parameters.values())
        accepts_request = len(parameters) >= 2 or any(
            parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD)
            for parameter in parameters
        )
    except (TypeError, ValueError):
        accepts_request = False
    return decoder(payload, request) if accepts_request else decoder(payload)


def _safe_protocol_header(value: str, name: str) -> str:
    """Reject control characters before a request value becomes an HTTP header."""

    normalized = str(value or "").strip()
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise ValueError(f"{name} contains a control character")
    return normalized


def _validated_configured_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Validate application headers before any transport sees them.

    SDK-owned protocol headers and content type are deliberately not
    configurable: accepting a case variant would let a caller spoof or race
    the request-binding envelope on transports that normalize header names.
    """

    normalized: dict[str, str] = {}
    seen: set[str] = set()
    for raw_name, raw_value in (headers or {}).items():
        name = str(raw_name)
        canonical_name = name.lower()
        value = str(raw_value)
        if not name or name != name.strip() or not _HEADER_NAME.fullmatch(name):
            raise ValueError("PDP header name is invalid")
        if canonical_name in _AUTHZ_PROTOCOL_HEADERS or canonical_name == "content-type":
            raise ValueError("PDP header name is reserved by the Authz protocol")
        if canonical_name in seen:
            raise ValueError("PDP header names must be unique case-insensitively")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("PDP header value contains a control character")
        seen.add(canonical_name)
        normalized[name] = value
    return normalized


def _protocol_headers(
    configured: Mapping[str, str],
    request: AuthorizationRequest,
    *,
    expected_policy_version: str = "",
    expected_policy_digest: str = "",
) -> dict[str, str]:
    """Build SDK-owned headers without allowing configured values to spoof them."""

    headers = dict(configured)
    headers["x-authz-contract-version"] = _safe_protocol_header(
        request.contract_version,
        "contract_version",
    )
    if request.request_id:
        headers["x-authz-request-id"] = _safe_protocol_header(request.request_id, "request_id")
    if request.trace_id:
        headers["x-authz-trace-id"] = _safe_protocol_header(request.trace_id, "trace_id")
    if request.catalog_fingerprint:
        headers["x-authz-catalog-fingerprint"] = _safe_protocol_header(
            request.catalog_fingerprint,
            "catalog_fingerprint",
        )
    if expected_policy_version:
        headers["x-authz-policy-version"] = _safe_protocol_header(
            expected_policy_version,
            "expected_policy_version",
        )
    if expected_policy_digest:
        headers["x-authz-policy-digest"] = _safe_protocol_header(
            expected_policy_digest,
            "expected_policy_digest",
        )
    return headers


@dataclass(frozen=True, init=False)
class CasbinRequestTemplate:
    """Immutable declarative argument mapping for a Casbin request.

    The default Casbin tuple is often sufficient.  Models that need a domain,
    resource coordinate, or request context can use this class (or the
    ergonomic ``request_fields=`` argument) without putting mutable Python
    code on a production authorization path.

    Supported fields are ``subject``, ``subject.id``, ``subject.email``,
    ``subject.actor_type``, ``subject.tenant_id``, ``resource``,
    ``resource.uri``, ``resource.type``, ``resource.id``, ``operation``, and
    ``entrypoint``. Dynamic data must name its source explicitly with
    ``context.<key>``, ``arguments.<key>``, ``subject.metadata.<key>``,
    ``resource.attributes.<key>``, or ``resource.relations.<key>``. A fixed
    value can use ``literal:<value>``.
    """

    _fields: tuple[str, ...]

    def __init__(self, fields: "CasbinRequestTemplate | Iterable[str]") -> None:
        if type(fields) is _REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE:
            normalized = _casbin_template_fields(fields)
            if normalized is None:
                raise ValueError("Casbin request template has an invalid immutable snapshot")
        else:
            raw_fields: Iterable[str]
            if isinstance(fields, str):
                raw_fields = (fields,)
            else:
                raw_fields = fields
            try:
                normalized = tuple(
                    _normalize_casbin_request_field(field)
                    for field in raw_fields
                )
            except TypeError as exc:
                raise TypeError("request_fields must be an iterable of field selectors") from exc
            if not normalized:
                raise ValueError("request_fields must include at least one field selector")
        object.__setattr__(self, "_fields", normalized)

    @property
    def fields(self) -> tuple[str, ...]:
        """Return immutable, normalized field selectors."""

        return self._fields

    def __call__(self, request: AuthorizationRequest) -> tuple[Any, ...]:
        return tuple(_casbin_request_value(request, field) for field in self._fields)


_CASBIN_TEMPLATE_MISSING = object()
_REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE = CasbinRequestTemplate
_REVIEWED_CASBIN_REQUEST_TEMPLATE_CLASS_SLOTS = tuple(
    (name, vars(CasbinRequestTemplate).get(name, _CASBIN_TEMPLATE_MISSING))
    for name in ("__call__", "__getattribute__")
)
_CASBIN_STATIC_FIELDS = frozenset(
    {
        "subject",
        "subject.id",
        "subject.email",
        "subject.actor_type",
        "subject.tenant_id",
        "resource",
        "resource.uri",
        "resource.type",
        "resource.id",
        "operation",
        "entrypoint",
    }
)
_CASBIN_DYNAMIC_FIELD_PREFIXES = (
    "context.",
    "arguments.",
    "subject.metadata.",
    "resource.attributes.",
    "resource.relations.",
)


def _normalize_casbin_request_field(value: object) -> str:
    field = str(value or "").strip()
    if field in _CASBIN_STATIC_FIELDS:
        return field
    if field.startswith("literal:"):
        if field.removeprefix("literal:"):
            return field
    for prefix in _CASBIN_DYNAMIC_FIELD_PREFIXES:
        if field.startswith(prefix) and field.removeprefix(prefix).strip():
            return field
    raise ValueError(f"unsupported Casbin request field selector: {field or '<empty>'}")


def _casbin_request_value(request: AuthorizationRequest, field: str) -> Any:
    subject = request.subject
    resource = request.resource
    if field == "subject":
        return _principal(request)
    if field == "subject.id":
        return subject.id
    if field == "subject.email":
        return subject.email
    if field == "subject.actor_type":
        return subject.actor_type
    if field == "subject.tenant_id":
        return subject.tenant_id
    if field == "resource" or field == "resource.uri":
        return resource.uri if resource else request.operation
    if field == "resource.type":
        return resource.type if resource else ""
    if field == "resource.id":
        return resource.id if resource else ""
    if field == "operation":
        return request.operation
    if field == "entrypoint":
        return request.entrypoint
    if field.startswith("literal:"):
        return field.removeprefix("literal:")
    if field.startswith("context."):
        return request.context.get(field.removeprefix("context."), "")
    if field.startswith("arguments."):
        return request.arguments.get(field.removeprefix("arguments."), "")
    if field.startswith("subject.metadata."):
        return subject.metadata.get(field.removeprefix("subject.metadata."), "")
    if field.startswith("resource.attributes."):
        return (resource.attributes if resource else {}).get(
            field.removeprefix("resource.attributes."),
            "",
        )
    if field.startswith("resource.relations."):
        return (resource.relations if resource else {}).get(
            field.removeprefix("resource.relations."),
            "",
        )
    raise ValueError(f"unsupported Casbin request field selector: {field}")


def _casbin_template_fields(
    builder: object,
) -> tuple[str, ...] | None:
    """Read a template's frozen selectors without a public property lookup."""

    if type(builder) is not _REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE:
        return None
    try:
        fields = vars(builder).get("_fields")
    except TypeError:
        return None
    return fields if isinstance(fields, tuple) else None


def _is_reviewed_casbin_request_template(builder: object) -> bool:
    """Return whether a static Casbin template still has its reviewed call surface."""

    return (
        type(builder) is _REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE
        and all(
            vars(_REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE).get(
                name,
                _CASBIN_TEMPLATE_MISSING,
            )
            is expected
            for name, expected in _REVIEWED_CASBIN_REQUEST_TEMPLATE_CLASS_SLOTS
        )
    )


class CasbinEvaluator:
    """Evaluate a request using an existing Casbin ``Enforcer``.

    The default mapping follows Casbin's common ``r = sub, obj, act`` model:
    ``sub`` is the stable subject ID/email, ``obj`` is the trusted resource
    URI, and ``act`` is the Authz business operation. Custom models can pass a
    ``request_builder`` and receive any arguments their matcher declares.
    """

    name = "casbin"
    enforcement_mode = "in_process"
    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent normal public reconfiguration after a production PEP accepts us."""

        if self.__dict__.get("_production_sealed", False):
            raise AttributeError(
                "production evaluator configuration is immutable; construct a new evaluator"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Keep the production seal effective for ordinary attribute deletion."""

        if self.__dict__.get("_production_sealed", False):
            raise AttributeError(
                "production evaluator configuration is immutable; construct a new evaluator"
            )
        object.__delattr__(self, name)

    def __init__(
        self,
        enforcer: Any,
        *,
        request_builder: RequestBuilder | CasbinRequestTemplate | None = None,
        request_fields: CasbinRequestTemplate | Iterable[str] | None = None,
        policy_version: str = "",
    ) -> None:
        if not callable(getattr(enforcer, "enforce", None)):
            raise TypeError("CasbinEvaluator requires an object with enforce()")
        self._production_sealed = False
        self.enforcer = enforcer
        self.request_builder = _coerce_casbin_request_builder(
            request_builder,
            request_fields,
        )
        self.policy_version = str(policy_version or "1")
        self._production_configuration = (
            self.enforcer,
            self.request_builder,
            self.policy_version,
        )
        self._production_request_builder = self.request_builder
        self._production_request_fields = _casbin_template_fields(
            self.request_builder
        )

    @staticmethod
    def default_request(request: AuthorizationRequest) -> tuple[str, str, str]:
        return (
            _principal(request),
            request.resource.uri if request.resource else request.operation,
            request.operation,
        )

    @classmethod
    def from_model_and_policy(
        cls,
        model_path: str,
        policy_path: str,
        *,
        request_builder: RequestBuilder | CasbinRequestTemplate | None = None,
        request_fields: CasbinRequestTemplate | Iterable[str] | None = None,
        policy_version: str = "",
    ) -> "CasbinEvaluator":
        try:
            import casbin
        except ImportError as exc:  # pragma: no cover - depends on installation
            raise BackendUnavailableError(
                "Casbin is optional; install agent-authz[casbin] first"
            ) from exc
        return cls(
            casbin.Enforcer(model_path, policy_path),
            request_builder=request_builder,
            request_fields=request_fields,
            policy_version=policy_version,
        )

    def _seal_for_production(self) -> None:
        """Freeze normal public configuration after the PEP captures this evaluator."""

        object.__setattr__(self, "_production_sealed", True)

    def authorize(self, request: AuthorizationRequest) -> Decision:
        try:
            result = self.enforcer.enforce(*self.request_builder(request))
            if isinstance(result, tuple):
                result = result[0]
            if not isinstance(result, bool):
                raise TypeError("Casbin enforcer must return a bool or a tuple whose first value is bool")
            allowed = result
            return _decision(
                request,
                allowed,
                backend=self.name,
                reason="Casbin matcher allowed the request" if allowed else "Casbin matcher denied the request",
                reason_code="casbin.allow" if allowed else "casbin.deny",
                policy_version=self.policy_version,
            )
        except Exception as exc:
            return _decision(
                request,
                False,
                backend=self.name,
                reason=f"Casbin evaluation failed: {type(exc).__name__}",
                reason_code="casbin.error",
                policy_version=self.policy_version,
            )

    def health(self) -> Mapping[str, object]:
        return {"status": "ok", "backend": self.name, "policy_version": self.policy_version}

    def production_readiness(self) -> Mapping[str, object]:
        """Reject a post-construction Casbin adapter swap at a PEP boundary.

        Policy writes inside the configured enforcer remain the policy system's
        responsibility. This only prevents replacing the enforcer or request
        mapper object after the adapter was accepted by ``Authz.production``.
        """

        configured = self._production_configuration
        intact = (
            self.enforcer is configured[0]
            and self.request_builder is configured[1]
            and self.policy_version == configured[2]
        )
        issues: list[str] = []
        if not intact:
            issues.append("backend.in_process_configuration_mutated")
        builder = self._production_request_builder
        if builder is _REVIEWED_CASBIN_DEFAULT_REQUEST:
            pass
        elif type(builder) is _REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE:
            if (
                not _is_reviewed_casbin_request_template(builder)
                or _casbin_template_fields(builder)
                != self._production_request_fields
            ):
                issues.append("backend.in_process_configuration_mutated")
        else:
            issues.append("backend.casbin_production_request_template_required")
        return {
            "ready": not issues,
            "issues": tuple(issues),
        }


_REVIEWED_CASBIN_DEFAULT_REQUEST = CasbinEvaluator.default_request


def _coerce_casbin_request_builder(
    request_builder: RequestBuilder | CasbinRequestTemplate | None,
    request_fields: CasbinRequestTemplate | Iterable[str] | None,
) -> RequestBuilder | CasbinRequestTemplate:
    """Normalize Casbin's default, a static template, or the development escape hatch."""

    if request_builder is not None and request_fields is not None:
        raise TypeError("pass either request_builder or request_fields, not both")
    configured = request_fields if request_fields is not None else request_builder
    if configured is None:
        return _REVIEWED_CASBIN_DEFAULT_REQUEST
    if type(configured) is _REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE:
        return _REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE(configured)
    if request_fields is not None:
        return _REVIEWED_CASBIN_REQUEST_TEMPLATE_TYPE(request_fields)
    if callable(configured):
        return configured
    raise TypeError("request_builder must be callable and request_fields must be an iterable")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect before another origin can receive credentials."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        return None


def _urllib_transport(
    endpoint: str,
    payload: Mapping[str, Any],
    headers: Mapping[str, str],
    timeout: float,
    *,
    ssl_context: ssl.SSLContext | None = None,
) -> Mapping[str, Any]:
    """POST a JSON decision request with TLS validation and redirects disabled."""

    if ssl_context is not None and not _verified_tls_context(ssl_context):
        raise ValueError("ssl_context must verify both the TLS certificate and hostname")
    body = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={"content-type": "application/json", **dict(headers)},
        method="POST",
    )
    try:
        https_handler = urllib.request.HTTPSHandler(context=ssl_context)
        # A PEP decision can carry stable principal and resource coordinates.
        # Do not silently widen the set of network recipients by inheriting a
        # developer workstation's HTTP(S) proxy configuration.  A deployment
        # that deliberately needs an egress proxy must put a reviewed gateway
        # at the configured PDP endpoint instead of making the standard
        # production transport depend on ambient process state.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            https_handler,
        )
        with opener.open(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"PDP request failed: {type(exc).__name__}") from exc
    value = json.loads(raw or "{}")
    if not isinstance(value, Mapping):
        raise ValueError("PDP response must be a JSON object")
    return value


class ResponseBindingError(ValueError):
    """A remote PDP response did not bind its decision to the request."""


def _response_value(
    response: Mapping[str, Any],
    details: Mapping[str, Any],
    name: str,
) -> str:
    """Read a response envelope value without treating a request value as proof."""

    envelopes: list[Mapping[str, Any]] = []
    for candidate in (details, response):
        if candidate not in envelopes:
            envelopes.append(candidate)
        authz = candidate.get("authz")
        if isinstance(authz, Mapping):
            envelopes.append(authz)
    for envelope in envelopes:
        value = envelope.get(name)
        if value is not None:
            return str(value).strip()
    return ""


class JsonPdpEvaluator:
    """Small HTTP adapter for a JSON PDP with injectable transport.

    Injecting ``transport`` makes the wire contract testable without a live
    policy service.  A production :meth:`Authz.production
    <authz_sdk.engine.Authz.production>` boundary accepts this evaluator only
    when it uses HTTPS with the standard transport, has an
    explicit expected policy revision/digest, and the PDP echoes the request
    envelope in its response. That prevents a stale or mismatched decision
    service from being mistaken for this PEP's decision. A caller-supplied
    Caller-supplied ``encoder`` and ``decoder`` functions remain useful for
    development and prototyping, but are never production-ready: a boolean
    assertion cannot prove that arbitrary code preserves a sparse projection
    or interprets a PDP denial faithfully. Production adapters use reviewed
    SDK payload encoders and decision decoders, or a future audited adapter
    interface.
    """

    name = "json_pdp"
    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent normal public reconfiguration after the PEP captures this adapter."""

        if self.__dict__.get("_production_sealed", False):
            raise AttributeError(
                "production evaluator configuration is immutable; construct a new evaluator"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Keep the production seal effective for ordinary attribute deletion."""

        if self.__dict__.get("_production_sealed", False):
            raise AttributeError(
                "production evaluator configuration is immutable; construct a new evaluator"
            )
        object.__delattr__(self, name)

    def __init__(
        self,
        endpoint: str,
        *,
        transport: Transport | None = None,
        encoder: Callable[[AuthorizationRequest], Mapping[str, Any]] | None = None,
        decoder: Decoder | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 3.0,
        policy_version: str = "",
        expected_policy_digest: str = "",
        projection: PdpRequestProjection | Mapping[str, Any] | None = None,
        projection_enforced: bool | None = None,
        ssl_context: ssl.SSLContext | None = None,
        allowed_hosts: tuple[str, ...] | list[str] | set[str] | None = None,
        transport_security: str = "",
        name: str = "json_pdp",
    ) -> None:
        if not str(endpoint or "").strip():
            raise ValueError("PDP endpoint is required")
        self._production_sealed = False
        self.endpoint = str(endpoint).strip()
        endpoint_parts = urllib.parse.urlsplit(self.endpoint)
        if endpoint_parts.scheme not in {"http", "https"} or not endpoint_parts.hostname:
            raise ValueError("PDP endpoint must be an absolute http(s) URL")
        if endpoint_parts.username or endpoint_parts.password:
            raise ValueError("PDP endpoint must not contain credentials")
        self._endpoint_scheme = endpoint_parts.scheme.lower()
        self._endpoint_host = str(endpoint_parts.hostname).lower()
        self.allowed_hosts = frozenset(
            str(host or "").strip().lower()
            for host in (allowed_hosts or ())
            if str(host or "").strip()
        )
        if self.allowed_hosts and self._endpoint_host not in self.allowed_hosts:
            raise ValueError("PDP endpoint host is not in allowed_hosts")
        normalized_transport_security = str(transport_security or "").strip().lower()
        if normalized_transport_security not in {"", "host_attested", "verified"}:
            raise ValueError(
                "transport_security must be empty, 'host_attested', or the legacy 'verified'"
            )
        self._uses_standard_transport = transport is None
        # A caller-controlled string cannot prove arbitrary transport code
        # validates TLS, resists credential leakage, or preserves the response
        # binding. Keep the legacy spelling source-compatible, but never let it
        # upgrade a custom transport into a production authority.
        if normalized_transport_security == "verified":
            normalized_transport_security = "host_attested"
        self.transport_security = (
            "standard_tls" if self._uses_standard_transport else normalized_transport_security
        )
        self.ssl_context = ssl_context
        if self.ssl_context is not None and not isinstance(self.ssl_context, ssl.SSLContext):
            raise TypeError("ssl_context must be an ssl.SSLContext")
        if (
            self._uses_standard_transport
            and self.ssl_context is not None
            and not _verified_tls_context(self.ssl_context)
        ):
            raise ValueError(
                "ssl_context must verify both the TLS certificate and hostname"
            )
        self.transport = transport or (
            lambda endpoint, payload, request_headers, request_timeout: _urllib_transport(
                endpoint,
                payload,
                request_headers,
                request_timeout,
                ssl_context=self.ssl_context,
            )
        )
        self.projection = PdpRequestProjection.coerce(projection)
        projection_snapshot = _projection_snapshot(self.projection)
        if projection_snapshot is None or not _is_reviewed_projection(self.projection):
            raise ValueError("projection must resolve to the reviewed immutable projection type")
        tls_context_snapshot = _tls_context_security_snapshot(self.ssl_context)
        if tls_context_snapshot is None:
            raise ValueError("ssl_context security configuration could not be inspected")
        self._custom_encoder = encoder
        # ``projection_enforced`` existed while custom encoders could
        # self-attest their safety. Keep accepting it for source compatibility,
        # but never let it upgrade arbitrary code into a production authority.
        self.projection_enforced = encoder is None
        self.encoder = encoder or (
            lambda request: request_payload(request, projection=self.projection)
        )
        self._custom_decoder = decoder
        self.decoder = decoder or _find_allowed
        self.headers = MappingProxyType(_validated_configured_headers(headers))
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("PDP timeout must be greater than zero")
        self.expected_policy_version = str(policy_version or "").strip()
        self.expected_policy_digest = str(expected_policy_digest or "").strip()
        self.policy_version = self.expected_policy_version or "1"
        self.name = str(name or "json_pdp")
        self.enforcement_mode = "remote"
        # The production profile needs to fail closed if a public attribute is
        # changed after construction.  These are intentionally identity checks
        # for code-bearing values and value checks for wire configuration.  A
        # same-process caller can still mutate private implementation state,
        # which is outside this SDK's trusted-host-process boundary, but an
        # ordinary post-construction configuration change cannot silently turn
        # a reviewed adapter into a different authority.
        self._production_configuration = (
            self.endpoint,
            self.transport,
            self.encoder,
            self.decoder,
            tuple(sorted(self.headers.items())),
            self.timeout,
            self.expected_policy_version,
            self.expected_policy_digest,
            self.policy_version,
            self.projection,
            projection_snapshot,
            self.ssl_context,
            tls_context_snapshot,
            self.allowed_hosts,
            self.transport_security,
            self._uses_standard_transport,
        )

    def _seal_for_production(self) -> None:
        """Freeze normal public configuration after the PEP captures this adapter."""

        object.__setattr__(self, "_production_sealed", True)

    def production_readiness(self) -> Mapping[str, object]:
        """Return machine-readable requirements for a production remote PDP.

        It is intentionally strict: a generic OPA/OpenFGA response that does
        not echo the authorization envelope remains useful in development, but
        cannot silently become a production execution authority.
        """

        issues: list[str] = []
        if self._endpoint_scheme != "https":
            issues.append("backend.remote_https_required")
        if self._uses_standard_transport and self.ssl_context is not None and not _verified_tls_context(self.ssl_context):
            issues.append("backend.remote_tls_context_unverified")
        if not self._uses_standard_transport:
            issues.append("backend.remote_custom_transport_unsupported")
        if not JsonPdpEvaluator._production_configuration_is_intact(self):
            issues.append("backend.remote_configuration_mutated")
        if not self.expected_policy_version:
            issues.append("backend.remote_policy_version_required")
        if not self.expected_policy_digest:
            issues.append("backend.remote_policy_digest_required")
        if self._custom_encoder is not None:
            issues.append("backend.remote_custom_encoder_unsupported")
        elif not self.projection_enforced:
            issues.append("backend.remote_projection_unverified")
        decoder_reviewed = (
            CerbosEvaluator._production_decoder_is_reviewed(self)
            if type(self) is CerbosEvaluator
            else JsonPdpEvaluator._production_decoder_is_reviewed(self)
        )
        if not decoder_reviewed:
            issues.append("backend.remote_custom_decoder_unsupported")
        return {"ready": not issues, "issues": tuple(issues)}

    def _production_configuration_is_intact(self) -> bool:
        """Detect public configuration drift before a production PDP call."""

        try:
            current_headers = tuple(sorted(dict(self.headers).items()))
        except (TypeError, ValueError):
            return False
        configured = self._production_configuration
        return (
            self.endpoint == configured[0]
            and self.transport is configured[1]
            and self.encoder is configured[2]
            and self.decoder is configured[3]
            and current_headers == configured[4]
            and self.timeout == configured[5]
            and self.expected_policy_version == configured[6]
            and self.expected_policy_digest == configured[7]
            and self.policy_version == configured[8]
            and self.projection is configured[9]
            and _is_reviewed_projection(self.projection)
            and _projection_snapshot(self.projection) == configured[10]
            and self.ssl_context is configured[11]
            and _tls_context_security_snapshot(self.ssl_context) == configured[12]
            and self.allowed_hosts == configured[13]
            and self.transport_security == configured[14]
            and self._uses_standard_transport == configured[15]
        )

    def _production_decoder_is_reviewed(self) -> bool:
        """Return whether this adapter retains the reviewed JSON decoder.

        A caller-provided decoder can turn an otherwise bound PDP denial into
        an allow.  Keep the exact function identity check local to the base
        JSON adapter; protocol adapters with a different reviewed response
        shape override this method explicitly.
        """

        return self._custom_decoder is None and self.decoder is _find_allowed

    def _encode_payload(self, request: AuthorizationRequest) -> Mapping[str, Any]:
        """Build a payload using the default or development-only encoder."""

        return self.encoder(request)

    def _validate_response_binding(
        self,
        response: Mapping[str, Any],
        details: Mapping[str, Any],
        request: AuthorizationRequest,
    ) -> dict[str, str]:
        """Require the remote response to prove which request/policy it used."""

        binding = {
            "request_id": _response_value(response, details, "request_id"),
            "trace_id": _response_value(response, details, "trace_id"),
            "contract_version": _response_value(response, details, "contract_version"),
            "catalog_fingerprint": _response_value(response, details, "catalog_fingerprint"),
            "policy_version": _response_value(response, details, "policy_version"),
            "policy_digest": _response_value(response, details, "policy_digest")
            or _response_value(response, details, "policy_hash"),
        }
        expected = {
            "request_id": request.request_id,
            "contract_version": request.contract_version,
            "catalog_fingerprint": request.catalog_fingerprint,
            "policy_version": self.expected_policy_version,
            "policy_digest": self.expected_policy_digest,
        }
        if request.trace_id:
            expected["trace_id"] = request.trace_id
        invalid = [
            field_name
            for field_name, expected_value in expected.items()
            if expected_value and binding.get(field_name, "") != expected_value
        ]
        if invalid:
            raise ResponseBindingError(
                "PDP response binding mismatch: " + ", ".join(sorted(invalid))
            )
        return binding

    def authorize(self, request: AuthorizationRequest) -> Decision:
        try:
            request_headers = _protocol_headers(
                self.headers,
                request,
                expected_policy_version=self.expected_policy_version,
                expected_policy_digest=self.expected_policy_digest,
            )
            response = self.transport(
                self.endpoint,
                self._encode_payload(request),
                request_headers,
                self.timeout,
            )
            if not isinstance(response, Mapping):
                raise ValueError("PDP response must be a JSON object")
            allowed = _decode(self.decoder, response, request)
            if allowed is None:
                raise ValueError("PDP response does not contain an authorization decision")
            details = _decision_details(response)
            obligations = details.get("obligations") or response.get("obligations") or {}
            trace = details.get("trace") or response.get("trace") or ()
            policy = str(details.get("policy") or details.get("policy_id") or response.get("policy") or "")
            binding = self._validate_response_binding(response, details, request) if (
                self.expected_policy_version or self.expected_policy_digest
            ) else {}
            response_version = _response_value(response, details, "policy_version") or self.policy_version
            response_digest = (
                _response_value(response, details, "policy_digest")
                or _response_value(response, details, "policy_hash")
            )
            return _decision(
                request,
                allowed,
                backend=self.name,
                reason=f"{self.name} returned {'allow' if allowed else 'deny'}",
                reason_code=f"{self.name}.{'allow' if allowed else 'deny'}",
                policy=policy,
                obligations=obligations if isinstance(obligations, Mapping) else {},
                trace=tuple(trace) if isinstance(trace, (list, tuple)) else (),
                policy_version=response_version,
                policy_digest=response_digest,
                request_id=(binding.get("request_id", "") if binding else None),
                trace_id=(binding.get("trace_id", "") if binding else None),
                contract_version=(binding.get("contract_version", "") if binding else None),
                catalog_fingerprint=(
                    binding.get("catalog_fingerprint", "") if binding else None
                ),
            )
        except ResponseBindingError as exc:
            return _decision(
                request,
                False,
                backend=self.name,
                reason=str(exc),
                reason_code=f"{self.name}.response_binding_invalid",
                policy_version=self.policy_version,
            )
        except Exception as exc:
            return _decision(
                request,
                False,
                backend=self.name,
                reason=f"{self.name} evaluation failed: {type(exc).__name__}",
                reason_code=f"{self.name}.error",
                policy_version=self.policy_version,
            )

    def health(self) -> Mapping[str, object]:
        return {
            "status": "configured",
            "backend": self.name,
            "endpoint": self.endpoint,
            "policy_version": self.policy_version,
            "expected_policy_digest_configured": bool(self.expected_policy_digest),
            "projection_enforced": self.projection_enforced,
            "decoder_reviewed": self._production_decoder_is_reviewed(),
            "production_configuration_intact": self._production_configuration_is_intact(),
            "transport_security": self.transport_security,
            "tls_context_verified": (
                self.ssl_context is None or _verified_tls_context(self.ssl_context)
            ) if self._uses_standard_transport else None,
            "production": self.production_readiness(),
        }


class OpaEvaluator(JsonPdpEvaluator):
    name = "opa"

    def __init__(
        self,
        endpoint: str,
        *,
        projection: PdpRequestProjection | Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if "encoder" in kwargs or "decoder" in kwargs:
            raise TypeError("OpaEvaluator has fixed reviewed payload and decision adapters")
        selected = PdpRequestProjection.coerce(projection)
        super().__init__(
            endpoint,
            projection=selected,
            name="opa",
            **kwargs,
        )

    def _encode_payload(self, request: AuthorizationRequest) -> Mapping[str, Any]:
        return {"input": request_payload(request, projection=self.projection)}


def _cerbos_payload(
    request: AuthorizationRequest,
    *,
    projection: PdpRequestProjection,
) -> dict[str, Any]:
    projected = request_payload(request, projection=projection)
    subject = projected["subject"]
    resource = projected["resource"]
    return {
        "requestId": request.request_id or request.entrypoint or request.operation,
        "principal": {
            "id": str(subject.get("id") or ""),
            "roles": list(subject.get("roles") or ()),
            "attr": {
                **dict(subject.get("metadata") or {}),
                **(
                    {"tenant_id": subject["tenant_id"]}
                    if "tenant_id" in subject
                    else {}
                ),
            },
        },
        "resource": {
            "id": resource["id"] if resource else request.operation,
            "kind": resource["type"] if resource else "operation",
            "attr": resource["attributes"] if resource else {},
        },
        "actions": [request.operation],
        "context": projected["context"],
    }


def _cerbos_decision(
    payload: Mapping[str, Any], request: AuthorizationRequest | None = None
) -> bool | None:
    # Cerbos CheckResources responses are a map of resource instances, not a
    # generic authorization envelope. A production request must consume only
    # the exact resource/action coordinate it asked Cerbos to decide. Scanning
    # arbitrary instances, accepting a sole action, or falling back to a
    # top-level boolean can turn an unrelated allow into this request's allow.
    # Keep the generic fallback solely for the legacy direct-decoder call that
    # has no request coordinate to bind.
    if request is None:
        return _find_allowed(payload)
    instances = payload.get("resourceInstances") or payload.get("resource_instances")
    if not isinstance(instances, Mapping):
        return None
    resource_id = request.resource.id if request.resource is not None else request.operation
    item = instances.get(resource_id)
    if not isinstance(item, Mapping):
        return None
    actions = item.get("actions")
    if not isinstance(actions, Mapping):
        return None
    action = actions.get(request.operation)
    return _find_allowed(action) if action is not None else None


class CerbosEvaluator(JsonPdpEvaluator):
    name = "cerbos"

    def __init__(
        self,
        endpoint: str,
        *,
        projection: PdpRequestProjection | Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if "encoder" in kwargs or "decoder" in kwargs:
            raise TypeError("CerbosEvaluator has fixed reviewed payload and decision adapters")
        selected = PdpRequestProjection.coerce(projection)
        super().__init__(
            endpoint,
            decoder=_cerbos_decision,
            projection=selected,
            name="cerbos",
            **kwargs,
        )

    def _encode_payload(self, request: AuthorizationRequest) -> Mapping[str, Any]:
        return _cerbos_payload(request, projection=self.projection)

    def _production_decoder_is_reviewed(self) -> bool:
        """Cerbos uses this SDK's reviewed response-shape decoder."""

        return self.decoder is _cerbos_decision


def _mapped_backend_operation(
    request: AuthorizationRequest,
    mapper: OperationMapper | None,
    *,
    backend: str,
    field: str,
    pattern: re.Pattern[str],
) -> str:
    """Require an explicit, backend-valid mapping from business operation.

    A Catalog operation such as ``document.read`` is deliberately a business
    identifier. It is not automatically a valid OpenFGA relation or SpiceDB
    permission, nor can the SDK infer the application's data-model semantics.
    """

    if mapper is None:
        raise ValueError(
            f"{backend} requires an explicit operation_mapper for {field}"
        )
    mapped = str(mapper(request) or "").strip()
    if not pattern.fullmatch(mapped):
        raise ValueError(f"{backend} operation_mapper returned an invalid {field}")
    return mapped


def _validate_static_operation_map(
    mapper: OperationMapper | OperationMap | None,
    *,
    backend: str,
    field: str,
    pattern: re.Pattern[str],
) -> None:
    """Reject malformed declarative mappings while configuring an evaluator.

    A callable mapper may depend on request data and remains validated at
    authorization time. A frozen ``OperationMap`` has no reason to defer that
    validation: a production readiness check must not report ready only to
    deny the first live request for a spelling error in static configuration.
    """

    entries = _operation_map_entries(mapper)
    if entries is None:
        return
    invalid = tuple(
        operation
        for operation, target in entries
        if not pattern.fullmatch(target)
    )
    if invalid:
        raise ValueError(
            f"{backend} operation_map contains invalid {field} values for: "
            + ", ".join(invalid)
        )


def _openfga_payload(
    request: AuthorizationRequest,
    *,
    projection: PdpRequestProjection,
    operation_mapper: OperationMapper | None,
) -> dict[str, Any]:
    resource = request.resource
    return {
        "tuple_key": {
            "user": f"user:{_remote_principal(request)}",
            "relation": _mapped_backend_operation(
                request,
                operation_mapper,
                backend="OpenFGA",
                field="relation",
                pattern=_OPENFGA_RELATION,
            ),
            "object": resource.uri if resource else f"operation:{request.operation}",
        },
        "context": request_payload(request, projection=projection)["context"],
    }


class OpenFgaEvaluator(JsonPdpEvaluator):
    name = "openfga"

    def __init__(
        self,
        endpoint: str,
        *,
        projection: PdpRequestProjection | Mapping[str, Any] | None = None,
        operation_mapper: OperationMapper | Mapping[str, str] | None = None,
        operation_map: OperationMap | Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        if "encoder" in kwargs or "decoder" in kwargs:
            raise TypeError("OpenFgaEvaluator has fixed reviewed payload and decision adapters")
        self.operation_mapper = _coerce_operation_mapper(operation_mapper, operation_map)
        _validate_static_operation_map(
            self.operation_mapper,
            backend="OpenFGA",
            field="relation",
            pattern=_OPENFGA_RELATION,
        )
        selected = PdpRequestProjection.coerce(projection)
        super().__init__(
            endpoint,
            projection=selected,
            name="openfga",
            **kwargs,
        )
        self._production_operation_mapper = self.operation_mapper
        self._production_operation_map_entries = _operation_map_entries(
            self.operation_mapper
        )

    def _encode_payload(self, request: AuthorizationRequest) -> Mapping[str, Any]:
        return _openfga_payload(
            request,
            projection=self.projection,
            operation_mapper=self.operation_mapper,
        )

    def production_readiness(self) -> Mapping[str, object]:
        readiness = dict(super().production_readiness())
        issues = list(readiness["issues"])
        if self.operation_mapper is not self._production_operation_mapper:
            issues.append("backend.remote_configuration_mutated")
        elif (
            _is_reviewed_operation_map(self._production_operation_mapper)
            and _operation_map_entries(self._production_operation_mapper)
            != self._production_operation_map_entries
        ):
            issues.append("backend.remote_configuration_mutated")
        elif type(self._production_operation_mapper) is _REVIEWED_OPERATION_MAP_TYPE and not _is_reviewed_operation_map(
            self._production_operation_mapper
        ):
            issues.append("backend.remote_configuration_mutated")
        if self.operation_mapper is None:
            issues.append("backend.openfga_operation_mapper_required")
        elif type(self._production_operation_mapper) is not _REVIEWED_OPERATION_MAP_TYPE:
            issues.append("backend.openfga_production_operation_map_required")
        return {"ready": not issues, "issues": tuple(issues)}


def _spicedb_payload(
    request: AuthorizationRequest,
    *,
    projection: PdpRequestProjection,
    operation_mapper: OperationMapper | None,
) -> dict[str, Any]:
    resource = request.resource
    return {
        "resource": {
            "objectType": resource.type if resource else "operation",
            "objectId": resource.id if resource else request.operation,
        },
        "permission": _mapped_backend_operation(
            request,
            operation_mapper,
            backend="SpiceDB",
            field="permission",
            pattern=_SPICEDB_PERMISSION,
        ),
        "subject": {
            "object": {
                "objectType": "user",
                "objectId": _remote_principal(request),
            }
        },
        "context": request_payload(request, projection=projection)["context"],
    }


class SpiceDbEvaluator(JsonPdpEvaluator):
    name = "spicedb"

    def __init__(
        self,
        endpoint: str,
        *,
        projection: PdpRequestProjection | Mapping[str, Any] | None = None,
        operation_mapper: OperationMapper | Mapping[str, str] | None = None,
        operation_map: OperationMap | Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        if "encoder" in kwargs or "decoder" in kwargs:
            raise TypeError("SpiceDbEvaluator has fixed reviewed payload and decision adapters")
        self.operation_mapper = _coerce_operation_mapper(operation_mapper, operation_map)
        _validate_static_operation_map(
            self.operation_mapper,
            backend="SpiceDB",
            field="permission",
            pattern=_SPICEDB_PERMISSION,
        )
        selected = PdpRequestProjection.coerce(projection)
        super().__init__(
            endpoint,
            projection=selected,
            name="spicedb",
            **kwargs,
        )
        self._production_operation_mapper = self.operation_mapper
        self._production_operation_map_entries = _operation_map_entries(
            self.operation_mapper
        )

    def _encode_payload(self, request: AuthorizationRequest) -> Mapping[str, Any]:
        return _spicedb_payload(
            request,
            projection=self.projection,
            operation_mapper=self.operation_mapper,
        )

    def production_readiness(self) -> Mapping[str, object]:
        readiness = dict(super().production_readiness())
        issues = list(readiness["issues"])
        if self.operation_mapper is not self._production_operation_mapper:
            issues.append("backend.remote_configuration_mutated")
        elif (
            _is_reviewed_operation_map(self._production_operation_mapper)
            and _operation_map_entries(self._production_operation_mapper)
            != self._production_operation_map_entries
        ):
            issues.append("backend.remote_configuration_mutated")
        elif type(self._production_operation_mapper) is _REVIEWED_OPERATION_MAP_TYPE and not _is_reviewed_operation_map(
            self._production_operation_mapper
        ):
            issues.append("backend.remote_configuration_mutated")
        if self.operation_mapper is None:
            issues.append("backend.spicedb_operation_mapper_required")
        elif type(self._production_operation_mapper) is not _REVIEWED_OPERATION_MAP_TYPE:
            issues.append("backend.spicedb_production_operation_map_required")
        return {"ready": not issues, "issues": tuple(issues)}


class AuthzenEvaluator(JsonPdpEvaluator):
    """Adapter for an AuthZEN-style decision endpoint."""

    name = "authzen"

    def __init__(
        self,
        endpoint: str,
        *,
        projection: PdpRequestProjection | Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if "encoder" in kwargs or "decoder" in kwargs:
            raise TypeError("AuthzenEvaluator has fixed reviewed payload and decision adapters")
        selected = PdpRequestProjection.coerce(projection)
        super().__init__(
            endpoint,
            projection=selected,
            name="authzen",
            **kwargs,
        )

    def _encode_payload(self, request: AuthorizationRequest) -> Mapping[str, Any]:
        return {
            "subject": {"type": "user", "id": _remote_principal(request)},
            "action": {"name": request.operation},
            "resource": {
                "type": request.resource.type if request.resource else "operation",
                "id": request.resource.id if request.resource else request.operation,
            },
            "context": request_payload(request, projection=self.projection)["context"],
        }


_register_reviewed_production_evaluator(CasbinEvaluator, mode="in_process")
for _reviewed_remote_evaluator_type in (
    JsonPdpEvaluator,
    OpaEvaluator,
    CerbosEvaluator,
    OpenFgaEvaluator,
    SpiceDbEvaluator,
    AuthzenEvaluator,
):
    _register_reviewed_production_evaluator(_reviewed_remote_evaluator_type, mode="remote")
del _reviewed_remote_evaluator_type


__all__ = [
    "AuthzenEvaluator",
    "CasbinRequestTemplate",
    "CasbinEvaluator",
    "CerbosEvaluator",
    "JsonPdpEvaluator",
    "OperationMap",
    "OperationMapper",
    "OpaEvaluator",
    "OpenFgaEvaluator",
    "PdpRequestProjection",
    "SpiceDbEvaluator",
    "request_payload",
]
