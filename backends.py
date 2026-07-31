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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from authz_sdk.evaluator import (
    BackendUnavailableError,
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
        if isinstance(values, OperationMap):
            entries = values._entries
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
    if isinstance(configured, OperationMap):
        # Copy even an existing map so this evaluator owns the frozen snapshot.
        return OperationMap(configured)
    if isinstance(configured, Mapping):
        return OperationMap(configured)
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
            return value
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


class CasbinEvaluator:
    """Evaluate a request using an existing Casbin ``Enforcer``.

    The default mapping follows Casbin's common ``r = sub, obj, act`` model:
    ``sub`` is the stable subject ID/email, ``obj`` is the trusted resource
    URI, and ``act`` is the Authz business operation. Custom models can pass a
    ``request_builder`` and receive any arguments their matcher declares.
    """

    name = "casbin"
    enforcement_mode = "in_process"

    def __init__(
        self,
        enforcer: Any,
        *,
        request_builder: RequestBuilder | None = None,
        policy_version: str = "",
    ) -> None:
        if not callable(getattr(enforcer, "enforce", None)):
            raise TypeError("CasbinEvaluator requires an object with enforce()")
        self.enforcer = enforcer
        self.request_builder = request_builder or self.default_request
        self.policy_version = str(policy_version or "1")
        self._production_configuration = (
            self.enforcer,
            self.request_builder,
            self.policy_version,
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
        request_builder: RequestBuilder | None = None,
        policy_version: str = "",
    ) -> "CasbinEvaluator":
        try:
            import casbin
        except ImportError as exc:  # pragma: no cover - depends on installation
            raise BackendUnavailableError(
                "Casbin is optional; install agent-authz-sdk[casbin] first"
            ) from exc
        return cls(
            casbin.Enforcer(model_path, policy_path),
            request_builder=request_builder,
            policy_version=policy_version,
        )

    def authorize(self, request: AuthorizationRequest) -> Decision:
        try:
            result = self.enforcer.enforce(*self.request_builder(request))
            if isinstance(result, tuple):
                allowed = bool(result[0])
            else:
                allowed = bool(result)
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
        return {
            "ready": intact,
            "issues": () if intact else ("backend.in_process_configuration_mutated",),
        }


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
        opener = urllib.request.build_opener(_NoRedirectHandler(), https_handler)
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
        self.headers = _validated_configured_headers(headers)
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
            self.ssl_context,
            self.allowed_hosts,
            self.transport_security,
            self._uses_standard_transport,
        )

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
            and self.projection == configured[9]
            and self.ssl_context is configured[10]
            and self.allowed_hosts == configured[11]
            and self.transport_security == configured[12]
            and self._uses_standard_transport == configured[13]
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
    direct = _find_allowed(payload)
    if direct is not None:
        return direct
    instances = payload.get("resourceInstances") or payload.get("resource_instances")
    if not isinstance(instances, Mapping):
        return None
    for item in instances.values():
        if not isinstance(item, Mapping):
            continue
        actions = item.get("actions")
        if isinstance(actions, Mapping) and actions:
            requested_action = request.operation if request is not None else ""
            if requested_action and requested_action in actions:
                return _find_allowed(actions[requested_action])
            if len(actions) == 1:
                return _find_allowed(next(iter(actions.values())))
    return None


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
        selected = PdpRequestProjection.coerce(projection)
        super().__init__(
            endpoint,
            projection=selected,
            name="openfga",
            **kwargs,
        )
        self._production_operation_mapper = self.operation_mapper
        self._production_operation_map_entries = (
            self.operation_mapper.entries
            if isinstance(self.operation_mapper, OperationMap)
            else None
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
            isinstance(self._production_operation_mapper, OperationMap)
            and self._production_operation_mapper.entries
            != self._production_operation_map_entries
        ):
            issues.append("backend.remote_configuration_mutated")
        if self.operation_mapper is None:
            issues.append("backend.openfga_operation_mapper_required")
        elif not isinstance(self._production_operation_mapper, OperationMap):
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
        selected = PdpRequestProjection.coerce(projection)
        super().__init__(
            endpoint,
            projection=selected,
            name="spicedb",
            **kwargs,
        )
        self._production_operation_mapper = self.operation_mapper
        self._production_operation_map_entries = (
            self.operation_mapper.entries
            if isinstance(self.operation_mapper, OperationMap)
            else None
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
            isinstance(self._production_operation_mapper, OperationMap)
            and self._production_operation_mapper.entries
            != self._production_operation_map_entries
        ):
            issues.append("backend.remote_configuration_mutated")
        if self.operation_mapper is None:
            issues.append("backend.spicedb_operation_mapper_required")
        elif not isinstance(self._production_operation_mapper, OperationMap):
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
    "CasbinEvaluator",
    "CerbosEvaluator",
    "JsonPdpEvaluator",
    "OperationMapper",
    "OpaEvaluator",
    "OpenFgaEvaluator",
    "PdpRequestProjection",
    "SpiceDbEvaluator",
    "request_payload",
]
