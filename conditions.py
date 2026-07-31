"""Small, safe condition language for policy bindings.

The SDK intentionally does not execute Python, Rego, or arbitrary expressions
from a dashboard. Conditions are JSON-shaped data and are evaluated against a
trusted subject, resource, and request context. Unknown paths and malformed
operators fail closed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from authz_sdk.models import Resource, Subject


_MISSING = object()
_OPERATORS = {
    "eq",
    "neq",
    "in",
    "not_in",
    "contains",
    "contains_any",
    "exists",
    "truthy",
    "gt",
    "gte",
    "lt",
    "lte",
}
_MAX_DEPTH = 24


def _read_path(value: Any, path: str) -> Any:
    current = value
    for part in str(path or "").split("."):
        if not part:
            return _MISSING
        if isinstance(current, Mapping):
            if part not in current:
                return _MISSING
            current = current[part]
            continue
        if hasattr(current, part):
            current = getattr(current, part)
            continue
        return _MISSING
    return current


def _root_value(name: str, subject: Subject, resource: Resource | None, context: Mapping[str, Any]) -> Any:
    roots = {
        "subject": subject,
        "resource": resource,
        "context": context,
    }
    root, _, path = str(name or "").partition(".")
    if root not in roots:
        return _MISSING
    if not path:
        return roots[root]
    resolved = _read_path(roots[root], path)
    if resolved is not _MISSING:
        return resolved
    if root == "subject" and path == "role":
        return subject.roles[0] if subject.roles else _MISSING
    if root == "subject" and path == "position":
        return subject.positions[0] if subject.positions else _MISSING
    if root == "resource" and resource is not None:
        return _read_path(resource.attributes, path)
    if root == "subject":
        return _read_path(subject.metadata, path)
    return _MISSING


def resolve_value(value: Any, *, subject: Subject, resource: Resource | None, context: Mapping[str, Any]) -> Any:
    """Resolve a literal or a ``{"ref": "subject.email"}`` value."""

    if isinstance(value, Mapping) and set(value) == {"ref"}:
        return _root_value(str(value.get("ref") or ""), subject, resource, context)
    if isinstance(value, Mapping) and len(value) == 1:
        root, path = next(iter(value.items()))
        if root in {"subject", "resource", "context"}:
            return _root_value(f"{root}.{path}", subject, resource, context)
    if isinstance(value, str) and value.startswith(("subject.", "resource.", "context.")):
        return _root_value(value, subject, resource, context)
    return value


def _relation(name: str, resource: Resource | None, subject: Subject) -> bool:
    """Resolve universal relationship predicates without application code."""

    if resource is None:
        return False
    normalized = str(name or "").strip().lower()
    if normalized == "unowned":
        owner = resource.attributes.get("owner_email") or resource.attributes.get("creator_email")
        return not bool(str(owner or "").strip())
    if normalized in {"not_owner", "not:owner"}:
        owner = resource.attributes.get("owner_email") or resource.attributes.get("creator_email")
        if "owner" in resource.relations or "owner" in resource.attributes:
            return not resource.related("owner")
        if not str(owner or "").strip():
            return False
        owner_id = str(resource.attributes.get("owner_id") or owner).strip().lower()
        return owner_id not in {str(subject.id or "").strip().lower(), str(subject.email or "").strip().lower()}
    if normalized.startswith("not:"):
        relation = normalized.removeprefix("not:").strip()
        # A missing relation is unknown, not proof of a negative relationship.
        return bool(relation and relation in resource.relations and not resource.related(relation))
    return bool(resource.related(normalized))


def _compare(operator: str, left: Any, right: Any) -> bool:
    if left is _MISSING or right is _MISSING:
        return False
    if operator == "eq":
        return left == right
    if operator == "neq":
        return left != right
    if operator in {"in", "not_in"}:
        try:
            return (left in (right or ())) if operator == "in" else (left not in (right or ()))
        except TypeError:
            return False
    if operator == "contains":
        try:
            return right in left
        except TypeError:
            return False
    if operator == "contains_any":
        try:
            return bool(set(left or ()).intersection(set(right or ())))
        except TypeError:
            return False
    if operator == "exists":
        return (left is not _MISSING and left is not None) is bool(right)
    if operator == "truthy":
        return bool(left) is bool(right)
    try:
        if operator == "gt":
            return left > right
        if operator == "gte":
            return left >= right
        if operator == "lt":
            return left < right
        if operator == "lte":
            return left <= right
    except TypeError:
        return False
    return False


def _simple_condition(
    condition: Mapping[str, Any],
    *,
    subject: Subject,
    resource: Resource | None,
    context: Mapping[str, Any],
) -> bool:
    if "relation" in condition:
        expected = bool(condition.get("value", True))
        return _relation(str(condition.get("relation") or ""), resource, subject) is expected

    # The long form is friendly to generated JSON and remains easy to render in
    # a dashboard: {"left": "subject.tenant_id", "operator": "eq", ...}.
    operator = str(condition.get("operator") or "").strip().lower()
    if operator:
        left = resolve_value(condition.get("left"), subject=subject, resource=resource, context=context)
        right = resolve_value(condition.get("right"), subject=subject, resource=resource, context=context)
        return _compare(operator, left, right)

    # The short form is convenient in hand-written policies:
    # {"eq": [{"subject": "tenant_id"}, {"resource": "tenant_id"}]}.
    for operator in _OPERATORS:
        if operator not in condition:
            continue
        raw = condition[operator]
        if operator in {"exists", "truthy"}:
            values = raw if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)) else (raw, True)
            if len(values) == 1:
                values = (values[0], True)
        else:
            values = raw if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)) else ()
        if len(values) != 2:
            return False
        left = resolve_value(values[0], subject=subject, resource=resource, context=context)
        right = resolve_value(values[1], subject=subject, resource=resource, context=context)
        return _compare(operator, left, right)
    return False


def _contains_unresolved(
    condition: Any,
    *,
    subject: Subject,
    resource: Resource | None,
    context: Mapping[str, Any],
) -> bool:
    """Detect missing facts before a logical negation can invert them."""

    if not isinstance(condition, Mapping):
        return True
    if "relation" in condition:
        relation = str(condition.get("relation") or "").strip()
        return resource is None or (
            relation not in resource.relations and relation not in resource.attributes
        )
    if "all" in condition or "any" in condition:
        return any(
            _contains_unresolved(item, subject=subject, resource=resource, context=context)
            for item in condition.get("all", condition.get("any", ())) or ()
        )
    if "not" in condition:
        return _contains_unresolved(condition.get("not"), subject=subject, resource=resource, context=context)
    operator = str(condition.get("operator") or "").strip().lower()
    if not operator:
        operator = next((item for item in _OPERATORS if item in condition), "")
        raw = condition.get(operator) if operator else ()
    else:
        raw = (condition.get("left"), condition.get("right"))
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return True
    for item in raw:
        value = resolve_value(item, subject=subject, resource=resource, context=context)
        if value is _MISSING:
            # Subject attributes are identity facts, not object facts. A
            # missing optional role/position/metadata flag is a normal false
            # value and must not prevent a deny rule such as ``not owner or
            # admin`` from matching. Missing resource/context facts remain
            # unresolved so negation cannot accidentally grant access.
            ref_name = ""
            if isinstance(item, str):
                ref_name = item
            elif isinstance(item, Mapping) and set(item) == {"ref"}:
                ref_name = str(item.get("ref") or "")
            if ref_name.startswith("subject."):
                continue
            return True
    return False


def matches(
    condition: Mapping[str, Any] | None,
    *,
    subject: Subject,
    resource: Resource | None,
    context: Mapping[str, Any] | None = None,
    _depth: int = 0,
) -> bool:
    """Evaluate one JSON condition; malformed or too-deep input returns false."""

    if condition is None:
        return True
    if not isinstance(condition, Mapping) or _depth > _MAX_DEPTH:
        return False
    if not condition:
        return True
    if validate(condition):
        return False
    request_context = dict(context or {})
    if "all" in condition:
        children = condition.get("all")
        return bool(isinstance(children, Sequence) and children and all(
            matches(item, subject=subject, resource=resource, context=request_context, _depth=_depth + 1)
            for item in children
        ))
    if "any" in condition:
        children = condition.get("any")
        return bool(isinstance(children, Sequence) and children and any(
            matches(item, subject=subject, resource=resource, context=request_context, _depth=_depth + 1)
            for item in children
        ))
    if "not" in condition:
        if _contains_unresolved(condition.get("not"), subject=subject, resource=resource, context=request_context):
            return False
        return not matches(condition.get("not"), subject=subject, resource=resource, context=request_context, _depth=_depth + 1)
    return _simple_condition(condition, subject=subject, resource=resource, context=request_context)


def validate(condition: Any, *, _path: str = "when", _depth: int = 0) -> list[str]:
    """Return human-readable validation errors without executing a condition."""

    if condition is None:
        return []
    if isinstance(condition, Mapping) and not condition:
        return []
    if _depth > _MAX_DEPTH:
        return [f"{_path} exceeds the maximum condition depth of {_MAX_DEPTH}"]
    if not isinstance(condition, Mapping):
        return [f"{_path} must be an object"]
    errors: list[str] = []
    logical = [key for key in ("all", "any") if key in condition]
    if logical:
        if len(logical) > 1 or "not" in condition:
            errors.append(f"{_path} must contain only one logical operator")
        key = logical[0]
        value = condition.get(key)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or not value:
            errors.append(f"{_path}.{key} must be a non-empty list")
        else:
            for index, child in enumerate(value):
                errors.extend(validate(child, _path=f"{_path}.{key}[{index}]", _depth=_depth + 1))
        return errors
    if "not" in condition:
        return validate(condition.get("not"), _path=f"{_path}.not", _depth=_depth + 1)
    if "relation" in condition:
        if not str(condition.get("relation") or "").strip():
            errors.append(f"{_path}.relation must not be empty")
        return errors
    operator = str(condition.get("operator") or "").strip().lower()
    if not operator:
        operator = next((item for item in _OPERATORS if item in condition), "")
        if not operator:
            errors.append(f"{_path} must contain relation, operator, or a logical operator")
            return errors
    if operator not in _OPERATORS:
        errors.append(f"{_path} uses unsupported operator {operator!r}")
        return errors
    if "operator" in condition and ("left" not in condition or "right" not in condition):
        errors.append(f"{_path} with operator form requires left and right")
        return errors
    raw = condition.get(operator) if "operator" not in condition else [condition.get("left"), condition.get("right")]
    if operator in {"exists", "truthy"} and not isinstance(raw, Sequence):
        raw = [raw]
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)) or len(raw) not in {1, 2}:
        errors.append(f"{_path} requires one or two operands")
    return errors


__all__ = ["matches", "resolve_value", "validate"]
