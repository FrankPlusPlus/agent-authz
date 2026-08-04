from authz_sdk.conditions import matches
from authz_sdk.models import Subject


def test_legacy_role_alias_matches_any_assigned_role() -> None:
    subject = Subject(roles=("member", "hr"))

    assert matches(
        {"left": "subject.role", "operator": "eq", "right": "hr"},
        subject=subject,
        resource=None,
        context={},
    )
    assert matches(
        {"left": "subject.role", "operator": "in", "right": ["developer", "hr"]},
        subject=subject,
        resource=None,
        context={},
    )


def test_legacy_position_alias_is_order_independent() -> None:
    condition = {"left": "subject.position", "operator": "in", "right": ["人力资源经理"]}
    first = Subject(positions=("工程师", "人力资源经理"))
    second = Subject(positions=("人力资源经理", "工程师"))

    assert matches(condition, subject=first, resource=None, context={})
    assert matches(condition, subject=second, resource=None, context={})
