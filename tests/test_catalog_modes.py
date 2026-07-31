from authz_sdk import Authz, CasbinEvaluator, Catalog, PolicySet, Resource, Subject


def _casbin_evaluator():
    import casbin

    model = casbin.Model()
    model.load_model_from_text(
        """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
    )
    enforcer = casbin.Enforcer(model)
    enforcer.add_policy("alice@example.com", "custom:1", "custom.publish")
    return CasbinEvaluator(enforcer)


def test_advisory_catalog_does_not_block_external_operation():
    catalog = Catalog()
    catalog.resource("known", actions=("read",))
    authz = Authz(
        catalog,
        PolicySet(),
        evaluator=_casbin_evaluator(),
        catalog_mode="advisory",
    )

    decision = authz.can(
        Subject(email="alice@example.com"),
        operation="custom.publish",
        resource=Resource("custom", "1"),
    )

    assert decision.allowed is True
    assert decision.reason_code == "casbin.allow"


def test_factory_methods_make_native_and_external_modes_explicit():
    catalog = Catalog()
    catalog.resource("document", actions=("read",))
    native = Authz.native(catalog, PolicySet())
    assert native.catalog_mode == "strict"
    external = Authz.connect(_casbin_evaluator(), catalog=catalog)
    assert external.catalog_mode == "advisory"


def test_off_mode_allows_external_engine_without_catalog():
    authz = Authz(
        None,
        PolicySet(),
        evaluator=_casbin_evaluator(),
        catalog_mode="off",
    )

    decision = authz.can(
        Subject(email="alice@example.com"),
        operation="custom.publish",
        resource=Resource("custom", "1"),
    )

    assert decision.allowed is True
    assert authz.health()["catalog_mode"] == "off"


def test_strict_mode_still_fails_closed_for_unknown_operations():
    catalog = Catalog()
    catalog.resource("known", actions=("read",))
    authz = Authz(catalog, PolicySet())

    decision = authz.can(
        Subject(email="alice@example.com"),
        operation="custom.publish",
    )

    assert decision.allowed is False
    assert decision.reason_code == "catalog.operation_unknown"
