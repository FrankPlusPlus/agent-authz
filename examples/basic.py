"""Minimal standalone example.

From a source checkout, first run ``python -m pip install -e .`` and then
``python examples/basic.py``. The package is intentionally not importable by
running this file directly before the checkout has been installed.
"""

from authz_sdk import Authz, Catalog, PolicySet, Resource, Subject


catalog = Catalog()
catalog.resource("ai_employee", title="AI Employee", crud=True, relations=("creator", "owner"))

policies = PolicySet()
policies.bind(
    id="delete_creator_or_admin",
    operation="ai_employee.delete",
    template="owner_or_admin",
    relations=("creator",),
    parameters={"admin_roles": ["admin"]},
)

authz = Authz(catalog, policies)
employee = Resource("ai_employee", "employee-1", relations={"creator": True})
decision = authz.can(Subject(email="alice@example.com"), resource=employee, action="delete")
print(decision.to_dict())
