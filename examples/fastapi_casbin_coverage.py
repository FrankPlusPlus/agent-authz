"""FastAPI + Casbin with one final execution guard and coverage evidence.

Install the example extras, then run it with::

    python -m pip install -e '.[fastapi,casbin]'
    uvicorn examples.fastapi_casbin_coverage:app --reload

Casbin remains the policy engine. Agent Authz owns the application-side PEP:
it maps the HTTP entrypoint to ``document.read``, resolves trusted resource
facts, performs the final check, and verifies that the mounted route has the
SDK guard. The default application returns 401 until host authentication puts a
verified ``Subject`` in ``request.state.authz_subject``.
"""

from __future__ import annotations

from collections.abc import Callable

import casbin
from fastapi import Depends, FastAPI, HTTPException, Request, status

from authz_sdk import (
    Authz,
    CasbinEvaluator,
    Catalog,
    CoverageManifest,
    FastAPIAuthz,
    PolicySet,
    ResourceRegistry,
    Subject,
    record_fastapi_inventory,
)


catalog = Catalog()
catalog.resource("document", actions=("read",), tenant_required=True)
catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")

documents = {
    "doc-1": {"tenant_id": "acme", "content": "Casbin-backed document"},
}
resources = ResourceRegistry()
resources.register(
    "document",
    lambda document_id, _subject, _context: (
        {
            "id": document_id,
            "attributes": {"tenant_id": row["tenant_id"]},
        }
        if (row := documents.get(document_id)) is not None
        else None
    ),
)


def _casbin_enforcer() -> casbin.Enforcer:
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
    enforcer.add_policy("alice", "document:doc-1", "document.read")
    return enforcer


authz = Authz.production(
    catalog,
    PolicySet(version="casbin-example-1"),
    resources,
    evaluator=CasbinEvaluator(_casbin_enforcer(), policy_version="casbin-example-1"),
)


def verified_subject(request: Request) -> Subject:
    """Read the host-installed identity; never authenticate from request input."""

    principal = getattr(request.state, "authz_subject", None)
    if not isinstance(principal, Subject) or not principal.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authenticated request.state.authz_subject is required",
        )
    return principal


def create_app(
    *,
    subject_provider: Callable[[Request], Subject] = verified_subject,
) -> FastAPI:
    """Build an app and retain a startup/CI coverage report on ``app.state``."""

    coverage = CoverageManifest(catalog).require_final_execution("document.read")
    guard = FastAPIAuthz(authz, subject=subject_provider, coverage=coverage).dependency(
        entrypoint="GET /documents/{document_id}",
        resource_type="document",
        resource_id=lambda request: request.path_params["document_id"],
    )
    app = FastAPI(title="Agent Authz + Casbin")

    @app.get("/documents/{document_id}")
    async def read_document(
        document_id: str,
        _decision=Depends(guard),
    ) -> dict[str, str]:
        return {"id": document_id, "content": str(documents[document_id]["content"])}

    # Call after every router is mounted. A missing/incorrect dependency makes
    # this report fail rather than treating the Casbin enforcer as proof that
    # this execution boundary is wired.
    app.state.authz_coverage = record_fastapi_inventory(coverage, app)
    coverage.assert_complete()
    return app


app = create_app()
