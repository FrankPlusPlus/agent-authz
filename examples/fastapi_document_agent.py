"""A production-shaped FastAPI boundary backed by ``Authz.production``.

Install the optional example dependencies and run it with::

    python -m pip install -e '.[fastapi]'
    uvicorn examples.fastapi_document_agent:app --reload

The application intentionally obtains only a document ID from the HTTP path.
``FastAPIAuthz`` passes it to ``ResourceRegistry``; it never trusts relation
facts from a request header, JSON body, or model output.

Your authentication middleware must set ``request.state.authz_subject`` to a
verified :class:`authz_sdk.Subject` before this route runs. This is a secure
integration template: the default app intentionally returns 401 until a host
authentication middleware has installed that value. It does not accept identity
or tenant headers as an authentication mechanism.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, FastAPI, HTTPException, Request, status

from authz_sdk import (
    Authz,
    Catalog,
    FastAPIAuthz,
    PolicySet,
    ResourceRegistry,
    Subject,
)


catalog = Catalog()
catalog.resource(
    "document",
    actions=("read",),
    relations=("viewer",),
    tenant_required=True,
)
catalog.bind_entrypoint("api", "GET /documents/{document_id}", "document.read")

policies = PolicySet()
policies.bind(
    id="document_viewer",
    operation="document.read",
    template="relation",
    relations=("viewer",),
)

documents = {
    "doc-public": {"tenant_id": "acme", "viewers": {"alice"}, "content": "approved"},
    "doc-private": {"tenant_id": "acme", "viewers": {"bob"}, "content": "not for Alice"},
}
resources = ResourceRegistry()


def load_document(document_id: str, subject: Subject, _context: dict[str, object]) -> dict[str, object] | None:
    row = documents.get(document_id)
    if row is None:
        return None
    return {
        "id": document_id,
        "attributes": {"tenant_id": row["tenant_id"]},
        "relations": {"viewer": subject.id in row["viewers"]},
    }


resources.register("document", load_document)
authz = Authz.production(catalog, policies, resources)


def verified_subject(request: Request) -> Subject:
    """Read a principal installed by the host authentication middleware."""

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
    """Create an app whose host supplies a verified request-local Subject.

    A production host can pass its own provider or use ``verified_subject``
    after authentication middleware writes ``request.state.authz_subject``.
    Tests can inject a trusted fixture without ever treating client headers as
    identity.
    """

    api_authz = FastAPIAuthz(authz, subject=subject_provider)
    read_document = api_authz.dependency(
        entrypoint="GET /documents/{document_id}",
        resource_type="document",
        resource_id=lambda request: request.path_params["document_id"],
    )
    app = FastAPI(title="Agent Authz FastAPI example")

    @app.get("/documents/{document_id}")
    async def get_document(
        document_id: str,
        _decision=Depends(read_document),
    ) -> dict[str, str]:
        """Return content only after the resource-aware API boundary allowed it."""

        return {"id": document_id, "content": str(documents[document_id]["content"])}

    return app


app = create_app()
