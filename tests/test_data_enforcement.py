from authz_sdk import Authz, Catalog, PolicySet, Resource, ResourceRegistry, Subject
from authz_sdk.data import CandidateFilter


def _chunk_authz() -> Authz:
    catalog = Catalog()
    catalog.resource("knowledge_chunk", title="Knowledge chunk", actions=("read",), relations=("viewer",))
    policies = PolicySet()
    policies.bind(
        id="read_visible_chunk",
        operation="knowledge_chunk.read",
        template="relation",
        relations=("viewer",),
    )
    return Authz(catalog, policies)


def test_rag_filter_keeps_only_authorized_candidate_and_audit_never_contains_body():
    candidates = (
        {"id": "chunk-allowed", "text": "ordinary internal guidance"},
        {"id": "chunk-denied", "text": "TOP SECRET: acquisition plan"},
    )

    candidate_filter = CandidateFilter(
        _chunk_authz(),
        resource_mapper=lambda candidate, _subject, _context: Resource(
            "knowledge_chunk",
            candidate["id"],
            relations={"viewer": candidate["id"] == "chunk-allowed"},
        ),
    )

    result = candidate_filter.filter(
        candidates,
        subject=Subject(id="alice"),
        operation="knowledge_chunk.read",
        entrypoint="rag.retrieve",
    )

    assert result.candidates == (candidates[0],)
    assert result.summary.input_count == 2
    assert result.summary.allowed_count == 1
    assert result.summary.excluded_count == 1
    assert [record.reason_code for record in result.summary.records] == [
        "authorization.allowed",
        "authorization.denied",
    ]
    audit_payload = result.summary.to_dict()
    assert "TOP SECRET" not in repr(audit_payload)
    assert "TOP SECRET" not in repr(result)
    assert "text" not in repr(audit_payload)


def test_loader_failure_is_excluded_before_candidate_reaches_prompt_context():
    candidates = (
        {"id": "chunk-allowed", "text": "permitted answer context"},
        {"id": "chunk-loader-failure", "text": "TOP SECRET: loader failure must not leak"},
    )
    registry = ResourceRegistry()

    def load_chunk(resource_id, _subject, _context):
        if resource_id == "chunk-loader-failure":
            raise RuntimeError("database timeout with TOP SECRET payload")
        return {"relations": {"viewer": True}}

    registry.register("knowledge_chunk", load_chunk)
    candidate_filter = CandidateFilter(
        _chunk_authz(),
        resource_mapper=lambda candidate, subject, context: registry.resolve(
            "knowledge_chunk",
            candidate["id"],
            subject,
            context=context,
        ),
    )

    result = candidate_filter.filter(
        candidates,
        subject=Subject(id="alice"),
        operation="knowledge_chunk.read",
    )

    assert result.candidates == (candidates[0],)
    assert [record.reason_code for record in result.summary.records] == [
        "authorization.allowed",
        "candidate.resource_mapping_failed",
    ]
    assert "TOP SECRET" not in repr(result.summary.to_dict())


def test_injected_checker_receives_rag_operation_and_entrypoint():
    calls = []

    def checker(subject, *, operation, resource, context, entrypoint):
        calls.append((subject.id, operation, resource.uri, dict(context), entrypoint))
        return resource.id == "chunk-allowed"

    candidate_filter = CandidateFilter(
        resource_mapper=lambda candidate, _subject, _context: Resource("knowledge_chunk", candidate["id"]),
        checker=checker,
    )
    candidates = (
        {"id": "chunk-allowed", "text": "allowed"},
        {"id": "chunk-denied", "text": "denied"},
    )

    result = candidate_filter.filter(
        candidates,
        subject=Subject(id="agent-1"),
        operation="knowledge_chunk.read",
        context={"tenant_id": "tenant-a"},
    )

    assert result.candidates == (candidates[0],)
    assert calls == [
        ("agent-1", "knowledge_chunk.read", "knowledge_chunk:chunk-allowed", {"tenant_id": "tenant-a"}, "rag.retrieve"),
        ("agent-1", "knowledge_chunk.read", "knowledge_chunk:chunk-denied", {"tenant_id": "tenant-a"}, "rag.retrieve"),
    ]


def test_missing_resource_and_checker_failure_are_fail_closed():
    candidates = (
        {"id": "missing", "text": "TOP SECRET: no resource identity"},
        {"id": "checker-fails", "text": "TOP SECRET: checker unavailable"},
    )

    def map_resource(candidate, _subject, _context):
        if candidate["id"] == "missing":
            return None
        return Resource("knowledge_chunk", candidate["id"])

    def unavailable_checker(_subject, **_kwargs):
        raise TimeoutError("PDP response contains TOP SECRET diagnostics")

    result = CandidateFilter(
        resource_mapper=map_resource,
        checker=unavailable_checker,
    ).filter(
        candidates,
        subject=Subject(id="alice"),
        operation="knowledge_chunk.read",
    )

    assert result.candidates == ()
    assert [record.reason_code for record in result.summary.records] == [
        "candidate.resource_missing",
        "candidate.authorization_failed",
    ]
    assert "TOP SECRET" not in repr(result.summary.to_dict())


def test_candidate_filter_deep_copies_context_and_hashes_mapper_resource_ids():
    seen_contexts = []

    def mapper(candidate, _subject, context):
        seen_contexts.append((context, context["nested"]["tenant_id"]))
        context["nested"]["tenant_id"] = "mutated"
        return Resource("knowledge_chunk", candidate["id"])

    result = CandidateFilter(
        resource_mapper=mapper,
        checker=lambda *_args, **_kwargs: True,
    ).filter(
        (
            {"id": "ordinary"},
            {"id": "TOP SECRET candidate body must never be logged"},
        ),
        subject=Subject(id="alice"),
        operation="knowledge_chunk.read",
        context={"nested": {"tenant_id": "acme"}},
    )

    assert len(result.candidates) == 2
    # Each mapper observes an unmodified nested value before making its own mutation.
    assert [before for _context, before in seen_contexts] == ["acme", "acme"]
    assert seen_contexts[0][0] is not seen_contexts[1][0]
    assert "TOP SECRET" not in repr(result.summary.to_dict())
    assert result.summary.records[1].resource_uri.startswith("sha256:")
