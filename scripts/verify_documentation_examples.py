"""Execute copy-and-paste critical README guard examples against an installed SDK."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

from authz_sdk import Authz, Catalog, PolicySet, ResourceRegistry


def _documented_guard_block(path: Path) -> str:
    """Return the fenced Python block that demonstrates ``@protect_tool``."""

    content = path.read_text(encoding="utf-8")
    for match in re.finditer(r"~~~python\n(.*?)~~~", content, re.DOTALL):
        block = match.group(1)
        if "@protect_tool(" in block:
            return block
    raise ValueError(f"{path} must contain a protect_tool Python example")


def _production_authz() -> Authz:
    catalog = Catalog()
    catalog.resource("document", actions=("read",), tenant_required=True)
    policies = PolicySet()
    policies.bind(
        id="allow_read",
        operation="document.read",
        template="allow",
    )
    resources = ResourceRegistry()
    resources.register(
        "document",
        lambda resource_id, _subject, _context: {
            "id": resource_id,
            "attributes": {"tenant_id": "acme"},
        },
    )
    return Authz.production(catalog, policies, resources)


def verify_documentation_examples(root: Path) -> None:
    """Compile and execute English and Chinese final-guard README snippets."""

    for relative_path, data_name in (
        ("README.md", "documents"),
        ("docs/zh-CN/README.md", "rows"),
    ):
        path = root / relative_path
        namespace: dict[str, Any] = {
            "__name__": "documentation_contract",
            "authz": _production_authz(),
            data_name: {"doc-1": {"body": "document body"}},
        }
        exec(compile(_documented_guard_block(path), str(path), "exec"), namespace)
        guard = namespace.get("read_document")
        if not callable(guard) or not getattr(guard, "authz_protected", False):
            raise ValueError(f"{path} protect_tool example did not create a protected callable")
        if getattr(guard, "authz_operation", "") != "document.read":
            raise ValueError(f"{path} protect_tool example has the wrong operation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="repository root containing the README files")
    args = parser.parse_args(argv)
    verify_documentation_examples(args.root.resolve())
    print("documentation examples verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
