"""Executable contracts for copy-and-paste critical documentation snippets."""

from __future__ import annotations

from pathlib import Path
import runpy

ROOT = Path(__file__).parents[1]


def test_readme_final_guard_examples_execute_as_documented() -> None:
    """Keep the English and Chinese first-run guard snippets API-correct."""

    namespace = runpy.run_path(str(ROOT / "scripts" / "verify_documentation_examples.py"))
    namespace["verify_documentation_examples"](ROOT)
