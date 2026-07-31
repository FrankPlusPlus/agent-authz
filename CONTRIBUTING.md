# Contributing

Thank you for helping make authorization easier to understand and safer to
operate.

## Local setup

Use an isolated environment and install the project in editable mode before
running tests. This repository intentionally keeps the package at its root, so
plain `pytest` without an installation cannot import `authz_sdk` reliably.

```bash
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest
```

## Before opening a pull request

1. Read the public contract in `README.md` and the architecture guide.
2. Keep the core package framework-independent and dependency-light.
3. Add or update tests for every behavior change.
4. Run `python -m pytest`, `python -m build`, and `git diff --check`.
5. Update the documentation when a public name, policy template, or decision
   behavior changes.

## Design principles

- Prefer `subject -> operation -> resource` over endpoint-specific checks.
- Do not add a new relation when a trusted resource adapter can compute an
  existing relation.
- Keep entrypoints as metadata that map to business operations.
- Fail closed for unknown resources, operations, policies, and entrypoints.
- Make denied decisions explainable without exposing secrets or private data.
- Keep database, network, identity, and Agent framework integrations outside
  the core package.

## Pull requests

Describe the user-facing problem, the compatibility impact, and the security
implications. Security-sensitive changes need tests for both allowed and denied
paths, including resource ownership and missing-resource behavior.
