"""Regression checks for public release helpers kept in the source tree."""

from __future__ import annotations

import hashlib
import io
import runpy
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest


def _write_sdist(artifact: Path, *, name: str, version: str) -> bytes:
    metadata = (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
        "License-Expression: Apache-2.0\n\n"
    ).encode("utf-8")
    root = f"{name.replace('-', '_')}-{version}"
    with tarfile.open(artifact, "w:gz") as distribution:
        info = tarfile.TarInfo(f"{root}/PKG-INFO")
        info.size = len(metadata)
        distribution.addfile(info, io.BytesIO(metadata))
    return artifact.read_bytes()

def test_sbom_identifies_the_exact_artifact_without_claiming_a_pypi_purl(tmp_path: Path) -> None:
    helper = Path(__file__).parents[1] / "scripts" / "generate_sbom.py"
    namespace = runpy.run_path(str(helper))
    artifact = tmp_path / "example_sdk-1.2.3.tar.gz"
    artifact_bytes = _write_sdist(artifact, name="example-sdk", version="1.2.3")

    document = namespace["build_sbom"](artifact)

    package = document["packages"][0]
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["name"] == "example_sdk-1.2.3-sbom"
    assert package["checksums"] == [
        {
            "algorithm": "SHA256",
            "checksumValue": hashlib.sha256(artifact_bytes).hexdigest(),
        }
    ]
    assert "externalRefs" not in package


def test_sbom_rejects_an_artifact_that_does_not_match_the_expected_project_identity(tmp_path: Path) -> None:
    helper = Path(__file__).parents[1] / "scripts" / "generate_sbom.py"
    namespace = runpy.run_path(str(helper))
    artifact = tmp_path / "example_sdk-1.2.3.tar.gz"
    _write_sdist(artifact, name="example-sdk", version="1.2.3")

    with pytest.raises(ValueError, match="does not match pyproject"):
        namespace["build_sbom"](
            artifact,
            expected_identity=("agent-authz-sdk", "0.7.0b1"),
        )


def test_distribution_verifier_rejects_credential_shaped_wheel_content(tmp_path: Path) -> None:
    helper = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
    namespace = runpy.run_path(str(helper))
    artifact = tmp_path / "agent_authz_sdk-0.7.0b1-py3-none-any.whl"

    with ZipFile(artifact, "w", compression=ZIP_DEFLATED) as wheel:
        wheel.writestr("authz_sdk/__init__.py", "-----BEGIN PRIVATE KEY-----")

    errors = namespace["_verify_wheel"](artifact, "agent-authz-sdk", "0.7.0b1")

    assert any("credential-shaped" in error for error in errors)


def test_distribution_verifier_rejects_path_traversal_in_source_archive(tmp_path: Path) -> None:
    helper = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
    namespace = runpy.run_path(str(helper))
    artifact = tmp_path / "agent_authz_sdk-0.7.0b1.tar.gz"

    with tarfile.open(artifact, "w:gz") as distribution:
        content = b"unexpected"
        member = tarfile.TarInfo("agent_authz_sdk-0.7.0b1/../../escaped.py")
        member.size = len(content)
        distribution.addfile(member, io.BytesIO(content))

    errors = namespace["_verify_sdist"](artifact, "agent-authz-sdk", "0.7.0b1")

    assert any("unsafe member path" in error for error in errors)


def test_distribution_verifier_rejects_wheel_record_hash_or_size_tampering(
    tmp_path: Path,
) -> None:
    helper = Path(__file__).parents[1] / "scripts" / "verify_distribution.py"
    namespace = runpy.run_path(str(helper))
    artifact = tmp_path / "agent_authz_sdk-0.7.0b1-py3-none-any.whl"
    package = b"__version__ = '0.7.0b1'\n"
    metadata = b"Metadata-Version: 2.4\nName: agent-authz-sdk\nVersion: 0.7.0b1\n\n"
    wheel = b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = "\n".join(
        (
            "authz_sdk/__init__.py,sha256=invalid,999",
            "agent_authz_sdk-0.7.0b1.dist-info/METADATA,,",
            "agent_authz_sdk-0.7.0b1.dist-info/WHEEL,,",
            "agent_authz_sdk-0.7.0b1.dist-info/top_level.txt,,",
            "agent_authz_sdk-0.7.0b1.dist-info/RECORD,,",
        )
    )
    with ZipFile(artifact, "w", compression=ZIP_DEFLATED) as distribution:
        distribution.writestr("authz_sdk/__init__.py", package)
        distribution.writestr("agent_authz_sdk-0.7.0b1.dist-info/METADATA", metadata)
        distribution.writestr("agent_authz_sdk-0.7.0b1.dist-info/WHEEL", wheel)
        distribution.writestr("agent_authz_sdk-0.7.0b1.dist-info/top_level.txt", "authz_sdk\n")
        distribution.writestr("agent_authz_sdk-0.7.0b1.dist-info/RECORD", record)

    errors = namespace["_verify_wheel"](artifact, "agent-authz-sdk", "0.7.0b1")

    assert any("RECORD hash mismatch: authz_sdk/__init__.py" in error for error in errors)
    assert any("RECORD size mismatch: authz_sdk/__init__.py" in error for error in errors)


def test_release_workflow_uses_hash_locked_read_only_build_and_separate_publish() -> None:
    root = Path(__file__).parents[1]
    workflow = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    lockfile = (root / "requirements" / "release.txt").read_text(encoding="utf-8")
    verify_job = workflow.split("  verify:\n", 1)[1].split("  attest-and-release:\n", 1)[0]
    publish_job = workflow.split("  attest-and-release:\n", 1)[1]

    assert "--hash=sha256:" in lockfile
    assert "python -m pip install --require-hashes -r requirements/release.txt" in verify_job
    assert "contents: write" not in verify_job
    assert "id-token: write" not in verify_job
    assert "attestations: write" not in verify_job
    assert "environment:" not in verify_job
    assert "environment:" in publish_job
    assert "contents: write" in publish_job
    assert "id-token: write" in publish_job
    assert "attestations: write" in publish_job
    assert "pip install" not in publish_job
    assert "python -m build" not in publish_job
    assert "fetch-depth: 0" in verify_job
    assert "git merge-base --is-ancestor \"$GITHUB_SHA\" \"origin/main\"" in verify_job
    assert "rm -rf dist" in verify_job
    assert 'test "$(find dist -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d \' \')" = "2"' in verify_job
    assert 'test "$(find . -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d \' \')" = "6"' in publish_job


def test_ci_verifies_the_linux_release_lock_before_a_tag_is_created() -> None:
    root = Path(__file__).parents[1]
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "release-lock:" in workflow
    assert 'name: Release lock (3.13)' in workflow
    assert "python -m pip install --require-hashes -r requirements/release.txt" in workflow
    assert "python -m pip install --no-deps --no-build-isolation ." in workflow
