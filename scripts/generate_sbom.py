"""Generate an SPDX 2.3 SBOM for one built Agent Authz distribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import tomllib
from datetime import datetime, timezone
from email import message_from_bytes
from pathlib import Path
from typing import Any
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity_from_message(content: bytes, source: str) -> dict[str, str]:
    message = message_from_bytes(content)
    name = str(message.get("Name") or "").strip()
    version = str(message.get("Version") or "").strip()
    license_expression = str(
        message.get("License-Expression") or message.get("License") or "NOASSERTION"
    ).strip() or "NOASSERTION"
    if not name or not version:
        raise ValueError(f"{source} is missing package Name or Version")
    return {"name": name, "version": version, "license": license_expression}


def artifact_identity(artifact: Path) -> dict[str, str]:
    """Read package identity from the artifact, never from an adjacent tree."""

    source = artifact.resolve()
    if source.suffix == ".whl":
        with ZipFile(source) as wheel:
            metadata = [
                name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata) != 1:
                raise ValueError("wheel must contain exactly one METADATA file")
            return _identity_from_message(wheel.read(metadata[0]), metadata[0])
    if source.name.endswith(".tar.gz"):
        with tarfile.open(source, "r:gz") as distribution:
            metadata = [
                member for member in distribution.getmembers()
                if member.isfile() and member.name.endswith("/PKG-INFO")
                and ".egg-info/" not in member.name
            ]
            if len(metadata) != 1:
                raise ValueError("source distribution must contain exactly one root PKG-INFO")
            stream = distribution.extractfile(metadata[0])
            if stream is None:
                raise ValueError("source distribution package metadata is unreadable")
            return _identity_from_message(stream.read(), metadata[0].name)
    raise ValueError(f"unsupported distribution artifact: {source.name}")


def _project_identity() -> tuple[str, str]:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream).get("project") or {}
    name = str(project.get("name") or "").strip()
    version = str(project.get("version") or "").strip()
    if not name or not version:
        raise ValueError("pyproject [project] name and version are required")
    return name, version


def build_sbom(
    artifact: Path,
    *,
    expected_identity: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Return a standards-shaped SPDX document for a single release artifact."""

    source = artifact.resolve()
    if not source.is_file():
        raise FileNotFoundError(f"artifact does not exist: {source}")
    metadata = artifact_identity(source)
    if expected_identity is not None and (
        metadata["name"],
        metadata["version"],
    ) != expected_identity:
        raise ValueError("artifact package identity does not match pyproject")
    digest = _sha256(source)
    artifact_label = (
        source.name.removesuffix(".tar.gz")
        if source.name.endswith(".tar.gz")
        else source.stem
    )
    created = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    package_id = "SPDXRef-Package-agent-authz-sdk"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{artifact_label}-sbom",
        "documentNamespace": (
            "https://spdx.org/spdxdocs/"
            f"{metadata['name']}-{metadata['version']}-{digest}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Tool: agent-authz-sdk/scripts/generate_sbom.py"],
        },
        "packages": [
            {
                "SPDXID": package_id,
                "name": metadata["name"],
                "versionInfo": metadata["version"],
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": metadata["license"],
                "licenseDeclared": metadata["license"],
                "copyrightText": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
            }
        ],
        "relationships": [],
        "annotations": [
            {
                "annotationType": "OTHER",
                "annotator": "Tool: agent-authz-sdk/scripts/generate_sbom.py",
                "annotationDate": created,
                "comment": (
                    "This SBOM describes the built distribution and its direct runtime "
                    "metadata. The project has no mandatory runtime dependencies."
                ),
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="wheel or sdist to describe")
    parser.add_argument("--output", required=True, type=Path, help="SPDX JSON destination")
    args = parser.parse_args(argv)
    document = build_sbom(args.artifact, expected_identity=_project_identity())
    destination = args.output.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote SPDX SBOM: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
