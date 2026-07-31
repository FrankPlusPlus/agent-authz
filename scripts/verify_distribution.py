"""Verify that release archives contain only the reviewed public SDK."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import re
import stat
import sys
import tarfile
import tomllib
from collections import Counter
from email import message_from_bytes
from pathlib import Path, PurePosixPath
from zipfile import ZipFile


PACKAGE_DIRECTORY = "authz_sdk"
ROOT = Path(__file__).resolve().parents[1]
PUBLIC_ROOT_FILES = frozenset(
    {
        ".gitignore",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "MANIFEST.in",
        "PKG-INFO",
        "README.md",
        "ROADMAP.md",
        "SECURITY.md",
        "SUPPLY_CHAIN.md",
        "__init__.py",
        "adapters.py",
        "audit.py",
        "backends.py",
        "bundle.py",
        "catalog.py",
        "conditions.py",
        "coverage.py",
        "data.py",
        "engine.py",
        "evaluator.py",
        "models.py",
        "permit.py",
        "permit_store.py",
        "py.typed",
        "pyproject.toml",
        "runtime.py",
    }
)
PUBLIC_DOCS = frozenset(
    {
        "docs/agent-runtime.md",
        "docs/architecture.md",
        "docs/backends.md",
        "docs/comparison.md",
        "docs/coverage.md",
        "docs/frameworks.md",
        "docs/mcp.md",
        "docs/migration.md",
        "docs/production.md",
        "docs/quickstart.md",
        "docs/threat-model.md",
        "docs/zh-CN/README.md",
    }
)
PUBLIC_EXAMPLES = frozenset(
    {
        "examples/agent_entrypoints.py",
        "examples/basic.py",
        "examples/fastapi_document_agent.py",
        "examples/secure_document_agent.py",
    }
)
GENERATED_SDIST_ROOT_FILES = frozenset({"setup.cfg"})
REQUIRED_WHEEL_MEMBERS = frozenset(
    {
        "authz_sdk/audit.py",
        "authz_sdk/bundle.py",
        "authz_sdk/coverage.py",
        "authz_sdk/data.py",
        "authz_sdk/integrations/fastapi.py",
        "authz_sdk/integrations/mcp.py",
        "authz_sdk/permit_store.py",
        "authz_sdk/py.typed",
    }
)
REQUIRED_SDIST_MEMBERS = frozenset(
    {
        "README.md",
        "ROADMAP.md",
        "SECURITY.md",
        "SUPPLY_CHAIN.md",
        "CONTRIBUTING.md",
        "docs/production.md",
        "docs/mcp.md",
        "examples/secure_document_agent.py",
        "examples/fastapi_document_agent.py",
    }
)
EGG_INFO_FILES = frozenset(
    {
        "PKG-INFO",
        "SOURCES.txt",
        "dependency_links.txt",
        "requires.txt",
        "top_level.txt",
    }
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def _project_identity() -> tuple[str, str]:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream).get("project") or {}
    name = str(project.get("name") or "").strip()
    version = str(project.get("version") or "").strip()
    if not name or not version:
        raise ValueError("pyproject [project] name and version are required")
    return name, version


def _distribution_stem(name: str) -> str:
    return re.sub(r"[-.]+", "_", name.strip().lower())


def _normal_member_name(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return bool(name) and not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _safe_text(content: bytes, member: str, errors: list[str]) -> None:
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{member}: unexpected non-text payload")
        return
    if any(pattern.search(decoded) for pattern in SECRET_PATTERNS):
        errors.append(f"{member}: contains a credential-shaped value")


def _metadata_identity(content: bytes, member: str, errors: list[str]) -> tuple[str, str]:
    message = message_from_bytes(content)
    name = str(message.get("Name") or "").strip()
    version = str(message.get("Version") or "").strip()
    if not name or not version:
        errors.append(f"{member}: package metadata is missing Name or Version")
    return name, version


def _wheel_allowed_member(member: str) -> bool:
    parts = PurePosixPath(member).parts
    if not parts:
        return False
    if parts[0] == PACKAGE_DIRECTORY:
        return (
            member == f"{PACKAGE_DIRECTORY}/py.typed"
            or (
                len(parts) == 2
                and parts[1].endswith(".py")
            )
            or (
                len(parts) == 3
                and parts[1] == "integrations"
                and parts[2].endswith(".py")
            )
        )
    if len(parts) >= 2 and parts[0].endswith(".dist-info"):
        return (
            len(parts) == 2
            and parts[1] in {"METADATA", "RECORD", "WHEEL", "top_level.txt"}
        ) or (
            len(parts) == 3
            and parts[1] == "licenses"
            and parts[2] == "LICENSE"
        )
    return False


def _sdist_allowed_member(relative: str) -> bool:
    if (
        relative in PUBLIC_ROOT_FILES
        or relative in GENERATED_SDIST_ROOT_FILES
        or relative in PUBLIC_DOCS
        or relative in PUBLIC_EXAMPLES
    ):
        return True
    parts = PurePosixPath(relative).parts
    return (
        len(parts) == 2
        and parts[0] == "integrations"
        and parts[1].endswith(".py")
    ) or (
        len(parts) == 2
        and parts[0].endswith(".egg-info")
        and parts[1] in EGG_INFO_FILES
    )


def _verify_wheel(archive: Path, expected_name: str, expected_version: str) -> list[str]:
    errors: list[str] = []
    try:
        with ZipFile(archive) as wheel:
            infos = [info for info in wheel.infolist() if not info.is_dir()]
            names = [info.filename for info in infos]
            duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
            if duplicates:
                errors.append(f"{archive.name}: duplicate members: {', '.join(duplicates)}")
            for info in infos:
                mode = info.external_attr >> 16
                if not _normal_member_name(info.filename):
                    errors.append(f"{archive.name}: unsafe member path: {info.filename}")
                    continue
                if stat.S_ISLNK(mode):
                    errors.append(f"{archive.name}: symbolic link member: {info.filename}")
                if not _wheel_allowed_member(info.filename):
                    errors.append(f"{archive.name}: unexpected member: {info.filename}")
                if info.filename.endswith((".pyc", ".pyo")) or "/__pycache__/" in info.filename:
                    errors.append(f"{archive.name}: bytecode member: {info.filename}")
                _safe_text(wheel.read(info), f"{archive.name}:{info.filename}", errors)

            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
            if len(metadata_names) != 1:
                errors.append(f"{archive.name}: expected exactly one METADATA file")
            else:
                name, version = _metadata_identity(wheel.read(metadata_names[0]), metadata_names[0], errors)
                if (name, version) != (expected_name, expected_version):
                    errors.append(f"{archive.name}: metadata identity does not match pyproject")
            if len(record_names) != 1:
                errors.append(f"{archive.name}: expected exactly one RECORD file")
            else:
                record_name = record_names[0]
                recorded: dict[str, tuple[str, str]] = {}
                for row in csv.reader(wheel.read(record_name).decode("utf-8").splitlines()):
                    if len(row) != 3 or not row[0]:
                        errors.append(f"{archive.name}: malformed RECORD row")
                        continue
                    if row[0] in recorded:
                        errors.append(f"{archive.name}: duplicate RECORD row: {row[0]}")
                        continue
                    recorded[row[0]] = (row[1], row[2])
                missing = sorted(set(names) - set(recorded))
                if missing:
                    errors.append(f"{archive.name}: RECORD misses members: {', '.join(missing)}")
                unexpected = sorted(set(recorded) - set(names))
                if unexpected:
                    errors.append(
                        f"{archive.name}: RECORD references missing members: {', '.join(unexpected)}"
                    )
                for info in infos:
                    record = recorded.get(info.filename)
                    if record is None:
                        continue
                    digest, size = record
                    if info.filename == record_name:
                        if digest or size:
                            errors.append(f"{archive.name}: RECORD must not hash itself")
                        continue
                    if not digest.startswith("sha256="):
                        errors.append(
                            f"{archive.name}: RECORD hash is missing or unsupported: {info.filename}"
                        )
                    else:
                        expected_hash = digest.removeprefix("sha256=")
                        actual_hash = base64.urlsafe_b64encode(
                            hashlib.sha256(wheel.read(info)).digest()
                        ).decode("ascii").rstrip("=")
                        if not hmac.compare_digest(expected_hash, actual_hash):
                            errors.append(f"{archive.name}: RECORD hash mismatch: {info.filename}")
                    if not size or not size.isdigit() or int(size) != info.file_size:
                        errors.append(f"{archive.name}: RECORD size mismatch: {info.filename}")
            missing_required = sorted(REQUIRED_WHEEL_MEMBERS - set(names))
            if missing_required:
                errors.append(
                    f"{archive.name}: missing required members: {', '.join(missing_required)}"
                )
    except Exception as exc:
        errors.append(f"{archive.name}: unreadable wheel: {type(exc).__name__}")
    return errors


def _verify_sdist(archive: Path, expected_name: str, expected_version: str) -> list[str]:
    errors: list[str] = []
    try:
        with tarfile.open(archive, "r:gz") as source:
            members = source.getmembers()
            files = [member for member in members if member.isfile()]
            names = [member.name for member in files]
            prefixes = {PurePosixPath(name).parts[0] for name in names if _normal_member_name(name)}
            expected_prefix = f"{_distribution_stem(expected_name)}-{expected_version}"
            if prefixes != {expected_prefix}:
                errors.append(f"{archive.name}: unexpected source root: {', '.join(sorted(prefixes))}")
            duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
            if duplicates:
                errors.append(f"{archive.name}: duplicate members: {', '.join(duplicates)}")
            for member in members:
                if member.isdir():
                    continue
                if not member.isfile():
                    errors.append(f"{archive.name}: unsupported archive member: {member.name}")
                    continue
                if not _normal_member_name(member.name):
                    errors.append(f"{archive.name}: unsafe member path: {member.name}")
                    continue
                parts = PurePosixPath(member.name).parts
                relative = "/".join(parts[1:])
                if not _sdist_allowed_member(relative):
                    errors.append(f"{archive.name}: unexpected member: {member.name}")
                if member.name.endswith((".pyc", ".pyo")) or "/__pycache__/" in member.name:
                    errors.append(f"{archive.name}: bytecode member: {member.name}")
                extracted = source.extractfile(member)
                if extracted is not None:
                    _safe_text(extracted.read(), f"{archive.name}:{member.name}", errors)

            metadata_names = [name for name in names if name.endswith("/PKG-INFO")]
            if len(metadata_names) != 2:
                errors.append(f"{archive.name}: expected root and egg-info PKG-INFO files")
            else:
                for metadata_name in metadata_names:
                    member = source.getmember(metadata_name)
                    extracted = source.extractfile(member)
                    if extracted is None:
                        errors.append(f"{archive.name}: unreadable package metadata")
                        continue
                    name, version = _metadata_identity(extracted.read(), metadata_name, errors)
                    if (name, version) != (expected_name, expected_version):
                        errors.append(f"{archive.name}: metadata identity does not match pyproject")
            relative_names = {"/".join(PurePosixPath(name).parts[1:]) for name in names}
            missing_required = sorted(REQUIRED_SDIST_MEMBERS - relative_names)
            if missing_required:
                errors.append(
                    f"{archive.name}: missing required members: {', '.join(missing_required)}"
                )
    except Exception as exc:
        errors.append(f"{archive.name}: unreadable source distribution: {type(exc).__name__}")
    return errors


def verify(directory: Path) -> list[str]:
    """Return release archive validation errors for one wheel and one sdist."""

    expected_name, expected_version = _project_identity()
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    extras = sorted(directory.glob("*"))
    archives = {*wheels, *sdists}
    errors: list[str] = []
    if len(wheels) != 1 or len(sdists) != 1 or any(path.is_file() and path.suffix in {".whl", ".gz"} and path not in archives for path in extras):
        errors.append("expected exactly one wheel and one source distribution")
        return errors

    wheel = wheels[0]
    sdist = sdists[0]
    expected_stem = _distribution_stem(expected_name)
    if not re.fullmatch(rf"{re.escape(expected_stem)}-{re.escape(expected_version)}-[^-]+-[^-]+-[^.]+[.]whl", wheel.name):
        errors.append(f"{wheel.name}: filename does not match project identity")
    if sdist.name != f"{expected_stem}-{expected_version}.tar.gz":
        errors.append(f"{sdist.name}: filename does not match project identity")
    errors.extend(_verify_wheel(wheel, expected_name, expected_version))
    errors.extend(_verify_sdist(sdist, expected_name, expected_version))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory containing release archives")
    args = parser.parse_args(argv)
    errors = verify(args.directory)
    if errors:
        print("distribution verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("distribution verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
