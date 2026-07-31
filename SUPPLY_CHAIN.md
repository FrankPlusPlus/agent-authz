# Supply-chain and release policy

Every public tag must reference a commit reachable from protected `main`, come
from a green commit, and match the package version exactly (`v0.7.0b2` for
package version `0.7.0b2`). The release workflow has two deliberately separated
jobs:

1. a read-only `verify` job installs `requirements/release.txt` with
   `--require-hashes`, then runs the test suite, builds wheel/sdist, validates
   archive contents, and checks package metadata;
2. that read-only job generates a separate SPDX 2.3 SBOM for the release wheel
   and source distribution;
3. a protected, write-capable `attest-and-release` job downloads the immutable
   verified artifact, rechecks its checksums, creates provenance/SBOM
   attestations, and attaches it to a GitHub Release.

The write-capable job does not run `pip`, build Python code, or install PyPI
packages. `requirements/release.in` documents its exact top-level inputs and
`requirements/release.txt` is the reviewed, hash-locked transitive closure.
The read-only job clears `dist/` and verifies the exact expected asset count at
each build/SBOM/checksum phase, so a pre-existing unreviewed sidecar cannot be
attached to a release.

Consumers should download the release wheel and its checksum together, then
verify both the bytes and GitHub's provenance:

```bash
gh release download v0.7.0b2 --repo FrankPlusPlus/agent-authz \
  --pattern 'agent_authz_sdk-0.7.0b2-py3-none-any.whl' --pattern WHEEL-SHA256SUMS
shasum -a 256 -c WHEEL-SHA256SUMS
gh attestation verify agent_authz_sdk-0.7.0b2-py3-none-any.whl \
  -R FrankPlusPlus/agent-authz
python -m pip install --no-deps agent_authz_sdk-0.7.0b2-py3-none-any.whl
```

No PyPI publishing occurs automatically. If maintainers later publish to
PyPI, they should use PyPI Trusted Publishing rather than a long-lived API
token and document the publisher identity in the release notes.

Until PyPI publishing is explicitly enabled, GitHub Releases are the
supported binary channel. A reviewed source-tag dependency is available for
source review and development, but Git tags are not content-addressed pins and
are not a substitute for verifying a release artifact:

```bash
python -m pip install "agent-authz-sdk @ git+https://github.com/FrankPlusPlus/agent-authz.git@v0.7.0b2"
```

The bundled SBOM describes the built SDK distribution and its direct runtime
metadata. It intentionally has no PyPI PURL while GitHub Releases are the only
published channel. It does not claim to be an inventory of a consumer
application, its optional extras, or the GitHub runner image.

## Required GitHub repository controls before a public tag

The workflow is only one part of a release boundary. Before the first public
tag, maintainers must configure the standalone repository with:

- GitHub Private Vulnerability Reporting and a monitored security contact.
- A `main` ruleset requiring pull requests, review, CI and CodeQL checks,
  with force-push and administrator bypass disabled.
- A `v*` tag ruleset that limits tag creation to release maintainers or a
  release bot.
- A protected `release` environment with manual approval; the release workflow
  deliberately targets that environment before receiving its write-capable
  token.
- Secret scanning, push protection, Dependabot alerts, and an Actions policy
  that permits only reviewed actions pinned to immutable commit SHAs.

The checked-in workflows pin their current action revisions to full commits and
Dependabot is configured to propose updates. A human must still review those
updates and verify them in the protected repository; a local build cannot
prove the hosted ruleset or GitHub environment configuration.
