# Security Policy

## Supported versions

Security fixes are prioritized for the latest `0.7.x` release while the public
API is stabilizing. Older minor versions are not maintained once a newer
release is available.

## Reporting a vulnerability

Do not open a public issue for an undisclosed vulnerability. Before the first
public release, maintainers must enable **GitHub Private Vulnerability
Reporting** for the standalone repository. Once enabled, use the repository's
**Security** tab and **Report a vulnerability** flow, including:

- affected version and deployment shape;
- a minimal reproduction or proof of concept;
- the impact and required privileges;
- any suggested mitigation.

Please do not include production credentials, personal data, prompts, Tool
arguments, or retrieved document contents in a report.

Until that private reporting channel exists, this source tree is not ready for
public security-sensitive release. Do not substitute a public issue for a
private report.

## Integration responsibilities

The SDK cannot secure an application if the host trusts relation facts from a
request body, skips the final check before a side effect, or treats an unknown
Tool as allowed. Integrators must authenticate the subject, load resources from
trusted data stores, enforce tenant boundaries, and route every relevant Agent
surface through the enforcement point.

For the production profile, also:

- use a shared, atomic `PermitStore` rather than the in-memory implementation
  for multiple workers or hosts;
- load bundle HMAC keys from a secret manager; HMAC is not signer identity or
  a replacement for a review/approval workflow;
- apply `CandidateFilter` before prompt assembly and add query pushdown in the
  data adapter where possible;
- configure a durable monitored `AuditSink` when the local JSONL sink is not
  sufficient for the application's retention or compliance requirements;
- use `AuditRedactor` with a secret-manager key if subject/resource/entrypoint/request IDs
  can contain personal or sensitive business data; the fixed audit schema does
  not automatically classify or redact application IDs;
- keep the final resource-version check inside the side-effect transaction.
- for a remote PDP, use the production evaluator profile: HTTPS with the SDK's
  standard verified TLS transport, an explicit field projection, pinned policy
  version/digest, a stable opaque `Subject.id` (never an email fallback), and
  a response envelope bound to the request/catalog.
- only use an exact reviewed SDK evaluator type at the final production
  boundary. A custom `Evaluator` (including a subclass) is intentionally
  denied even if it reports a production-looking mode or readiness result;
  put custom protocol code behind a reviewed gateway or contribute an audited
  adapter.
- raw custom remote PDP encoders and decoders are development-only and are
  always rejected by the production profile, including if legacy code sets
  `projection_enforced=True`. Use a reviewed built-in adapter or keep the
  custom gateway outside the final production authority path.
- treat a production remote-PDP evaluator as immutable after construction. The
  SDK detects public configuration drift and denies before transport, but code
  that can alter private process memory is already inside the trusted host
  boundary.
- `Authz.production(...)` retains an internal production marker. Changing the
  public `profile` display field or a backend's public `enforcement_mode`
  attribute cannot downgrade the production checks.
- production invokes reviewed evaluator methods from their exact registered
  class and rejects public per-instance method shadowing. It also checks the
  supported adapter configuration that could redirect a request or remap an
  operation after construction.
- production also binds the Catalog, PolicySet, ResourceRegistry, evaluator,
  and audit collaborators selected at construction. Replace the facade when a
  boundary collaborator changes; the SDK fails closed rather than accepting an
  in-place swap.
- for a multi-tenant MCP server, have the `MCPAuthz` subject provider read a
  request-local principal only after the server/host has verified it; never
  derive identity from Tool arguments. Production MCP registration requires a
  catalog binding by default so Tool surfaces remain reviewable.
