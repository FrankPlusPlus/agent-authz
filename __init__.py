"""Small, framework-independent authorization SDK.

The package intentionally exposes the business vocabulary first:
``subject -> operation -> resource``. Web, Agent, Tool, Pack, and RAG
integrations can bind their entrypoints to the same operation without making
application developers learn the policy engine internals.
"""

__version__ = "0.7.0b1"

from authz_sdk.catalog import (
    CRUD_ACTIONS,
    ActionDefinition,
    Catalog,
    EntrypointDefinition,
    OperationDefinition,
    ResourceDefinition,
)
from authz_sdk.coverage import CoverageError, CoverageIssue, CoverageManifest, CoverageReport
from authz_sdk.adapters import RelationResolver, ResourceLoader, ResourceRegistry
from authz_sdk.audit import AuditRedactor, AuditSink, AuditWriteError, DecisionEvent, InMemoryAuditSink, JsonlAuditSink
from authz_sdk.engine import Authz, AuthorizationError, PolicySet, SUPPORTED_TEMPLATES
from authz_sdk.bundle import (
    POLICY_BUNDLE_SCHEMA_VERSION,
    POLICY_BUNDLE_SIGNATURE_ALGORITHM,
    BundleValidationIssue,
    PolicyBundle,
    PolicyBundleStore,
    PolicyBundleValidationError,
)
from authz_sdk.data import (
    AuthorizedCandidateFilter,
    CandidateFilter,
    CandidateFilterRecord,
    CandidateFilterResult,
    CandidateFilterSummary,
)
from authz_sdk.evaluator import BackendUnavailableError, Evaluator
from authz_sdk.models import (
    AUTHZ_CONTRACT_VERSION,
    AuthorizationRequest,
    Decision,
    Resource,
    Subject,
)
from authz_sdk.permit import ExecutionPermit
from authz_sdk.permit_store import (
    InMemoryPermitStore,
    PermitStore,
    PermitStoreCleanupResult,
    PermitStoreResult,
    PermitStoreStatus,
)
from authz_sdk.runtime import AGENT_PHASES, AgentRequest, AgentRuntime
from authz_sdk.backends import (
    AuthzenEvaluator,
    CasbinEvaluator,
    CerbosEvaluator,
    JsonPdpEvaluator,
    OpaEvaluator,
    OpenFgaEvaluator,
    OperationMap,
    OperationMapper,
    PdpRequestProjection,
    SpiceDbEvaluator,
)
from authz_sdk.integrations import AgnoAuthz, CallInput, FastAPIAuthz, LangGraphAuthz, MCPAuthz, protect_tool

__all__ = [
    "ActionDefinition",
    "AUTHZ_CONTRACT_VERSION",
    "AuditRedactor",
    "AuditSink",
    "AuditWriteError",
    "BundleValidationIssue",
    "Authz",
    "AuthorizationRequest",
    "AuthorizationError",
    "AuthorizedCandidateFilter",
    "CRUD_ACTIONS",
    "Catalog",
    "CoverageError",
    "CoverageIssue",
    "CoverageManifest",
    "CoverageReport",
    "CandidateFilter",
    "CandidateFilterRecord",
    "CandidateFilterResult",
    "CandidateFilterSummary",
    "Decision",
    "DecisionEvent",
    "ExecutionPermit",
    "InMemoryPermitStore",
    "InMemoryAuditSink",
    "JsonlAuditSink",
    "Evaluator",
    "BackendUnavailableError",
    "AuthzenEvaluator",
    "CasbinEvaluator",
    "CerbosEvaluator",
    "JsonPdpEvaluator",
    "OpaEvaluator",
    "OpenFgaEvaluator",
    "OperationMap",
    "OperationMapper",
    "PdpRequestProjection",
    "SpiceDbEvaluator",
    "EntrypointDefinition",
    "OperationDefinition",
    "PolicySet",
    "PolicyBundle",
    "PolicyBundleStore",
    "PolicyBundleValidationError",
    "POLICY_BUNDLE_SCHEMA_VERSION",
    "POLICY_BUNDLE_SIGNATURE_ALGORITHM",
    "PermitStore",
    "PermitStoreCleanupResult",
    "PermitStoreResult",
    "PermitStoreStatus",
    "Resource",
    "ResourceDefinition",
    "ResourceLoader",
    "ResourceRegistry",
    "RelationResolver",
    "Subject",
    "SUPPORTED_TEMPLATES",
    "AGENT_PHASES",
    "AgentRequest",
    "AgentRuntime",
    "AgnoAuthz",
    "CallInput",
    "FastAPIAuthz",
    "LangGraphAuthz",
    "MCPAuthz",
    "protect_tool",
    "__version__",
]
