"""Toroka Enterprise Bank Integration Gateway."""
from .base import BankConnector, ConnectorBatch, ConnectorContext
from .contracts import (
    CanonicalAccountRecord,
    CanonicalCustomerChangeRecord,
    CanonicalEmploymentEventRecord,
    CanonicalPaymentEventRecord,
    CanonicalRecord,
    CanonicalSecurityEventRecord,
    CanonicalStaffAccessRecord,
    CanonicalTransactionRecord,
    Provenance,
    RecordType,
    SourceSystem,
)
from .exceptions import (
    ConnectorAuthenticationError,
    ConnectorNetworkError,
    ConnectorRateLimitError,
    IntegrationError,
    ReplayError,
    SSRFProtectionError,
    SchemaValidationError,
)
from .ingestion import IngestionResult, canonical_digest, ingest_batch
from .models import (
    IntegrationCursor,
    IntegrationEventInbox,
    IntegrationJobRecord,
    IntegrationRecord,
    IntegrationRejectedRecord,
)
from .quality import QualityIssue, QualityReport, assess_canonical_batch
from .registry import ConnectorRegistry, DEFAULT_CONNECTOR_REGISTRY

__all__ = [
    "BankConnector",
    "ConnectorContext",
    "ConnectorBatch",
    "SourceSystem",
    "RecordType",
    "Provenance",
    "CanonicalRecord",
    "CanonicalTransactionRecord",
    "CanonicalAccountRecord",
    "CanonicalStaffAccessRecord",
    "CanonicalCustomerChangeRecord",
    "CanonicalPaymentEventRecord",
    "CanonicalSecurityEventRecord",
    "CanonicalEmploymentEventRecord",
    "IntegrationError",
    "ConnectorAuthenticationError",
    "ConnectorNetworkError",
    "ConnectorRateLimitError",
    "ReplayError",
    "SchemaValidationError",
    "SSRFProtectionError",
    "IngestionResult",
    "canonical_digest",
    "ingest_batch",
    "IntegrationRecord",
    "IntegrationCursor",
    "IntegrationJobRecord",
    "IntegrationEventInbox",
    "IntegrationRejectedRecord",
    "QualityIssue",
    "QualityReport",
    "assess_canonical_batch",
    "ConnectorRegistry",
    "DEFAULT_CONNECTOR_REGISTRY",
]
