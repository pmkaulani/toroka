"""Exceptions for the Toroka Enterprise Bank Integration Layer."""
from __future__ import annotations


class IntegrationError(Exception):
    """Base exception for all integration gateway failures."""
    pass


class ConnectorAuthenticationError(IntegrationError):
    """Raised when authentication to the upstream bank system fails."""
    pass


class ConnectorNetworkError(IntegrationError):
    """Raised on connection timeout or unreachability of bank interfaces."""
    pass


class ConnectorRateLimitError(IntegrationError):
    """Raised when the bank endpoint throttles the connector."""
    pass


class ReplayError(IntegrationError):
    """Raised when an incoming event violates replay protection checks."""
    pass


class SchemaValidationError(IntegrationError):
    """Raised when a bank source payload cannot be mapped to canonical contract."""
    pass


class SSRFProtectionError(IntegrationError):
    """Raised when a connector configuration attempts to contact an unapproved target."""
    pass
