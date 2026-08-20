"""Domain-specific exceptions for RansomWatch."""


class RansomWatchError(Exception):
    """Base class for expected application failures."""


class ConfigurationError(RansomWatchError):
    """Raised when command-line or filesystem configuration is unsafe."""


class CanaryError(RansomWatchError):
    """Raised when canary deployment or verification cannot continue safely."""


class MonitoringError(RansomWatchError):
    """Raised when the filesystem observer cannot run reliably."""


class ReportingError(RansomWatchError):
    """Raised when an alert cannot be delivered."""
