from abc import ABC, abstractmethod
from enum import Enum
from typing import TypedDict


class HealthStatus(Enum):
    """Standard health status values."""
    OK = "OK"
    ERROR = "ERROR"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"


class HealthCheckResult(TypedDict):
    """Standard health check result structure."""
    status: HealthStatus  # Required field with predefined values


class SupportsHealthcheck(ABC):
    #: Capability flag advertised in ``DriverMeta.capabilities`` when a
    #: driver (or decorator) in the stack satisfies this contract.
    CAPABILITY = "healthcheck"

    @abstractmethod
    def healthcheck(self) -> HealthCheckResult:
        """Perform a health check on the driver.

        Returns
        -------
        HealthCheckResult
            Health status information with required 'status' field.
        """
