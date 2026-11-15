"""Baseline dimensions, observation windows, and maturity states."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class BaselineDimension(StrEnum):
    HOURLY_ACTIVITY = "hourly_activity"
    DAILY_ACTIVITY = "daily_activity"
    TRANSACTION_VALUE = "transaction_value"
    TRANSACTION_COUNT = "transaction_count"
    CUSTOMER_ACCESS = "customer_access"
    BENEFICIARY_CHANGES = "beneficiary_changes"
    LOGIN_FREQUENCY = "login_frequency"
    DEVICE_USAGE = "device_usage"
    BRANCH_ACTIVITY = "branch_activity"


class MaturityState(StrEnum):
    INSUFFICIENT = "insufficient"
    DEVELOPING = "developing"
    MATURE = "mature"


@dataclass(frozen=True)
class BaselineWindow:
    start: datetime
    end: datetime

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise ValueError("baseline window must have positive duration")
