"""Behavioral profile aggregating baseline statistics across multiple dimensions."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .baselines import BaselineDimension, MaturityState
from .statistics import BaselineStatistics


@dataclass
class BehavioralProfile:
    installation_id: str
    subject_id: str
    subject_type: str

    observation_start: datetime
    observation_end: datetime

    dimensions: dict[
        BaselineDimension,
        BaselineStatistics,
    ] = field(default_factory=dict)

    sample_count: int = 0
    minimum_required_samples: int = 20

    @property
    def mature(self) -> bool:
        return self.sample_count >= self.minimum_required_samples

    @property
    def maturity_state(self) -> MaturityState:
        if self.sample_count < 10:
            return MaturityState.INSUFFICIENT
        if self.sample_count < self.minimum_required_samples:
            return MaturityState.DEVELOPING
        return MaturityState.MATURE

    def add_dimension(
        self,
        dimension: BaselineDimension,
        statistics: BaselineStatistics,
    ) -> None:
        self.dimensions[dimension] = statistics
