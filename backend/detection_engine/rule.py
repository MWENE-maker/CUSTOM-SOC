from dataclasses import dataclass
from typing import Callable

from backend.models.event import SecurityEvent


@dataclass
class DetectionRule:
    name: str
    description: str
    severity: str
    condition: Callable[[SecurityEvent], bool]

    def matches(
        self,
        event: SecurityEvent,
    ) -> bool:
        return self.condition(event)