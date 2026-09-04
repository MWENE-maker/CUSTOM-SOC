from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class SecurityEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str
    message: str
    raw_data: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def create(
        cls,
        source: str,
        event_type: str,
        severity: str,
        message: str,
        raw_data: Optional[str] = None,
    ) -> "SecurityEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source=source,
            event_type=event_type,
            severity=severity.upper(),
            message=message,
            raw_data=raw_data,
        )