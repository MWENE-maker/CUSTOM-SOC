from dataclasses import asdict, dataclass
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

    # Structured network / HTTP fields
    source_ip: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    response_size: Optional[int] = None

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
        source_ip: Optional[str] = None,
        http_method: Optional[str] = None,
        http_path: Optional[str] = None,
        http_status: Optional[int] = None,
        response_size: Optional[int] = None,
    ) -> "SecurityEvent":
        return cls(
            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),
            source=source,
            event_type=event_type,
            severity=severity.upper(),
            message=message,
            raw_data=raw_data,
            source_ip=source_ip,
            http_method=http_method,
            http_path=http_path,
            http_status=http_status,
            response_size=response_size,
        )