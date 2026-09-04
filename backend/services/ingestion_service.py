from backend.core.logger import get_logger
from backend.models.event import SecurityEvent
from backend.services.event_service import save_event


logger = get_logger(__name__)


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def ingest_event(
    source: str,
    event_type: str,
    severity: str,
    message: str,
    raw_data: str | None = None,
) -> int:
    normalized_severity = severity.upper()

    if normalized_severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity: {severity}"
        )

    event = SecurityEvent.create(
        source=source,
        event_type=event_type,
        severity=normalized_severity,
        message=message,
        raw_data=raw_data,
    )

    event_id = save_event(event)

    logger.info(
        "Event ingested successfully: %s",
        event_id,
    )

    return event_id