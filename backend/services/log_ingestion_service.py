from backend.core.logger import get_logger
from backend.log_ingestion.web_log_parser import (
    normalize_web_log,
)
from backend.services.event_service import save_event


logger = get_logger(__name__)


def ingest_web_log(log_line: str) -> int:
    event = normalize_web_log(log_line)

    event_id = save_event(event)

    logger.info(
        "Web log ingested successfully: %s",
        event_id,
    )

    return event_id