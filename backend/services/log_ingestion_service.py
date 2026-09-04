from backend.core.logger import get_logger
from backend.detection_engine.engine import (
    evaluate_event,
)
from backend.log_ingestion.web_log_parser import (
    normalize_web_log,
)
from backend.services.alert_service import (
    create_alert,
)
from backend.services.event_service import save_event


logger = get_logger(__name__)


def ingest_web_log(log_line: str) -> int:
    event = normalize_web_log(log_line)

    event_id = save_event(event)

    matched_rules = evaluate_event(event)

    for rule in matched_rules:
        alert_id = create_alert(
            event_id,
            rule,
        )

        logger.info(
            "Alert %s generated from event %s",
            alert_id,
            event_id,
        )

    logger.info(
        "Web log ingested successfully: %s",
        event_id,
    )

    return event_id