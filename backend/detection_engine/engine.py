from backend.core.logger import get_logger
from backend.detection_engine.rules import (
    DETECTION_RULES,
)
from backend.models.event import SecurityEvent


logger = get_logger(__name__)


def evaluate_event(
    event: SecurityEvent,
) -> list:
    matched_rules = []

    for rule in DETECTION_RULES:
        if rule.matches(event):
            matched_rules.append(rule)

            logger.info(
                "Detection rule matched: %s",
                rule.name,
            )

    return matched_rules