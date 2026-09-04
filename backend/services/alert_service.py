from datetime import datetime, timezone

from backend.core.logger import get_logger
from backend.database.connection import get_connection
from backend.detection_engine.rule import DetectionRule


logger = get_logger(__name__)


def create_alert(
    event_id: int,
    rule: DetectionRule,
) -> int:
    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO alerts (
                event_id,
                rule_name,
                severity,
                status,
                description,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                rule.name,
                rule.severity,
                "open",
                rule.description,
                created_at,
            ),
        )

        connection.commit()

        alert_id = cursor.lastrowid

        logger.info(
            "Alert created with ID %s "
            "for event %s",
            alert_id,
            event_id,
        )

        return alert_id

    finally:
        connection.close()
    