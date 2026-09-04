from backend.core.logger import get_logger
from backend.database.connection import get_connection
from backend.models.event import SecurityEvent


logger = get_logger(__name__)


def save_event(event: SecurityEvent) -> int:
    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO events (
                timestamp,
                source,
                event_type,
                severity,
                message,
                raw_data
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.source,
                event.event_type,
                event.severity,
                event.message,
                event.raw_data,
            ),
        )

        connection.commit()

        event_id = cursor.lastrowid

        logger.info(
            "Security event stored with ID %s",
            event_id,
        )

        return event_id

    finally:
        connection.close()
        