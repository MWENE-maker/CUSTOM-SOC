from datetime import datetime, timezone

from backend.core.logger import get_logger
from backend.database.connection import get_connection

logger = get_logger(__name__)


VALID_ALERT_STATUSES = {
    "open",
    "acknowledged",
    "investigating",
    "resolved",
    "closed",
}


ALLOWED_STATUS_TRANSITIONS = {
    "open": {
        "acknowledged",
    },
    "acknowledged": {
        "investigating",
    },
    "investigating": {
        "resolved",
    },
    "resolved": {
        "closed",
    },
    "closed": set(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_alert_with_connection(connection, alert_id: int):
    return connection.execute(
        """
        SELECT *
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,),
    ).fetchone()


def _record_alert_history(
    connection,
    alert_id: int,
    action: str,
    created_at: str,
    old_value: str | None = None,
    new_value: str | None = None,
    note: str | None = None,
    analyst: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO alert_history (
            alert_id,
            action,
            old_value,
            new_value,
            note,
            analyst,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            action,
            old_value,
            new_value,
            note,
            analyst,
            created_at,
        ),
    )


def create_alert(
    event_id: int,
    rule,
) -> int:
    connection = get_connection()
    timestamp = utc_now()

    try:
        cursor = connection.execute(
            """
            INSERT INTO alerts (
                event_id,
                rule_name,
                severity,
                status,
                description,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                rule.name,
                rule.severity,
                "open",
                rule.description,
                timestamp,
                timestamp,
            ),
        )

        alert_id = cursor.lastrowid

        _record_alert_history(
            connection=connection,
            alert_id=alert_id,
            action="created",
            new_value="open",
            created_at=timestamp,
        )

        connection.commit()

        logger.info(
            "Alert created with ID %s for event %s",
            alert_id,
            event_id,
        )

        return alert_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

def get_alert(alert_id: int):
    connection = get_connection()

    try:
        row = _get_alert_with_connection(connection, alert_id)

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


def list_alerts(status: str | None = None):
    connection = get_connection()

    try:
        if status is None:
            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY id ASC
                """
            ).fetchall()

        else:
            normalized_status = status.strip().lower()

            if normalized_status not in VALID_ALERT_STATUSES:
                raise ValueError(
                    f"Invalid alert status: {status}"
                )

            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                WHERE status = ?
                ORDER BY id ASC
                """,
                (normalized_status,),
            ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def alert_exists(alert_id: int) -> bool:
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT 1
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()

        return row is not None

    finally:
        connection.close()


def update_alert_status(
    alert_id: int,
    new_status: str,
    analyst: str | None = None,
) -> None:
    normalized_status = new_status.strip().lower()

    if normalized_status not in VALID_ALERT_STATUSES:
        raise ValueError(
            f"Invalid alert status: {new_status}"
        )

    connection = get_connection()

    try:
        alert = _get_alert_with_connection(
            connection,
            alert_id,
        )

        if alert is None:
            raise ValueError(
                f"Alert {alert_id} does not exist"
            )

        current_status = alert["status"]

        if normalized_status == current_status:
            raise ValueError(
                f"Alert {alert_id} is already in status "
                f"'{current_status}'"
            )

        allowed_transitions = ALLOWED_STATUS_TRANSITIONS.get(
            current_status,
            set(),
        )

        if normalized_status not in allowed_transitions:
            raise ValueError(
                f"Invalid alert status transition: "
                f"{current_status} -> {normalized_status}"
            )

        timestamp = utc_now()

        connection.execute(
            """
            UPDATE alerts
            SET status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                normalized_status,
                timestamp,
                alert_id,
            ),
        )

        _record_alert_history(
            connection=connection,
            alert_id=alert_id,
            action="status_changed",
            old_value=current_status,
            new_value=normalized_status,
            analyst=analyst,
            created_at=timestamp,
        )

        connection.commit()

        logger.info(
            "Alert %s status updated from %s to %s",
            alert_id,
            current_status,
            normalized_status,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def assign_alert(
    alert_id: int,
    analyst: str,
) -> None:
    normalized_analyst = analyst.strip()

    if not normalized_analyst:
        raise ValueError(
            "Analyst assignment cannot be empty"
        )

    connection = get_connection()

    try:
        alert = _get_alert_with_connection(
            connection,
            alert_id,
        )

        if alert is None:
            raise ValueError(
                f"Alert {alert_id} does not exist"
            )

        previous_assignment = alert["assigned_to"]
        timestamp = utc_now()

        connection.execute(
            """
            UPDATE alerts
            SET assigned_to = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                normalized_analyst,
                timestamp,
                alert_id,
            ),
        )

        _record_alert_history(
            connection=connection,
            alert_id=alert_id,
            action="assigned",
            old_value=previous_assignment,
            new_value=normalized_analyst,
            analyst=normalized_analyst,
            created_at=timestamp,
        )

        connection.commit()

        logger.info(
            "Alert %s assigned to %s",
            alert_id,
            normalized_analyst,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def add_alert_note(
    alert_id: int,
    note: str,
    analyst: str | None = None,
) -> None:
    normalized_note = note.strip()

    if not normalized_note:
        raise ValueError(
            "Analyst note cannot be empty"
        )

    connection = get_connection()

    try:
        alert = _get_alert_with_connection(
            connection,
            alert_id,
        )

        if alert is None:
            raise ValueError(
                f"Alert {alert_id} does not exist"
            )

        existing_notes = alert["analyst_notes"]

        if existing_notes:
            updated_notes = (
                f"{existing_notes}\n{normalized_note}"
            )
        else:
            updated_notes = normalized_note

        timestamp = utc_now()

        connection.execute(
            """
            UPDATE alerts
            SET analyst_notes = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                updated_notes,
                timestamp,
                alert_id,
            ),
        )

        _record_alert_history(
            connection=connection,
            alert_id=alert_id,
            action="note_added",
            note=normalized_note,
            analyst=analyst,
            created_at=timestamp,
        )

        connection.commit()

        logger.info(
            "Analyst note added to alert %s",
            alert_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_alert_history(alert_id: int):
    connection = get_connection()

    try:
        alert = _get_alert_with_connection(
            connection,
            alert_id,
        )

        if alert is None:
            raise ValueError(
                f"Alert {alert_id} does not exist"
            )

        rows = connection.execute(
            """
            SELECT *
            FROM alert_history
            WHERE alert_id = ?
            ORDER BY id ASC
            """,
            (alert_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()