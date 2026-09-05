from datetime import datetime, timezone

from backend.core.logger import get_logger
from backend.database.connection import get_connection


logger = get_logger(__name__)


VALID_INVESTIGATION_STATUSES = {
    "open",
    "investigating",
    "resolved",
    "closed",
}

VALID_INVESTIGATION_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

VALID_INVESTIGATION_DISPOSITIONS = {
    "false_positive",
    "benign",
    "confirmed_incident",
    "inconclusive",
}

ALLOWED_INVESTIGATION_STATUS_TRANSITIONS = {
    "open": {"investigating"},
    "investigating": {"resolved"},
    "resolved": {"closed"},
    "closed": set(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_investigation_with_connection(
    connection,
    investigation_id: int,
):
    investigation = connection.execute(
        """
        SELECT
            id,
            title,
            status,
            severity,
            assigned_to,
            summary,
            findings,
            disposition,
            created_at,
            updated_at,
            closed_at
        FROM investigations
        WHERE id = ?
        """,
        (investigation_id,),
    ).fetchone()

    if investigation is None:
        raise ValueError(
            f"Investigation {investigation_id} does not exist"
        )

    return investigation


def _get_alert_with_connection(
    connection,
    alert_id: int,
):
    alert = connection.execute(
        """
        SELECT id
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,),
    ).fetchone()

    if alert is None:
        raise ValueError(
            f"Alert {alert_id} does not exist"
        )

    return alert


def _record_investigation_history(
    connection,
    investigation_id: int,
    action: str,
    old_value: str | None = None,
    new_value: str | None = None,
    note: str | None = None,
    analyst: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO investigation_history (
            investigation_id,
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
            investigation_id,
            action,
            old_value,
            new_value,
            note,
            analyst,
            utc_now(),
        ),
    )


def create_investigation(
    title: str,
    severity: str,
    alert_ids: list[int],
    summary: str | None = None,
    assigned_to: str | None = None,
) -> int:
    if not title or not title.strip():
        raise ValueError(
            "Investigation title cannot be empty"
        )

    normalized_severity = severity.strip().upper()

    if normalized_severity not in VALID_INVESTIGATION_SEVERITIES:
        raise ValueError(
            f"Invalid investigation severity: {severity}"
        )

    if not alert_ids:
        raise ValueError(
            "An investigation must contain at least one alert"
        )

    unique_alert_ids = list(dict.fromkeys(alert_ids))

    if assigned_to is not None:
        assigned_to = assigned_to.strip()

        if not assigned_to:
            raise ValueError(
                "Assigned analyst cannot be empty"
            )

    now = utc_now()

    connection = get_connection()

    try:
        for alert_id in unique_alert_ids:
            _get_alert_with_connection(
                connection,
                alert_id,
            )

        cursor = connection.execute(
            """
            INSERT INTO investigations (
                title,
                status,
                severity,
                assigned_to,
                summary,
                findings,
                disposition,
                created_at,
                updated_at,
                closed_at
            )
            VALUES (?, 'open', ?, ?, ?, NULL, NULL, ?, ?, NULL)
            """,
            (
                title.strip(),
                normalized_severity,
                assigned_to,
                summary,
                now,
                now,
            ),
        )

        investigation_id = cursor.lastrowid

        for alert_id in unique_alert_ids:
            connection.execute(
                """
                INSERT INTO investigation_alerts (
                    investigation_id,
                    alert_id,
                    linked_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    investigation_id,
                    alert_id,
                    now,
                ),
            )

        _record_investigation_history(
            connection,
            investigation_id,
            action="created",
            new_value="open",
            analyst=assigned_to,
        )

        connection.commit()

        logger.info(
            "Investigation created with ID %s",
            investigation_id,
        )

        return investigation_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_investigation(
    investigation_id: int,
) -> dict:
    connection = get_connection()

    try:
        investigation = _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        return dict(investigation)

    finally:
        connection.close()


def list_investigations(
    status: str | None = None,
) -> list[dict]:
    connection = get_connection()

    try:
        if status is None:
            rows = connection.execute(
                """
                SELECT
                    id,
                    title,
                    status,
                    severity,
                    assigned_to,
                    summary,
                    findings,
                    disposition,
                    created_at,
                    updated_at,
                    closed_at
                FROM investigations
                ORDER BY id DESC
                """
            ).fetchall()

        else:
            normalized_status = status.strip().lower()

            if normalized_status not in VALID_INVESTIGATION_STATUSES:
                raise ValueError(
                    f"Invalid investigation status: {status}"
                )

            rows = connection.execute(
                """
                SELECT
                    id,
                    title,
                    status,
                    severity,
                    assigned_to,
                    summary,
                    findings,
                    disposition,
                    created_at,
                    updated_at,
                    closed_at
                FROM investigations
                WHERE status = ?
                ORDER BY id DESC
                """,
                (normalized_status,),
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


def get_investigation_alerts(
    investigation_id: int,
) -> list[dict]:
    connection = get_connection()

    try:
        _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        rows = connection.execute(
            """
            SELECT
                a.id,
                a.event_id,
                a.rule_name,
                a.severity,
                a.status,
                a.description,
                a.created_at,
                a.assigned_to,
                a.updated_at,
                ia.linked_at
            FROM investigation_alerts ia
            JOIN alerts a
                ON a.id = ia.alert_id
            WHERE ia.investigation_id = ?
            ORDER BY ia.linked_at ASC, a.id ASC
            """,
            (investigation_id,),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


def link_alert_to_investigation(
    investigation_id: int,
    alert_id: int,
    analyst: str | None = None,
) -> None:
    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    connection = get_connection()

    try:
        investigation = _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        _get_alert_with_connection(
            connection,
            alert_id,
        )

        if investigation["status"] == "closed":
            raise ValueError(
                "Cannot link alerts to a closed investigation"
            )

        existing_link = connection.execute(
            """
            SELECT 1
            FROM investigation_alerts
            WHERE investigation_id = ?
              AND alert_id = ?
            """,
            (
                investigation_id,
                alert_id,
            ),
        ).fetchone()

        if existing_link is not None:
            raise ValueError(
                f"Alert {alert_id} is already linked "
                f"to investigation {investigation_id}"
            )

        now = utc_now()

        connection.execute(
            """
            INSERT INTO investigation_alerts (
                investigation_id,
                alert_id,
                linked_at
            )
            VALUES (?, ?, ?)
            """,
            (
                investigation_id,
                alert_id,
                now,
            ),
        )

        connection.execute(
            """
            UPDATE investigations
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now,
                investigation_id,
            ),
        )

        _record_investigation_history(
            connection,
            investigation_id,
            action="alert_linked",
            new_value=str(alert_id),
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Alert %s linked to investigation %s",
            alert_id,
            investigation_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def assign_investigation(
    investigation_id: int,
    assigned_to: str,
    analyst: str | None = None,
) -> None:
    assigned_to = assigned_to.strip()

    if not assigned_to:
        raise ValueError(
            "Assigned analyst cannot be empty"
        )

    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    connection = get_connection()

    try:
        investigation = _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        if investigation["status"] == "closed":
            raise ValueError(
                "Cannot reassign a closed investigation"
            )

        old_value = investigation["assigned_to"]

        now = utc_now()

        connection.execute(
            """
            UPDATE investigations
            SET
                assigned_to = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                assigned_to,
                now,
                investigation_id,
            ),
        )

        _record_investigation_history(
            connection,
            investigation_id,
            action="assigned",
            old_value=old_value,
            new_value=assigned_to,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Investigation %s assigned to %s",
            investigation_id,
            assigned_to,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def update_investigation_findings(
    investigation_id: int,
    findings: str,
    analyst: str | None = None,
) -> None:
    findings = findings.strip()

    if not findings:
        raise ValueError(
            "Investigation findings cannot be empty"
        )

    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    connection = get_connection()

    try:
        investigation = _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        if investigation["status"] == "closed":
            raise ValueError(
                "Cannot update findings on a closed investigation"
            )

        old_value = investigation["findings"]

        now = utc_now()

        connection.execute(
            """
            UPDATE investigations
            SET
                findings = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                findings,
                now,
                investigation_id,
            ),
        )

        _record_investigation_history(
            connection,
            investigation_id,
            action="findings_updated",
            old_value=old_value,
            new_value=findings,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Investigation %s findings updated",
            investigation_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def set_investigation_disposition(
    investigation_id: int,
    disposition: str,
    analyst: str | None = None,
) -> None:
    normalized_disposition = disposition.strip().lower()

    if normalized_disposition not in VALID_INVESTIGATION_DISPOSITIONS:
        raise ValueError(
            f"Invalid investigation disposition: {disposition}"
        )

    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    connection = get_connection()

    try:
        investigation = _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        if investigation["status"] == "closed":
            raise ValueError(
                "Cannot change disposition on a closed investigation"
            )

        old_value = investigation["disposition"]

        now = utc_now()

        connection.execute(
            """
            UPDATE investigations
            SET
                disposition = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                normalized_disposition,
                now,
                investigation_id,
            ),
        )

        _record_investigation_history(
            connection,
            investigation_id,
            action="disposition_updated",
            old_value=old_value,
            new_value=normalized_disposition,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Investigation %s disposition set to %s",
            investigation_id,
            normalized_disposition,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def update_investigation_status(
    investigation_id: int,
    new_status: str,
    analyst: str | None = None,
    note: str | None = None,
) -> None:
    normalized_status = new_status.strip().lower()

    if normalized_status not in VALID_INVESTIGATION_STATUSES:
        raise ValueError(
            f"Invalid investigation status: {new_status}"
        )

    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    if note is not None:
        note = note.strip()

        if not note:
            raise ValueError(
                "Status note cannot be empty"
            )

    connection = get_connection()

    try:
        investigation = _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        current_status = investigation["status"]

        if normalized_status == current_status:
            raise ValueError(
                f"Investigation is already {current_status}"
            )

        allowed_transitions = (
            ALLOWED_INVESTIGATION_STATUS_TRANSITIONS[
                current_status
            ]
        )

        if normalized_status not in allowed_transitions:
            raise ValueError(
                f"Invalid investigation status transition: "
                f"{current_status} -> {normalized_status}"
            )

        if (
            normalized_status == "resolved"
            and investigation["disposition"] is None
        ):
            raise ValueError(
                "Investigation disposition must be set "
                "before resolution"
            )

        now = utc_now()

        closed_at = (
            now
            if normalized_status == "closed"
            else investigation["closed_at"]
        )

        connection.execute(
            """
            UPDATE investigations
            SET
                status = ?,
                updated_at = ?,
                closed_at = ?
            WHERE id = ?
            """,
            (
                normalized_status,
                now,
                closed_at,
                investigation_id,
            ),
        )

        _record_investigation_history(
            connection,
            investigation_id,
            action="status_updated",
            old_value=current_status,
            new_value=normalized_status,
            note=note,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Investigation %s status updated "
            "from %s to %s",
            investigation_id,
            current_status,
            normalized_status,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def add_investigation_note(
    investigation_id: int,
    note: str,
    analyst: str | None = None,
) -> None:
    note = note.strip()

    if not note:
        raise ValueError(
            "Investigation note cannot be empty"
        )

    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    connection = get_connection()

    try:
        investigation = _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        if investigation["status"] == "closed":
            raise ValueError(
                "Cannot add notes to a closed investigation"
            )

        now = utc_now()

        connection.execute(
            """
            UPDATE investigations
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now,
                investigation_id,
            ),
        )

        _record_investigation_history(
            connection,
            investigation_id,
            action="note_added",
            note=note,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Investigation note added to investigation %s",
            investigation_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_investigation_history(
    investigation_id: int,
) -> list[dict]:
    connection = get_connection()

    try:
        _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        rows = connection.execute(
            """
            SELECT
                id,
                investigation_id,
                action,
                old_value,
                new_value,
                note,
                analyst,
                created_at
            FROM investigation_history
            WHERE investigation_id = ?
            ORDER BY id ASC
            """,
            (investigation_id,),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()
