from datetime import datetime, timezone
import sqlite3

from backend.core.logger import get_logger
from backend.database.connection import get_connection


logger = get_logger(__name__)


VALID_INCIDENT_STATUSES = {
    "open",
    "closed",
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


def _get_incident_with_connection(
    connection,
    incident_id: int,
):
    incident = connection.execute(
        """
        SELECT
            id,
            title,
            severity,
            status,
            description,
            created_at,
            closed_at,
            investigation_id,
            assigned_to,
            updated_at
        FROM incidents
        WHERE id = ?
        """,
        (incident_id,),
    ).fetchone()

    if incident is None:
        raise ValueError(
            f"Incident {incident_id} does not exist"
        )

    return incident


def _get_incident_for_investigation_with_connection(
    connection,
    investigation_id: int,
):
    return connection.execute(
        """
        SELECT
            id,
            title,
            severity,
            status,
            description,
            created_at,
            closed_at,
            investigation_id,
            assigned_to,
            updated_at
        FROM incidents
        WHERE investigation_id = ?
        """,
        (investigation_id,),
    ).fetchone()


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


def create_incident_from_investigation(
    investigation_id: int,
    analyst: str | None = None,
) -> int:
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

        if investigation["status"] != "resolved":
            raise ValueError(
                "Only resolved investigations can create incidents"
            )

        if investigation["disposition"] != "confirmed_incident":
            raise ValueError(
                "Investigation disposition must be confirmed_incident "
                "before incident creation"
            )

        existing_incident = (
            _get_incident_for_investigation_with_connection(
                connection,
                investigation_id,
            )
        )

        if existing_incident is not None:
            raise ValueError(
                f"Investigation {investigation_id} already has "
                f"incident {existing_incident['id']}"
            )

        now = utc_now()

        description_parts = []

        if investigation["summary"]:
            description_parts.append(
                investigation["summary"]
            )

        if investigation["findings"]:
            description_parts.append(
                investigation["findings"]
            )

        description = (
            "\n\n".join(description_parts)
            if description_parts
            else None
        )

        try:
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    title,
                    severity,
                    status,
                    description,
                    created_at,
                    closed_at,
                    investigation_id,
                    assigned_to,
                    updated_at
                )
                VALUES (?, ?, 'open', ?, ?, NULL, ?, ?, ?)
                """,
                (
                    investigation["title"],
                    investigation["severity"],
                    description,
                    now,
                    investigation_id,
                    investigation["assigned_to"],
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Investigation {investigation_id} already has an incident"
            ) from exc

        incident_id = cursor.lastrowid

        _record_investigation_history(
            connection,
            investigation_id,
            action="incident_created",
            new_value=str(incident_id),
            note="Investigation escalated to incident",
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Incident %s created from investigation %s",
            incident_id,
            investigation_id,
        )

        return incident_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_incident(
    incident_id: int,
) -> dict:
    connection = get_connection()

    try:
        incident = _get_incident_with_connection(
            connection,
            incident_id,
        )

        return dict(incident)

    finally:
        connection.close()


def get_incident_for_investigation(
    investigation_id: int,
) -> dict | None:
    connection = get_connection()

    try:
        _get_investigation_with_connection(
            connection,
            investigation_id,
        )

        incident = (
            _get_incident_for_investigation_with_connection(
                connection,
                investigation_id,
            )
        )

        if incident is None:
            return None

        return dict(incident)

    finally:
        connection.close()


def list_incidents(
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
                    severity,
                    status,
                    description,
                    created_at,
                    closed_at,
                    investigation_id,
                    assigned_to,
                    updated_at
                FROM incidents
                ORDER BY id DESC
                """
            ).fetchall()

        else:
            normalized_status = status.strip().lower()

            if normalized_status not in VALID_INCIDENT_STATUSES:
                raise ValueError(
                    f"Invalid incident status: {status}"
                )

            rows = connection.execute(
                """
                SELECT
                    id,
                    title,
                    severity,
                    status,
                    description,
                    created_at,
                    closed_at,
                    investigation_id,
                    assigned_to,
                    updated_at
                FROM incidents
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
