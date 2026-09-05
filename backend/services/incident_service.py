from datetime import datetime, timezone
import sqlite3

from backend.core.logger import get_logger
from backend.database.connection import get_connection


logger = get_logger(__name__)


VALID_INCIDENT_STATUSES = {
    "open",
    "contained",
    "eradicated",
    "recovered",
    "closed",
}


ALLOWED_INCIDENT_STATUS_TRANSITIONS = {
    "open": {"contained"},
    "contained": {"eradicated"},
    "eradicated": {"recovered"},
    "recovered": {"closed"},
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
            updated_at,
            resolution
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
            updated_at,
            resolution
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


def _record_incident_history(
    connection,
    incident_id: int,
    action: str,
    old_value: str | None = None,
    new_value: str | None = None,
    note: str | None = None,
    analyst: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO incident_history (
            incident_id,
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
            incident_id,
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

        if (
            investigation["disposition"]
            != "confirmed_incident"
        ):
            raise ValueError(
                "Investigation disposition must be "
                "confirmed_incident before incident creation"
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
                    updated_at,
                    resolution
                )
                VALUES (
                    ?,
                    ?,
                    'open',
                    ?,
                    ?,
                    NULL,
                    ?,
                    ?,
                    ?,
                    NULL
                )
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
                f"Investigation {investigation_id} "
                "already has an incident"
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

        _record_incident_history(
            connection,
            incident_id,
            action="created",
            new_value="open",
            note=(
                f"Incident created from investigation "
                f"{investigation_id}"
            ),
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
                    updated_at,
                    resolution
                FROM incidents
                ORDER BY id DESC
                """
            ).fetchall()

        else:
            normalized_status = status.strip().lower()

            if (
                normalized_status
                not in VALID_INCIDENT_STATUSES
            ):
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
                    updated_at,
                    resolution
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


def assign_incident(
    incident_id: int,
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
        incident = _get_incident_with_connection(
            connection,
            incident_id,
        )

        if incident["status"] == "closed":
            raise ValueError(
                "Closed incidents cannot be reassigned"
            )

        old_value = incident["assigned_to"]
        now = utc_now()

        connection.execute(
            """
            UPDATE incidents
            SET
                assigned_to = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                assigned_to,
                now,
                incident_id,
            ),
        )

        _record_incident_history(
            connection,
            incident_id,
            action="assigned",
            old_value=old_value,
            new_value=assigned_to,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Incident %s assigned to %s",
            incident_id,
            assigned_to,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def add_incident_note(
    incident_id: int,
    note: str,
    analyst: str | None = None,
) -> None:
    note = note.strip()

    if not note:
        raise ValueError(
            "Incident note cannot be empty"
        )

    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    connection = get_connection()

    try:
        incident = _get_incident_with_connection(
            connection,
            incident_id,
        )

        if incident["status"] == "closed":
            raise ValueError(
                "Closed incidents cannot receive notes"
            )

        now = utc_now()

        connection.execute(
            """
            UPDATE incidents
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                now,
                incident_id,
            ),
        )

        _record_incident_history(
            connection,
            incident_id,
            action="note_added",
            note=note,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Incident note added to incident %s",
            incident_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def set_incident_resolution(
    incident_id: int,
    resolution: str,
    analyst: str | None = None,
) -> None:
    resolution = resolution.strip()

    if not resolution:
        raise ValueError(
            "Incident resolution cannot be empty"
        )

    if analyst is not None:
        analyst = analyst.strip()

        if not analyst:
            raise ValueError(
                "Analyst cannot be empty"
            )

    connection = get_connection()

    try:
        incident = _get_incident_with_connection(
            connection,
            incident_id,
        )

        if incident["status"] == "closed":
            raise ValueError(
                "Closed incidents cannot change resolution"
            )

        old_value = incident["resolution"]
        now = utc_now()

        connection.execute(
            """
            UPDATE incidents
            SET
                resolution = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                resolution,
                now,
                incident_id,
            ),
        )

        _record_incident_history(
            connection,
            incident_id,
            action="resolution_updated",
            old_value=old_value,
            new_value=resolution,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Resolution updated for incident %s",
            incident_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def update_incident_status(
    incident_id: int,
    new_status: str,
    analyst: str | None = None,
    note: str | None = None,
) -> None:
    normalized_status = new_status.strip().lower()

    if normalized_status not in VALID_INCIDENT_STATUSES:
        raise ValueError(
            f"Invalid incident status: {new_status}"
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
        incident = _get_incident_with_connection(
            connection,
            incident_id,
        )

        current_status = incident["status"]

        if normalized_status == current_status:
            raise ValueError(
                f"Incident is already {current_status}"
            )

        allowed_transitions = (
            ALLOWED_INCIDENT_STATUS_TRANSITIONS.get(
                current_status,
                set(),
            )
        )

        if normalized_status not in allowed_transitions:
            raise ValueError(
                f"Invalid incident status transition: "
                f"{current_status} -> {normalized_status}"
            )

        if (
            normalized_status == "closed"
            and not incident["resolution"]
        ):
            raise ValueError(
                "Incident resolution is required "
                "before closure"
            )

        now = utc_now()

        closed_at = (
            now
            if normalized_status == "closed"
            else incident["closed_at"]
        )

        connection.execute(
            """
            UPDATE incidents
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
                incident_id,
            ),
        )

        _record_incident_history(
            connection,
            incident_id,
            action="status_changed",
            old_value=current_status,
            new_value=normalized_status,
            note=note,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Incident %s status updated from %s to %s",
            incident_id,
            current_status,
            normalized_status,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_incident_history(
    incident_id: int,
) -> list[dict]:
    connection = get_connection()

    try:
        _get_incident_with_connection(
            connection,
            incident_id,
        )

        rows = connection.execute(
            """
            SELECT
                id,
                incident_id,
                action,
                old_value,
                new_value,
                note,
                analyst,
                created_at
            FROM incident_history
            WHERE incident_id = ?
            ORDER BY id ASC
            """,
            (incident_id,),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()