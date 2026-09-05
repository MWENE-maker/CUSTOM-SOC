# backend/services/response_action_service.py

from datetime import datetime, timezone

from backend.core.logger import get_logger
from backend.database.connection import get_connection


logger = get_logger(__name__)


VALID_RESPONSE_ACTION_TYPES = {
    "block_ip",
    "isolate_host",
    "disable_account",
    "terminate_session",
    "collect_evidence",
    "reset_credentials",
}


VALID_RESPONSE_ACTION_STATUSES = {
    "proposed",
    "approved",
    "executed",
    "failed",
    "cancelled",
}


ALLOWED_RESPONSE_ACTION_TRANSITIONS = {
    "proposed": {
        "approved",
        "cancelled",
    },
    "approved": {
        "executed",
        "failed",
        "cancelled",
    },
    "executed": set(),
    "failed": set(),
    "cancelled": set(),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_incident_with_connection(
    connection,
    incident_id: int,
):
    incident = connection.execute(
        """
        SELECT
            id,
            status,
            assigned_to
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


def _get_response_action_with_connection(
    connection,
    action_id: int,
):
    action = connection.execute(
        """
        SELECT
            id,
            incident_id,
            action_type,
            target,
            status,
            requested_by,
            approved_by,
            created_at,
            approved_at,
            executed_at,
            updated_at,
            notes,
            result
        FROM response_actions
        WHERE id = ?
        """,
        (action_id,),
    ).fetchone()

    if action is None:
        raise ValueError(
            f"Response action {action_id} does not exist"
        )

    return action


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


def propose_response_action(
    incident_id: int,
    action_type: str,
    target: str | None,
    requested_by: str,
    notes: str | None = None,
) -> int:
    normalized_type = action_type.strip().lower()

    if normalized_type not in VALID_RESPONSE_ACTION_TYPES:
        raise ValueError(
            f"Invalid response action type: {action_type}"
        )

    requested_by = requested_by.strip()

    if not requested_by:
        raise ValueError(
            "Requested by cannot be empty"
        )

    if target is not None:
        target = target.strip()

        if not target:
            raise ValueError(
                "Target cannot be empty"
            )

    if notes is not None:
        notes = notes.strip()

        if not notes:
            raise ValueError(
                "Notes cannot be empty"
            )

    connection = get_connection()

    try:
        incident = _get_incident_with_connection(
            connection,
            incident_id,
        )

        if incident["status"] == "closed":
            raise ValueError(
                "Closed incidents cannot receive "
                "new response actions"
            )

        now = utc_now()

        cursor = connection.execute(
            """
            INSERT INTO response_actions (
                incident_id,
                action_type,
                target,
                status,
                requested_by,
                approved_by,
                created_at,
                approved_at,
                executed_at,
                updated_at,
                notes,
                result
            )
            VALUES (
                ?,
                ?,
                ?,
                'proposed',
                ?,
                NULL,
                ?,
                NULL,
                NULL,
                ?,
                ?,
                NULL
            )
            """,
            (
                incident_id,
                normalized_type,
                target,
                requested_by,
                now,
                now,
                notes,
            ),
        )

        action_id = cursor.lastrowid

        _record_incident_history(
            connection,
            incident_id,
            action="response_action_proposed",
            new_value=str(action_id),
            note=(
                f"{normalized_type}"
                + (
                    f" target={target}"
                    if target
                    else ""
                )
            ),
            analyst=requested_by,
        )

        connection.commit()

        logger.info(
            "Response action %s proposed for incident %s",
            action_id,
            incident_id,
        )

        return action_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_response_action(
    action_id: int,
) -> dict:
    connection = get_connection()

    try:
        action = _get_response_action_with_connection(
            connection,
            action_id,
        )

        return dict(action)

    finally:
        connection.close()


def list_response_actions(
    incident_id: int | None = None,
    status: str | None = None,
) -> list[dict]:
    connection = get_connection()

    try:
        clauses = []
        values = []

        if incident_id is not None:
            _get_incident_with_connection(
                connection,
                incident_id,
            )

            clauses.append(
                "incident_id = ?"
            )
            values.append(
                incident_id
            )

        if status is not None:
            normalized_status = status.strip().lower()

            if (
                normalized_status
                not in VALID_RESPONSE_ACTION_STATUSES
            ):
                raise ValueError(
                    f"Invalid response action status: "
                    f"{status}"
                )

            clauses.append(
                "status = ?"
            )
            values.append(
                normalized_status
            )

        where_clause = ""

        if clauses:
            where_clause = (
                "WHERE "
                + " AND ".join(clauses)
            )

        rows = connection.execute(
            f"""
            SELECT
                id,
                incident_id,
                action_type,
                target,
                status,
                requested_by,
                approved_by,
                created_at,
                approved_at,
                executed_at,
                updated_at,
                notes,
                result
            FROM response_actions
            {where_clause}
            ORDER BY id DESC
            """,
            tuple(values),
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        connection.close()


def approve_response_action(
    action_id: int,
    approved_by: str,
) -> None:
    approved_by = approved_by.strip()

    if not approved_by:
        raise ValueError(
            "Approved by cannot be empty"
        )

    connection = get_connection()

    try:
        action = _get_response_action_with_connection(
            connection,
            action_id,
        )

        incident = _get_incident_with_connection(
            connection,
            action["incident_id"],
        )

        if incident["status"] == "closed":
            raise ValueError(
                "Closed incidents cannot approve "
                "response actions"
            )

        current_status = action["status"]

        if "approved" not in (
            ALLOWED_RESPONSE_ACTION_TRANSITIONS[
                current_status
            ]
        ):
            raise ValueError(
                f"Invalid response action transition: "
                f"{current_status} -> approved"
            )

        now = utc_now()

        connection.execute(
            """
            UPDATE response_actions
            SET
                status = 'approved',
                approved_by = ?,
                approved_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                approved_by,
                now,
                now,
                action_id,
            ),
        )

        _record_incident_history(
            connection,
            action["incident_id"],
            action="response_action_approved",
            old_value=current_status,
            new_value="approved",
            note=f"Response action {action_id}",
            analyst=approved_by,
        )

        connection.commit()

        logger.info(
            "Response action %s approved",
            action_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def execute_response_action(
    action_id: int,
    analyst: str,
) -> None:
    analyst = analyst.strip()

    if not analyst:
        raise ValueError(
            "Analyst cannot be empty"
        )

    connection = get_connection()

    try:
        action = _get_response_action_with_connection(
            connection,
            action_id,
        )

        incident = _get_incident_with_connection(
            connection,
            action["incident_id"],
        )

        if incident["status"] == "closed":
            raise ValueError(
                "Closed incidents cannot execute "
                "response actions"
            )

        current_status = action["status"]

        if "executed" not in (
            ALLOWED_RESPONSE_ACTION_TRANSITIONS[
                current_status
            ]
        ):
            raise ValueError(
                f"Invalid response action transition: "
                f"{current_status} -> executed"
            )

        now = utc_now()

        result = (
            "SIMULATED EXECUTION ONLY: "
            f"{action['action_type']}"
            + (
                f" against {action['target']}"
                if action["target"]
                else ""
            )
            + ". No real system, account, host, "
            "network device, or endpoint was changed."
        )

        connection.execute(
            """
            UPDATE response_actions
            SET
                status = 'executed',
                executed_at = ?,
                updated_at = ?,
                result = ?
            WHERE id = ?
            """,
            (
                now,
                now,
                result,
                action_id,
            ),
        )

        _record_incident_history(
            connection,
            action["incident_id"],
            action="response_action_executed",
            old_value=current_status,
            new_value="executed",
            note=result,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Response action %s simulated successfully",
            action_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def fail_response_action(
    action_id: int,
    result: str,
    analyst: str,
) -> None:
    result = result.strip()

    if not result:
        raise ValueError(
            "Failure result cannot be empty"
        )

    analyst = analyst.strip()

    if not analyst:
        raise ValueError(
            "Analyst cannot be empty"
        )

    connection = get_connection()

    try:
        action = _get_response_action_with_connection(
            connection,
            action_id,
        )

        current_status = action["status"]

        if "failed" not in (
            ALLOWED_RESPONSE_ACTION_TRANSITIONS[
                current_status
            ]
        ):
            raise ValueError(
                f"Invalid response action transition: "
                f"{current_status} -> failed"
            )

        now = utc_now()

        connection.execute(
            """
            UPDATE response_actions
            SET
                status = 'failed',
                executed_at = ?,
                updated_at = ?,
                result = ?
            WHERE id = ?
            """,
            (
                now,
                now,
                result,
                action_id,
            ),
        )

        _record_incident_history(
            connection,
            action["incident_id"],
            action="response_action_failed",
            old_value=current_status,
            new_value="failed",
            note=result,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Response action %s marked failed",
            action_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def cancel_response_action(
    action_id: int,
    analyst: str,
    reason: str | None = None,
) -> None:
    analyst = analyst.strip()

    if not analyst:
        raise ValueError(
            "Analyst cannot be empty"
        )

    if reason is not None:
        reason = reason.strip()

        if not reason:
            raise ValueError(
                "Cancellation reason cannot be empty"
            )

    connection = get_connection()

    try:
        action = _get_response_action_with_connection(
            connection,
            action_id,
        )

        current_status = action["status"]

        if "cancelled" not in (
            ALLOWED_RESPONSE_ACTION_TRANSITIONS[
                current_status
            ]
        ):
            raise ValueError(
                f"Invalid response action transition: "
                f"{current_status} -> cancelled"
            )

        now = utc_now()

        connection.execute(
            """
            UPDATE response_actions
            SET
                status = 'cancelled',
                updated_at = ?,
                result = ?
            WHERE id = ?
            """,
            (
                now,
                reason,
                action_id,
            ),
        )

        _record_incident_history(
            connection,
            action["incident_id"],
            action="response_action_cancelled",
            old_value=current_status,
            new_value="cancelled",
            note=reason,
            analyst=analyst,
        )

        connection.commit()

        logger.info(
            "Response action %s cancelled",
            action_id,
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()