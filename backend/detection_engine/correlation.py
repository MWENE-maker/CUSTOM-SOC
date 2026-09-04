from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from backend.core.logger import get_logger
from backend.database.connection import get_connection
from backend.models.event import SecurityEvent


logger = get_logger(__name__)


@dataclass
class CorrelationRule:
    name: str
    description: str
    severity: str
    threshold: int
    window_minutes: int


REPEATED_FAILED_LOGIN_RULE = CorrelationRule(
    name="WEB_REPEATED_FAILED_LOGIN",
    description=(
        "At least 5 failed login attempts were observed "
        "from the same source IP within 5 minutes."
    ),
    severity="HIGH",
    threshold=5,
    window_minutes=5,
)


def parse_event_timestamp(
    timestamp: str,
) -> datetime:
    """
    Convert an ISO event timestamp into a
    timezone-aware UTC datetime.
    """
    parsed = datetime.fromisoformat(
        timestamp
    )

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def is_failed_login(
    event: SecurityEvent,
) -> bool:
    """
    Determine whether an event represents a
    structured failed web login.
    """
    return (
        event.event_type == "HTTP_REQUEST"
        and event.source_ip is not None
        and event.http_method == "POST"
        and event.http_path == "/login"
        and event.http_status == 401
    )


def count_recent_failed_logins(
    event: SecurityEvent,
    window_start: datetime,
    reference_time: datetime,
) -> int:
    """
    Count failed login events from the same
    source IP inside the correlation window.
    """
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT timestamp
            FROM events
            WHERE source_ip = ?
              AND event_type = ?
              AND http_method = ?
              AND http_path = ?
              AND http_status = ?
            """,
            (
                event.source_ip,
                "HTTP_REQUEST",
                "POST",
                "/login",
                401,
            ),
        ).fetchall()

    finally:
        connection.close()

    count = 0

    for row in rows:
        timestamp = parse_event_timestamp(
            row["timestamp"]
        )

        if (
            window_start
            <= timestamp
            <= reference_time
        ):
            count += 1

    return count


def recent_correlation_alert_exists(
    source_ip: str,
    rule: CorrelationRule,
    window_start: datetime,
    reference_time: datetime,
) -> bool:
    """
    Prevent repeated correlation alerts from being
    created continuously inside the same time window.
    """
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT events.timestamp
            FROM alerts
            JOIN events
                ON alerts.event_id = events.id
            WHERE alerts.rule_name = ?
              AND events.source_ip = ?
            """,
            (
                rule.name,
                source_ip,
            ),
        ).fetchall()

    finally:
        connection.close()

    for row in rows:
        timestamp = parse_event_timestamp(
            row["timestamp"]
        )

        if (
            window_start
            <= timestamp
            <= reference_time
        ):
            return True

    return False


def evaluate_correlations(
    event: SecurityEvent,
) -> list[CorrelationRule]:
    """
    Evaluate stateful correlation rules against
    previously stored events.
    """
    if not is_failed_login(event):
        return []

    reference_time = parse_event_timestamp(
        event.timestamp
    )

    window_start = (
        reference_time
        - timedelta(
            minutes=(
                REPEATED_FAILED_LOGIN_RULE
                .window_minutes
            )
        )
    )

    failed_login_count = (
        count_recent_failed_logins(
            event,
            window_start,
            reference_time,
        )
    )

    logger.info(
        "Failed-login correlation count "
        "for %s: %s",
        event.source_ip,
        failed_login_count,
    )

    if (
        failed_login_count
        < REPEATED_FAILED_LOGIN_RULE.threshold
    ):
        return []

    alert_exists = (
        recent_correlation_alert_exists(
            event.source_ip,
            REPEATED_FAILED_LOGIN_RULE,
            window_start,
            reference_time,
        )
    )

    if alert_exists:
        logger.info(
            "Correlation alert already exists "
            "for source IP %s within the window",
            event.source_ip,
        )

        return []

    logger.info(
        "Correlation rule matched: %s",
        REPEATED_FAILED_LOGIN_RULE.name,
    )

    return [
        REPEATED_FAILED_LOGIN_RULE
    ]