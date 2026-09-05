from backend.database.connection import get_connection


VALID_ALERT_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_INCIDENT_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

VALID_ALERT_STATUSES = {
    "open",
    "acknowledged",
    "investigating",
    "resolved",
    "closed",
}

VALID_INVESTIGATION_STATUSES = {
    "open",
    "investigating",
    "resolved",
    "closed",
}

VALID_INVESTIGATION_DISPOSITIONS = {
    "false_positive",
    "benign",
    "confirmed_incident",
    "inconclusive",
}

VALID_INCIDENT_STATUSES = {
    "open",
    "contained",
    "eradicated",
    "recovered",
    "closed",
}

VALID_RESPONSE_ACTION_STATUSES = {
    "proposed",
    "approved",
    "executed",
    "failed",
    "cancelled",
}

ACTIVE_ALERT_STATUSES = {
    "open",
    "acknowledged",
    "investigating",
}

ACTIVE_INVESTIGATION_STATUSES = {
    "open",
    "investigating",
}

ACTIVE_INCIDENT_STATUSES = {
    "open",
    "contained",
    "eradicated",
    "recovered",
}

PENDING_RESPONSE_ACTION_STATUSES = {
    "proposed",
    "approved",
}

def _count_rows(connection, table_name):
    """
    Count all rows in a trusted CUSTOM-SOC table.

    table_name is supplied only by this module, never by user input.
    """
    trusted_tables = {
        "events",
        "alerts",
        "investigations",
        "incidents",
        "response_actions",
    }

    if table_name not in trusted_tables:
        raise ValueError(f"Unsupported reporting table: {table_name}")

    row = connection.execute(
        f"SELECT COUNT(*) AS total FROM {table_name}"
    ).fetchone()

    return row["total"]


def _count_by_column(connection, table_name, column_name, allowed_values):
    """
    Return counts for every expected value, including zero-count values.

    Table and column identifiers are restricted to trusted internal
    allowlists. Runtime values remain parameterized.
    """
    trusted_columns = {
        ("alerts", "severity"),
        ("alerts", "status"),
        ("investigations", "status"),
        ("investigations", "disposition"),
        ("incidents", "severity"),
        ("incidents", "status"),
        ("response_actions", "status"),
    }

    if (table_name, column_name) not in trusted_columns:
        raise ValueError(
            f"Unsupported reporting field: {table_name}.{column_name}"
        )

    counts = {value: 0 for value in sorted(allowed_values)}

    rows = connection.execute(
        f"""
        SELECT {column_name}, COUNT(*) AS total
        FROM {table_name}
        GROUP BY {column_name}
        """
    ).fetchall()

    for row in rows:
        value = row[column_name]

        if value in counts:
            counts[value] = row["total"]

    return counts


def get_event_metrics():
    """
    Return aggregate security-event metrics.
    """
    connection = get_connection()

    try:
        return {
            "total": _count_rows(connection, "events"),
        }
    finally:
        connection.close()


def get_alert_metrics():
    """
    Return aggregate alert metrics.
    """
    connection = get_connection()

    try:
        return {
            "total": _count_rows(connection, "alerts"),
            "by_severity": _count_by_column(
                connection,
                "alerts",
                "severity",
                VALID_ALERT_SEVERITIES,
            ),
            "by_status": _count_by_column(
                connection,
                "alerts",
                "status",
                VALID_ALERT_STATUSES,
            ),
        }
    finally:
        connection.close()


def get_investigation_metrics():
    """
    Return aggregate investigation metrics.
    """
    connection = get_connection()

    try:
        return {
            "total": _count_rows(connection, "investigations"),
            "by_status": _count_by_column(
                connection,
                "investigations",
                "status",
                VALID_INVESTIGATION_STATUSES,
            ),
            "by_disposition": _count_by_column(
                connection,
                "investigations",
                "disposition",
                VALID_INVESTIGATION_DISPOSITIONS,
            ),
        }
    finally:
        connection.close()


def get_incident_metrics():
    """
    Return aggregate incident metrics.
    """
    connection = get_connection()

    try:
        return {
            "total": _count_rows(connection, "incidents"),
            "by_severity": _count_by_column(
                connection,
                "incidents",
                "severity",
                VALID_INCIDENT_SEVERITIES,
            ),
            "by_status": _count_by_column(
                connection,
                "incidents",
                "status",
                VALID_INCIDENT_STATUSES,
            ),
        }
    finally:
        connection.close()


def get_response_action_metrics():
    """
    Return aggregate response-action metrics.

    An "executed" response action means CUSTOM-SOC recorded a simulated
    execution. It does not prove that an external firewall, account,
    endpoint, host, or network device was actually changed.
    """
    connection = get_connection()

    try:
        return {
            "total": _count_rows(connection, "response_actions"),
            "by_status": _count_by_column(
                connection,
                "response_actions",
                "status",
                VALID_RESPONSE_ACTION_STATUSES,
            ),
        }
    finally:
        connection.close()

def get_workload_metrics():
    """
    Return current active SOC workload counts.

    These counts represent active records in each workflow layer.
    They must not be summed and interpreted as unique security cases,
    because one security case may be represented by records across
    multiple workflow layers.
    """
    connection = get_connection()

    try:
        alert_counts = _count_by_column(
            connection,
            "alerts",
            "status",
            VALID_ALERT_STATUSES,
        )

        investigation_counts = _count_by_column(
            connection,
            "investigations",
            "status",
            VALID_INVESTIGATION_STATUSES,
        )

        incident_counts = _count_by_column(
            connection,
            "incidents",
            "status",
            VALID_INCIDENT_STATUSES,
        )

        response_action_counts = _count_by_column(
            connection,
            "response_actions",
            "status",
            VALID_RESPONSE_ACTION_STATUSES,
        )

        return {
            "active_alerts": sum(
                alert_counts[status]
                for status in ACTIVE_ALERT_STATUSES
            ),
            "active_investigations": sum(
                investigation_counts[status]
                for status in ACTIVE_INVESTIGATION_STATUSES
            ),
            "active_incidents": sum(
                incident_counts[status]
                for status in ACTIVE_INCIDENT_STATUSES
            ),
            "pending_response_actions": sum(
                response_action_counts[status]
                for status in PENDING_RESPONSE_ACTION_STATUSES
            ),
        }

    finally:
        connection.close()

def get_soc_summary():
    """
    Return the complete high-level CUSTOM-SOC metrics summary.

    This service is intentionally read-only. It derives metrics from
    operational tables and does not modify SOC records.

    Workload metrics represent active records across workflow layers.
    They must not be summed and interpreted as unique security cases.
    """
    return {
        "events": get_event_metrics(),
        "alerts": get_alert_metrics(),
        "investigations": get_investigation_metrics(),
        "incidents": get_incident_metrics(),
        "response_actions": get_response_action_metrics(),
        "workload": get_workload_metrics(),
    }