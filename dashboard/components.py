"""
Reusable Streamlit presentation components for CUSTOM-SOC.

Security design:
- This module displays already-aggregated reporting data.
- It does not query SQLite directly.
- It does not create or modify SOC records.
- It does not contain detection, investigation, incident, or response logic.
"""

from collections.abc import Mapping

import streamlit as st


def render_page_header() -> None:
    """Render the main CUSTOM-SOC dashboard heading."""

    st.title("CUSTOM-SOC")
    st.subheader("SOC Operations Dashboard")

    st.caption(
        "Read-only operational view powered by trusted CUSTOM-SOC reporting metrics."
    )


def render_primary_metrics(summary: Mapping) -> None:
    """
    Render primary SOC record totals.

    Expected metric groups:
    - events
    - alerts
    - investigations
    - incidents
    - response_actions
    """

    events = summary.get("events", {})
    alerts = summary.get("alerts", {})
    investigations = summary.get("investigations", {})
    incidents = summary.get("incidents", {})
    response_actions = summary.get("response_actions", {})

    columns = st.columns(5)

    columns[0].metric(
        label="Security Events",
        value=events.get("total", 0),
    )

    columns[1].metric(
        label="Alerts",
        value=alerts.get("total", 0),
    )

    columns[2].metric(
        label="Investigations",
        value=investigations.get("total", 0),
    )

    columns[3].metric(
        label="Incidents",
        value=incidents.get("total", 0),
    )

    columns[4].metric(
        label="Response Actions",
        value=response_actions.get("total", 0),
    )


def render_workload_metrics(summary: Mapping) -> None:
    """
    Render active workflow workload.

    Important:
    These values represent different SOC workflow layers.

    They must not be summed into a single unique-case workload metric because
    one security case may exist simultaneously as an alert, investigation,
    incident, and response action.
    """

    workload = summary.get("workload", {})

    st.header("Operational Workload")

    columns = st.columns(4)

    columns[0].metric(
        label="Active Alerts",
        value=workload.get("active_alerts", 0),
    )

    columns[1].metric(
        label="Active Investigations",
        value=workload.get("active_investigations", 0),
    )

    columns[2].metric(
        label="Active Incidents",
        value=workload.get("active_incidents", 0),
    )

    columns[3].metric(
        label="Pending Response Actions",
        value=workload.get("pending_response_actions", 0),
    )

    st.caption(
        "Workload values represent separate workflow layers and should not be "
        "summed as unique security cases."
    )


def render_distribution(
    title: str,
    distribution: Mapping,
    empty_message: str,
) -> None:
    """
    Render a simple category/count distribution.

    The reporting service is responsible for deciding what categories exist.
    This component only displays the provided trusted metrics.
    """

    st.subheader(title)

    if not distribution:
        st.info(empty_message)
        return

    rows = [
        {
            "Category": str(category),
            "Count": int(count),
        }
        for category, count in distribution.items()
    ]

    st.dataframe(
        rows,
        width="stretch",
        hide_index=True,
    )


def render_alert_overview(summary: Mapping) -> None:
    """Render alert severity and lifecycle distributions."""

    alerts = summary.get("alerts", {})

    st.header("Alert Overview")

    severity_column, status_column = st.columns(2)

    with severity_column:
        render_distribution(
            title="Alerts by Severity",
            distribution=alerts.get("by_severity", {}),
            empty_message="No alert severity metrics are available.",
        )

    with status_column:
        render_distribution(
            title="Alerts by Status",
            distribution=alerts.get("by_status", {}),
            empty_message="No alert status metrics are available.",
        )


def render_investigation_overview(summary: Mapping) -> None:
    """Render investigation lifecycle and disposition distributions."""

    investigations = summary.get("investigations", {})

    st.header("Investigation Overview")

    status_column, disposition_column = st.columns(2)

    with status_column:
        render_distribution(
            title="Investigations by Status",
            distribution=investigations.get("by_status", {}),
            empty_message="No investigation status metrics are available.",
        )

    with disposition_column:
        render_distribution(
            title="Investigations by Disposition",
            distribution=investigations.get("by_disposition", {}),
            empty_message="No investigation disposition metrics are available.",
        )


def render_incident_overview(summary: Mapping) -> None:
    """Render incident severity and lifecycle distributions."""

    incidents = summary.get("incidents", {})

    st.header("Incident Overview")

    severity_column, status_column = st.columns(2)

    with severity_column:
        render_distribution(
            title="Incidents by Severity",
            distribution=incidents.get("by_severity", {}),
            empty_message="No incident severity metrics are available.",
        )

    with status_column:
        render_distribution(
            title="Incidents by Status",
            distribution=incidents.get("by_status", {}),
            empty_message="No incident status metrics are available.",
        )


def render_response_action_overview(summary: Mapping) -> None:
    """
    Render response-action workflow metrics.

    Executed actions are simulated CUSTOM-SOC workflow records.
    They do not prove that real infrastructure was changed.
    """

    response_actions = summary.get("response_actions", {})

    st.header("Response Actions")

    render_distribution(
        title="Response Actions by Status",
        distribution=response_actions.get("by_status", {}),
        empty_message="No response-action status metrics are available.",
    )

    st.warning(
        "Response actions marked as executed represent simulated CUSTOM-SOC "
        "workflow execution only. They do not mean that a real IP address was "
        "blocked, account disabled, host isolated, session terminated, or "
        "endpoint/network system changed."
    )


def render_empty_soc_notice(summary: Mapping) -> None:
    """
    Show an informational message when the SOC contains no operational records.
    """

    total_records = (
        summary.get("events", {}).get("total", 0)
        + summary.get("alerts", {}).get("total", 0)
        + summary.get("investigations", {}).get("total", 0)
        + summary.get("incidents", {}).get("total", 0)
        + summary.get("response_actions", {}).get("total", 0)
    )

    if total_records == 0:
        st.info(
            "CUSTOM-SOC currently contains no operational records. "
            "The dashboard is ready and will display metrics when data exists."
        )


def render_security_notice() -> None:
    """Render dashboard trust and scope information."""

    st.divider()

    st.header("Dashboard Security Notice")

    st.markdown(
        """
        - This dashboard is **read-only**.
        - Metrics come from the CUSTOM-SOC reporting service.
        - The dashboard does **not** query SQLite directly.
        - The dashboard does **not** create or modify alerts, investigations,
          incidents, or response actions.
        - Displayed response execution is **simulated only**.
        - This interface does not claim real-time enterprise monitoring.
        """
    )