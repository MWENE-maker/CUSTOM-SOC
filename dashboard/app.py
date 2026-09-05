"""
CUSTOM-SOC Streamlit dashboard.

Mission 016 design contract:
- Read-only dashboard.
- Uses backend.services.reporting_service.get_soc_summary().
- No direct SQLite access.
- No SOC aggregation logic duplicated here.
- No operational record modification.
- No claims of real-time enterprise monitoring.
- Simulated response actions remain explicitly identified as simulated.
"""

from pathlib import Path
import sys

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from backend.services.reporting_service import get_soc_summary
from dashboard.components import (
    render_alert_overview,
    render_empty_soc_notice,
    render_incident_overview,
    render_investigation_overview,
    render_page_header,
    render_primary_metrics,
    render_response_action_overview,
    render_security_notice,
    render_workload_metrics,
)


def configure_page() -> None:
    """Configure Streamlit page metadata."""

    st.set_page_config(
        page_title="CUSTOM-SOC Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )


def load_soc_summary() -> dict:
    """
    Load trusted SOC reporting metrics.

    The dashboard intentionally delegates aggregation to the reporting service.
    """

    return get_soc_summary()


def render_sidebar() -> None:
    """Render dashboard scope information."""

    with st.sidebar:
        st.header("CUSTOM-SOC")

        st.write("SOC Operations Dashboard")

        st.divider()

        st.subheader("Dashboard Mode")

        st.success("Read-only")

        st.caption(
            "Metrics are derived from CUSTOM-SOC operational records through "
            "the reporting service."
        )

        st.divider()

        st.subheader("Scope")

        st.write(
            "This dashboard currently displays aggregate operational metrics."
        )

        st.write(
            "Investigation editing, incident management, response execution, "
            "authentication, and RBAC are not dashboard features in Mission 016."
        )


def main() -> None:
    """Render the CUSTOM-SOC dashboard."""

    configure_page()
    render_sidebar()
    render_page_header()

    try:
        summary = load_soc_summary()
    except Exception as exc:
        st.error(
            "CUSTOM-SOC could not load dashboard metrics from the reporting service."
        )

        st.exception(exc)

        st.stop()

    render_empty_soc_notice(summary)

    render_primary_metrics(summary)

    st.divider()

    render_workload_metrics(summary)

    st.divider()

    render_alert_overview(summary)

    st.divider()

    render_investigation_overview(summary)

    st.divider()

    render_incident_overview(summary)

    st.divider()

    render_response_action_overview(summary)

    render_security_notice()


if __name__ == "__main__":
    main()