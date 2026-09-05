"""
Automated tests for the CUSTOM-SOC Streamlit dashboard.

Mission 016 goals:
- Verify the dashboard starts successfully.
- Verify trusted reporting metrics reach the presentation layer.
- Verify important security/scope messages remain visible.
- Verify the dashboard handles an empty SOC.
- Protect against accidental hardcoded dashboard values.

These tests do not require a browser.
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_APP = PROJECT_ROOT / "dashboard" / "app.py"


def build_summary(
    *,
    events=0,
    alerts=0,
    investigations=0,
    incidents=0,
    response_actions=0,
    active_alerts=0,
    active_investigations=0,
    active_incidents=0,
    pending_response_actions=0,
):
    """Return a complete reporting-service-compatible SOC summary."""

    return {
        "events": {
            "total": events,
        },
        "alerts": {
            "total": alerts,
            "by_severity": {
                "LOW": 0,
                "MEDIUM": alerts,
                "HIGH": 0,
                "CRITICAL": 0,
            },
            "by_status": {
                "open": alerts,
                "acknowledged": 0,
                "investigating": 0,
                "resolved": 0,
                "closed": 0,
            },
        },
        "investigations": {
            "total": investigations,
            "by_status": {
                "open": investigations,
                "investigating": 0,
                "resolved": 0,
                "closed": 0,
            },
            "by_disposition": {
                "false_positive": 0,
                "benign": 0,
                "confirmed_incident": 0,
                "inconclusive": 0,
            },
        },
        "incidents": {
            "total": incidents,
            "by_severity": {
                "LOW": 0,
                "MEDIUM": incidents,
                "HIGH": 0,
                "CRITICAL": 0,
            },
            "by_status": {
                "open": incidents,
                "contained": 0,
                "eradicated": 0,
                "recovered": 0,
                "closed": 0,
            },
        },
        "response_actions": {
            "total": response_actions,
            "by_status": {
                "proposed": response_actions,
                "approved": 0,
                "executed": 0,
                "failed": 0,
                "cancelled": 0,
            },
        },
        "workload": {
            "active_alerts": active_alerts,
            "active_investigations": active_investigations,
            "active_incidents": active_incidents,
            "pending_response_actions": pending_response_actions,
        },
    }


class TestDashboard(unittest.TestCase):
    """Mission 016 Streamlit dashboard regression tests."""

    def run_dashboard(self, summary):
        """
        Run the dashboard while replacing the reporting-service result.

        This isolates presentation testing from the real SQLite database.
        """

        with patch(
            "backend.services.reporting_service.get_soc_summary",
            return_value=summary,
        ):
            app = AppTest.from_file(str(DASHBOARD_APP))
            app.run(timeout=10)

        return app

    def test_dashboard_starts_without_exception(self):
        """The dashboard should render without an uncaught exception."""

        summary = build_summary()

        app = self.run_dashboard(summary)

        self.assertEqual(len(app.exception), 0)

    def test_dashboard_uses_reporting_metrics(self):
        """
        Distinct values must reach dashboard metric widgets.

        Using unusual values helps detect accidental hardcoded numbers.
        """

        summary = build_summary(
            events=17,
            alerts=6,
            investigations=4,
            incidents=2,
            response_actions=9,
            active_alerts=5,
            active_investigations=3,
            active_incidents=2,
            pending_response_actions=7,
        )

        app = self.run_dashboard(summary)

        metric_values = [str(metric.value) for metric in app.metric]

        self.assertEqual(
            metric_values,
            [
                "17",
                "6",
                "4",
                "2",
                "9",
                "5",
                "3",
                "2",
                "7",
            ],
        )

    def test_dashboard_metric_labels_are_stable(self):
        """Important dashboard metric labels should remain visible."""

        summary = build_summary()

        app = self.run_dashboard(summary)

        metric_labels = [metric.label for metric in app.metric]

        self.assertEqual(
            metric_labels,
            [
                "Security Events",
                "Alerts",
                "Investigations",
                "Incidents",
                "Response Actions",
                "Active Alerts",
                "Active Investigations",
                "Active Incidents",
                "Pending Response Actions",
            ],
        )

    def test_empty_soc_displays_empty_notice(self):
        """An empty SOC should display a clear informational message."""

        summary = build_summary()

        app = self.run_dashboard(summary)

        messages = [info.value for info in app.info]

        self.assertTrue(
            any(
                "currently contains no operational records" in message
                for message in messages
            )
        )

    def test_nonempty_soc_does_not_display_empty_notice(self):
        """A SOC with records must not be described as empty."""

        summary = build_summary(
            events=1,
        )

        app = self.run_dashboard(summary)

        messages = [info.value for info in app.info]

        self.assertFalse(
            any(
                "currently contains no operational records" in message
                for message in messages
            )
        )

    def test_simulated_response_warning_is_visible(self):
        """
        Dashboard must preserve the simulated-response security disclaimer.
        """

        summary = build_summary(
            response_actions=1,
            pending_response_actions=1,
        )

        app = self.run_dashboard(summary)

        warning_messages = [warning.value for warning in app.warning]

        self.assertTrue(
            any(
                "simulated CUSTOM-SOC workflow execution only" in message
                for message in warning_messages
            )
        )

    def test_workload_non_summing_notice_is_visible(self):
        """
        Dashboard should warn that workflow-layer workload is not a unique-case
        total.
        """

        summary = build_summary(
            alerts=1,
            investigations=1,
            incidents=1,
            response_actions=1,
            active_alerts=1,
            active_investigations=1,
            active_incidents=1,
            pending_response_actions=1,
        )

        app = self.run_dashboard(summary)

        captions = [caption.value for caption in app.caption]

        self.assertTrue(
            any(
                "should not be summed as unique security cases" in caption
                for caption in captions
            )
        )


if __name__ == "__main__":
    unittest.main()