"""
Hardening tests for the CUSTOM-SOC Streamlit dashboard.

Mission 016 Phase 4 goals:
- Verify safe behavior when metric groups are missing.
- Verify safe behavior when distributions are empty.
- Verify reporting-service failures do not silently produce fake metrics.
- Verify the dashboard stops after a reporting failure.
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_APP = PROJECT_ROOT / "dashboard" / "app.py"


class TestDashboardHardening(unittest.TestCase):
    """Dashboard edge-case and failure-handling tests."""

    def run_dashboard_with_summary(self, summary):
        """Run dashboard with a mocked reporting summary."""

        with patch(
            "backend.services.reporting_service.get_soc_summary",
            return_value=summary,
        ):
            app = AppTest.from_file(str(DASHBOARD_APP))
            app.run(timeout=10)

        return app

    def run_dashboard_with_error(self, error):
        """Run dashboard while forcing reporting-service failure."""

        with patch(
            "backend.services.reporting_service.get_soc_summary",
            side_effect=error,
        ):
            app = AppTest.from_file(str(DASHBOARD_APP))
            app.run(timeout=10)

        return app

    def test_missing_metric_groups_default_to_zero(self):
        """
        Missing groups should not crash the dashboard.

        Presentation components use safe zero defaults for absent totals.
        """

        summary = {
            "events": {
                "total": 8,
            },
        }

        app = self.run_dashboard_with_summary(summary)

        self.assertEqual(len(app.exception), 0)

        metric_values = [str(metric.value) for metric in app.metric]

        self.assertEqual(
            metric_values,
            [
                "8",
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
            ],
        )

    def test_empty_distributions_do_not_crash(self):
        """Empty distribution dictionaries should remain renderable."""

        summary = {
            "events": {
                "total": 1,
            },
            "alerts": {
                "total": 0,
                "by_severity": {},
                "by_status": {},
            },
            "investigations": {
                "total": 0,
                "by_status": {},
                "by_disposition": {},
            },
            "incidents": {
                "total": 0,
                "by_severity": {},
                "by_status": {},
            },
            "response_actions": {
                "total": 0,
                "by_status": {},
            },
            "workload": {
                "active_alerts": 0,
                "active_investigations": 0,
                "active_incidents": 0,
                "pending_response_actions": 0,
            },
        }

        app = self.run_dashboard_with_summary(summary)

        self.assertEqual(len(app.exception), 0)

        info_messages = [info.value for info in app.info]

        expected_messages = {
            "No alert severity metrics are available.",
            "No alert status metrics are available.",
            "No investigation status metrics are available.",
            "No investigation disposition metrics are available.",
            "No incident severity metrics are available.",
            "No incident status metrics are available.",
            "No response-action status metrics are available.",
        }

        self.assertTrue(
            expected_messages.issubset(set(info_messages))
        )

    def test_reporting_failure_displays_error(self):
        """
        Reporting-service failure must be visible to the analyst.

        The dashboard must not replace a failed reporting call with fake zeros.
        """

        app = self.run_dashboard_with_error(
            RuntimeError("simulated reporting failure")
        )

        error_messages = [error.value for error in app.error]

        self.assertTrue(
            any(
                "could not load dashboard metrics from the reporting service"
                in message
                for message in error_messages
            )
        )

    def test_reporting_failure_does_not_render_metrics(self):
        """
        Metrics must not render after reporting failure.

        Fake fallback values would hide a real backend/reporting problem.
        """

        app = self.run_dashboard_with_error(
            RuntimeError("simulated reporting failure")
        )

        self.assertEqual(len(app.metric), 0)

    def test_reporting_failure_exposes_exception_context(self):
        """
        The dashboard should expose exception context during this local
        development phase to aid troubleshooting.
        """

        app = self.run_dashboard_with_error(
            RuntimeError("simulated reporting failure")
        )

        exception_text = " ".join(
            str(exception.value)
            for exception in app.exception
        )

        self.assertIn(
            "simulated reporting failure",
            exception_text,
        )


if __name__ == "__main__":
    unittest.main()