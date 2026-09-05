import tempfile
import unittest
from pathlib import Path

from backend.core.config import settings
from backend.database.connection import get_connection
from backend.database.init_db import initialize_database
from backend.services.reporting_service import (
    get_alert_metrics,
    get_event_metrics,
    get_incident_metrics,
    get_investigation_metrics,
    get_response_action_metrics,
    get_soc_summary,
    get_workload_metrics,
)


class TestReportingService(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.original_database_path = settings.DATABASE_PATH

        settings.DATABASE_PATH = str(
            Path(self.temp_directory.name) / "reporting_test.db"
        )

        initialize_database()

    def tearDown(self):
        settings.DATABASE_PATH = self.original_database_path
        self.temp_directory.cleanup()

    def test_empty_workload_metrics(self):
        metrics = get_workload_metrics()

        self.assertEqual(
            metrics,
            {
                "active_alerts": 0,
                "active_investigations": 0,
                "active_incidents": 0,
                "pending_response_actions": 0,
            },
        )

    def test_empty_event_metrics(self):
        metrics = get_event_metrics()

        self.assertEqual(
            metrics,
            {
                "total": 0,
            },
        )

    def test_empty_alert_metrics(self):
        metrics = get_alert_metrics()

        self.assertEqual(metrics["total"], 0)

        self.assertEqual(
            metrics["by_severity"],
            {
                "CRITICAL": 0,
                "HIGH": 0,
                "LOW": 0,
                "MEDIUM": 0,
            },
        )

        self.assertEqual(
            metrics["by_status"],
            {
                "acknowledged": 0,
                "closed": 0,
                "investigating": 0,
                "open": 0,
                "resolved": 0,
            },
        )

    def test_empty_investigation_metrics(self):
        metrics = get_investigation_metrics()

        self.assertEqual(metrics["total"], 0)

        self.assertEqual(
            metrics["by_status"],
            {
                "closed": 0,
                "investigating": 0,
                "open": 0,
                "resolved": 0,
            },
        )

        self.assertEqual(
            metrics["by_disposition"],
            {
                "benign": 0,
                "confirmed_incident": 0,
                "false_positive": 0,
                "inconclusive": 0,
            },
        )

    def test_empty_incident_metrics(self):
        metrics = get_incident_metrics()

        self.assertEqual(metrics["total"], 0)

        self.assertEqual(
            metrics["by_severity"],
            {
                "CRITICAL": 0,
                "HIGH": 0,
                "LOW": 0,
                "MEDIUM": 0,
            },
        )

        self.assertEqual(
            metrics["by_status"],
            {
                "closed": 0,
                "contained": 0,
                "eradicated": 0,
                "open": 0,
                "recovered": 0,
            },
        )

    def test_empty_response_action_metrics(self):
        metrics = get_response_action_metrics()

        self.assertEqual(metrics["total"], 0)

        self.assertEqual(
            metrics["by_status"],
            {
                "approved": 0,
                "cancelled": 0,
                "executed": 0,
                "failed": 0,
                "proposed": 0,
            },
        )

    def test_empty_soc_summary(self):
        summary = get_soc_summary()

        self.assertEqual(
            set(summary.keys()),
            {
                "events",
                "alerts",
                "investigations",
                "incidents",
                "response_actions",
                "workload",
            },
        )

        self.assertEqual(
            summary["workload"],
            {
                "active_alerts": 0,
                "active_investigations": 0,
                "active_incidents": 0,
                "pending_response_actions": 0,
            },
        )

        self.assertEqual(summary["events"]["total"], 0)
        self.assertEqual(summary["alerts"]["total"], 0)
        self.assertEqual(summary["investigations"]["total"], 0)
        self.assertEqual(summary["incidents"]["total"], 0)
        self.assertEqual(summary["response_actions"]["total"], 0)

    def test_alert_metrics_with_sample_rows(self):
        connection = get_connection()

        try:
            connection.execute(
                """
                INSERT INTO events (
                    timestamp,
                    source,
                    event_type,
                    severity,
                    message
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "2026-09-05T10:00:00+00:00",
                    "reporting-test",
                    "web_security_event",
                    "MEDIUM",
                    "Synthetic reporting test event",
                ),
            )

            event_id = connection.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0]

            connection.execute(
                """
                INSERT INTO alerts (
                    event_id,
                    rule_name,
                    severity,
                    status,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    "REPORTING_TEST_RULE_1",
                    "MEDIUM",
                    "open",
                    "Synthetic reporting test alert",
                    "2026-09-05T10:01:00+00:00",
                    "2026-09-05T10:01:00+00:00",
                ),
            )

            connection.execute(
                """
                INSERT INTO alerts (
                    event_id,
                    rule_name,
                    severity,
                    status,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    "REPORTING_TEST_RULE_2",
                    "HIGH",
                    "acknowledged",
                    "Second synthetic reporting test alert",
                    "2026-09-05T10:02:00+00:00",
                    "2026-09-05T10:02:00+00:00",
                ),
            )

            connection.commit()

        finally:
            connection.close()

        event_metrics = get_event_metrics()
        alert_metrics = get_alert_metrics()

        self.assertEqual(event_metrics["total"], 1)

        self.assertEqual(alert_metrics["total"], 2)
        self.assertEqual(alert_metrics["by_severity"]["MEDIUM"], 1)
        self.assertEqual(alert_metrics["by_severity"]["HIGH"], 1)
        self.assertEqual(alert_metrics["by_severity"]["LOW"], 0)
        self.assertEqual(alert_metrics["by_severity"]["CRITICAL"], 0)

        self.assertEqual(alert_metrics["by_status"]["open"], 1)
        self.assertEqual(
            alert_metrics["by_status"]["acknowledged"],
            1,
        )

    def test_investigation_metrics_with_null_disposition(self):
        connection = get_connection()

        try:
            connection.execute(
                """
                INSERT INTO investigations (
                    title,
                    status,
                    severity,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "Open reporting investigation",
                    "open",
                    "MEDIUM",
                    "2026-09-05T11:00:00+00:00",
                    "2026-09-05T11:00:00+00:00",
                ),
            )

            connection.execute(
                """
                INSERT INTO investigations (
                    title,
                    status,
                    severity,
                    disposition,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "Resolved reporting investigation",
                    "resolved",
                    "HIGH",
                    "false_positive",
                    "2026-09-05T11:10:00+00:00",
                    "2026-09-05T11:20:00+00:00",
                ),
            )

            connection.commit()

        finally:
            connection.close()

        metrics = get_investigation_metrics()

        self.assertEqual(metrics["total"], 2)
        self.assertEqual(metrics["by_status"]["open"], 1)
        self.assertEqual(metrics["by_status"]["resolved"], 1)

        self.assertEqual(
            metrics["by_disposition"]["false_positive"],
            1,
        )

        disposition_total = sum(
            metrics["by_disposition"].values()
        )

        self.assertEqual(disposition_total, 1)

    def test_incident_metrics_with_sample_rows(self):
        connection = get_connection()

        try:
            connection.execute(
                """
                INSERT INTO incidents (
                    title,
                    severity,
                    status,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "Reporting incident one",
                    "HIGH",
                    "open",
                    "Synthetic incident for reporting tests",
                    "2026-09-05T12:00:00+00:00",
                    "2026-09-05T12:00:00+00:00",
                ),
            )

            connection.execute(
                """
                INSERT INTO incidents (
                    title,
                    severity,
                    status,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "Reporting incident two",
                    "CRITICAL",
                    "contained",
                    "Second synthetic incident for reporting tests",
                    "2026-09-05T12:10:00+00:00",
                    "2026-09-05T12:20:00+00:00",
                ),
            )

            connection.commit()

        finally:
            connection.close()

        metrics = get_incident_metrics()

        self.assertEqual(metrics["total"], 2)
        self.assertEqual(metrics["by_severity"]["HIGH"], 1)
        self.assertEqual(metrics["by_severity"]["CRITICAL"], 1)
        self.assertEqual(metrics["by_status"]["open"], 1)
        self.assertEqual(metrics["by_status"]["contained"], 1)

    def test_response_action_metrics_with_sample_rows(self):
        connection = get_connection()

        try:
            connection.execute(
                """
                INSERT INTO incidents (
                    title,
                    severity,
                    status,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "Response reporting incident",
                    "HIGH",
                    "open",
                    "Incident used for response-action metrics",
                    "2026-09-05T13:00:00+00:00",
                    "2026-09-05T13:00:00+00:00",
                ),
            )

            incident_id = connection.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0]

            connection.execute(
                """
                INSERT INTO response_actions (
                    incident_id,
                    action_type,
                    target,
                    status,
                    requested_by,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    "block_ip",
                    "192.0.2.10",
                    "proposed",
                    "SOC Analyst",
                    "2026-09-05T13:10:00+00:00",
                    "2026-09-05T13:10:00+00:00",
                ),
            )

            connection.execute(
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
                    result
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    "isolate_host",
                    "host-lab-01",
                    "executed",
                    "SOC Analyst",
                    "SOC Lead",
                    "2026-09-05T13:20:00+00:00",
                    "2026-09-05T13:21:00+00:00",
                    "2026-09-05T13:22:00+00:00",
                    "2026-09-05T13:22:00+00:00",
                    (
                        "SIMULATED EXECUTION ONLY: no real "
                        "endpoint was changed."
                    ),
                ),
            )

            connection.commit()

        finally:
            connection.close()

        metrics = get_response_action_metrics()

        self.assertEqual(metrics["total"], 2)
        self.assertEqual(metrics["by_status"]["proposed"], 1)
        self.assertEqual(metrics["by_status"]["executed"], 1)
        self.assertEqual(metrics["by_status"]["approved"], 0)
        self.assertEqual(metrics["by_status"]["failed"], 0)
        self.assertEqual(metrics["by_status"]["cancelled"], 0)

    def test_soc_summary_reflects_all_metric_groups(self):
        connection = get_connection()

        try:
            connection.execute(
                """
                INSERT INTO incidents (
                    title,
                    severity,
                    status,
                    description,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "Summary incident",
                    "MEDIUM",
                    "open",
                    "Synthetic summary test incident",
                    "2026-09-05T14:00:00+00:00",
                    "2026-09-05T14:00:00+00:00",
                ),
            )

            connection.commit()

        finally:
            connection.close()

        summary = get_soc_summary()

        self.assertEqual(summary["incidents"]["total"], 1)
        self.assertEqual(
            summary["incidents"]["by_status"]["open"],
            1,
        )

        self.assertEqual(summary["events"]["total"], 0)
        self.assertEqual(summary["alerts"]["total"], 0)
        self.assertEqual(summary["investigations"]["total"], 0)
        self.assertEqual(summary["response_actions"]["total"], 0)


if __name__ == "__main__":
    unittest.main()