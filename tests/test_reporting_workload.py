import tempfile
import unittest
from pathlib import Path

from backend.core.config import settings
from backend.database.connection import get_connection
from backend.database.init_db import initialize_database
from backend.services.reporting_service import get_workload_metrics


class TestReportingWorkload(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.original_database_path = settings.DATABASE_PATH

        settings.DATABASE_PATH = str(
            Path(self.temp_directory.name) / "reporting_workload_test.db"
        )

        initialize_database()

    def tearDown(self):
        settings.DATABASE_PATH = self.original_database_path
        self.temp_directory.cleanup()

    def _create_event(self):
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
                    "2026-09-05T15:00:00+00:00",
                    "reporting-workload-test",
                    "web_security_event",
                    "MEDIUM",
                    "Synthetic workload reporting event",
                ),
            )

            event_id = connection.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0]

            connection.commit()

            return event_id

        finally:
            connection.close()

    def _create_incident(self, status="open"):
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
                    f"Workload incident - {status}",
                    "HIGH",
                    status,
                    "Synthetic incident for workload reporting tests",
                    "2026-09-05T16:00:00+00:00",
                    "2026-09-05T16:00:00+00:00",
                ),
            )

            incident_id = connection.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0]

            connection.commit()

            return incident_id

        finally:
            connection.close()

    def test_empty_workload_is_zero(self):
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

    def test_active_alert_statuses_are_counted(self):
        event_id = self._create_event()
        connection = get_connection()

        try:
            statuses = [
                "open",
                "acknowledged",
                "investigating",
                "resolved",
                "closed",
            ]

            for index, status in enumerate(statuses, start=1):
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
                        f"WORKLOAD_ALERT_RULE_{index}",
                        "MEDIUM",
                        status,
                        f"Synthetic alert in {status} state",
                        "2026-09-05T15:10:00+00:00",
                        "2026-09-05T15:10:00+00:00",
                    ),
                )

            connection.commit()

        finally:
            connection.close()

        metrics = get_workload_metrics()

        # Active:
        # open
        # acknowledged
        # investigating
        #
        # Not active:
        # resolved
        # closed
        self.assertEqual(metrics["active_alerts"], 3)

    def test_active_investigation_statuses_are_counted(self):
        connection = get_connection()

        try:
            statuses = [
                "open",
                "investigating",
                "resolved",
                "closed",
            ]

            for status in statuses:
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
                        f"Workload investigation - {status}",
                        status,
                        "MEDIUM",
                        "2026-09-05T15:20:00+00:00",
                        "2026-09-05T15:20:00+00:00",
                    ),
                )

            connection.commit()

        finally:
            connection.close()

        metrics = get_workload_metrics()

        # Active:
        # open
        # investigating
        #
        # Not active:
        # resolved
        # closed
        self.assertEqual(metrics["active_investigations"], 2)

    def test_active_incident_statuses_are_counted(self):
        connection = get_connection()

        try:
            statuses = [
                "open",
                "contained",
                "eradicated",
                "recovered",
                "closed",
            ]

            for status in statuses:
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
                        f"Workload incident - {status}",
                        "HIGH",
                        status,
                        f"Synthetic incident in {status} state",
                        "2026-09-05T15:30:00+00:00",
                        "2026-09-05T15:30:00+00:00",
                    ),
                )

            connection.commit()

        finally:
            connection.close()

        metrics = get_workload_metrics()

        # Active:
        # open
        # contained
        # eradicated
        # recovered
        #
        # Not active:
        # closed
        self.assertEqual(metrics["active_incidents"], 4)

    def test_pending_response_action_statuses_are_counted(self):
        incident_id = self._create_incident()
        connection = get_connection()

        try:
            statuses = [
                "proposed",
                "approved",
                "executed",
                "failed",
                "cancelled",
            ]

            for index, status in enumerate(statuses, start=1):
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
                        "collect_evidence",
                        f"workload-target-{index}",
                        status,
                        "SOC Analyst",
                        "2026-09-05T16:10:00+00:00",
                        "2026-09-05T16:10:00+00:00",
                    ),
                )

            connection.commit()

        finally:
            connection.close()

        metrics = get_workload_metrics()

        # Pending:
        # proposed
        # approved
        #
        # Not pending:
        # executed
        # failed
        # cancelled
        self.assertEqual(metrics["pending_response_actions"], 2)


if __name__ == "__main__":
    unittest.main()