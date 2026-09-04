import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.core.config import settings
from backend.database.connection import (
    get_connection,
    get_database_path,
)
from backend.database.init_db import (
    initialize_database,
)
from backend.detection_engine.rule import (
    DetectionRule,
)
from backend.models.event import SecurityEvent
from backend.services.alert_service import (
    create_alert,
)
from backend.services.event_service import (
    save_event,
)


class TestDatabaseIntegration(unittest.TestCase):

    def setUp(self):
        """
        Create an isolated temporary SQLite database
        before every integration test.
        """
        self.original_database_path = (
            settings.DATABASE_PATH
        )

        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        self.test_database_path = (
            Path(self.temp_directory.name)
            / "custom_soc_test.db"
        )

        settings.DATABASE_PATH = str(
            self.test_database_path
        )

        initialize_database()

    def tearDown(self):
        """
        Restore the original development database path
        and remove the temporary test database.
        """
        settings.DATABASE_PATH = (
            self.original_database_path
        )

        self.temp_directory.cleanup()

    def test_uses_isolated_database(self):
        """
        Verify that integration tests use the temporary
        database instead of the development database.
        """
        active_path = (
            get_database_path().resolve()
        )

        development_path = Path(
            self.original_database_path
        ).resolve()

        self.assertEqual(
            active_path,
            self.test_database_path.resolve(),
        )

        self.assertNotEqual(
            active_path,
            development_path,
        )

    def test_schema_contains_structured_http_fields(
        self,
    ):
        """
        Verify that the events table contains the
        structured HTTP fields required for correlation.
        """
        connection = get_connection()

        try:
            columns = connection.execute(
                "PRAGMA table_info(events)"
            ).fetchall()

            column_names = {
                column["name"]
                for column in columns
            }

            expected_columns = {
                "source_ip",
                "http_method",
                "http_path",
                "http_status",
                "response_size",
            }

            self.assertTrue(
                expected_columns.issubset(
                    column_names
                )
            )

        finally:
            connection.close()

    def test_event_persistence(self):
        """
        Verify that a structured SecurityEvent can be
        written to and retrieved from the temporary
        database with all HTTP metadata preserved.
        """
        event = SecurityEvent.create(
            source="integration-test",
            event_type="HTTP_REQUEST",
            severity="medium",
            message=(
                "POST /login returned HTTP 401"
            ),
            raw_data=(
                "192.168.1.30 "
                "POST /login 401 412"
            ),
            source_ip="192.168.1.30",
            http_method="POST",
            http_path="/login",
            http_status=401,
            response_size=412,
        )

        event_id = save_event(event)

        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT
                    id,
                    source,
                    event_type,
                    severity,
                    message,
                    raw_data,
                    source_ip,
                    http_method,
                    http_path,
                    http_status,
                    response_size
                FROM events
                WHERE id = ?
                """,
                (event_id,),
            ).fetchone()

            self.assertIsNotNone(row)

            self.assertEqual(
                row["id"],
                event_id,
            )

            self.assertEqual(
                row["source"],
                "integration-test",
            )

            self.assertEqual(
                row["event_type"],
                "HTTP_REQUEST",
            )

            self.assertEqual(
                row["severity"],
                "MEDIUM",
            )

            self.assertEqual(
                row["message"],
                "POST /login returned HTTP 401",
            )

            self.assertEqual(
                row["raw_data"],
                (
                    "192.168.1.30 "
                    "POST /login 401 412"
                ),
            )

            self.assertEqual(
                row["source_ip"],
                "192.168.1.30",
            )

            self.assertEqual(
                row["http_method"],
                "POST",
            )

            self.assertEqual(
                row["http_path"],
                "/login",
            )

            self.assertEqual(
                row["http_status"],
                401,
            )

            self.assertEqual(
                row["response_size"],
                412,
            )

        finally:
            connection.close()

    def test_alert_persistence(self):
        """
        Verify that an alert can be linked to a real
        event inside the temporary database.
        """
        event = SecurityEvent.create(
            source="integration-test",
            event_type="HTTP_REQUEST",
            severity="medium",
            message=(
                "GET /admin returned HTTP 403"
            ),
            raw_data=(
                "192.168.1.25 "
                "GET /admin 403 321"
            ),
            source_ip="192.168.1.25",
            http_method="GET",
            http_path="/admin",
            http_status=403,
            response_size=321,
        )

        event_id = save_event(event)

        rule = DetectionRule(
            name="INTEGRATION_TEST_RULE",
            description=(
                "Integration test alert"
            ),
            severity="MEDIUM",
            condition=lambda event: True,
        )

        alert_id = create_alert(
            event_id,
            rule,
        )

        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT
                    id,
                    event_id,
                    rule_name,
                    severity,
                    status,
                    description
                FROM alerts
                WHERE id = ?
                """,
                (alert_id,),
            ).fetchone()

            self.assertIsNotNone(row)

            self.assertEqual(
                row["id"],
                alert_id,
            )

            self.assertEqual(
                row["event_id"],
                event_id,
            )

            self.assertEqual(
                row["rule_name"],
                "INTEGRATION_TEST_RULE",
            )

            self.assertEqual(
                row["severity"],
                "MEDIUM",
            )

            self.assertEqual(
                row["status"],
                "open",
            )

            self.assertEqual(
                row["description"],
                "Integration test alert",
            )

        finally:
            connection.close()

    def test_foreign_key_rejects_orphan_alert(
        self,
    ):
        """
        Verify that SQLite foreign-key enforcement
        prevents an alert from referencing an event
        that does not exist.
        """
        connection = get_connection()

        try:
            with self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    """
                    INSERT INTO alerts (
                        event_id,
                        rule_name,
                        severity,
                        status,
                        description,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        999999,
                        "ORPHAN_TEST",
                        "LOW",
                        "open",
                        "Invalid orphan alert",
                        (
                            "2026-09-04"
                            "T00:00:00+00:00"
                        ),
                    ),
                )

                connection.commit()

        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()