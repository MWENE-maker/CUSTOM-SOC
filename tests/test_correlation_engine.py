import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.core.config import settings
from backend.database.connection import (
    get_connection,
)
from backend.database.init_db import (
    initialize_database,
)
from backend.detection_engine.correlation import (
    evaluate_correlations,
)
from backend.models.event import SecurityEvent
from backend.services.event_service import (
    save_event,
)
from backend.services.log_ingestion_service import (
    ingest_web_log,
)


class TestCorrelationEngine(
    unittest.TestCase
):

    def setUp(self):
        """
        Create an isolated SQLite database for
        every correlation test.
        """
        self.original_database_path = (
            settings.DATABASE_PATH
        )

        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        self.test_database_path = (
            Path(self.temp_directory.name)
            / "correlation_test.db"
        )

        settings.DATABASE_PATH = str(
            self.test_database_path
        )

        initialize_database()

    def tearDown(self):
        """
        Restore the normal database configuration
        and delete the temporary database.
        """
        settings.DATABASE_PATH = (
            self.original_database_path
        )

        self.temp_directory.cleanup()

    def count_correlation_alerts(
        self,
    ) -> int:
        connection = get_connection()

        try:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE rule_name = ?
                """,
                (
                    "WEB_REPEATED_FAILED_LOGIN",
                ),
            ).fetchone()[0]

            return count

        finally:
            connection.close()

    def create_failed_login_event(
        self,
        source_ip: str,
        timestamp: datetime,
    ) -> SecurityEvent:
        """
        Create a failed-login SecurityEvent with
        a deterministic timestamp for correlation
        window testing.
        """
        return SecurityEvent(
            timestamp=timestamp.isoformat(),
            source="web-access-log",
            event_type="HTTP_REQUEST",
            severity="MEDIUM",
            message=(
                "POST /login returned HTTP 401"
            ),
            raw_data=(
                f"{source_ip} "
                "POST /login 401 412"
            ),
            source_ip=source_ip,
            http_method="POST",
            http_path="/login",
            http_status=401,
            response_size=412,
        )

    def test_four_failed_logins_do_not_correlate(
        self,
    ):
        """
        Four failed logins are below the
        threshold of five.
        """
        for _ in range(4):
            ingest_web_log(
                (
                    "192.168.50.10 "
                    "POST /login 401 412"
                )
            )

        self.assertEqual(
            self.count_correlation_alerts(),
            0,
        )

    def test_fifth_failed_login_creates_alert(
        self,
    ):
        """
        The fifth failed login from the same
        source IP should create one HIGH
        correlation alert.
        """
        last_event_id = None

        for _ in range(5):
            last_event_id = (
                ingest_web_log(
                    (
                        "192.168.50.20 "
                        "POST /login 401 412"
                    )
                )
            )

        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT
                    event_id,
                    rule_name,
                    severity,
                    status
                FROM alerts
                WHERE rule_name = ?
                """,
                (
                    "WEB_REPEATED_FAILED_LOGIN",
                ),
            ).fetchone()

            self.assertIsNotNone(
                row
            )

            self.assertEqual(
                row["event_id"],
                last_event_id,
            )

            self.assertEqual(
                row["rule_name"],
                "WEB_REPEATED_FAILED_LOGIN",
            )

            self.assertEqual(
                row["severity"],
                "HIGH",
            )

            self.assertEqual(
                row["status"],
                "open",
            )

        finally:
            connection.close()

    def test_sixth_failed_login_does_not_duplicate_alert(
        self,
    ):
        """
        Additional failed logins inside the same
        five-minute window must not create duplicate
        correlation alerts.
        """
        for _ in range(6):
            ingest_web_log(
                (
                    "192.168.50.30 "
                    "POST /login 401 412"
                )
            )

        self.assertEqual(
            self.count_correlation_alerts(),
            1,
        )

    def test_different_source_ips_do_not_combine(
        self,
    ):
        """
        Failed logins from different IP addresses
        must not be combined into one threshold.
        """
        for _ in range(3):
            ingest_web_log(
                (
                    "192.168.50.40 "
                    "POST /login 401 412"
                )
            )

        for _ in range(2):
            ingest_web_log(
                (
                    "192.168.50.41 "
                    "POST /login 401 412"
                )
            )

        self.assertEqual(
            self.count_correlation_alerts(),
            0,
        )

    def test_old_failed_logins_outside_window_do_not_correlate(
        self,
    ):
        """
        Failed login events older than five minutes
        must not contribute to the current threshold.
        """
        source_ip = "192.168.50.60"

        reference_time = datetime(
            2026,
            9,
            4,
            12,
            0,
            0,
            tzinfo=timezone.utc,
        )

        old_time = (
            reference_time
            - timedelta(
                minutes=6,
            )
        )

        #
        # Four failures happened six minutes earlier.
        # They are outside the five-minute window.
        #
        for _ in range(4):
            old_event = (
                self.create_failed_login_event(
                    source_ip,
                    old_time,
                )
            )

            save_event(
                old_event
            )

        #
        # This is the current failed login.
        #
        current_event = (
            self.create_failed_login_event(
                source_ip,
                reference_time,
            )
        )

        save_event(
            current_event
        )

        matched_rules = (
            evaluate_correlations(
                current_event
            )
        )

        self.assertEqual(
            matched_rules,
            [],
        )

    def test_failures_inside_window_do_correlate(
        self,
    ):
        """
        Five failed login events from the same IP
        inside the five-minute window should match
        the repeated failed-login correlation rule.
        """
        source_ip = "192.168.50.70"

        reference_time = datetime(
            2026,
            9,
            4,
            12,
            0,
            0,
            tzinfo=timezone.utc,
        )

        #
        # Four previous failures occurred within
        # the five-minute correlation window.
        #
        for minutes_ago in (
            4,
            3,
            2,
            1,
        ):
            event_time = (
                reference_time
                - timedelta(
                    minutes=minutes_ago,
                )
            )

            event = (
                self.create_failed_login_event(
                    source_ip,
                    event_time,
                )
            )

            save_event(
                event
            )

        #
        # Fifth failure occurs at reference time.
        #
        current_event = (
            self.create_failed_login_event(
                source_ip,
                reference_time,
            )
        )

        save_event(
            current_event
        )

        matched_rules = (
            evaluate_correlations(
                current_event
            )
        )

        self.assertEqual(
            len(matched_rules),
            1,
        )

        self.assertEqual(
            matched_rules[0].name,
            "WEB_REPEATED_FAILED_LOGIN",
        )

        self.assertEqual(
            matched_rules[0].severity,
            "HIGH",
        )


if __name__ == "__main__":
    unittest.main()