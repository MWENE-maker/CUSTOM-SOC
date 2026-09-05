import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.core.config import settings
from backend.database.init_db import initialize_database
from backend.detection_engine.rules import DetectionRule
from backend.models.event import SecurityEvent
from backend.services.alert_service import create_alert
from backend.services.event_service import save_event
from backend.services.incident_service import (
    create_incident_from_investigation,
    get_incident,
    get_incident_for_investigation,
    list_incidents,
)
from backend.services.investigation_service import (
    create_investigation,
    get_investigation_history,
    set_investigation_disposition,
    update_investigation_findings,
    update_investigation_status,
)


class TestIncidentBridge(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()

        self.original_database_path = settings.DATABASE_PATH

        settings.DATABASE_PATH = str(
            Path(self.temp_directory.name)
            / "test_custom_soc.db"
        )

        initialize_database()

        self.event = SecurityEvent(
            timestamp="2026-09-05T10:00:00+00:00",
            source="web",
            event_type="web_request",
            severity="HIGH",
            message="Controlled confirmed incident event",
            raw_data="controlled incident bridge test",
            source_ip="192.168.50.90",
            http_method="POST",
            http_path="/login",
            http_status=401,
            response_size=222,
        )

        self.event_id = save_event(
            self.event
        )

        self.rule = DetectionRule(
            name="TEST_INCIDENT_BRIDGE_RULE",
            severity="HIGH",
            description="Controlled incident bridge test rule",
            condition=lambda event: True,
        )

        self.alert_id = create_alert(
            self.event_id,
            self.rule,
        )

    def tearDown(self) -> None:
        settings.DATABASE_PATH = (
            self.original_database_path
        )

        self.temp_directory.cleanup()

    def _create_open_investigation(self) -> int:
        return create_investigation(
            title="Confirmed failed-login incident",
            severity="HIGH",
            alert_ids=[self.alert_id],
            summary="Review suspicious failed-login activity.",
            assigned_to="SOC Analyst 1",
        )

    def _create_resolved_confirmed_investigation(
        self,
    ) -> int:
        investigation_id = (
            self._create_open_investigation()
        )

        update_investigation_status(
            investigation_id,
            "investigating",
            analyst="SOC Analyst 1",
        )

        update_investigation_findings(
            investigation_id,
            "Activity was confirmed as a security incident.",
            analyst="SOC Analyst 1",
        )

        set_investigation_disposition(
            investigation_id,
            "confirmed_incident",
            analyst="SOC Analyst 1",
        )

        update_investigation_status(
            investigation_id,
            "resolved",
            analyst="SOC Analyst 1",
        )

        return investigation_id

    def test_create_incident_from_resolved_confirmed_investigation(
        self,
    ) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        incident_id = create_incident_from_investigation(
            investigation_id,
            analyst="SOC Lead",
        )

        incident = get_incident(
            incident_id
        )

        self.assertEqual(
            incident["investigation_id"],
            investigation_id,
        )

        self.assertEqual(
            incident["status"],
            "open",
        )

        self.assertEqual(
            incident["severity"],
            "HIGH",
        )

        self.assertEqual(
            incident["assigned_to"],
            "SOC Analyst 1",
        )

    def test_incident_inherits_title_and_description(
        self,
    ) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        incident_id = create_incident_from_investigation(
            investigation_id
        )

        incident = get_incident(
            incident_id
        )

        self.assertEqual(
            incident["title"],
            "Confirmed failed-login incident",
        )

        self.assertIn(
            "Review suspicious failed-login activity.",
            incident["description"],
        )

        self.assertIn(
            "Activity was confirmed as a security incident.",
            incident["description"],
        )

    def test_missing_investigation_rejected(self) -> None:
        with self.assertRaises(ValueError):
            create_incident_from_investigation(
                999999
            )

    def test_open_investigation_rejected(self) -> None:
        investigation_id = (
            self._create_open_investigation()
        )

        with self.assertRaises(ValueError):
            create_incident_from_investigation(
                investigation_id
            )

    def test_investigating_investigation_rejected(
        self,
    ) -> None:
        investigation_id = (
            self._create_open_investigation()
        )

        update_investigation_status(
            investigation_id,
            "investigating",
        )

        set_investigation_disposition(
            investigation_id,
            "confirmed_incident",
        )

        with self.assertRaises(ValueError):
            create_incident_from_investigation(
                investigation_id
            )

    def test_resolved_non_confirmed_investigation_rejected(
        self,
    ) -> None:
        investigation_id = (
            self._create_open_investigation()
        )

        update_investigation_status(
            investigation_id,
            "investigating",
        )

        set_investigation_disposition(
            investigation_id,
            "benign",
        )

        update_investigation_status(
            investigation_id,
            "resolved",
        )

        with self.assertRaises(ValueError):
            create_incident_from_investigation(
                investigation_id
            )

    def test_closed_investigation_rejected(self) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        update_investigation_status(
            investigation_id,
            "closed",
        )

        with self.assertRaises(ValueError):
            create_incident_from_investigation(
                investigation_id
            )

    def test_duplicate_incident_rejected(self) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        create_incident_from_investigation(
            investigation_id
        )

        with self.assertRaises(ValueError):
            create_incident_from_investigation(
                investigation_id
            )

    def test_incident_creation_records_investigation_history(
        self,
    ) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        incident_id = create_incident_from_investigation(
            investigation_id,
            analyst="SOC Lead",
        )

        history = get_investigation_history(
            investigation_id
        )

        entry = history[-1]

        self.assertEqual(
            entry["action"],
            "incident_created",
        )

        self.assertEqual(
            entry["new_value"],
            str(incident_id),
        )

        self.assertEqual(
            entry["analyst"],
            "SOC Lead",
        )

    def test_get_incident_for_investigation(
        self,
    ) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        incident_id = create_incident_from_investigation(
            investigation_id
        )

        incident = get_incident_for_investigation(
            investigation_id
        )

        self.assertIsNotNone(
            incident
        )

        self.assertEqual(
            incident["id"],
            incident_id,
        )

    def test_get_incident_for_investigation_returns_none_before_escalation(
        self,
    ) -> None:
        investigation_id = (
            self._create_open_investigation()
        )

        incident = get_incident_for_investigation(
            investigation_id
        )

        self.assertIsNone(
            incident
        )

    def test_missing_incident_rejected(self) -> None:
        with self.assertRaises(ValueError):
            get_incident(
                999999
            )

    def test_list_incidents(self) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        incident_id = create_incident_from_investigation(
            investigation_id
        )

        incidents = list_incidents()

        self.assertTrue(
            any(
                item["id"] == incident_id
                for item in incidents
            )
        )

    def test_list_incidents_by_status(self) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        incident_id = create_incident_from_investigation(
            investigation_id
        )

        incidents = list_incidents(
            status="open"
        )

        self.assertTrue(
            any(
                item["id"] == incident_id
                for item in incidents
            )
        )

    def test_invalid_incident_list_status_rejected(
        self,
    ) -> None:
        with self.assertRaises(ValueError):
            list_incidents(
                status="investigating"
            )

    def test_incident_foreign_key_rejects_orphan_investigation(
        self,
    ) -> None:
        connection = sqlite3.connect(
            settings.DATABASE_PATH
        )

        try:
            connection.execute(
                "PRAGMA foreign_keys = ON"
            )

            with self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    """
                    INSERT INTO incidents (
                        title,
                        severity,
                        status,
                        created_at,
                        investigation_id
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "Orphan incident",
                        "HIGH",
                        "open",
                        "2026-09-05T10:00:00+00:00",
                        999999,
                    ),
                )

        finally:
            connection.close()

    def test_unique_index_rejects_duplicate_investigation_incident(
        self,
    ) -> None:
        investigation_id = (
            self._create_resolved_confirmed_investigation()
        )

        create_incident_from_investigation(
            investigation_id
        )

        connection = sqlite3.connect(
            settings.DATABASE_PATH
        )

        try:
            with self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    """
                    INSERT INTO incidents (
                        title,
                        severity,
                        status,
                        created_at,
                        investigation_id
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        "Duplicate incident",
                        "HIGH",
                        "open",
                        "2026-09-05T10:00:00+00:00",
                        investigation_id,
                    ),
                )

        finally:
            connection.close()

    def test_incident_unique_partial_index_exists(
        self,
    ) -> None:
        connection = sqlite3.connect(
            settings.DATABASE_PATH
        )

        try:
            indexes = connection.execute(
                "PRAGMA index_list(incidents)"
            ).fetchall()

            matching = [
                row
                for row in indexes
                if row[1]
                == "idx_incidents_investigation_id"
            ]

            self.assertEqual(
                len(matching),
                1,
            )

            self.assertEqual(
                matching[0][2],
                1,
            )

            self.assertEqual(
                matching[0][4],
                1,
            )

        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
