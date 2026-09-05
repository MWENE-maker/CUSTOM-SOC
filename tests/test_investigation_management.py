import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.core.config import settings
from backend.database.init_db import initialize_database
from backend.services.alert_service import create_alert
from backend.services.event_service import save_event
from backend.services.investigation_service import (
    add_investigation_note,
    assign_investigation,
    create_investigation,
    get_investigation,
    get_investigation_alerts,
    get_investigation_history,
    link_alert_to_investigation,
    list_investigations,
    set_investigation_disposition,
    update_investigation_findings,
    update_investigation_status,
)
from backend.models.event import SecurityEvent
from backend.detection_engine.rules import DetectionRule


class TestInvestigationManagement(unittest.TestCase):
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
            severity="MEDIUM",
            message="POST /login returned 401",
            raw_data="controlled test event",
            source_ip="192.168.50.10",
            http_method="POST",
            http_path="/login",
            http_status=401,
            response_size=123,
        )

        
        self.event_id = save_event(
            self.event
        )

        self.rule = DetectionRule(
            name="TEST_INVESTIGATION_RULE",
            severity="HIGH",
            description="Controlled investigation test rule",
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

    def _create_second_alert(self) -> int:
        second_event = SecurityEvent(
            timestamp="2026-09-05T10:01:00+00:00",
            source="web",
            event_type="web_request",
            severity="MEDIUM",
            message="POST /login returned 401 again",
            raw_data="controlled second test event",
            source_ip="192.168.50.10",
            http_method="POST",
            http_path="/login",
            http_status=401,
            response_size=124,
        )

        second_event_id = save_event(
            second_event
        )

        return create_alert(
            second_event_id,
            self.rule,
        )

    def _create_investigation(self) -> int:
        return create_investigation(
            title="Repeated failed-login investigation",
            severity="HIGH",
            alert_ids=[self.alert_id],
            summary="Review repeated failed-login activity.",
            assigned_to="SOC Analyst 1",
        )

    def test_investigation_tables_exist(self) -> None:
        connection = sqlite3.connect(
            settings.DATABASE_PATH
        )

        try:
            tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                ).fetchall()
            }

            self.assertIn(
                "investigations",
                tables,
            )

            self.assertIn(
                "investigation_alerts",
                tables,
            )

            self.assertIn(
                "investigation_history",
                tables,
            )

        finally:
            connection.close()

    def test_create_investigation(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        investigation = get_investigation(
            investigation_id
        )

        self.assertEqual(
            investigation["title"],
            "Repeated failed-login investigation",
        )

        self.assertEqual(
            investigation["status"],
            "open",
        )

        self.assertEqual(
            investigation["severity"],
            "HIGH",
        )

        self.assertEqual(
            investigation["assigned_to"],
            "SOC Analyst 1",
        )

    def test_creation_links_alert(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        alerts = get_investigation_alerts(
            investigation_id
        )

        self.assertEqual(
            len(alerts),
            1,
        )

        self.assertEqual(
            alerts[0]["id"],
            self.alert_id,
        )

    def test_creation_creates_history(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        history = get_investigation_history(
            investigation_id
        )

        self.assertEqual(
            len(history),
            1,
        )

        self.assertEqual(
            history[0]["action"],
            "created",
        )

        self.assertEqual(
            history[0]["new_value"],
            "open",
        )

    def test_empty_title_rejected(self) -> None:
        with self.assertRaises(ValueError):
            create_investigation(
                title="   ",
                severity="HIGH",
                alert_ids=[self.alert_id],
            )

    def test_invalid_severity_rejected(self) -> None:
        with self.assertRaises(ValueError):
            create_investigation(
                title="Test investigation",
                severity="EXTREME",
                alert_ids=[self.alert_id],
            )

    def test_investigation_requires_alert(self) -> None:
        with self.assertRaises(ValueError):
            create_investigation(
                title="Test investigation",
                severity="HIGH",
                alert_ids=[],
            )

    def test_missing_alert_rejected(self) -> None:
        with self.assertRaises(ValueError):
            create_investigation(
                title="Test investigation",
                severity="HIGH",
                alert_ids=[999999],
            )

    def test_duplicate_alert_ids_are_deduplicated(
        self,
    ) -> None:
        investigation_id = create_investigation(
            title="Deduplicated investigation",
            severity="HIGH",
            alert_ids=[
                self.alert_id,
                self.alert_id,
            ],
        )

        alerts = get_investigation_alerts(
            investigation_id
        )

        self.assertEqual(
            len(alerts),
            1,
        )

    def test_link_second_alert(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        second_alert_id = (
            self._create_second_alert()
        )

        link_alert_to_investigation(
            investigation_id,
            second_alert_id,
            analyst="SOC Analyst 1",
        )

        alerts = get_investigation_alerts(
            investigation_id
        )

        self.assertEqual(
            len(alerts),
            2,
        )

    def test_duplicate_alert_link_rejected(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        with self.assertRaises(ValueError):
            link_alert_to_investigation(
                investigation_id,
                self.alert_id,
            )

    def test_missing_investigation_rejected(self) -> None:
        with self.assertRaises(ValueError):
            get_investigation(
                999999
            )

    def test_list_investigations(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        investigations = list_investigations()

        self.assertTrue(
            any(
                item["id"]
                == investigation_id
                for item in investigations
            )
        )

    def test_list_investigations_by_status(
        self,
    ) -> None:
        investigation_id = (
            self._create_investigation()
        )

        investigations = (
            list_investigations(
                status="open"
            )
        )

        self.assertTrue(
            any(
                item["id"]
                == investigation_id
                for item in investigations
            )
        )

    def test_invalid_list_status_rejected(
        self,
    ) -> None:
        with self.assertRaises(ValueError):
            list_investigations(
                status="invalid"
            )

    def test_assign_investigation(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        assign_investigation(
            investigation_id,
            "SOC Analyst 2",
            analyst="SOC Lead",
        )

        investigation = get_investigation(
            investigation_id
        )

        self.assertEqual(
            investigation["assigned_to"],
            "SOC Analyst 2",
        )

    def test_assignment_creates_history(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        assign_investigation(
            investigation_id,
            "SOC Analyst 2",
            analyst="SOC Lead",
        )

        history = get_investigation_history(
            investigation_id
        )

        assignment_entry = history[-1]

        self.assertEqual(
            assignment_entry["action"],
            "assigned",
        )

        self.assertEqual(
            assignment_entry["old_value"],
            "SOC Analyst 1",
        )

        self.assertEqual(
            assignment_entry["new_value"],
            "SOC Analyst 2",
        )

    def test_empty_assignment_rejected(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        with self.assertRaises(ValueError):
            assign_investigation(
                investigation_id,
                "   ",
            )

    def test_update_findings(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        update_investigation_findings(
            investigation_id,
            "Five related failed logins "
            "originated from one source.",
            analyst="SOC Analyst 1",
        )

        investigation = get_investigation(
            investigation_id
        )

        self.assertIn(
            "Five related failed logins",
            investigation["findings"],
        )

    def test_empty_findings_rejected(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        with self.assertRaises(ValueError):
            update_investigation_findings(
                investigation_id,
                "   ",
            )

    def test_valid_disposition(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        set_investigation_disposition(
            investigation_id,
            "confirmed_incident",
            analyst="SOC Analyst 1",
        )

        investigation = get_investigation(
            investigation_id
        )

        self.assertEqual(
            investigation["disposition"],
            "confirmed_incident",
        )

    def test_invalid_disposition_rejected(
        self,
    ) -> None:
        investigation_id = (
            self._create_investigation()
        )

        with self.assertRaises(ValueError):
            set_investigation_disposition(
                investigation_id,
                "malicious_but_unknown",
            )

    def test_valid_status_lifecycle(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        update_investigation_status(
            investigation_id,
            "investigating",
            analyst="SOC Analyst 1",
        )

        set_investigation_disposition(
            investigation_id,
            "inconclusive",
            analyst="SOC Analyst 1",
        )

        update_investigation_status(
            investigation_id,
            "resolved",
            analyst="SOC Analyst 1",
        )

        update_investigation_status(
            investigation_id,
            "closed",
            analyst="SOC Analyst 1",
        )

        investigation = get_investigation(
            investigation_id
        )

        self.assertEqual(
            investigation["status"],
            "closed",
        )

        self.assertIsNotNone(
            investigation["closed_at"]
        )

    def test_invalid_status_jump_rejected(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        with self.assertRaises(ValueError):
            update_investigation_status(
                investigation_id,
                "resolved",
            )

    def test_resolution_requires_disposition(
        self,
    ) -> None:
        investigation_id = (
            self._create_investigation()
        )

        update_investigation_status(
            investigation_id,
            "investigating",
        )

        with self.assertRaises(ValueError):
            update_investigation_status(
                investigation_id,
                "resolved",
            )

    def test_closed_investigation_cannot_reopen(
        self,
    ) -> None:
        investigation_id = (
            self._create_investigation()
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

        update_investigation_status(
            investigation_id,
            "closed",
        )

        with self.assertRaises(ValueError):
            update_investigation_status(
                investigation_id,
                "open",
            )

    def test_closed_investigation_rejects_findings(
        self,
    ) -> None:
        investigation_id = (
            self._create_investigation()
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

        update_investigation_status(
            investigation_id,
            "closed",
        )

        with self.assertRaises(ValueError):
            update_investigation_findings(
                investigation_id,
                "Should not be accepted",
            )

    def test_closed_investigation_rejects_alert_link(
        self,
    ) -> None:
        investigation_id = (
            self._create_investigation()
        )

        second_alert_id = (
            self._create_second_alert()
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

        update_investigation_status(
            investigation_id,
            "closed",
        )

        with self.assertRaises(ValueError):
            link_alert_to_investigation(
                investigation_id,
                second_alert_id,
            )

    def test_add_note(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        add_investigation_note(
            investigation_id,
            "Reviewed source IP activity.",
            analyst="SOC Analyst 1",
        )

        history = get_investigation_history(
            investigation_id
        )

        note_entry = history[-1]

        self.assertEqual(
            note_entry["action"],
            "note_added",
        )

        self.assertEqual(
            note_entry["note"],
            "Reviewed source IP activity.",
        )

    def test_empty_note_rejected(self) -> None:
        investigation_id = (
            self._create_investigation()
        )

        with self.assertRaises(ValueError):
            add_investigation_note(
                investigation_id,
                "   ",
            )

    def test_history_preserves_full_lifecycle(
        self,
    ) -> None:
        investigation_id = (
            self._create_investigation()
        )

        update_investigation_status(
            investigation_id,
            "investigating",
        )

        update_investigation_findings(
            investigation_id,
            "Controlled findings",
        )

        set_investigation_disposition(
            investigation_id,
            "false_positive",
        )

        update_investigation_status(
            investigation_id,
            "resolved",
        )

        update_investigation_status(
            investigation_id,
            "closed",
        )

        history = get_investigation_history(
            investigation_id
        )

        actions = [
            entry["action"]
            for entry in history
        ]

        self.assertEqual(
            actions,
            [
                "created",
                "status_updated",
                "findings_updated",
                "disposition_updated",
                "status_updated",
                "status_updated",
            ],
        )

    def test_investigation_alert_foreign_key_rejects_orphan(
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
                    INSERT INTO investigation_alerts (
                        investigation_id,
                        alert_id,
                        linked_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        999999,
                        self.alert_id,
                        "2026-09-05T10:00:00+00:00",
                    ),
                )

        finally:
            connection.close()

    def test_investigation_history_foreign_key_rejects_orphan(
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
                    INSERT INTO investigation_history (
                        investigation_id,
                        action,
                        created_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        999999,
                        "test",
                        "2026-09-05T10:00:00+00:00",
                    ),
                )

        finally:
            connection.close()

    def test_closed_investigation_rejects_assignment(
        self,
    ) -> None:
        investigation_id = self._create_investigation()

        update_investigation_status(
            investigation_id,
            "investigating",
            analyst="SOC Analyst 1",
        )

        set_investigation_disposition(
            investigation_id,
            "benign",
            analyst="SOC Analyst 1",
        )

        update_investigation_status(
            investigation_id,
            "resolved",
            analyst="SOC Analyst 1",
        )

        update_investigation_status(
            investigation_id,
            "closed",
            analyst="SOC Analyst 1",
        )

        with self.assertRaises(ValueError):
            assign_investigation(
                investigation_id,
                "SOC Analyst 2",
                analyst="SOC Lead",
            )


if __name__ == "__main__":
    unittest.main()
