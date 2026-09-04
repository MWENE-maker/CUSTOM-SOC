import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.core.config import settings
from backend.database.connection import get_connection
from backend.database.init_db import initialize_database
from backend.detection_engine.rule import DetectionRule
from backend.models.event import SecurityEvent
from backend.services.alert_service import (
    add_alert_note,
    assign_alert,
    create_alert,
    get_alert,
    get_alert_history,
    list_alerts,
    update_alert_status,
)
from backend.services.event_service import save_event


class TestAlertManagement(unittest.TestCase):

    def setUp(self):
        self.original_database_path = (
            settings.DATABASE_PATH
        )

        self.temp_directory = (
            tempfile.TemporaryDirectory()
        )

        settings.DATABASE_PATH = str(
            Path(
                self.temp_directory.name
            )
            / "alert_management.db"
        )

        initialize_database()

        self.event = SecurityEvent.create(
            source="test-source",
            event_type="HTTP_REQUEST",
            severity="MEDIUM",
            message="Test alert event",
            source_ip="192.168.100.10",
            http_method="POST",
            http_path="/login",
            http_status=401,
            response_size=200,
        )

        self.event_id = save_event(
            self.event
        )

        self.rule = DetectionRule(
            name="TEST_ALERT_RULE",
            description="Test alert rule",
            severity="MEDIUM",
            condition=lambda event: True,
        )

        self.alert_id = create_alert(
            self.event_id,
            self.rule,
        )

    def tearDown(self):
        settings.DATABASE_PATH = (
            self.original_database_path
        )

        self.temp_directory.cleanup()

    def test_get_alert(self):
        alert = get_alert(
            self.alert_id
        )

        self.assertIsNotNone(
            alert
        )

        self.assertEqual(
            alert["id"],
            self.alert_id,
        )

        self.assertEqual(
            alert["status"],
            "open",
        )

        self.assertEqual(
            alert["rule_name"],
            "TEST_ALERT_RULE",
        )

        self.assertIsNotNone(
            alert["created_at"]
        )

        self.assertIsNotNone(
            alert["updated_at"]
        )

    def test_list_alerts(self):
        alerts = list_alerts()

        self.assertEqual(
            len(alerts),
            1,
        )

        self.assertEqual(
            alerts[0]["id"],
            self.alert_id,
        )

    def test_list_alerts_by_status(self):
        update_alert_status(
            self.alert_id,
            "acknowledged",
        )

        acknowledged_alerts = (
            list_alerts(
                status="acknowledged"
            )
        )

        open_alerts = (
            list_alerts(
                status="open"
            )
        )

        self.assertEqual(
            len(acknowledged_alerts),
            1,
        )

        self.assertEqual(
            len(open_alerts),
            0,
        )

    def test_valid_alert_lifecycle(self):
        update_alert_status(
            self.alert_id,
            "acknowledged",
        )

        update_alert_status(
            self.alert_id,
            "investigating",
        )

        update_alert_status(
            self.alert_id,
            "resolved",
        )

        update_alert_status(
            self.alert_id,
            "closed",
        )

        alert = get_alert(
            self.alert_id
        )

        self.assertEqual(
            alert["status"],
            "closed",
        )

    def test_invalid_status_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            update_alert_status(
                self.alert_id,
                "hacked",
            )

    def test_invalid_status_jump_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            update_alert_status(
                self.alert_id,
                "investigating",
            )

        alert = get_alert(
            self.alert_id
        )

        self.assertEqual(
            alert["status"],
            "open",
        )

    def test_closed_alert_cannot_reopen(self):
        update_alert_status(
            self.alert_id,
            "acknowledged",
        )

        update_alert_status(
            self.alert_id,
            "investigating",
        )

        update_alert_status(
            self.alert_id,
            "resolved",
        )

        update_alert_status(
            self.alert_id,
            "closed",
        )

        with self.assertRaises(
            ValueError
        ):
            update_alert_status(
                self.alert_id,
                "open",
            )

        alert = get_alert(
            self.alert_id
        )

        self.assertEqual(
            alert["status"],
            "closed",
        )

    def test_assign_alert(self):
        assign_alert(
            self.alert_id,
            "SOC Analyst 1",
        )

        alert = get_alert(
            self.alert_id
        )

        self.assertEqual(
            alert["assigned_to"],
            "SOC Analyst 1",
        )

    def test_empty_assignment_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            assign_alert(
                self.alert_id,
                "   ",
            )

    def test_add_alert_note(self):
        add_alert_note(
            self.alert_id,
            "Reviewed authentication activity.",
        )

        alert = get_alert(
            self.alert_id
        )

        self.assertIn(
            "Reviewed authentication activity.",
            alert["analyst_notes"],
        )

    def test_multiple_notes_are_preserved(self):
        add_alert_note(
            self.alert_id,
            "First analyst note.",
        )

        add_alert_note(
            self.alert_id,
            "Second analyst note.",
        )

        alert = get_alert(
            self.alert_id
        )

        self.assertIn(
            "First analyst note.",
            alert["analyst_notes"],
        )

        self.assertIn(
            "Second analyst note.",
            alert["analyst_notes"],
        )

    def test_empty_note_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            add_alert_note(
                self.alert_id,
                "   ",
            )

    def test_missing_alert_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            update_alert_status(
                999999,
                "acknowledged",
            )

    def test_alert_history_table_exists(self):
        connection = get_connection()

        try:
            row = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'alert_history'
                """
            ).fetchone()

            self.assertIsNotNone(
                row
            )

        finally:
            connection.close()

    def test_alert_creation_creates_history(self):
        history = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history),
            1,
        )

        entry = history[0]

        self.assertEqual(
            entry["action"],
            "created",
        )

        self.assertIsNone(
            entry["old_value"]
        )

        self.assertEqual(
            entry["new_value"],
            "open",
        )

        self.assertIsNotNone(
            entry["created_at"]
        )

    def test_status_changes_create_history(self):
        update_alert_status(
            self.alert_id,
            "acknowledged",
            analyst="SOC Analyst 1",
        )

        history = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history),
            2,
        )

        status_entry = history[1]

        self.assertEqual(
            status_entry["action"],
            "status_changed",
        )

        self.assertEqual(
            status_entry["old_value"],
            "open",
        )

        self.assertEqual(
            status_entry["new_value"],
            "acknowledged",
        )

        self.assertEqual(
            status_entry["analyst"],
            "SOC Analyst 1",
        )

    def test_full_lifecycle_is_preserved_in_history(self):
        update_alert_status(
            self.alert_id,
            "acknowledged",
            analyst="SOC Analyst 1",
        )

        update_alert_status(
            self.alert_id,
            "investigating",
            analyst="SOC Analyst 1",
        )

        update_alert_status(
            self.alert_id,
            "resolved",
            analyst="SOC Analyst 1",
        )

        update_alert_status(
            self.alert_id,
            "closed",
            analyst="SOC Analyst 1",
        )

        history = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history),
            5,
        )

        actions = [
            entry["action"]
            for entry in history
        ]

        self.assertEqual(
            actions,
            [
                "created",
                "status_changed",
                "status_changed",
                "status_changed",
                "status_changed",
            ],
        )

        transitions = [
            (
                entry["old_value"],
                entry["new_value"],
            )
            for entry in history[1:]
        ]

        self.assertEqual(
            transitions,
            [
                (
                    "open",
                    "acknowledged",
                ),
                (
                    "acknowledged",
                    "investigating",
                ),
                (
                    "investigating",
                    "resolved",
                ),
                (
                    "resolved",
                    "closed",
                ),
            ],
        )

    def test_assignment_creates_history(self):
        assign_alert(
            self.alert_id,
            "SOC Analyst 1",
        )

        history = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history),
            2,
        )

        assignment_entry = history[1]

        self.assertEqual(
            assignment_entry["action"],
            "assigned",
        )

        self.assertIsNone(
            assignment_entry["old_value"]
        )

        self.assertEqual(
            assignment_entry["new_value"],
            "SOC Analyst 1",
        )

        self.assertEqual(
            assignment_entry["analyst"],
            "SOC Analyst 1",
        )

    def test_reassignment_preserves_old_and_new_values(self):
        assign_alert(
            self.alert_id,
            "SOC Analyst 1",
        )

        assign_alert(
            self.alert_id,
            "SOC Analyst 2",
        )

        history = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history),
            3,
        )

        reassignment_entry = history[2]

        self.assertEqual(
            reassignment_entry["action"],
            "assigned",
        )

        self.assertEqual(
            reassignment_entry["old_value"],
            "SOC Analyst 1",
        )

        self.assertEqual(
            reassignment_entry["new_value"],
            "SOC Analyst 2",
        )

    def test_notes_create_separate_history_entries(self):
        add_alert_note(
            self.alert_id,
            "First analyst note.",
            analyst="SOC Analyst 1",
        )

        add_alert_note(
            self.alert_id,
            "Second analyst note.",
            analyst="SOC Analyst 1",
        )

        history = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history),
            3,
        )

        first_note = history[1]
        second_note = history[2]

        self.assertEqual(
            first_note["action"],
            "note_added",
        )

        self.assertEqual(
            first_note["note"],
            "First analyst note.",
        )

        self.assertEqual(
            second_note["action"],
            "note_added",
        )

        self.assertEqual(
            second_note["note"],
            "Second analyst note.",
        )

        self.assertEqual(
            first_note["analyst"],
            "SOC Analyst 1",
        )

        self.assertEqual(
            second_note["analyst"],
            "SOC Analyst 1",
        )

    def test_invalid_transition_does_not_create_history(self):
        history_before = get_alert_history(
            self.alert_id
        )

        with self.assertRaises(
            ValueError
        ):
            update_alert_status(
                self.alert_id,
                "investigating",
                analyst="SOC Analyst 1",
            )

        history_after = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history_before),
            1,
        )

        self.assertEqual(
            len(history_after),
            1,
        )

        self.assertEqual(
            history_after[0]["action"],
            "created",
        )

    def test_empty_assignment_does_not_create_history(self):
        history_before = get_alert_history(
            self.alert_id
        )

        with self.assertRaises(
            ValueError
        ):
            assign_alert(
                self.alert_id,
                "   ",
            )

        history_after = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history_before),
            len(history_after),
        )

    def test_empty_note_does_not_create_history(self):
        history_before = get_alert_history(
            self.alert_id
        )

        with self.assertRaises(
            ValueError
        ):
            add_alert_note(
                self.alert_id,
                "   ",
                analyst="SOC Analyst 1",
            )

        history_after = get_alert_history(
            self.alert_id
        )

        self.assertEqual(
            len(history_before),
            len(history_after),
        )

    def test_missing_alert_history_rejected(self):
        with self.assertRaises(
            ValueError
        ):
            get_alert_history(
                999999
            )

    def test_alert_history_foreign_key_rejects_orphan(self):
        connection = get_connection()

        try:
            with self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    """
                    INSERT INTO alert_history (
                        alert_id,
                        action,
                        old_value,
                        new_value,
                        note,
                        analyst,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        999999,
                        "status_changed",
                        "open",
                        "acknowledged",
                        None,
                        "SOC Analyst 1",
                        "2026-09-05T00:00:00+00:00",
                    ),
                )

                connection.commit()

        finally:
            connection.rollback()
            connection.close()


if __name__ == "__main__":
    unittest.main()