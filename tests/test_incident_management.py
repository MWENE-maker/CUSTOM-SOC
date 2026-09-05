import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.core import config
from backend.database.connection import get_connection
from backend.database.init_db import initialize_database
from backend.services.incident_service import (
    add_incident_note,
    assign_incident,
    get_incident,
    get_incident_history,
    list_incidents,
    set_incident_resolution,
    update_incident_status,
)


class TestIncidentManagement(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.original_database_path = (
            config.settings.DATABASE_PATH
        )

        config.settings.DATABASE_PATH = str(
            Path(self.temp_dir.name)
            / "test_custom_soc.db"
        )

        initialize_database()

        connection = get_connection()

        try:
            now = "2026-09-05T00:00:00+00:00"

            cursor = connection.execute(
                """
                INSERT INTO investigations (
                    title,
                    status,
                    severity,
                    assigned_to,
                    summary,
                    findings,
                    disposition,
                    created_at,
                    updated_at,
                    closed_at
                )
                VALUES (
                    ?,
                    'resolved',
                    'HIGH',
                    ?,
                    ?,
                    ?,
                    'confirmed_incident',
                    ?,
                    ?,
                    NULL
                )
                """,
                (
                    "Repeated failed login investigation",
                    "SOC Analyst 1",
                    "Possible credential attack",
                    "Multiple authentication failures observed",
                    now,
                    now,
                ),
            )

            self.investigation_id = cursor.lastrowid

            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    title,
                    severity,
                    status,
                    description,
                    created_at,
                    closed_at,
                    investigation_id,
                    assigned_to,
                    updated_at,
                    resolution
                )
                VALUES (
                    ?,
                    'HIGH',
                    'open',
                    ?,
                    ?,
                    NULL,
                    ?,
                    ?,
                    ?,
                    NULL
                )
                """,
                (
                    "Repeated failed login investigation",
                    "Possible credential attack",
                    now,
                    self.investigation_id,
                    "SOC Analyst 1",
                    now,
                ),
            )

            self.incident_id = cursor.lastrowid

            connection.execute(
                """
                INSERT INTO incident_history (
                    incident_id,
                    action,
                    old_value,
                    new_value,
                    note,
                    analyst,
                    created_at
                )
                VALUES (?, 'created', NULL, 'open', ?, ?, ?)
                """,
                (
                    self.incident_id,
                    "Test incident created",
                    "SOC Analyst 1",
                    now,
                ),
            )

            connection.commit()

        finally:
            connection.close()

    def tearDown(self):
        config.settings.DATABASE_PATH = (
            self.original_database_path
        )

        self.temp_dir.cleanup()

    def advance_to_recovered(self):
        update_incident_status(
            self.incident_id,
            "contained",
            analyst="SOC Analyst 1",
        )

        update_incident_status(
            self.incident_id,
            "eradicated",
            analyst="SOC Analyst 1",
        )

        update_incident_status(
            self.incident_id,
            "recovered",
            analyst="SOC Analyst 1",
        )

    def close_incident(self):
        self.advance_to_recovered()

        set_incident_resolution(
            self.incident_id,
            "Threat contained and affected credentials reset.",
            analyst="SOC Analyst 1",
        )

        update_incident_status(
            self.incident_id,
            "closed",
            analyst="SOC Analyst 1",
        )

    def test_get_incident(self):
        incident = get_incident(
            self.incident_id
        )

        self.assertEqual(
            incident["id"],
            self.incident_id,
        )

        self.assertEqual(
            incident["status"],
            "open",
        )

    def test_assign_incident(self):
        assign_incident(
            self.incident_id,
            "SOC Analyst 2",
            analyst="SOC Lead",
        )

        incident = get_incident(
            self.incident_id
        )

        self.assertEqual(
            incident["assigned_to"],
            "SOC Analyst 2",
        )

    def test_empty_assignment_rejected(self):
        with self.assertRaises(ValueError):
            assign_incident(
                self.incident_id,
                "   ",
            )

    def test_assignment_creates_history(self):
        assign_incident(
            self.incident_id,
            "SOC Analyst 2",
            analyst="SOC Lead",
        )

        history = get_incident_history(
            self.incident_id
        )

        self.assertEqual(
            history[-1]["action"],
            "assigned",
        )

        self.assertEqual(
            history[-1]["new_value"],
            "SOC Analyst 2",
        )

    def test_add_incident_note(self):
        add_incident_note(
            self.incident_id,
            "IP address added to containment review.",
            analyst="SOC Analyst 1",
        )

        history = get_incident_history(
            self.incident_id
        )

        self.assertEqual(
            history[-1]["action"],
            "note_added",
        )

    def test_empty_note_rejected(self):
        with self.assertRaises(ValueError):
            add_incident_note(
                self.incident_id,
                "   ",
            )

    def test_set_resolution(self):
        set_incident_resolution(
            self.incident_id,
            "Credential exposure mitigated.",
            analyst="SOC Analyst 1",
        )

        incident = get_incident(
            self.incident_id
        )

        self.assertEqual(
            incident["resolution"],
            "Credential exposure mitigated.",
        )

    def test_empty_resolution_rejected(self):
        with self.assertRaises(ValueError):
            set_incident_resolution(
                self.incident_id,
                "   ",
            )

    def test_valid_incident_lifecycle(self):
        self.advance_to_recovered()

        incident = get_incident(
            self.incident_id
        )

        self.assertEqual(
            incident["status"],
            "recovered",
        )

    def test_full_lifecycle_can_close(self):
        self.close_incident()

        incident = get_incident(
            self.incident_id
        )

        self.assertEqual(
            incident["status"],
            "closed",
        )

        self.assertIsNotNone(
            incident["closed_at"]
        )

    def test_open_to_closed_rejected(self):
        with self.assertRaises(ValueError):
            update_incident_status(
                self.incident_id,
                "closed",
            )

    def test_open_to_eradicated_rejected(self):
        with self.assertRaises(ValueError):
            update_incident_status(
                self.incident_id,
                "eradicated",
            )

    def test_contained_to_recovered_rejected(self):
        update_incident_status(
            self.incident_id,
            "contained",
        )

        with self.assertRaises(ValueError):
            update_incident_status(
                self.incident_id,
                "recovered",
            )

    def test_recovered_requires_resolution_before_closure(self):
        self.advance_to_recovered()

        with self.assertRaises(ValueError):
            update_incident_status(
                self.incident_id,
                "closed",
            )

    def test_closed_incident_cannot_reopen(self):
        self.close_incident()

        with self.assertRaises(ValueError):
            update_incident_status(
                self.incident_id,
                "open",
            )

    def test_closed_incident_rejects_assignment(self):
        self.close_incident()

        with self.assertRaises(ValueError):
            assign_incident(
                self.incident_id,
                "SOC Analyst 3",
            )

    def test_closed_incident_rejects_note(self):
        self.close_incident()

        with self.assertRaises(ValueError):
            add_incident_note(
                self.incident_id,
                "Late note",
            )

    def test_closed_incident_rejects_resolution_change(self):
        self.close_incident()

        with self.assertRaises(ValueError):
            set_incident_resolution(
                self.incident_id,
                "Changed after closure",
            )

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            update_incident_status(
                self.incident_id,
                "destroyed",
            )

    def test_same_status_rejected(self):
        with self.assertRaises(ValueError):
            update_incident_status(
                self.incident_id,
                "open",
            )

    def test_status_changes_create_history(self):
        update_incident_status(
            self.incident_id,
            "contained",
            analyst="SOC Analyst 1",
        )

        history = get_incident_history(
            self.incident_id
        )

        self.assertEqual(
            history[-1]["action"],
            "status_changed",
        )

        self.assertEqual(
            history[-1]["old_value"],
            "open",
        )

        self.assertEqual(
            history[-1]["new_value"],
            "contained",
        )

    def test_resolution_creates_history(self):
        set_incident_resolution(
            self.incident_id,
            "Threat mitigated.",
            analyst="SOC Analyst 1",
        )

        history = get_incident_history(
            self.incident_id
        )

        self.assertEqual(
            history[-1]["action"],
            "resolution_updated",
        )

    def test_history_foreign_key_rejects_orphan(self):
        connection = get_connection()

        try:
            with self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    """
                    INSERT INTO incident_history (
                        incident_id,
                        action,
                        created_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        999999,
                        "test",
                        "2026-09-05T00:00:00+00:00",
                    ),
                )

        finally:
            connection.rollback()
            connection.close()

    def test_list_incidents(self):
        incidents = list_incidents()

        self.assertEqual(
            len(incidents),
            1,
        )

    def test_list_incidents_by_status(self):
        incidents = list_incidents(
            status="open"
        )

        self.assertEqual(
            len(incidents),
            1,
        )

    def test_invalid_list_status_rejected(self):
        with self.assertRaises(ValueError):
            list_incidents(
                status="invalid"
            )


if __name__ == "__main__":
    unittest.main()