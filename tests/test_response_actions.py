import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.core import config
from backend.database.connection import get_connection
from backend.database.init_db import initialize_database
from backend.services.response_action_service import (
    approve_response_action,
    cancel_response_action,
    execute_response_action,
    fail_response_action,
    get_response_action,
    list_response_actions,
    propose_response_action,
)


class TestResponseActions(unittest.TestCase):

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
                    disposition,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?,
                    'resolved',
                    'HIGH',
                    'confirmed_incident',
                    ?,
                    ?
                )
                """,
                (
                    "Response action test investigation",
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
                    created_at,
                    investigation_id,
                    updated_at
                )
                VALUES (
                    ?,
                    'HIGH',
                    'open',
                    ?,
                    ?,
                    ?
                )
                """,
                (
                    "Response action test incident",
                    now,
                    self.investigation_id,
                    now,
                ),
            )

            self.incident_id = cursor.lastrowid

            connection.commit()

        finally:
            connection.close()

    def tearDown(self):
        config.settings.DATABASE_PATH = (
            self.original_database_path
        )

        self.temp_dir.cleanup()

    def propose_action(
        self,
        action_type="block_ip",
        target="192.168.50.20",
    ):
        return propose_response_action(
            self.incident_id,
            action_type,
            target,
            requested_by="SOC Analyst 1",
            notes="Controlled response test",
        )

    def test_propose_response_action(self):
        action_id = self.propose_action()

        action = get_response_action(
            action_id
        )

        self.assertEqual(
            action["status"],
            "proposed",
        )

    def test_invalid_action_type_rejected(self):
        with self.assertRaises(ValueError):
            propose_response_action(
                self.incident_id,
                "launch_missile",
                "test",
                requested_by="SOC Analyst 1",
            )

    def test_empty_requester_rejected(self):
        with self.assertRaises(ValueError):
            propose_response_action(
                self.incident_id,
                "block_ip",
                "192.168.50.20",
                requested_by="   ",
            )

    def test_missing_incident_rejected(self):
        with self.assertRaises(ValueError):
            propose_response_action(
                999999,
                "block_ip",
                "192.168.50.20",
                requested_by="SOC Analyst 1",
            )

    def test_approve_response_action(self):
        action_id = self.propose_action()

        approve_response_action(
            action_id,
            approved_by="SOC Lead",
        )

        action = get_response_action(
            action_id
        )

        self.assertEqual(
            action["status"],
            "approved",
        )

        self.assertEqual(
            action["approved_by"],
            "SOC Lead",
        )

        self.assertIsNotNone(
            action["approved_at"]
        )

    def test_execute_requires_approval(self):
        action_id = self.propose_action()

        with self.assertRaises(ValueError):
            execute_response_action(
                action_id,
                analyst="SOC Analyst 1",
            )

    def test_execute_approved_action(self):
        action_id = self.propose_action()

        approve_response_action(
            action_id,
            approved_by="SOC Lead",
        )

        execute_response_action(
            action_id,
            analyst="SOC Analyst 1",
        )

        action = get_response_action(
            action_id
        )

        self.assertEqual(
            action["status"],
            "executed",
        )

        self.assertIn(
            "SIMULATED EXECUTION ONLY",
            action["result"],
        )

        self.assertIsNotNone(
            action["executed_at"]
        )

    def test_executed_action_cannot_execute_again(self):
        action_id = self.propose_action()

        approve_response_action(
            action_id,
            approved_by="SOC Lead",
        )

        execute_response_action(
            action_id,
            analyst="SOC Analyst 1",
        )

        with self.assertRaises(ValueError):
            execute_response_action(
                action_id,
                analyst="SOC Analyst 1",
            )

    def test_failed_action(self):
        action_id = self.propose_action()

        approve_response_action(
            action_id,
            approved_by="SOC Lead",
        )

        fail_response_action(
            action_id,
            "Simulated action could not complete.",
            analyst="SOC Analyst 1",
        )

        action = get_response_action(
            action_id
        )

        self.assertEqual(
            action["status"],
            "failed",
        )

    def test_failure_requires_approval(self):
        action_id = self.propose_action()

        with self.assertRaises(ValueError):
            fail_response_action(
                action_id,
                "Failure",
                analyst="SOC Analyst 1",
            )

    def test_cancel_proposed_action(self):
        action_id = self.propose_action()

        cancel_response_action(
            action_id,
            analyst="SOC Analyst 1",
            reason="No longer required",
        )

        action = get_response_action(
            action_id
        )

        self.assertEqual(
            action["status"],
            "cancelled",
        )

    def test_cancel_approved_action(self):
        action_id = self.propose_action()

        approve_response_action(
            action_id,
            approved_by="SOC Lead",
        )

        cancel_response_action(
            action_id,
            analyst="SOC Lead",
            reason="Change in containment plan",
        )

        action = get_response_action(
            action_id
        )

        self.assertEqual(
            action["status"],
            "cancelled",
        )

    def test_executed_action_cannot_cancel(self):
        action_id = self.propose_action()

        approve_response_action(
            action_id,
            approved_by="SOC Lead",
        )

        execute_response_action(
            action_id,
            analyst="SOC Analyst 1",
        )

        with self.assertRaises(ValueError):
            cancel_response_action(
                action_id,
                analyst="SOC Lead",
            )

    def test_list_response_actions(self):
        self.propose_action()
        self.propose_action(
            action_type="collect_evidence",
            target="web-server-01",
        )

        actions = list_response_actions(
            incident_id=self.incident_id
        )

        self.assertEqual(
            len(actions),
            2,
        )

    def test_list_response_actions_by_status(self):
        action_id = self.propose_action()

        approve_response_action(
            action_id,
            approved_by="SOC Lead",
        )

        approved = list_response_actions(
            incident_id=self.incident_id,
            status="approved",
        )

        self.assertEqual(
            len(approved),
            1,
        )

    def test_invalid_list_status_rejected(self):
        with self.assertRaises(ValueError):
            list_response_actions(
                status="unknown",
            )

    def test_closed_incident_rejects_new_action(self):
        connection = get_connection()

        try:
            connection.execute(
                """
                UPDATE incidents
                SET status = 'closed'
                WHERE id = ?
                """,
                (self.incident_id,),
            )

            connection.commit()

        finally:
            connection.close()

        with self.assertRaises(ValueError):
            self.propose_action()

    def test_response_action_fk_rejects_orphan(self):
        connection = get_connection()

        try:
            with self.assertRaises(
                sqlite3.IntegrityError
            ):
                connection.execute(
                    """
                    INSERT INTO response_actions (
                        incident_id,
                        action_type,
                        status,
                        created_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        999999,
                        "block_ip",
                        "proposed",
                        "2026-09-05T00:00:00+00:00",
                    ),
                )

        finally:
            connection.rollback()
            connection.close()


if __name__ == "__main__":
    unittest.main()