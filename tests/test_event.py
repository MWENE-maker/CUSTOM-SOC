import unittest

from backend.models.event import SecurityEvent


class TestSecurityEvent(unittest.TestCase):

    def test_create_security_event(self):
        event = SecurityEvent.create(
            source="test-source",
            event_type="TEST_EVENT",
            severity="medium",
            message="Test security event",
        )

        self.assertEqual(
            event.source,
            "test-source",
        )

        self.assertEqual(
            event.event_type,
            "TEST_EVENT",
        )

        self.assertEqual(
            event.severity,
            "MEDIUM",
        )

        self.assertEqual(
            event.message,
            "Test security event",
        )

        self.assertIsNotNone(
            event.timestamp,
        )

    def test_event_to_dict(self):
        event = SecurityEvent.create(
            source="test-source",
            event_type="TEST_EVENT",
            severity="low",
            message="Dictionary test",
        )

        event_dict = event.to_dict()

        self.assertEqual(
            event_dict["severity"],
            "LOW",
        )

        self.assertEqual(
            event_dict["source"],
            "test-source",
        )


if __name__ == "__main__":
    unittest.main()
    