import unittest

from backend.detection_engine.engine import (
    evaluate_event,
)
from backend.log_ingestion.web_log_parser import (
    normalize_web_log,
)


class TestDetectionEngine(unittest.TestCase):

    def test_clean_event_has_no_matches(self):
        event = normalize_web_log(
            "192.168.1.10 GET /index.html 200 1540"
        )

        matches = evaluate_event(event)

        self.assertEqual(
            len(matches),
            0,
        )

    def test_admin_denied_rule_matches(self):
        event = normalize_web_log(
            "192.168.1.25 GET /admin 403 321"
        )

        matches = evaluate_event(event)

        rule_names = [
            rule.name
            for rule in matches
        ]

        self.assertIn(
            "WEB_ADMIN_ACCESS_DENIED",
            rule_names,
        )

    def test_failed_login_rule_matches(self):
        event = normalize_web_log(
            "192.168.1.30 POST /login 401 412"
        )

        matches = evaluate_event(event)

        rule_names = [
            rule.name
            for rule in matches
        ]

        self.assertIn(
            "WEB_FAILED_LOGIN",
            rule_names,
        )

    def test_server_error_does_not_alert(self):
        event = normalize_web_log(
            "192.168.1.40 GET /api/data 500 90"
        )

        matches = evaluate_event(event)

        self.assertEqual(
            len(matches),
            0,
        )


if __name__ == "__main__":
    unittest.main()