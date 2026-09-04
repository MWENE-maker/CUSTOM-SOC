import unittest

from backend.log_ingestion.web_log_parser import (
    determine_severity,
    normalize_web_log,
    parse_web_log,
)


class TestWebLogParser(unittest.TestCase):

    def test_parse_valid_web_log(self):
        parsed = parse_web_log(
            "192.168.1.25 GET /admin 403 321"
        )

        self.assertEqual(
            parsed.ip,
            "192.168.1.25",
        )

        self.assertEqual(
            parsed.method,
            "GET",
        )

        self.assertEqual(
            parsed.path,
            "/admin",
        )

        self.assertEqual(
            parsed.status,
            403,
        )

        self.assertEqual(
            parsed.size,
            321,
        )

    def test_invalid_web_log_rejected(self):
        with self.assertRaises(ValueError):
            parse_web_log(
                "THIS IS NOT A VALID WEB LOG"
            )

    def test_normalize_web_log(self):
        event = normalize_web_log(
            "192.168.1.10 GET /index.html 200 1540"
        )

        self.assertEqual(
            event.source,
            "web-access-log",
        )

        self.assertEqual(
            event.event_type,
            "HTTP_REQUEST",
        )

        self.assertEqual(
            event.severity,
            "LOW",
        )

    def test_severity_mapping(self):
        test_cases = [
            (
                "192.168.1.10 GET / 200 100",
                "LOW",
            ),
            (
                "192.168.1.10 GET / 403 100",
                "MEDIUM",
            ),
            (
                "192.168.1.10 GET / 500 100",
                "HIGH",
            ),
        ]

        for log_line, expected in test_cases:
            with self.subTest(
                log_line=log_line
            ):
                parsed = parse_web_log(
                    log_line
                )

                self.assertEqual(
                    determine_severity(parsed),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()