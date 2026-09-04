import re
from dataclasses import dataclass

from backend.models.event import SecurityEvent


WEB_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) '
    r'(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) '
    r'(?P<path>\S+) '
    r'(?P<status>\d{3}) '
    r'(?P<size>\d+)$'
)


@dataclass
class ParsedWebLog:
    ip: str
    method: str
    path: str
    status: int
    size: int


def parse_web_log(log_line: str) -> ParsedWebLog:
    match = WEB_LOG_PATTERN.match(log_line.strip())

    if not match:
        raise ValueError(
            f"Invalid web log format: {log_line}"
        )

    return ParsedWebLog(
        ip=match.group("ip"),
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        size=int(match.group("size")),
    )


def determine_severity(parsed_log: ParsedWebLog) -> str:
    if parsed_log.status >= 500:
        return "HIGH"

    if parsed_log.status >= 400:
        return "MEDIUM"

    return "LOW"


def normalize_web_log(
    log_line: str,
) -> SecurityEvent:
    parsed = parse_web_log(log_line)

    severity = determine_severity(parsed)

    return SecurityEvent.create(
        source="web-access-log",
        event_type="HTTP_REQUEST",
        severity=severity,
        message=(
            f"{parsed.method} {parsed.path} "
            f"returned HTTP {parsed.status}"
        ),
        raw_data=log_line,
    )