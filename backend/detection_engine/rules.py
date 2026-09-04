from backend.detection_engine.rule import DetectionRule
from backend.models.event import SecurityEvent


def admin_access_denied(
    event: SecurityEvent,
) -> bool:
    return (
        event.event_type == "HTTP_REQUEST"
        and "/admin" in event.message
        and "HTTP 403" in event.message
    )


def failed_login(
    event: SecurityEvent,
) -> bool:
    return (
        event.event_type == "HTTP_REQUEST"
        and "/login" in event.message
        and "HTTP 401" in event.message
    )


DETECTION_RULES = [
    DetectionRule(
        name="WEB_ADMIN_ACCESS_DENIED",
        description=(
            "Access to an administrative web path "
            "was denied."
        ),
        severity="MEDIUM",
        condition=admin_access_denied,
    ),
    DetectionRule(
        name="WEB_FAILED_LOGIN",
        description=(
            "A web login attempt returned "
            "HTTP 401."
        ),
        severity="MEDIUM",
        condition=failed_login,
    ),
]