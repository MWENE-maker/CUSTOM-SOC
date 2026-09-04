from backend.core.config import settings
from backend.core.logger import get_logger


logger = get_logger(__name__)


def main():
    logger.info("%s starting", settings.APP_NAME)

    print(settings.APP_NAME)
    print("Cybersecurity Operations & Detection Platform")
    print(f"Environment: {settings.APP_ENV}")
    print("Status: Configuration and logging initialized")

    logger.info("Application initialization completed")


if __name__ == "__main__":
    main()