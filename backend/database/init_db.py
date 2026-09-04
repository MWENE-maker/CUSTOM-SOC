from backend.core.logger import get_logger
from backend.database.connection import get_connection
from backend.database.schema import SCHEMA


logger = get_logger(__name__)


def initialize_database() -> None:
    connection = get_connection()

    try:
        connection.executescript(SCHEMA)
        connection.commit()

        logger.info(
            "Database initialized successfully"
        )

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()