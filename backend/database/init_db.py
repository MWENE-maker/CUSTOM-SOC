from backend.core.logger import get_logger
from backend.database.connection import get_connection
from backend.database.schema import (
    EVENT_COLUMN_MIGRATIONS,
    SCHEMA,
)


logger = get_logger(__name__)


def migrate_events_table(
    connection,
) -> None:
    existing_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(events)"
        ).fetchall()
    }

    for column_name, column_type in (
        EVENT_COLUMN_MIGRATIONS.items()
    ):
        if column_name not in existing_columns:
            connection.execute(
                f"""
                ALTER TABLE events
                ADD COLUMN {column_name} {column_type}
                """
            )

            logger.info(
                "Added events column: %s",
                column_name,
            )


def initialize_database() -> None:
    connection = get_connection()

    try:
        connection.executescript(
            SCHEMA
        )

        migrate_events_table(
            connection
        )

        connection.commit()

        logger.info(
            "Database initialized successfully"
        )

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()