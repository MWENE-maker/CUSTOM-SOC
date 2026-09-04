from backend.core.logger import get_logger
from backend.database.connection import get_connection
from backend.database.schema import (
    ALERT_COLUMN_MIGRATIONS,
    EVENT_COLUMN_MIGRATIONS,
    SCHEMA,
)


logger = get_logger(__name__)


def migrate_table_columns(
    connection,
    table_name: str,
    migrations: dict[str, str],
) -> None:
    """
    Add missing columns to an existing SQLite table.

    Column definitions are supplied only from
    trusted, hardcoded migration dictionaries.
    """
    existing_columns = {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()
    }

    for column_name, column_type in (
        migrations.items()
    ):
        if column_name not in existing_columns:
            connection.execute(
                f"""
                ALTER TABLE {table_name}
                ADD COLUMN {column_name} {column_type}
                """
            )

            logger.info(
                "Added %s column: %s",
                table_name,
                column_name,
            )


def migrate_events_table(
    connection,
) -> None:
    migrate_table_columns(
        connection,
        "events",
        EVENT_COLUMN_MIGRATIONS,
    )


def migrate_alerts_table(
    connection,
) -> None:
    migrate_table_columns(
        connection,
        "alerts",
        ALERT_COLUMN_MIGRATIONS,
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

        migrate_alerts_table(
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