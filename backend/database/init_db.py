from backend.core.logger import get_logger
from backend.database.connection import get_connection
from backend.database.schema import (
    ALERT_COLUMN_MIGRATIONS,
    EVENT_COLUMN_MIGRATIONS,
    INCIDENT_COLUMN_MIGRATIONS,
    RESPONSE_ACTION_COLUMN_MIGRATIONS,
    SCHEMA,
)


logger = get_logger(__name__)


def migrate_table_columns(
    connection,
    table_name: str,
    migrations: dict[str, str],
) -> None:
    existing_columns = {
        row["name"]
        for row in connection.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()
    }

    for column_name, column_definition in migrations.items():
        if column_name in existing_columns:
            continue

        connection.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
            """
        )

        logger.info(
            "Added column %s.%s",
            table_name,
            column_name,
        )


def migrate_events_table(connection) -> None:
    migrate_table_columns(
        connection,
        "events",
        EVENT_COLUMN_MIGRATIONS,
    )


def migrate_alerts_table(connection) -> None:
    migrate_table_columns(
        connection,
        "alerts",
        ALERT_COLUMN_MIGRATIONS,
    )


def migrate_incidents_table(connection) -> None:
    migrate_table_columns(
        connection,
        "incidents",
        INCIDENT_COLUMN_MIGRATIONS,
    )


def migrate_response_actions_table(connection) -> None:
    migrate_table_columns(
        connection,
        "response_actions",
        RESPONSE_ACTION_COLUMN_MIGRATIONS,
    )


def create_post_migration_indexes(connection) -> None:
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_incidents_investigation_id
        ON incidents(investigation_id)
        WHERE investigation_id IS NOT NULL
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_response_actions_incident_id
        ON response_actions(incident_id)
        """
    )


def initialize_database() -> None:
    connection = get_connection()

    try:
        connection.executescript(SCHEMA)

        migrate_events_table(connection)
        migrate_alerts_table(connection)
        migrate_incidents_table(connection)
        migrate_response_actions_table(connection)

        create_post_migration_indexes(connection)

        connection.commit()

        logger.info(
            "Database initialized successfully"
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()