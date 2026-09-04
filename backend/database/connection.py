import sqlite3
from pathlib import Path

from backend.core.config import settings


def get_database_path() -> Path:
    return Path(settings.DATABASE_PATH)


def get_connection() -> sqlite3.Connection:
    database_path = get_database_path()

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(database_path)

    connection.row_factory = sqlite3.Row

    return connection