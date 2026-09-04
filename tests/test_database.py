import unittest

from backend.database.connection import (
    get_connection,
)


class TestDatabase(unittest.TestCase):

    def test_foreign_keys_enabled(self):
        connection = get_connection()

        try:
            value = connection.execute(
                "PRAGMA foreign_keys"
            ).fetchone()[0]

            self.assertEqual(
                value,
                1,
            )

        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()