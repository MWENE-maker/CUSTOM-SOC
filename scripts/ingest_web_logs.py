from pathlib import Path

from backend.services.log_ingestion_service import (
    ingest_web_log,
)


LOG_FILE = Path(
    "sample_logs/web_access.log"
)


def main():
    with LOG_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            log_line = line.strip()

            if not log_line:
                continue

            try:
                event_id = ingest_web_log(
                    log_line
                )

                print(
                    f"Line {line_number}: "
                    f"stored as event {event_id}"
                )

            except ValueError as error:
                print(
                    f"Line {line_number}: "
                    f"rejected - {error}"
                )


if __name__ == "__main__":
    main()