from backend.services.ingestion_service import ingest_event


def main():
    event_id = ingest_event(
        source="web-server-01",
        event_type="HTTP_REQUEST",
        severity="medium",
        message="Suspicious request observed",
        raw_data='GET /admin HTTP/1.1',
    )

    print(
        f"Sample event stored successfully with ID: {event_id}"
    )


if __name__ == "__main__":
    main()