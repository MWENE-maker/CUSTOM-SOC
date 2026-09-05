SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    raw_data TEXT,
    source_ip TEXT,
    http_method TEXT,
    http_path TEXT,
    http_status INTEGER,
    response_size INTEGER
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    description TEXT,
    created_at TEXT NOT NULL,
    assigned_to TEXT,
    analyst_notes TEXT,
    updated_at TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    note TEXT,
    analyst TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

CREATE INDEX IF NOT EXISTS idx_alert_history_alert_id
ON alert_history(alert_id);

CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL,
    assigned_to TEXT,
    summary TEXT,
    findings TEXT,
    disposition TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT
);

CREATE TABLE IF NOT EXISTS investigation_alerts (
    investigation_id INTEGER NOT NULL,
    alert_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (investigation_id, alert_id),
    FOREIGN KEY (investigation_id) REFERENCES investigations(id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

CREATE INDEX IF NOT EXISTS idx_investigation_alerts_investigation_id
ON investigation_alerts(investigation_id);

CREATE INDEX IF NOT EXISTS idx_investigation_alerts_alert_id
ON investigation_alerts(alert_id);

CREATE TABLE IF NOT EXISTS investigation_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    note TEXT,
    analyst TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE INDEX IF NOT EXISTS idx_investigation_history_investigation_id
ON investigation_history(investigation_id);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    description TEXT,
    created_at TEXT NOT NULL,
    closed_at TEXT,
    investigation_id INTEGER,
    assigned_to TEXT,
    updated_at TEXT,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence INTEGER,
    source TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER,
    action_type TEXT NOT NULL,
    target TEXT,
    status TEXT NOT NULL,
    executed_at TEXT,
    notes TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);
"""


EVENT_COLUMN_MIGRATIONS = {
    "source_ip": "TEXT",
    "http_method": "TEXT",
    "http_path": "TEXT",
    "http_status": "INTEGER",
    "response_size": "INTEGER",
}


ALERT_COLUMN_MIGRATIONS = {
    "assigned_to": "TEXT",
    "analyst_notes": "TEXT",
    "updated_at": "TEXT",
}


INCIDENT_COLUMN_MIGRATIONS = {
    "investigation_id": (
        "INTEGER REFERENCES investigations(id)"
    ),
    "assigned_to": "TEXT",
    "updated_at": "TEXT",
}