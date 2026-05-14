"""
Database Importer
=================
Reads events from events.jsonl and inserts them into a SQLite database.
Uses MD5 hashing for deduplication — safe to run multiple times.

Usage:
  python3 db.py
"""

import json
import sqlite3
import hashlib
import os

LOG_FILE = "events.jsonl"
DB_FILE  = "honey.db"


def create_db(con):
    con.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp      TEXT,
            type           TEXT,
            ip             TEXT,
            source_port    INTEGER,
            username       TEXT,
            password       TEXT,
            client_version TEXT,
            attempt_n      INTEGER,
            error          TEXT,
            event_hash     TEXT UNIQUE
        )
    """)
    con.commit()


def insert_event(con, event, raw_line):
    """
    Insert an event using INSERT OR IGNORE with a unique hash.
    If the same raw line is imported again, it is silently skipped.
    This makes the importer idempotent — safe to re-run at any time.
    """
    event_hash = hashlib.md5(raw_line.encode()).hexdigest()

    con.execute("""
        INSERT OR IGNORE INTO logs (
            timestamp, type, ip, source_port,
            username, password, client_version, attempt_n,
            error, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp"),
        event.get("type"),
        event.get("ip"),
        event.get("source_port"),
        event.get("username"),
        event.get("password"),
        event.get("client_version"),
        event.get("attempt_n"),
        event.get("error") or event.get("unexpected_error"),
        event_hash
    ))
    con.commit()
    return con.execute("SELECT changes()").fetchone()[0]


def import_logs(con):
    if not os.path.exists(LOG_FILE):
        print(f"[!] Log file not found: {LOG_FILE}")
        return

    inserted = 0
    skipped  = 0

    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                changed = insert_event(con, event, line)
                if changed:
                    inserted += 1
                else:
                    skipped += 1
            except json.JSONDecodeError:
                print(f"[!] Skipping malformed line: {line[:60]}")

    print(f"[*] Import complete — inserted: {inserted} | already present: {skipped}")


if __name__ == "__main__":
    con = sqlite3.connect(DB_FILE)
    create_db(con)
    import_logs(con)
    con.close()
