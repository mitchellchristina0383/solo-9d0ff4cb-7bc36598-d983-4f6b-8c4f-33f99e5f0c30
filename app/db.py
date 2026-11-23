"""SQLite storage layer.

The admission database is deliberately append-oriented: digests and releases
are never rewritten, tags keep a revision and an append-only history, and
policies are versioned rows.  A request's verification snapshots live on the
attempt row, so later registry changes cannot alter a past result.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .util import utc_now


SCHEMA = """
CREATE TABLE IF NOT EXISTS digests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository TEXT NOT NULL,
    digest TEXT NOT NULL,
    build_source TEXT NOT NULL,
    source_status TEXT NOT NULL
        CHECK (source_status IN ('verified', 'unverified')),
    signature_status TEXT NOT NULL
        CHECK (signature_status IN ('verified', 'unverified', 'missing', 'invalid')),
    signer TEXT,
    signature_ref TEXT,
    note TEXT,
    registered_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (repository, digest)
);

CREATE TABLE IF NOT EXISTS digest_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository TEXT NOT NULL,
    digest TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('registered', 'updated')),
    previous_source_status TEXT,
    source_status TEXT NOT NULL,
    previous_signature_status TEXT,
    signature_status TEXT NOT NULL,
    previous_signer TEXT,
    signer TEXT,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_digest_history ON digest_history (repository, digest, id);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    digest TEXT NOT NULL,
    revision INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (repository, tag),
    FOREIGN KEY (repository, digest) REFERENCES digests (repository, digest)
);

CREATE TABLE IF NOT EXISTS tag_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    previous_digest TEXT,
    digest TEXT NOT NULL,
    revision INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('registered', 'repointed')),
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL UNIQUE,
    require_provenance INTEGER NOT NULL,
    require_signature INTEGER NOT NULL,
    required_signer TEXT,
    note TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    expected_digest TEXT,
    environment TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL REFERENCES requests (id),
    attempt_no INTEGER NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('running', 'allowed', 'rejected', 'aborted')),
    tag_snapshot TEXT NOT NULL,
    digest_snapshot TEXT,
    policy_snapshot TEXT NOT NULL,
    checks TEXT NOT NULL DEFAULT '[]',
    reasons TEXT NOT NULL DEFAULT '[]',
    drift TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    actor TEXT NOT NULL,
    UNIQUE (request_id, attempt_no)
);

-- At most one verification may run per request, even across processes.
CREATE UNIQUE INDEX IF NOT EXISTS ux_attempts_one_running
    ON attempts (request_id) WHERE status = 'running';

CREATE INDEX IF NOT EXISTS ix_attempts_request ON attempts (request_id, attempt_no);

CREATE TABLE IF NOT EXISTS releases (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES requests (id),
    attempt_id INTEGER NOT NULL UNIQUE REFERENCES attempts (id),
    repository TEXT NOT NULL,
    tag TEXT NOT NULL,
    digest TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    environment TEXT NOT NULL,
    released_at TEXT NOT NULL,
    released_by TEXT NOT NULL,
    tag_snapshot TEXT NOT NULL,
    digest_snapshot TEXT NOT NULL,
    policy_snapshot TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_releases_repository ON releases (repository, released_at);
"""


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open a connection with deterministic pragmas.

    A fresh connection per operation keeps the sync helpers safe to call from
    worker threads.  WAL permits readers while a verification commit is in
    progress.
    """

    conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(db_path: Path | str) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(SCHEMA)
        _seed_default_policy(conn)
        conn.execute("PRAGMA user_version = 1")
    finally:
        conn.close()


def _seed_default_policy(conn: sqlite3.Connection) -> None:
    row = conn.execute("SELECT COUNT(*) AS n FROM policies").fetchone()
    if row["n"] != 0:
        return
    conn.execute(
        """
        INSERT INTO policies
            (version, require_provenance, require_signature, required_signer, note, created_by, created_at)
        VALUES (1, 1, 1, NULL, ?, 'system', ?)
        """,
        ("初始策略：要求构建来源已核验且签名已验证", utc_now()),
    )
