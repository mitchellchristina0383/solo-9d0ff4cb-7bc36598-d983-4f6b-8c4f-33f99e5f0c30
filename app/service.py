"""Application services.

Verification is intentionally a two-phase operation:

1. **Snapshot phase** (one ``BEGIN IMMEDIATE`` transaction): lock the write
   path, confirm no other attempt is running for this request, read the live
   tag / digest / policy rows, persist them verbatim on the attempt row, and
   mark the attempt ``running``.  Commit so the in-flight state is visible.
2. **Evaluate & commit phase** (after the configured observation delay): read
   the live state again only to record *drift*, evaluate the decision from the
   saved snapshots, and — solely when allowed — insert the release row in the
   same transaction.  A rejected or aborted attempt can never leave a release.

Because every rule reads the saved snapshots and the release copies them, a
later tag re-point or policy edit cannot rewrite a past verdict.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .db import connect
from .rules import (
    Decision,
    DigestRecord,
    Policy,
    SIGNATURE_STATUSES,
    SOURCE_STATUSES,
    TagRecord,
    ValidationError,
    evaluate,
    latest_policy,
    normalize_actor,
    normalize_build_source,
    normalize_digest,
    normalize_environment,
    normalize_repository,
    normalize_status,
    normalize_tag,
    policy_expectations,
    read_snapshot,
)
from .util import clamp_text, utc_now


class ConflictError(Exception):
    """Raised when an operation conflicts with current state (HTTP 409)."""


class Service:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db_path: Path = settings.db_path

    # ---------------------------------------------------------------- helpers
    def _connect(self) -> sqlite3.Connection:
        return connect(self.db_path)

    # ---------------------------------------------------------------- digests
    def list_digests(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT d.*, COUNT(t.id) AS tag_count
                FROM digests d
                LEFT JOIN tags t ON t.repository = d.repository AND t.digest = d.digest
                GROUP BY d.id
                ORDER BY d.repository, d.created_at DESC, d.id DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def get_digest(self, repository: str, digest: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM digests WHERE repository = ? AND digest = ?",
                (repository, digest),
            ).fetchone()
        return dict(row) if row else None

    def upsert_digest(
        self,
        *,
        repository: str,
        digest: str,
        build_source: str,
        source_status: str,
        signature_status: str,
        signer: str | None,
        signature_ref: str | None,
        note: str | None,
        actor: str,
    ) -> tuple[dict[str, Any], bool]:
        repo = normalize_repository(repository)
        dig = normalize_digest(digest)
        source = normalize_build_source(build_source)
        source_status = normalize_status(source_status, SOURCE_STATUSES, "source_status")
        signature_status = normalize_status(
            signature_status, SIGNATURE_STATUSES, "signature_status"
        )
        signer = clamp_text(signer, 120)
        signature_ref = clamp_text(signature_ref, 400)
        note = clamp_text(note, 500)
        actor = normalize_actor(actor)

        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute(
                    "SELECT * FROM digests WHERE repository = ? AND digest = ?",
                    (repo, dig),
                ).fetchone()
                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO digests
                            (repository, digest, build_source, source_status,
                             signature_status, signer, signature_ref, note,
                             registered_by, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (repo, dig, source, source_status, signature_status, signer,
                         signature_ref, note, actor, now, now),
                    )
                    action = "registered"
                else:
                    conn.execute(
                        """
                        UPDATE digests
                           SET build_source = ?, source_status = ?, signature_status = ?,
                               signer = ?, signature_ref = ?, note = ?, updated_at = ?
                         WHERE id = ?
                        """,
                        (source, source_status, signature_status, signer,
                         signature_ref, note, now, existing["id"]),
                    )
                    action = "updated"
                conn.execute(
                    """
                    INSERT INTO digest_history
                        (repository, digest, action,
                         previous_source_status, source_status,
                         previous_signature_status, signature_status,
                         previous_signer, signer, actor, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        repo, dig, action,
                        existing["source_status"] if existing else None,
                        source_status,
                        existing["signature_status"] if existing else None,
                        signature_status,
                        existing["signer"] if existing else None,
                        signer, actor, now,
                    ),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            row = conn.execute(
                "SELECT * FROM digests WHERE repository = ? AND digest = ?",
                (repo, dig),
            ).fetchone()
        return dict(row), existing is None

    def digest_history(self, repository: str, digest: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM digest_history
                 WHERE repository = ? AND digest = ?
                 ORDER BY id DESC
                """,
                (repository, digest),
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_digest(self, digest_id: int, actor: str) -> None:
        """Deletion is only permitted when nothing references the digest."""
        actor = normalize_actor(actor)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM digests WHERE id = ?", (digest_id,)).fetchone()
                if row is None:
                    raise ConflictError("digest 记录不存在")
                refs = conn.execute(
                    "SELECT COUNT(*) AS n FROM tags WHERE repository = ? AND digest = ?",
                    (row["repository"], row["digest"]),
                ).fetchone()["n"]
                if refs:
                    raise ConflictError("该 digest 仍被标签引用，不能删除")
                conn.execute("DELETE FROM digests WHERE id = ?", (digest_id,))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------- tags
    def list_tags(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT t.*, d.source_status, d.signature_status, d.signer
                FROM tags t
                JOIN digests d ON d.repository = t.repository AND d.digest = t.digest
                ORDER BY t.repository, t.tag
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def tag_history(self, repository: str | None = None, tag: str | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        args: list[Any] = []
        if repository:
            clauses.append("repository = ?")
            args.append(repository)
        if tag:
            clauses.append("tag = ?")
            args.append(tag)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM tag_history {where} ORDER BY id DESC", args
            ).fetchall()
        return [dict(r) for r in rows]

    def set_tag(self, *, repository: str, tag: str, digest: str, actor: str) -> dict[str, Any]:
        """Register or re-point a tag at an already-registered digest."""
        repo = normalize_repository(repository)
        tag_name = normalize_tag(tag)
        dig = normalize_digest(digest)
        actor = normalize_actor(actor)
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                digest_row = conn.execute(
                    "SELECT * FROM digests WHERE repository = ? AND digest = ?",
                    (repo, dig),
                ).fetchone()
                if digest_row is None:
                    raise ValidationError(
                        "该 digest 尚未登记，请先登记不可变 digest 与构建来源、签名状态",
                        "digest",
                    )
                existing = conn.execute(
                    "SELECT * FROM tags WHERE repository = ? AND tag = ?",
                    (repo, tag_name),
                ).fetchone()
                if existing is None:
                    revision = 1
                    conn.execute(
                        """
                        INSERT INTO tags
                            (repository, tag, digest, revision, updated_by, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (repo, tag_name, dig, revision, actor, now, now),
                    )
                    action = "registered"
                    previous = None
                elif existing["digest"] == dig:
                    conn.execute("COMMIT")
                    return dict(existing) | {"changed": False}
                else:
                    revision = existing["revision"] + 1
                    conn.execute(
                        """
                        UPDATE tags SET digest = ?, revision = ?, updated_by = ?, updated_at = ?
                         WHERE id = ?
                        """,
                        (dig, revision, actor, now, existing["id"]),
                    )
                    action = "repointed"
                    previous = existing["digest"]
                conn.execute(
                    """
                    INSERT INTO tag_history
                        (repository, tag, previous_digest, digest, revision, action, actor, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (repo, tag_name, previous, dig, revision, action, actor, now),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            row = conn.execute(
                "SELECT * FROM tags WHERE repository = ? AND tag = ?",
                (repo, tag_name),
            ).fetchone()
        return dict(row) | {"changed": True}

    # --------------------------------------------------------------- policies
    def list_policies(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM policies ORDER BY version DESC").fetchall()
        return [dict(r) for r in rows]

    def current_policy(self) -> dict[str, Any]:
        with self._connect() as conn:
            policy = latest_policy(conn)
        return policy.snapshot() | {"label": policy.label, "expectations": policy_expectations(policy)}

    def create_policy(
        self,
        *,
        require_provenance: bool,
        require_signature: bool,
        required_signer: str | None,
        note: str | None,
        actor: str,
    ) -> dict[str, Any]:
        actor = normalize_actor(actor)
        note = clamp_text(note, 500)
        required_signer = clamp_text(required_signer, 120)
        if not require_signature:
            required_signer = None
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT MAX(version) AS v FROM policies").fetchone()
                version = (row["v"] or 0) + 1
                conn.execute(
                    """
                    INSERT INTO policies
                        (version, require_provenance, require_signature, required_signer,
                         note, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (version, int(require_provenance), int(require_signature),
                     required_signer, note, actor, now),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            created = conn.execute(
                "SELECT * FROM policies WHERE version = ?", (version,)
            ).fetchone()
        return dict(created)

    # --------------------------------------------------------------- requests
    def create_request(
        self,
        *,
        repository: str,
        tag: str,
        expected_digest: str | None,
        environment: str,
        requested_by: str,
        note: str | None,
    ) -> dict[str, Any]:
        repo = normalize_repository(repository)
        tag_name = normalize_tag(tag)
        env = normalize_environment(environment)
        actor = normalize_actor(requested_by)
        expected = normalize_digest(expected_digest) if (expected_digest or "").strip() else None
        note = clamp_text(note, 500)
        request_id = f"REQ-{uuid.uuid4().hex[:12].upper()}"
        now = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if conn.execute("SELECT 1 FROM tags WHERE repository = ? AND tag = ?",
                                (repo, tag_name)).fetchone() is None:
                    raise ValidationError(
                        f"标签 {repo}:{tag_name} 尚未登记，无法提交部署请求", "tag"
                    )
                if expected is not None:
                    tag_row = conn.execute(
                        "SELECT * FROM tags WHERE repository = ? AND tag = ?",
                        (repo, tag_name),
                    ).fetchone()
                    if tag_row["digest"] != expected:
                        raise ValidationError(
                            f"标签当前指向 {tag_row['digest']}，与请求声明的 digest 不一致",
                            "expected_digest",
                        )
                conn.execute(
                    """
                    INSERT INTO requests
                        (id, repository, tag, expected_digest, environment,
                         requested_by, note, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (request_id, repo, tag_name, expected, env, actor, note, now),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
        return dict(row)

    def list_requests(self, *, status: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT r.*,
                       (SELECT COUNT(*) FROM attempts a WHERE a.request_id = r.id) AS attempt_count,
                       rel.id AS release_id,
                       rel.released_at AS released_at,
                       rel.digest AS released_digest,
                       rel.policy_version AS released_policy_version,
                       (SELECT a.status FROM attempts a WHERE a.request_id = r.id
                         ORDER BY a.attempt_no DESC LIMIT 1) AS last_status,
                       (SELECT a.finished_at FROM attempts a WHERE a.request_id = r.id
                         ORDER BY a.attempt_no DESC LIMIT 1) AS last_finished_at
                FROM requests r
                LEFT JOIN releases rel ON rel.request_id = r.id
                ORDER BY r.created_at DESC, r.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        items = [dict(r) for r in rows]
        if status:
            if status == "released":
                items = [i for i in items if i["release_id"]]
            elif status == "rejected":
                items = [i for i in items if not i["release_id"] and i["last_status"] == "rejected"]
            elif status == "pending":
                items = [i for i in items if i["last_status"] in (None, "running")]
            elif status == "aborted":
                items = [i for i in items if not i["release_id"] and i["last_status"] == "aborted"]
        return items

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
            if row is None:
                return None
            attempts = conn.execute(
                "SELECT * FROM attempts WHERE request_id = ? ORDER BY attempt_no",
                (request_id,),
            ).fetchall()
            release = conn.execute(
                "SELECT * FROM releases WHERE request_id = ?", (request_id,)
            ).fetchone()
            tag_live = conn.execute(
                "SELECT * FROM tags WHERE repository = ? AND tag = ?",
                (row["repository"], row["tag"]),
            ).fetchone()
        result = dict(row)
        result["attempts"] = [self._hydrate_attempt(dict(a)) for a in attempts]
        result["release"] = self._hydrate_release(dict(release)) if release else None
        result["tag_live"] = dict(tag_live) if tag_live else None
        return result

    def list_releases(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM releases ORDER BY released_at DESC, id DESC"
            ).fetchall()
        return [self._hydrate_release(dict(r)) for r in rows]

    def list_attempts(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT a.*, r.repository AS repository, r.tag AS tag, r.environment AS environment
                FROM attempts a JOIN requests r ON r.id = a.request_id
                ORDER BY a.id DESC LIMIT 300
                """
            ).fetchall()
        return [self._hydrate_attempt(dict(r)) for r in rows]

    @staticmethod
    def _hydrate_attempt(raw: dict[str, Any]) -> dict[str, Any]:
        raw["tag_snapshot_obj"] = read_snapshot(raw.get("tag_snapshot"))
        raw["digest_snapshot_obj"] = read_snapshot(raw.get("digest_snapshot"))
        raw["policy_snapshot_obj"] = read_snapshot(raw.get("policy_snapshot"))
        raw["checks_obj"] = read_snapshot_list(raw.get("checks"))
        raw["reasons_obj"] = read_snapshot_list(raw.get("reasons"))
        raw["drift_obj"] = read_snapshot_list(raw.get("drift"))
        return raw

    @staticmethod
    def _hydrate_release(raw: dict[str, Any]) -> dict[str, Any]:
        raw["tag_snapshot_obj"] = read_snapshot(raw.get("tag_snapshot"))
        raw["digest_snapshot_obj"] = read_snapshot(raw.get("digest_snapshot"))
        raw["policy_snapshot_obj"] = read_snapshot(raw.get("policy_snapshot"))
        return raw

    # ------------------------------------------------------------ verification
    def verify(self, request_id: str, *, actor: str) -> dict[str, Any]:
        """Run one verification attempt and return the hydrated attempt row."""
        actor = normalize_actor(actor)
        delay = max(0, self.settings.verify_delay_ms) / 1000.0

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                request = conn.execute(
                    "SELECT * FROM requests WHERE id = ?", (request_id,)
                ).fetchone()
                if request is None:
                    raise ConflictError("部署请求不存在")
                release = conn.execute(
                    "SELECT id, digest, released_at FROM releases WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if release is not None:
                    raise ConflictError(
                        f"请求已于 {release['released_at']} 放行（发布记录 {release['id']}，"
                        f"digest {release['digest']}），不再重新校验；已放行结果保持冻结"
                    )
                running = conn.execute(
                    "SELECT attempt_no FROM attempts WHERE request_id = ? AND status = 'running'",
                    (request_id,),
                ).fetchone()
                if running is not None:
                    raise ConflictError(
                        f"该请求的第 {running['attempt_no']} 次校验仍在进行，请等待结果"
                    )
                last = conn.execute(
                    "SELECT MAX(attempt_no) AS n FROM attempts WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                attempt_no = (last["n"] or 0) + 1

                policy_row = latest_policy(conn)
                policy_snap = policy_row.snapshot()
                tag_row = conn.execute(
                    "SELECT * FROM tags WHERE repository = ? AND tag = ?",
                    (request["repository"], request["tag"]),
                ).fetchone()
                tag_snap = dict(tag_row) if tag_row else None
                digest_snap = None
                if tag_snap is not None:
                    digest_row = conn.execute(
                        "SELECT * FROM digests WHERE repository = ? AND digest = ?",
                        (tag_snap["repository"], tag_snap["digest"]),
                    ).fetchone()
                    digest_snap = dict(digest_row) if digest_row else None

                started_at = utc_now()
                conn.execute(
                    """
                    INSERT INTO attempts
                        (request_id, attempt_no, status, tag_snapshot, digest_snapshot,
                         policy_snapshot, started_at, actor)
                    VALUES (?, ?, 'running', ?, ?, ?, ?, ?)
                    """,
                    (
                        request_id, attempt_no,
                        json.dumps(tag_snap, ensure_ascii=False, sort_keys=True),
                        json.dumps(digest_snap, ensure_ascii=False, sort_keys=True) if digest_snap else None,
                        json.dumps(policy_snap, ensure_ascii=False, sort_keys=True),
                        started_at, actor,
                    ),
                )
                conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                raise ConflictError("该请求已有校验在进行中") from exc
            except Exception:
                conn.execute("ROLLBACK")
                raise

        if delay:
            import time

            time.sleep(delay)

        return self._finalize_attempt(request_id, attempt_no, actor)

    def _finalize_attempt(self, request_id: str, attempt_no: int, actor: str) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                request = conn.execute(
                    "SELECT * FROM requests WHERE id = ?", (request_id,)
                ).fetchone()
                attempt = conn.execute(
                    "SELECT * FROM attempts WHERE request_id = ? AND attempt_no = ?",
                    (request_id, attempt_no),
                ).fetchone()
                if request is None or attempt is None:
                    raise ConflictError("校验记录缺失")
                if attempt["status"] != "running":
                    raise ConflictError("校验已结束，不能重复提交结果")

                tag_snap = read_snapshot(attempt["tag_snapshot"])
                digest_snap = read_snapshot(attempt["digest_snapshot"])
                policy_snap = read_snapshot(attempt["policy_snapshot"]) or {}

                # Live state is consulted *only* to record drift, never to decide.
                drift: list[dict[str, Any]] = []
                live_policy = latest_policy(conn)
                if live_policy.version != int(policy_snap.get("version", -1)):
                    drift.append(
                        {
                            "key": "policy",
                            "label": "策略已更新",
                            "snapshot": f"v{policy_snap.get('version')}",
                            "live": live_policy.label,
                        }
                    )
                live_tag_row = conn.execute(
                    "SELECT * FROM tags WHERE repository = ? AND tag = ?",
                    (request["repository"], request["tag"]),
                ).fetchone()
                live_tag = dict(live_tag_row) if live_tag_row else None
                snap_digest = (tag_snap or {}).get("digest")
                live_digest = (live_tag or {}).get("digest")
                if tag_snap is None and live_tag is not None:
                    drift.append(
                        {
                            "key": "tag",
                            "label": "校验开始后标签被登记",
                            "snapshot": "（未登记）",
                            "live": live_digest,
                        }
                    )
                elif snap_digest != live_digest:
                    drift.append(
                        {
                            "key": "tag",
                            "label": "标签已改指向",
                            "snapshot": snap_digest or "（未登记）",
                            "live": live_digest or "（已移除）",
                        }
                    )
                if tag_snap is not None and live_tag is not None and tag_snap.get("revision") != live_tag.get("revision"):
                    drift.append(
                        {
                            "key": "tag_revision",
                            "label": "标签修订号变化",
                            "snapshot": str(tag_snap.get("revision")),
                            "live": str(live_tag.get("revision")),
                        }
                    )
                if digest_snap is not None and live_digest:
                    live_digest_row = conn.execute(
                        "SELECT source_status, signature_status, signer FROM digests "
                        "WHERE repository = ? AND digest = ?",
                        (request["repository"], live_digest),
                    ).fetchone()
                    if live_digest_row is not None:
                        for key, label in (
                            ("source_status", "当前 digest 构建来源状态变化"),
                            ("signature_status", "当前 digest 签名状态变化"),
                            ("signer", "当前 digest 签名者变化"),
                        ):
                            if digest_snap.get(key) != live_digest_row[key]:
                                drift.append(
                                    {
                                        "key": f"digest_{key}",
                                        "label": label,
                                        "snapshot": str(digest_snap.get(key)),
                                        "live": str(live_digest_row[key]),
                                    }
                                )

                decision: Decision = evaluate(
                    repository=request["repository"],
                    tag_name=request["tag"],
                    tag_snapshot=tag_snap,
                    digest_snapshot=digest_snap,
                    policy_snapshot=policy_snap,
                    expected_digest=request["expected_digest"],
                )
                finished_at = utc_now()
                status = "allowed" if decision.allowed else "rejected"
                conn.execute(
                    """
                    UPDATE attempts
                       SET status = ?, checks = ?, reasons = ?, drift = ?, finished_at = ?
                     WHERE request_id = ? AND attempt_no = ?
                    """,
                    (
                        status,
                        decision.checks_json(),
                        decision.reasons_json(),
                        json.dumps(drift, ensure_ascii=False) if drift else None,
                        finished_at,
                        request_id,
                        attempt_no,
                    ),
                )
                if decision.allowed:
                    release_id = f"REL-{uuid.uuid4().hex[:12].upper()}"
                    digest_for_release = (tag_snap or {}).get("digest")
                    if not digest_for_release:
                        raise ConflictError("放行快照缺少 digest，拒绝生成发布记录")
                    conn.execute(
                        """
                        INSERT INTO releases
                            (id, request_id, attempt_id, repository, tag, digest,
                             policy_version, environment, released_at, released_by,
                             tag_snapshot, digest_snapshot, policy_snapshot)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            release_id,
                            request_id,
                            attempt["id"],
                            request["repository"],
                            request["tag"],
                            digest_for_release,
                            int(policy_snap.get("version", 0)),
                            request["environment"],
                            finished_at,
                            actor,
                            attempt["tag_snapshot"],
                            attempt["digest_snapshot"] or "{}",
                            attempt["policy_snapshot"],
                        ),
                    )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            final = conn.execute(
                "SELECT * FROM attempts WHERE request_id = ? AND attempt_no = ?",
                (request_id, attempt_no),
            ).fetchone()
        hydrated = self._hydrate_attempt(dict(final))
        hydrated["repository"] = request["repository"]
        hydrated["tag"] = request["tag"]
        hydrated["environment"] = request["environment"]
        return hydrated

    # --------------------------------------------------------------- dashboard
    def stats(self) -> dict[str, int]:
        with self._connect() as conn:
            def count(sql: str, *args: Any) -> int:
                return int(conn.execute(sql, args).fetchone()[0])

            return {
                "digests": count("SELECT COUNT(*) FROM digests"),
                "tags": count("SELECT COUNT(*) FROM tags"),
                "requests": count("SELECT COUNT(*) FROM requests"),
                "releases": count("SELECT COUNT(*) FROM releases"),
                "rejected": count(
                    """
                    SELECT COUNT(*) FROM requests r
                     WHERE NOT EXISTS (SELECT 1 FROM releases rel WHERE rel.request_id = r.id)
                       AND (SELECT a.status FROM attempts a WHERE a.request_id = r.id
                             ORDER BY a.attempt_no DESC LIMIT 1) = 'rejected'
                    """
                ),
                "policy_version": count("SELECT MAX(version) FROM policies"),
            }


def read_snapshot_list(value: str | None) -> list[dict[str, Any]]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return []
    return data if isinstance(data, list) else []
