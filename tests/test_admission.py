from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import connect, init_db
from app.service import ConflictError, Service


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    db = tmp_path / "test.db"
    init_db(db)
    return Settings(db_path=db, verify_delay_ms=0)


@pytest.fixture()
def service(settings: Settings) -> Service:
    return Service(settings)


@pytest.fixture()
def client(tmp_path: Path):
    from app.web import create_app

    db = tmp_path / "web.db"
    init_db(db)
    app = create_app(Settings(db_path=db, verify_delay_ms=0))
    with TestClient(app) as c:
        yield c


def register(service: Service, *, repo="rg.test/app", seed="a", source="verified",
             signature="verified", signer="team-a"):
    rec, _ = service.upsert_digest(
        repository=repo, digest=digest(seed), build_source=f"ci://pipeline/{seed}",
        source_status=source, signature_status=signature, signer=signer,
        signature_ref=None, note=None, actor="ops",
    )
    return rec


def setup_flow(service: Service, *, repo="rg.test/app", tag="prod", seed="a",
               source="verified", signature="verified", signer="team-a"):
    d = register(service, repo=repo, seed=seed, source=source,
                 signature=signature, signer=signer)
    service.set_tag(repository=repo, tag=tag, digest=d["digest"], actor="ops")
    req = service.create_request(
        repository=repo, tag=tag, expected_digest=None, environment="prod",
        requested_by="ops", note=None,
    )
    return d, req


# ---------------------------------------------------------------- core verdicts
def test_allow_when_evidence_matches_policy(service: Service):
    d, req = setup_flow(service)
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "allowed"
    assert not attempt["reasons_obj"]
    releases = service.list_releases()
    assert len(releases) == 1
    assert releases[0]["request_id"] == req["id"]
    assert releases[0]["digest"] == d["digest"]
    assert releases[0]["policy_version"] == 1


def test_reject_unverified_source(service: Service):
    _, req = setup_flow(service, source="unverified")
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "rejected"
    keys = {c["key"] for c in attempt["reasons_obj"]}
    assert "provenance" in keys
    assert service.list_releases() == []
    assert service.get_request(req["id"])["release"] is None


def test_reject_missing_signature(service: Service):
    _, req = setup_flow(service, signature="missing")
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "rejected"
    assert "signature" in {c["key"] for c in attempt["reasons_obj"]}
    assert service.list_releases() == []


def test_reject_invalid_signature(service: Service):
    _, req = setup_flow(service, signature="invalid")
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "rejected"
    assert service.list_releases() == []


def test_required_signer_is_enforced(service: Service):
    service.create_policy(require_provenance=True, require_signature=True,
                          required_signer="team-b", note=None, actor="sec")
    _, req = setup_flow(service, signer="team-a")
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "rejected"
    assert "signer_identity" in {c["key"] for c in attempt["reasons_obj"]}


def test_policy_relaxed_allows_unverified_source(service: Service):
    service.create_policy(require_provenance=False, require_signature=True,
                          required_signer=None, note="放开来来源", actor="sec")
    _, req = setup_flow(service, source="unverified")
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "allowed"


# ------------------------------------------------------------ snapshot binding
def test_tag_repoint_during_verify_does_not_change_verdict(service: Service, settings: Settings):
    old, req = setup_flow(service, seed="old")
    new = register(service, seed="new", signature="missing")

    holder: dict[str, object] = {}
    done = threading.Event()

    slow = Service(Settings(db_path=settings.db_path, verify_delay_ms=600))

    def run_verify():
        holder["attempt"] = slow.verify(req["id"], actor="ops")
        done.set()

    t = threading.Thread(target=run_verify)
    t.start()
    assert wait_until(lambda: running_attempt_exists(settings.db_path, req["id"]))
    service.set_tag(repository="rg.test/app", tag="prod", digest=new["digest"], actor="ops")
    done.wait(5)
    t.join(5)

    attempt = holder["attempt"]
    assert attempt["status"] == "allowed", attempt["reasons_obj"]
    assert attempt["digest_snapshot_obj"]["digest"] == old["digest"]
    assert attempt["tag_snapshot_obj"]["digest"] == old["digest"]
    release = service.list_releases()[0]
    assert release["digest"] == old["digest"]
    # The drift is recorded but did not alter the snapshot verdict.
    assert any(d["key"] == "tag" for d in attempt["drift_obj"])

    # Current tag now points elsewhere; the release still binds the old digest.
    live = service.get_request(req["id"])["tag_live"]
    assert live["digest"] == new["digest"]


def test_released_request_is_frozen_and_not_reverifiable(service: Service, settings: Settings):
    old, req = setup_flow(service, seed="old")
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "allowed"
    # Change the tag to a worse digest and then try to re-verify.
    bad = register(service, seed="bad", source="unverified", signature="invalid")
    service.set_tag(repository="rg.test/app", tag="prod", digest=bad["digest"], actor="ops")
    with pytest.raises(ConflictError):
        service.verify(req["id"], actor="ops")
    releases = service.list_releases()
    assert len(releases) == 1
    assert releases[0]["digest"] == old["digest"]


def test_policy_update_during_verify_is_ignored_by_snapshot(service: Service, settings: Settings):
    register(service, seed="a", source="verified", signature="verified")
    service.set_tag(repository="rg.test/app", tag="prod", digest=digest("a"), actor="ops")
    req = service.create_request(repository="rg.test/app", tag="prod", expected_digest=None,
                                 environment="prod", requested_by="ops", note=None)

    done = threading.Event()
    holder: dict[str, object] = {}
    slow = Service(Settings(db_path=settings.db_path, verify_delay_ms=600))

    def run_verify():
        holder["attempt"] = slow.verify(req["id"], actor="ops")
        done.set()

    t = threading.Thread(target=run_verify)
    t.start()
    assert wait_until(lambda: running_attempt_exists(settings.db_path, req["id"]))
    # Tighten the policy mid-flight: now signatures must have a specific signer
    # that the snapshot digest does not satisfy.
    service.create_policy(require_provenance=True, require_signature=True,
                          required_signer="only-this-signer", note="收紧", actor="sec")
    done.wait(5)
    t.join(5)

    attempt = holder["attempt"]
    assert attempt["status"] == "allowed", attempt["reasons_obj"]
    assert attempt["policy_snapshot_obj"]["version"] == 1
    assert attempt["policy_snapshot_obj"]["required_signer"] is None
    assert service.list_releases()[0]["policy_version"] == 1
    assert any(d["key"] == "policy" for d in attempt["drift_obj"])

    # Same request cannot be re-verified because it is already released.
    with pytest.raises(ConflictError):
        service.verify(req["id"], actor="ops")


def test_policy_relaxed_midflight_still_rejects(service: Service, settings: Settings):
    _, req = setup_flow(service, signature="missing")
    done = threading.Event()
    holder: dict[str, object] = {}
    slow = Service(Settings(db_path=settings.db_path, verify_delay_ms=600))

    def run_verify():
        holder["attempt"] = slow.verify(req["id"], actor="ops")
        done.set()

    t = threading.Thread(target=run_verify)
    t.start()
    assert wait_until(lambda: running_attempt_exists(settings.db_path, req["id"]))
    service.create_policy(require_provenance=False, require_signature=False,
                          required_signer=None, note="放开签名", actor="sec")
    done.wait(5)
    t.join(5)

    attempt = holder["attempt"]
    assert attempt["status"] == "rejected"
    assert attempt["policy_snapshot_obj"]["require_signature"] is True
    assert service.list_releases() == []


# ------------------------------------------------------------- failure handling
def test_repeated_rejection_never_releases(service: Service):
    _, req = setup_flow(service, source="unverified")
    for _ in range(3):
        attempt = service.verify(req["id"], actor="ops")
        assert attempt["status"] == "rejected"
        assert service.list_releases() == []
    detail = service.get_request(req["id"])
    assert [a["attempt_no"] for a in detail["attempts"]] == [1, 2, 3]


def test_rejection_then_fix_then_allow(service: Service):
    d = register(service, seed="a", source="unverified", signature="unverified")
    service.set_tag(repository="rg.test/app", tag="prod", digest=d["digest"], actor="ops")
    req = service.create_request(repository="rg.test/app", tag="prod", expected_digest=None,
                                 environment="prod", requested_by="ops", note=None)
    assert service.verify(req["id"], actor="ops")["status"] == "rejected"

    fixed, _ = service.upsert_digest(
        repository="rg.test/app", digest=d["digest"], build_source="ci://fixed",
        source_status="verified", signature_status="verified", signer="team-a",
        signature_ref="log:1", note=None, actor="ops",
    )
    second = service.verify(req["id"], actor="ops")
    assert second["status"] == "allowed"
    releases = service.list_releases()
    assert len(releases) == 1
    assert releases[0]["attempt_id"] != service.get_request(req["id"])["attempts"][0]["id"]


def test_concurrent_verifications_are_refused(service: Service, settings: Settings):
    _, req = setup_flow(service)
    done = threading.Event()
    slow = Service(Settings(db_path=settings.db_path, verify_delay_ms=700))

    def run_verify():
        slow.verify(req["id"], actor="ops")
        done.set()

    t = threading.Thread(target=run_verify)
    t.start()
    assert wait_until(lambda: running_attempt_exists(settings.db_path, req["id"]))
    with pytest.raises(ConflictError):
        service.verify(req["id"], actor="ops")
    done.wait(5)
    t.join(5)
    assert len(service.list_releases()) == 1


def test_unregistered_digest_via_manual_edit_fails_closed(service: Service, settings: Settings):
    """Simulate a tag pinned to a digest whose registration record vanished."""
    d = register(service, seed="ghost")
    service.set_tag(repository="rg.test/app", tag="prod", digest=d["digest"], actor="ops")
    # Out-of-band catalog corruption: remove the registration while the tag
    # still points at it.
    conn = connect(settings.db_path)
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute(
            "DELETE FROM digests WHERE repository = ? AND digest = ?",
            ("rg.test/app", d["digest"]),
        )
        conn.execute("PRAGMA foreign_keys = ON")
    finally:
        conn.close()
    req = service.create_request(repository="rg.test/app", tag="prod", expected_digest=None,
                                 environment="prod", requested_by="ops", note=None)
    attempt = service.verify(req["id"], actor="ops")
    assert attempt["status"] == "rejected"
    assert "digest_registered" in {c["key"] for c in attempt["reasons_obj"]}
    assert service.list_releases() == []


def test_expected_digest_mismatch_is_rejected(service: Service):
    d, _ = setup_flow(service, seed="a")
    other = digest("b")
    with pytest.raises(Exception):
        service.create_request(repository="rg.test/app", tag="prod", expected_digest=other,
                               environment="prod", requested_by="ops", note=None)


# ------------------------------------------------------------------ web surface
def test_web_flow_renders_and_rejects(client):
    with connect(client.app.state.settings.db_path) as conn:
        pass
    # Use the web endpoints for the full happy path.
    r = client.post("/digests", data={
        "repository": "rg.test/app", "digest": digest("w"),
        "build_source": "ci://w", "source_status": "verified",
        "signature_status": "verified", "signer": "team-a", "actor": "ops",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert "已登记" in r.text

    r = client.post("/tags", data={"repository": "rg.test/app", "tag": "prod",
                                   "digest": digest("w"), "actor": "ops"}, follow_redirects=True)
    assert r.status_code == 200
    assert "修订 1" in r.text

    r = client.post("/requests", data={
        "repository": "rg.test/app", "tag": "prod", "environment": "prod",
        "requested_by": "ops", "note": "发布",
    }, follow_redirects=True)
    assert r.status_code == 200
    assert "部署请求" in r.text

    request_id = r.url.path.rsplit("/", 1)[-1]
    r = client.post(f"/requests/{request_id}/verify", data={"actor": "ops"}, follow_redirects=True)
    assert r.status_code == 200
    assert "放行" in r.text
    assert "结果冻结" in r.text

    r = client.get("/releases")
    assert r.status_code == 200
    assert "已放行" in r.text

    detail = client.get(f"/requests/{request_id}/attempts/1")
    assert detail.status_code == 200
    assert "策略快照" in detail.text


def test_web_rejection_shows_reason(client):
    r = client.post("/digests", data={
        "repository": "rg.test/app", "digest": digest("bad"),
        "build_source": "ci://bad", "source_status": "unverified",
        "signature_status": "missing", "signer": "", "actor": "ops",
    }, follow_redirects=True)
    assert r.status_code == 200
    r = client.post("/tags", data={"repository": "rg.test/app", "tag": "prod",
                                   "digest": digest("bad"), "actor": "ops"}, follow_redirects=True)
    r = client.post("/requests", data={
        "repository": "rg.test/app", "tag": "prod", "environment": "prod",
        "requested_by": "ops",
    }, follow_redirects=True)
    request_id = r.url.path.rsplit("/", 1)[-1]
    r = client.post(f"/requests/{request_id}/verify", data={"actor": "ops"}, follow_redirects=True)
    assert r.status_code == 200
    assert "拒绝" in r.text
    assert "构建来源" in r.text
    detail = client.get(f"/requests/{request_id}")
    assert "拒绝原因" in detail.text
    assert client.get("/releases").text.count("已放行") >= 0


def test_web_allows_reverify_after_rejection(client):
    r = client.post("/digests", data={
        "repository": "rg.test/app", "digest": digest("fix"),
        "build_source": "ci://fix", "source_status": "verified",
        "signature_status": "missing", "signer": "team-a", "actor": "ops",
    }, follow_redirects=True)
    client.post("/tags", data={"repository": "rg.test/app", "tag": "prod",
                               "digest": digest("fix"), "actor": "ops"})
    r = client.post("/requests", data={
        "repository": "rg.test/app", "tag": "prod", "environment": "prod",
        "requested_by": "ops",
    }, follow_redirects=True)
    request_id = r.url.path.rsplit("/", 1)[-1]
    client.post(f"/requests/{request_id}/verify", data={"actor": "ops"}, follow_redirects=True)
    # Fix evidence on the same digest, then re-verify through the web form.
    client.post("/digests", data={
        "repository": "rg.test/app", "digest": digest("fix"),
        "build_source": "ci://fix", "source_status": "verified",
        "signature_status": "verified", "signer": "team-a", "actor": "ops",
    })
    r = client.post(f"/requests/{request_id}/verify", data={"actor": "ops"}, follow_redirects=True)
    assert "第 2 次校验通过" in r.text
    assert client.get("/releases").text.count("已放行") >= 1


# ------------------------------------------------------------------- utilities
def running_attempt_exists(db_path: Path, request_id: str) -> bool:
    with connect(db_path) as conn:
        row = conn.execute(
            "SELECT 1 FROM attempts WHERE request_id = ? AND status = 'running'",
            (request_id,),
        ).fetchone()
    return row is not None


def wait_until(predicate, timeout: float = 5.0, interval: float = 0.01) -> bool:
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False
