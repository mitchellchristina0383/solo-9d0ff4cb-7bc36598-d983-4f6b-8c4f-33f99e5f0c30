from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

import pytest

from app.config import Settings
from app.db import init_db
from app.handover import (
    BlobVerificationError,
    BlobWriteError,
    HandoverError,
    HandoverService,
    LayoutMissingError,
    ReferenceNotFoundError,
)
from app.service import ConflictError, Service

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write_blob(root: Path, data: bytes) -> tuple[str, int]:
    digest = sha256_digest(data)
    path = root / "blobs" / "sha256" / digest.split(":", 1)[1]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return digest, len(data)


def init_layout(root: Path, descriptors: list[dict]) -> None:
    (root / "oci-layout").write_text(
        json.dumps({"imageLayoutVersion": "1.0.0"}), encoding="utf-8"
    )
    (root / "index.json").write_text(
        json.dumps({"schemaVersion": 2, "manifests": descriptors}), encoding="utf-8"
    )


def make_config(arch: str = "amd64", env_name: str = "app") -> bytes:
    return json.dumps(
        {
            "architecture": arch,
            "os": "linux",
            "config": {"Env": [f"NAME={env_name}"]},
            "rootfs": {"type": "layers", "diff_ids": []},
        },
        sort_keys=True,
    ).encode()


def make_manifest(root: Path, *, layers: list[bytes], config: bytes | None = None,
                  arch: str = "amd64", media_type: str = OCI_MANIFEST) -> tuple[str, int]:
    config = config if config is not None else make_config(arch)
    config_digest, config_size = write_blob(root, config)
    layer_refs = []
    for layer in layers:
        d, s = write_blob(root, layer)
        layer_refs.append(
            {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": d, "size": s}
        )
    manifest = {
        "schemaVersion": 2,
        "mediaType": media_type,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_size,
        },
        "layers": layer_refs,
    }
    raw = json.dumps(manifest, sort_keys=True).encode()
    digest, size = write_blob(root, raw)
    return digest, size


def make_index(root: Path, children: list[tuple[str, int, dict]]) -> tuple[str, int]:
    doc = {
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [
            {"mediaType": OCI_MANIFEST, "digest": d, "size": s, "platform": p}
            for d, s, p in children
        ],
    }
    raw = json.dumps(doc, sort_keys=True).encode()
    return write_blob(root, raw)


@pytest.fixture()
def source_dir(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    root.mkdir()
    return root


@pytest.fixture()
def target_dir(tmp_path: Path) -> Path:
    return tmp_path / "handover"


@pytest.fixture()
def engine(source_dir: Path, target_dir: Path) -> HandoverService:
    return HandoverService(source_dir, target_dir)


@pytest.fixture()
def service(tmp_path: Path, source_dir: Path, target_dir: Path) -> Service:
    db = tmp_path / "test.db"
    init_db(db)
    settings = Settings(
        db_path=db,
        verify_delay_ms=0,
        handover_source_dir=source_dir,
        handover_target_dir=target_dir,
    )
    return Service(settings)


def release_row(
    digest: str, *, rid: str = "REL-1", repo: str = "rg.test/app", tag: str = "prod"
) -> dict:
    return {
        "id": rid,
        "repository": repo,
        "tag": tag,
        "digest": digest,
        "released_at": "2026-11-23T00:00:00.000000Z",
    }


def index_manifests(target_dir: Path) -> list[dict]:
    return json.loads((target_dir / "index.json").read_text())["manifests"]


# ------------------------------------------------------------- OCI 解析与布局
def test_missing_source_layout_raises(engine: HandoverService, tmp_path: Path):
    with pytest.raises(LayoutMissingError):
        engine.handover(release_row("sha256:" + "a" * 64))


def test_unknown_digest_is_reference_not_found(source_dir: Path, engine: HandoverService):
    init_layout(source_dir, [])
    with pytest.raises((ReferenceNotFoundError, HandoverError)):
        engine.handover(release_row("sha256:" + "a" * 64))


def test_platform_missing_in_index(source_dir: Path, engine: HandoverService):
    d, s = make_manifest(source_dir, layers=[b"arm-layer"])
    idx_d, idx_s = make_index(
        source_dir, [(d, s, {"os": "linux", "architecture": "arm64"})]
    )
    init_layout(source_dir, [{"mediaType": OCI_INDEX, "digest": idx_d, "size": idx_s}])
    with pytest.raises(ReferenceNotFoundError, match="linux/amd64"):
        engine.handover(release_row(idx_d))


# ------------------------------------------------------------------ 主流程
def test_single_arch_handover_copies_all_refs_and_writes_index_once(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    big = os.urandom(3 * 1024 * 1024)
    digest, size = make_manifest(source_dir, layers=[b"small-layer", big])
    init_layout(
        source_dir,
        [{"mediaType": OCI_MANIFEST, "digest": digest, "size": size}],
    )

    result = engine.handover(release_row(digest))

    assert result["manifest_digest"] == digest
    assert result["blob_count"] == 4  # manifest + config + 2 layers
    assert result["already_listed"] is False
    roles = [b["role"] for b in result["blobs"]]
    assert roles == ["manifest", "config", "layer", "layer"]

    # 目标是合法 OCI Image Layout，且 blob 与清单声明一一对应。
    assert json.loads((target_dir / "oci-layout").read_text()) == {
        "imageLayoutVersion": "1.0.0"
    }
    manifests = index_manifests(target_dir)
    assert len(manifests) == 1
    descriptor = manifests[0]
    assert descriptor["digest"] == digest
    assert descriptor["annotations"]["io.admission.release.id"] == "REL-1"

    manifest_doc = json.loads(
        (target_dir / "blobs" / "sha256" / digest.split(":", 1)[1]).read_bytes()
    )
    expected_blobs = [digest, manifest_doc["config"]["digest"]] + [
        layer["digest"] for layer in manifest_doc["layers"]
    ]
    for blob_digest in expected_blobs:
        path = target_dir / "blobs" / "sha256" / blob_digest.split(":", 1)[1]
        assert path.is_file()
        assert sha256_digest(path.read_bytes()) == blob_digest
    assert result["total_bytes"] == sum(
        (target_dir / "blobs" / "sha256" / d.split(":", 1)[1]).stat().st_size
        for d in expected_blobs
    )


def test_multi_arch_selects_only_amd64_child_and_skips_index_blob(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    amd_d, amd_s = make_manifest(source_dir, layers=[b"amd-layer"], arch="amd64")
    arm_d, arm_s = make_manifest(source_dir, layers=[b"arm-layer"], arch="arm64")
    idx_d, idx_s = make_index(
        source_dir,
        [
            (amd_d, amd_s, {"os": "linux", "architecture": "amd64"}),
            (arm_d, arm_s, {"os": "linux", "architecture": "arm64"}),
        ],
    )
    init_layout(source_dir, [{"mediaType": OCI_INDEX, "digest": idx_d, "size": idx_s}])

    result = engine.handover(release_row(idx_d))

    assert result["manifest_digest"] == amd_d
    assert result["resolution_chain"] == [idx_d, amd_d]
    stored = {p.name for p in (target_dir / "blobs" / "sha256").iterdir()}
    assert idx_d.split(":", 1)[1] not in stored  # 清单列表本身不交接
    assert amd_d.split(":", 1)[1] in stored
    assert arm_d.split(":", 1)[1] not in stored  # 另一架构不交接
    descriptor = index_manifests(target_dir)[0]
    assert descriptor["platform"] == {"os": "linux", "architecture": "amd64"}


def test_non_default_platform_is_selected_and_recorded(
    source_dir: Path, target_dir: Path
):
    amd_d, amd_s = make_manifest(source_dir, layers=[b"amd-layer"], arch="amd64")
    arm_d, arm_s = make_manifest(source_dir, layers=[b"arm-layer"], arch="arm64")
    idx_d, idx_s = make_index(
        source_dir,
        [
            (amd_d, amd_s, {"os": "linux", "architecture": "amd64"}),
            (arm_d, arm_s, {"os": "linux", "architecture": "arm64"}),
        ],
    )
    init_layout(source_dir, [{"mediaType": OCI_INDEX, "digest": idx_d, "size": idx_s}])

    engine = HandoverService(source_dir, target_dir, platform_os="linux", platform_arch="arm64")
    result = engine.handover(release_row(idx_d))

    assert result["manifest_digest"] == arm_d
    assert result["platform"] == "linux/arm64"
    descriptor = index_manifests(target_dir)[0]
    assert descriptor["platform"] == {"os": "linux", "architecture": "arm64"}
    stored = {p.name for p in (target_dir / "blobs" / "sha256").iterdir()}
    assert arm_d.split(":", 1)[1] in stored
    assert amd_d.split(":", 1)[1] not in stored


def test_verified_blob_stored_once_and_reused_on_retry(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    shared = b"shared-base-layer"
    d1, s1 = make_manifest(source_dir, layers=[shared, b"top-a"])
    d2, s2 = make_manifest(source_dir, layers=[shared, b"top-b"])
    init_layout(
        source_dir,
        [
            {"mediaType": OCI_MANIFEST, "digest": d1, "size": s1},
            {"mediaType": OCI_MANIFEST, "digest": d2, "size": s2},
        ],
    )

    r1 = engine.handover(release_row(d1, rid="REL-1"))
    r2 = engine.handover(release_row(d2, rid="REL-2"))
    r3 = engine.handover(release_row(d1, rid="REL-1"))  # 重试同一镜像

    blobs_dir = target_dir / "blobs" / "sha256"
    names = [p.name for p in blobs_dir.iterdir()]
    assert len(names) == len(set(names))  # 同一 blob 只有一份

    shared_digest = sha256_digest(shared)
    # 第二次交接时共享层被复用；重试时全部 blob 都已在卷内。
    reused_r2 = {b["digest"] for b in r2["blobs"] if b["reused"]}
    assert shared_digest in reused_r2
    assert all(b["reused"] for b in r3["blobs"])
    # 索引去重：同 digest 重复交接只列一次。
    digests = [d["digest"] for d in index_manifests(target_dir)]
    assert digests == [d1, d2]
    assert r3["already_listed"] is True


def test_missing_layer_fails_before_index_write(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    digest, size = make_manifest(source_dir, layers=[b"layer-ok", b"layer-gone"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": digest, "size": size}])
    manifest = json.loads(
        (source_dir / "blobs" / "sha256" / digest.split(":", 1)[1]).read_bytes()
    )
    gone = manifest["layers"][1]["digest"].split(":", 1)[1]
    (source_dir / "blobs" / "sha256" / gone).unlink()

    with pytest.raises(HandoverError):
        engine.handover(release_row(digest))

    # 没有索引项；卷内没有该镜像的完整内容，临时文件被清理。
    assert not (target_dir / "index.json").exists() or index_manifests(target_dir) == []
    leftovers = list((target_dir / ".tmp").glob("blob-*"))
    assert leftovers == []


def test_missing_blob_stat_fails_before_copy(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    digest, size = make_manifest(source_dir, layers=[b"layer"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": digest, "size": size}])
    manifest = json.loads(
        (source_dir / "blobs" / "sha256" / digest.split(":", 1)[1]).read_bytes()
    )
    layer_hex = manifest["layers"][0]["digest"].split(":", 1)[1]
    (source_dir / "blobs" / "sha256" / layer_hex).unlink()
    with pytest.raises(HandoverError):
        engine.handover(release_row(digest))
    assert not (target_dir / "index.json").exists() or index_manifests(target_dir) == []


def test_corrupt_blob_detected_during_streaming_copy(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    digest, _ = make_manifest(source_dir, layers=[b"layer-good", b"layer-bad"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": digest, "size": 0}])
    manifest_path = source_dir / "blobs" / "sha256" / digest.split(":", 1)[1]
    manifest = json.loads(manifest_path.read_bytes())
    bad_hex = manifest["layers"][1]["digest"].split(":", 1)[1]
    # 保持大小不变但改内容：预检（大小）通过，流式 sha256 校验必须失败。
    original_size = (source_dir / "blobs" / "sha256" / bad_hex).stat().st_size
    (source_dir / "blobs" / "sha256" / bad_hex).write_bytes(b"x" * original_size)

    with pytest.raises(BlobVerificationError):
        engine.handover(release_row(digest))
    assert not (target_dir / "index.json").exists() or index_manifests(target_dir) == []


def test_write_failure_leaves_no_index_entry(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    digest, size = make_manifest(source_dir, layers=[b"layer"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": digest, "size": size}])
    engine.store.ensure_layout()
    os.chmod(target_dir / "blobs" / "sha256", 0o500)  # 只读，写盘必失败
    try:
        with pytest.raises(BlobWriteError):
            engine.handover(release_row(digest))
    finally:
        os.chmod(target_dir / "blobs" / "sha256", 0o700)
    assert index_manifests(target_dir) == []


def test_interrupted_copy_cleans_partial_and_is_retryable(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    digest, size = make_manifest(source_dir, layers=[b"layer-one", b"layer-two"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": digest, "size": size}])
    calls = {"n": 0}

    def flaky_hook(ref, chunk, written):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated interruption")

    with pytest.raises(RuntimeError):
        engine.handover(release_row(digest), hook=flaky_hook)
    assert list((target_dir / ".tmp").glob("blob-*")) == []
    assert index_manifests(target_dir) == []

    # 重试后完整成功，半成品没有污染 blob 存储。
    result = engine.handover(release_row(digest))
    assert result["blob_count"] == 4  # manifest + config + 2 layers
    assert index_manifests(target_dir)[0]["digest"] == digest


def test_concurrent_handovers_do_not_overwrite_index_entries(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    digests = []
    for i in range(6):
        d, s = make_manifest(source_dir, layers=[f"layer-{i}".encode()])
        digests.append((d, s))
    init_layout(
        source_dir,
        [{"mediaType": OCI_MANIFEST, "digest": d, "size": s} for d, s in digests],
    )

    errors: list[Exception] = []

    def worker(index: int):
        try:
            d, _ = digests[index]
            engine.handover(release_row(d, rid=f"REL-{index}"))
        except Exception as exc:  # pragma: no cover - 测试失败诊断
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(digests))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)

    assert errors == []
    listed = sorted(d["digest"] for d in index_manifests(target_dir))
    assert listed == sorted(d for d, _ in digests)


def test_slow_large_image_does_not_block_another_ready_handover(
    source_dir: Path, target_dir: Path, engine: HandoverService
):
    big = os.urandom(5 * 1024 * 1024)
    big_d, big_s = make_manifest(source_dir, layers=[big])
    small_d, small_s = make_manifest(source_dir, layers=[b"quick"])
    init_layout(
        source_dir,
        [
            {"mediaType": OCI_MANIFEST, "digest": big_d, "size": big_s},
            {"mediaType": OCI_MANIFEST, "digest": small_d, "size": small_s},
        ],
    )

    release_event = threading.Event()
    order: list[str] = []

    def slow_hook(ref, chunk, written):
        if ref.digest == big_d or ref.size > 1_000_000:
            release_event.wait(5)

    def big_worker():
        engine.handover(release_row(big_d, rid="REL-BIG"), hook=slow_hook)
        order.append("big")

    t = threading.Thread(target=big_worker)
    t.start()
    # 等大镜像确实进入流式复制，再交接内容已齐的小镜像。
    release_event.clear()
    started = threading.Event()

    def waiter():
        started.set()
        while not release_event.is_set():
            if any(
                p.name.startswith("blob-")
                for p in (target_dir / ".tmp").glob("blob-*")
            ):
                release_event.set()
                return
    w = threading.Thread(target=waiter)
    w.start()
    w.join(5)

    engine.handover(release_row(small_d, rid="REL-SMALL"))
    order.append("small")
    release_event.set()
    t.join(15)

    assert order == ["small", "big"]  # 小单先完成
    assert {d["digest"] for d in index_manifests(target_dir)} == {big_d, small_d}


def test_concurrent_processes_keep_both_index_entries(source_dir: Path, target_dir: Path):
    """跨进程并发交接不同 digest：flock + 原子 rename 必须保住两条索引项。"""
    import subprocess
    import sys

    digests = []
    for i in range(2):
        d, s = make_manifest(source_dir, layers=[f"proc-layer-{i}".encode()])
        digests.append((d, s))
    init_layout(
        source_dir,
        [{"mediaType": OCI_MANIFEST, "digest": d, "size": s} for d, s in digests],
    )

    script = (
        "import sys; from pathlib import Path; "
        "from app.handover import HandoverService; "
        "svc = HandoverService(Path(sys.argv[1]), Path(sys.argv[2])); "
        "svc.handover({'id': sys.argv[3], 'repository': 'rg.test/app', 'tag': 'prod', "
        "'digest': sys.argv[4], 'released_at': ''})"
    )
    env = dict(os.environ)
    extra = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = extra + os.pathsep + env.get("PYTHONPATH", "")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(source_dir), str(target_dir),
             f"REL-P{i}", digests[i][0]],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for i in range(2)
    ]
    outputs = [(p.wait(30), p.stdout.read(), p.stderr.read()) for p in procs]
    for code, _out, err in outputs:
        assert code == 0, err.decode()

    listed = {d["digest"] for d in index_manifests(target_dir)}
    assert listed == {d for d, _ in digests}
    # 卷内每个 blob 都与文件名摘要一致。
    for blob in (target_dir / "blobs" / "sha256").iterdir():
        assert "sha256:" + blob.name == sha256_digest(blob.read_bytes())


def test_handover_streaming_uses_bounded_chunk_size(source_dir: Path, engine: HandoverService):
    from app import handover as handover_module

    assert handover_module.CHUNK_SIZE <= 4 * 1024 * 1024
    seen_chunk_sizes: list[int] = []

    def measure(ref, chunk, written):
        seen_chunk_sizes.append(chunk)

    big = os.urandom(2_500_000)
    digest, size = make_manifest(source_dir, layers=[big])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": digest, "size": size}])
    engine.handover(release_row(digest), hook=measure)
    assert seen_chunk_sizes
    assert max(seen_chunk_sizes) <= handover_module.CHUNK_SIZE


# ------------------------------------------------------------------ 服务/DB
def _seed_released_request(service: Service, digest: str) -> dict:
    rec, _ = service.upsert_digest(
        repository="rg.test/app", digest=digest, build_source="ci://x",
        source_status="verified", signature_status="verified", signer="team-a",
        signature_ref=None, note=None, actor="ops",
    )
    service.set_tag(repository="rg.test/app", tag="prod", digest=rec["digest"], actor="ops")
    req = service.create_request(
        repository="rg.test/app", tag="prod", expected_digest=None, environment="prod",
        requested_by="ops", note=None,
    )
    service.verify(req["id"], actor="ops")
    return service.list_releases()[0]


def test_service_handover_success_and_audit_row(service: Service, source_dir: Path, target_dir: Path):
    d, s = make_manifest(source_dir, layers=[b"layer"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": d, "size": s}])
    release = _seed_released_request(service, d)

    item = service.handover_release(release["id"], actor="ops")
    assert item["status"] == "completed"
    assert item["blob_count"] == 3  # manifest + config + 1 layer
    assert item["detail_obj"]["manifest_digest"] == d
    rows = service.list_handovers()
    assert len(rows) == 1 and rows[0]["status"] == "completed"


def test_service_failure_records_failed_row_but_no_index(service: Service, target_dir: Path):
    ghost = "sha256:" + hashlib.sha256(b"missing").hexdigest()
    release = _seed_released_request(service, ghost)
    item = service.handover_release(release["id"], actor="ops")
    assert item["status"] == "failed"
    assert item["error"]
    assert not (target_dir / "index.json").exists()
    # 已有放行记录不受影响。
    assert len(service.list_releases()) == 1


def test_concurrent_service_calls_refused_while_running(
    service: Service, source_dir: Path, target_dir: Path
):
    d, s = make_manifest(source_dir, layers=[b"layer"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": d, "size": s}])
    release = _seed_released_request(service, d)

    entered = threading.Event()
    release_hook = threading.Event()

    def hold(ref, chunk, written):
        entered.set()
        release_hook.wait(5)

    errors: list[Exception] = []

    def first():
        service.handover_release(release["id"], actor="ops", copy_hook=hold)

    t = threading.Thread(target=first)
    t.start()
    assert entered.wait(5)
    try:
        with pytest.raises(ConflictError):
            service.handover_release(release["id"], actor="ops")
    finally:
        release_hook.set()
        t.join(15)
    assert errors == []
    assert [h["status"] for h in service.list_handovers()] == ["completed"]


def test_target_index_corruption_blocks_rewrite(service: Service, source_dir: Path, target_dir: Path):
    d, s = make_manifest(source_dir, layers=[b"layer"])
    init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": d, "size": s}])
    release = _seed_released_request(service, d)
    service.handover_service.store.ensure_layout()
    (target_dir / "index.json").write_text("{not-json")
    item = service.handover_release(release["id"], actor="ops")
    assert item["status"] == "failed"
    assert "index.json" in item["error"]


# ------------------------------------------------------------------ Web 层
def _web_client(tmp_path: Path, name: str):
    from fastapi.testclient import TestClient
    from app.web import create_app

    source_dir = tmp_path / f"{name}-source"
    target_dir = tmp_path / f"{name}-handover"
    source_dir.mkdir()
    db = tmp_path / f"{name}.db"
    init_db(db)
    settings = Settings(
        db_path=db, verify_delay_ms=0,
        handover_source_dir=source_dir, handover_target_dir=target_dir,
    )
    app = create_app(settings)
    return TestClient(app), source_dir, target_dir, app


def _release_via_web(client, app, manifest_digest: str) -> dict:
    client.post("/digests", data={
        "repository": "rg.test/app", "digest": manifest_digest,
        "build_source": "ci://w", "source_status": "verified",
        "signature_status": "verified", "signer": "team-a", "actor": "ops",
    })
    client.post("/tags", data={"repository": "rg.test/app", "tag": "prod",
                               "digest": manifest_digest, "actor": "ops"})
    r = client.post("/requests", data={
        "repository": "rg.test/app", "tag": "prod", "environment": "prod",
        "requested_by": "ops",
    }, follow_redirects=True)
    request_id = r.url.path.rsplit("/", 1)[-1]
    client.post(f"/requests/{request_id}/verify", data={"actor": "ops"})
    return app.state.service.list_releases()[0]


def test_web_handover_flow(tmp_path: Path):
    client, source_dir, target_dir, app = _web_client(tmp_path, "web")
    with client:
        d, s = make_manifest(source_dir, layers=[b"web-layer"])
        release = _release_via_web(client, app, d)
        init_layout(source_dir, [{"mediaType": OCI_MANIFEST, "digest": d, "size": s}])

        r = client.post(f"/releases/{release['id']}/handover",
                        data={"actor": "ops"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/handovers")

        page = client.get("/handovers")
        assert page.status_code == 200 and "已完成" in page.text
        detail = client.get("/handovers/1")
        assert "实际交接 blob 核对" in detail.text

        # 重复交接：索引去重，页面提示复用。
        r = client.post(f"/releases/{release['id']}/handover",
                        data={"actor": "ops"}, follow_redirects=True)
        assert "未重复列项" in r.text
        index = json.loads((target_dir / "index.json").read_text())
        assert len(index["manifests"]) == 1


def test_web_handover_failure_shows_error(tmp_path: Path):
    client, source_dir, target_dir, app = _web_client(tmp_path, "web2")
    with client:
        ghost = "sha256:" + hashlib.sha256(b"web2").hexdigest()
        release = _release_via_web(client, app, ghost)
        # 源卷存在布局但没有该 digest 的 blob。
        init_layout(source_dir, [])
        r = client.post(f"/releases/{release['id']}/handover",
                        data={"actor": "ops"}, follow_redirects=True)
        assert "交接失败" in r.text
        assert "未新增索引项" in r.text
        assert app.state.service.list_handovers()[0]["status"] == "failed"
