"""OCI Image Layout 交接：把已放行镜像复制到隔离集群的交接卷。

交接卷与源卷都遵循 `OCI Image Layout` 规范：

* ``oci-layout``      固定为 ``{"imageLayoutVersion": "1.0.0"}``
* ``index.json``      镜像清单描述符列表（交接卷的“索引”）
* ``blobs/sha256/``   按摘要寻址的 blob（清单、配置、层）

关键约定（对应交接需求）：

* 放行 digest 可能直接指向单架构清单，也可能指向 manifest list；后者只选择
  隔离集群所需平台（默认 ``linux/amd64``）的**单架构子清单**交接，清单列表
  本身不复制。
* 复制以 1 MiB 分块流式进行，边读边算 sha256 与字节数，大层不会整体进入
  内存；摘要或大小不符即判定失败并清理临时文件。
* blob 按内容摘要寻址，校验通过的 blob 在卷里只存一份；同一 blob 的复制由
  进程内锁 + ``flock`` 跨进程锁串行化，重试或并发交接直接复用。
* 只有当清单、配置、所有层 blob 都复制并校验通过后，才把描述符原子追加进
  ``index.json``；任何缺件/校验/写盘错误都不会产生新的索引项。
* ``index.json`` 的更新在全局索引锁内读改写并以临时文件 + ``rename`` 原子
  替换，并发交接不会覆盖彼此的条目，同一 digest 只列一次。
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

IMAGE_INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
IMAGE_MANIFEST_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
DEFAULT_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
LAYOUT_VERSION = {"imageLayoutVersion": "1.0.0"}
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
CHUNK_SIZE = 1024 * 1024  # 1 MiB：任何层都按该粒度流式复制，不整体读入内存

#: 复制分块回调：(blob 引用, 本次块字节数, 已复制字节数)，测试用来注入减速/中断。
CopyHook = Callable[["BlobRef", int, int], None]


class HandoverError(Exception):
    """交接失败的基类；失败时目标索引保证不新增条目。"""


class LayoutMissingError(HandoverError):
    """源/目标目录不是合法的 OCI Image Layout。"""


class ReferenceNotFoundError(HandoverError):
    """放行 digest 在源布局中无法解析到目标平台的单架构清单。"""


class BlobMissingError(HandoverError):
    """源布局缺少被引用的 blob。"""

    def __init__(self, digest: str, role: str = "blob") -> None:
        super().__init__(f"源布局缺少{role} blob：{digest}")
        self.digest = digest
        self.role = role


class BlobVerificationError(HandoverError):
    """复制后实际摘要或大小与清单声明不符。"""


class BlobWriteError(HandoverError):
    """blob 或索引写盘失败。"""


class ManifestValidationError(HandoverError):
    """清单内容不符合 OCI/Docker 镜像清单结构。"""


@dataclass(frozen=True)
class BlobRef:
    """清单中声明的一个 blob 引用（摘要 + 声明大小）。"""

    digest: str
    size: int


@dataclass
class ManifestPlan:
    """一次交接需要复制的全部内容。"""

    manifest_digest: str
    manifest_bytes: bytes
    media_type: str
    config: BlobRef | None
    layers: tuple[BlobRef, ...]
    platform: dict[str, str] | None
    resolution_chain: tuple[str, ...] = field(default_factory=tuple)

    def refs(self) -> list[tuple[str, BlobRef]]:
        """返回 ``(角色, 引用)`` 列表，manifest 永远在最前。"""
        out: list[tuple[str, BlobRef]] = [
            ("manifest", BlobRef(self.manifest_digest, len(self.manifest_bytes)))
        ]
        if self.config is not None:
            out.append(("config", self.config))
        out.extend(("layer", ref) for ref in self.layers)
        return out


def _digest_hex(digest: str) -> str:
    match = DIGEST_RE.match(digest or "")
    if not match:
        raise ManifestValidationError(f"非法 digest：{digest!r}")
    return match.group(1)


def _descriptor_ref(doc: dict[str, Any], *, allow_missing_size: bool = False) -> BlobRef:
    digest = doc.get("digest")
    hexpart = _digest_hex(digest if isinstance(digest, str) else "")
    size = doc.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        if not allow_missing_size:
            raise ManifestValidationError(f"描述符 {digest} 缺少合法 size")
        size = -1
    return BlobRef(f"sha256:{hexpart}", size)


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class OciLayout:
    """只读 OCI Image Layout（挂载的放行镜像源卷）。"""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)

    def blob_path(self, digest: str) -> Path:
        return self.root / "blobs" / "sha256" / _digest_hex(digest)

    def ensure_valid(self) -> None:
        layout_file = self.root / "oci-layout"
        index_file = self.root / "index.json"
        if not self.root.is_dir() or not layout_file.is_file() or not index_file.is_file():
            raise LayoutMissingError(f"源目录不是合法 OCI Image Layout：{self.root}")
        try:
            layout = json.loads(layout_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LayoutMissingError(f"源 oci-layout 无法读取：{exc}") from exc
        if layout.get("imageLayoutVersion") != LAYOUT_VERSION["imageLayoutVersion"]:
            raise LayoutMissingError("源 oci-layout 的 imageLayoutVersion 不受支持")
        try:
            index = json.loads(index_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LayoutMissingError(f"源 index.json 无法解析：{exc}") from exc
        if not isinstance(index.get("manifests"), list):
            raise LayoutMissingError("源 index.json 缺少 manifests 列表")

    def resolve(
        self, digest: str, *, want_os: str = "linux", want_arch: str = "amd64"
    ) -> ManifestPlan:
        """把放行 digest 解析为目标平台的单架构清单交接计划。"""
        self.ensure_valid()
        _digest_hex(digest)
        return self._resolve(digest, want_os, want_arch, visited=set(), chain=())

    def _resolve(
        self,
        digest: str,
        want_os: str,
        want_arch: str,
        *,
        visited: set[str],
        chain: tuple[str, ...],
    ) -> ManifestPlan:
        if digest in visited:
            raise ReferenceNotFoundError(f"清单引用出现循环：{digest}")
        visited = visited | {digest}
        chain = chain + (digest,)

        path = self.blob_path(digest)
        if not path.is_file():
            raise BlobMissingError(digest, "清单")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise BlobMissingError(digest, "清单") from exc
        actual = "sha256:" + hashlib.sha256(raw).hexdigest()
        if actual != digest:
            raise BlobVerificationError(
                f"清单 blob 内容与文件名摘要不符：声明 {digest}，实际 {actual}"
            )
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ManifestValidationError(f"清单 {digest} 不是合法 JSON：{exc}") from exc
        if not isinstance(doc, dict):
            raise ManifestValidationError(f"清单 {digest} 结构非法")

        if "manifests" in doc:
            if not isinstance(doc["manifests"], list) or not doc["manifests"]:
                raise ManifestValidationError(f"清单列表 {digest} 没有子清单")
            chosen = None
            available: list[str] = []
            for child in doc["manifests"]:
                if not isinstance(child, dict) or not isinstance(child.get("digest"), str):
                    continue
                platform = child.get("platform") or {}
                available.append(
                    f"{platform.get('os', '?')}/{platform.get('architecture', '?')}"
                )
                if (
                    platform.get("os") == want_os
                    and platform.get("architecture") == want_arch
                ):
                    chosen = child["digest"]
                    break
            if chosen is None:
                raise ReferenceNotFoundError(
                    f"清单列表 {digest} 中没有平台 {want_os}/{want_arch} 的子清单"
                    f"（可用：{', '.join(available) or '无'}）"
                )
            resolved = self._resolve(chosen, want_os, want_arch, visited=visited, chain=chain)
            # 记录实际选中的平台，而不是硬编码。
            resolved.platform = {"os": want_os, "architecture": want_arch}
            return resolved

        if "layers" not in doc:
            raise ManifestValidationError(
                f"清单 {digest} 既不是镜像清单也不是清单列表（缺少 layers/manifests）"
            )
        return self._build_plan(digest, raw, doc, chain)

    def _build_plan(
        self, digest: str, raw: bytes, doc: dict[str, Any], chain: tuple[str, ...]
    ) -> ManifestPlan:
        layers_raw = doc["layers"]
        if not isinstance(layers_raw, list) or not layers_raw:
            raise ManifestValidationError(f"镜像清单 {digest} 缺少非空 layers")
        layers: list[BlobRef] = []
        for desc in layers_raw:
            if not isinstance(desc, dict):
                raise ManifestValidationError(f"清单 {digest} 的 layer 描述符非法")
            layers.append(_descriptor_ref(desc))

        config: BlobRef | None = None
        config_desc = doc.get("config")
        if config_desc is not None:
            if not isinstance(config_desc, dict):
                raise ManifestValidationError(f"清单 {digest} 的 config 描述符非法")
            config = _descriptor_ref(config_desc)

        media_type = doc.get("mediaType")
        if media_type not in IMAGE_MANIFEST_MEDIA_TYPES:
            media_type = DEFAULT_MANIFEST_MEDIA_TYPE

        return ManifestPlan(
            manifest_digest=digest,
            manifest_bytes=raw,
            media_type=media_type,
            config=config,
            layers=tuple(layers),
            platform=None,  # 由上层在清单列表解析时按目标平台回填
            resolution_chain=chain,
        )


class HandoverStore:
    """可写 OCI Image Layout（隔离集群交接卷），负责 blob 与索引的安全落盘。"""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.blobs_dir = self.root / "blobs" / "sha256"
        self.locks_dir = self.root / ".locks"
        self.tmp_dir = self.root / ".tmp"
        self._index_thread_lock = threading.Lock()
        self._blob_guard = threading.Lock()
        self._blob_locks: dict[str, threading.Lock] = {}

    # ------------------------------------------------------------- layout 初始化
    def ensure_layout(self) -> None:
        try:
            self.blobs_dir.mkdir(parents=True, exist_ok=True)
            self.locks_dir.mkdir(parents=True, exist_ok=True)
            self.tmp_dir.mkdir(parents=True, exist_ok=True)
            layout_file = self.root / "oci-layout"
            if not layout_file.exists():
                self._atomic_write(layout_file, json.dumps(LAYOUT_VERSION).encode("utf-8"))
            index_file = self.root / "index.json"
            if not index_file.exists():
                self._atomic_write(
                    index_file,
                    json.dumps({"schemaVersion": 2, "manifests": []}).encode("utf-8"),
                )
            # 注意：不在此处清理 .tmp 遗留文件。其他进程可能正持有同名前缀的
            # 临时 blob，任何“启动时清扫”都可能删掉在途数据。复制失败时由
            # copy_blob 自行清理本进程的临时文件；崩溃遗留文件只会占空间，
            # 永远不会进入 blobs/ 或 index.json，不影响正确性。
        except OSError as exc:
            raise BlobWriteError(f"初始化交接卷失败：{exc}") from exc

    def blob_path(self, digest: str) -> Path:
        return self.blobs_dir / _digest_hex(digest)

    def _blob_lock(self, digest: str) -> threading.Lock:
        key = _digest_hex(digest)
        with self._blob_guard:
            lock = self._blob_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._blob_locks[key] = lock
            return lock

    def _file_lock(self, name: str):
        path = self.locks_dir / name
        f = open(path, "w")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return f

    def _verify_stored_blob(self, path: Path, ref: BlobRef) -> None:
        """回读卷内实际 blob，流式核对 sha256 与字节数；不符即删除并报错。"""
        hasher = hashlib.sha256()
        counted = 0
        try:
            with open(path, "rb") as fin:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    counted += len(chunk)
        except OSError as exc:
            raise BlobWriteError(f"回读校验失败（{ref.digest}）：{exc}") from exc
        if counted != ref.size or hasher.hexdigest() != _digest_hex(ref.digest):
            self._silent_unlink(path)
            raise BlobVerificationError(
                f"落盘 blob 复核不符（{ref.digest}）："
                f"卷内实际 sha256:{hasher.hexdigest()} / {counted} 字节，"
                f"声明 {ref.digest} / {ref.size} 字节"
            )

    # ------------------------------------------------------------------ blob 复制
    def copy_blob(
        self,
        source: OciLayout,
        ref: BlobRef,
        *,
        hook: CopyHook | None = None,
    ) -> bool:
        """流式复制并校验单个 blob，返回 ``True`` 表示复用了卷内已有 blob。"""
        src = source.blob_path(ref.digest)
        if not src.is_file():
            raise BlobMissingError(ref.digest)
        try:
            actual_src_size = src.stat().st_size
        except OSError as exc:
            raise BlobMissingError(ref.digest) from exc
        if actual_src_size != ref.size:
            raise BlobVerificationError(
                f"源 blob {ref.digest} 大小不符：清单声明 {ref.size}，实际 {actual_src_size}"
            )

        with self._blob_lock(ref.digest):
            lock_file = self._file_lock(f"blob-{_digest_hex(ref.digest)}.lock")
            try:
                final = self.blob_path(ref.digest)
                if final.exists():
                    # 内容寻址且此前已校验通过；回读复核大小与摘要后直接复用，
                    # 不再从源卷复制，但复用本身也不跳过校验。
                    self._verify_stored_blob(final, ref)
                    return True

                tmp = self.tmp_dir / (
                    f"blob-{_digest_hex(ref.digest)}-{os.getpid()}-{threading.get_ident()}"
                )
                hasher = hashlib.sha256()
                written = 0
                try:
                    with open(src, "rb") as fin, open(tmp, "wb") as fout:
                        while True:
                            chunk = fin.read(CHUNK_SIZE)  # 固定小块读取，大层不进内存
                            if not chunk:
                                break
                            hasher.update(chunk)
                            fout.write(chunk)
                            written += len(chunk)
                            if hook is not None:
                                hook(ref, len(chunk), written)
                        fout.flush()
                        os.fsync(fout.fileno())
                except OSError as exc:
                    self._silent_unlink(tmp)
                    raise BlobWriteError(f"写盘失败（{ref.digest}）：{exc}") from exc
                except Exception:
                    # 复制中断（含注入故障）：清理半成品，不留下伪 blob。
                    self._silent_unlink(tmp)
                    raise

                actual_hex = hasher.hexdigest()
                if actual_hex != _digest_hex(ref.digest) or written != ref.size:
                    self._silent_unlink(tmp)
                    raise BlobVerificationError(
                        f"blob {ref.digest} 校验不符："
                        f"实际 sha256:{actual_hex} / {written} 字节，"
                        f"声明 {ref.digest} / {ref.size} 字节"
                    )
                try:
                    os.replace(tmp, final)
                    _fsync_dir(self.blobs_dir)
                except OSError as exc:
                    self._silent_unlink(tmp)
                    raise BlobWriteError(f"落盘失败（{ref.digest}）：{exc}") from exc
                # 再按 1 MiB 分块回读已落盘的 blob，核对实际摘要与大小，
                # 而不是只信任写入前的内存哈希。
                self._verify_stored_blob(final, ref)
                return False
            finally:
                try:
                    lock_file.close()  # 同时释放 flock
                except OSError:
                    pass

    # ----------------------------------------------------------------- 索引更新
    def upsert_index_descriptor(self, descriptor: dict[str, Any]) -> bool:
        """原子追加索引描述符；已存在同 digest 时跳过，返回 ``True`` 表示已列。"""
        index_file = self.root / "index.json"
        with self._index_thread_lock:
            lock_file = self._file_lock("index.lock")
            try:
                try:
                    index = json.loads(index_file.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise HandoverError(f"目标 index.json 无法读取，拒绝改写：{exc}") from exc
                if not isinstance(index, dict) or not isinstance(index.get("manifests"), list):
                    raise HandoverError("目标 index.json 结构非法，拒绝改写")
                for existing in index["manifests"]:
                    if isinstance(existing, dict) and existing.get("digest") == descriptor["digest"]:
                        return True
                index.setdefault("schemaVersion", 2)
                index["manifests"].append(descriptor)
                self._atomic_write(index_file, json.dumps(index, ensure_ascii=False, indent=2).encode("utf-8"))
                return False
            finally:
                lock_file.close()

    def index_contains(self, manifest_digest: str) -> bool:
        index_file = self.root / "index.json"
        if not index_file.is_file():
            return False
        try:
            index = json.loads(index_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return any(
            isinstance(d, dict) and d.get("digest") == manifest_digest
            for d in index.get("manifests", [])
        )

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.tmp_dir / f"file-{path.name}-{os.getpid()}-{threading.get_ident()}"
        try:
            with open(tmp, "wb") as fout:
                fout.write(payload)
                fout.flush()
                os.fsync(fout.fileno())
            os.replace(tmp, path)
            _fsync_dir(path.parent)
        except OSError as exc:
            self._silent_unlink(tmp)
            raise BlobWriteError(f"写入 {path} 失败：{exc}") from exc

    @staticmethod
    def _silent_unlink(path: Path) -> None:
        try:
            path.unlink()
        except OSError:
            pass


class HandoverService:
    """编排一次放行记录的完整交接。"""

    def __init__(
        self,
        source_root: Path | str,
        target_root: Path | str,
        *,
        platform_os: str = "linux",
        platform_arch: str = "amd64",
    ) -> None:
        self.source = OciLayout(source_root)
        self.store = HandoverStore(target_root)
        self.platform_os = platform_os
        self.platform_arch = platform_arch

    def handover(
        self, release: dict[str, Any], *, hook: CopyHook | None = None
    ) -> dict[str, Any]:
        """交接一条放行记录，返回供审计落库的结果字典。

        所有引用 blob 齐全且校验通过后才写索引；失败时抛 ``HandoverError``，
        目标索引保持原样。
        """
        plan = self.source.resolve(
            release["digest"], want_os=self.platform_os, want_arch=self.platform_arch
        )

        # 预检：任何缺件/大小不符都在写盘之前失败，本次交接不会产生半成品。
        refs = plan.refs()
        for _role, ref in refs:
            path = self.source.blob_path(ref.digest)
            if not path.is_file():
                raise BlobMissingError(ref.digest, _role)
            if path.stat().st_size != ref.size:
                raise BlobVerificationError(
                    f"源 {_role} blob {ref.digest} 大小不符："
                    f"声明 {ref.size}，实际 {path.stat().st_size}"
                )

        self.store.ensure_layout()
        blob_details: list[dict[str, Any]] = []
        total_bytes = 0
        for role, ref in refs:
            reused = self.store.copy_blob(self.source, ref, hook=hook)
            blob_details.append(
                {
                    "role": role,
                    "digest": ref.digest,
                    "size": ref.size,
                    "reused": reused,
                }
            )
            total_bytes += ref.size

        descriptor = self._build_descriptor(release, plan)
        already_listed = self.store.upsert_index_descriptor(descriptor)
        return {
            "manifest_digest": plan.manifest_digest,
            "media_type": plan.media_type,
            "platform": (
                f"{self.platform_os}/{self.platform_arch}" if plan.platform is not None else None
            ),
            "resolution_chain": list(plan.resolution_chain),
            "blobs": blob_details,
            "blob_count": len(blob_details),
            "total_bytes": total_bytes,
            "already_listed": already_listed,
        }

    @staticmethod
    def _build_descriptor(release: dict[str, Any], plan: ManifestPlan) -> dict[str, Any]:
        descriptor: dict[str, Any] = {
            "mediaType": plan.media_type,
            "digest": plan.manifest_digest,
            "size": len(plan.manifest_bytes),
            "annotations": {
                "org.opencontainers.image.ref.name": f"{release['repository']}:{release['tag']}",
                "io.admission.release.id": str(release["id"]),
                "io.admission.repository": str(release["repository"]),
                "io.admission.tag": str(release["tag"]),
                "io.admission.released.at": str(release.get("released_at", "")),
            },
        }
        if plan.platform is not None:
            descriptor["platform"] = plan.platform
        return descriptor
