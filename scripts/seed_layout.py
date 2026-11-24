#!/usr/bin/env python3
"""在源卷生成示例 OCI Image Layout，供交接演示与自测。

只依赖标准库；通过环境变量接收路径，避免把脚本所在目录加入导入路径：

    SOURCE_OCI_DIR=/volumes/source TARGET_OCI_DIR=/volumes/handover \
        python3 -I scripts/seed_layout.py

生成内容：
* ``rg.test/app`` 的单架构清单（digest 与放行记录 ``sha256-app-a`` 对齐时
  以实际 sha256 为准，脚本末尾会打印各 digest 供登记）；
* ``rg.test/multi`` 的多架构 manifest list（linux/amd64 + linux/arm64），
  其中 amd64 子清单与单架构镜像共享同一基础层 blob，用于验证去重复用；
* 一个大层（默认 8 MiB，可用 LAYER_BIG_BYTES 调整），验证流式复制不整层入内存。
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pattern_bytes(seed: str, size: int) -> bytes:
    """确定性生成任意大小内容，避免把随机大缓冲长期保留在内存里。"""
    out = bytearray()
    counter = 0
    while len(out) < size:
        block = hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:size])


class LayoutWriter:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.blobs = root / "blobs" / "sha256"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.descriptors: list[dict] = []

    def add_blob(self, data: bytes) -> tuple[str, int]:
        digest = sha256_digest(data)
        path = self.blobs / digest.split(":", 1)[1]
        if not path.exists():
            tmp = path.with_suffix(".seed-tmp")
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        return digest, len(data)

    def add_manifest(self, descriptor: dict) -> None:
        self.descriptors.append(descriptor)

    def finalize(self) -> None:
        (self.root / "oci-layout").write_text(
            json.dumps({"imageLayoutVersion": "1.0.0"}), encoding="utf-8"
        )
        index = {"schemaVersion": 2, "manifests": self.descriptors}
        tmp = self.root / "index.json.seed-tmp"
        tmp.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.root / "index.json")


def image_manifest(writer: LayoutWriter, *, name: str, layer_seeds: list[tuple[str, int]],
                   env: dict[str, str]) -> tuple[str, int, list[tuple[str, int]]]:
    layer_refs: list[tuple[str, int]] = []
    for seed, size in layer_seeds:
        digest, size_actual = writer.add_blob(pattern_bytes(seed, size))
        layer_refs.append((digest, size_actual))
    config_doc = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": [f"{k}={v}" for k, v in env.items()]},
        "rootfs": {"type": "layers", "diff_ids": [d for d, _ in layer_refs]},
        "history": [{"created_by": f"seed {name}"}],
    }
    config_raw = json.dumps(config_doc, sort_keys=True).encode("utf-8")
    config_digest, config_size = writer.add_blob(config_raw)
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": config_size},
        "layers": [
            {"mediaType": OCI_LAYER, "digest": d, "size": s} for d, s in layer_refs
        ],
    }
    raw = json.dumps(manifest, sort_keys=True).encode("utf-8")
    digest, size = writer.add_blob(raw)
    return digest, size, layer_refs


def main() -> None:
    source = Path(os.environ.get("SOURCE_OCI_DIR", "/volumes/source"))
    target = Path(os.environ.get("TARGET_OCI_DIR", "/volumes/handover"))
    big = int(os.environ.get("LAYER_BIG_BYTES", str(8 * 1024 * 1024)))
    source.mkdir(parents=True, exist_ok=True)
    target.mkdir(parents=True, exist_ok=True)

    writer = LayoutWriter(source)

    # 单架构镜像：小层 + 大层。
    app_digest, app_size, app_layers = image_manifest(
        writer,
        name="app",
        layer_seeds=[("app-base", 512), ("app-big", big)],
        env={"IMAGE": "app"},
    )
    writer.add_manifest(
        {
            "mediaType": OCI_MANIFEST,
            "digest": app_digest,
            "size": app_size,
            "annotations": {"org.opencontainers.image.ref.name": "rg.test/app:prod"},
        }
    )

    # 多架构镜像：amd64 子清单刻意复用 app 的基础层 blob（同摘要只存一份）。
    amd_digest, amd_size, _ = image_manifest(
        writer,
        name="multi-amd64",
        layer_seeds=[("app-base", 512), ("multi-amd64-top", 2048)],
        env={"IMAGE": "multi", "ARCH": "amd64"},
    )
    arm_digest, arm_size, _ = image_manifest(
        writer,
        name="multi-arm64",
        layer_seeds=[("arm-base", 768), ("multi-arm64-top", 1024)],
        env={"IMAGE": "multi", "ARCH": "arm64"},
    )
    index_doc = {
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [
            {
                "mediaType": OCI_MANIFEST,
                "digest": amd_digest,
                "size": amd_size,
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            {
                "mediaType": OCI_MANIFEST,
                "digest": arm_digest,
                "size": arm_size,
                "platform": {"os": "linux", "architecture": "arm64"},
            },
        ],
    }
    index_raw = json.dumps(index_doc, sort_keys=True).encode("utf-8")
    index_digest, index_size = writer.add_blob(index_raw)
    writer.add_manifest(
        {
            "mediaType": OCI_INDEX,
            "digest": index_digest,
            "size": index_size,
            "annotations": {"org.opencontainers.image.ref.name": "rg.test/multi:prod"},
        }
    )

    writer.finalize()

    summary = {
        "source_dir": str(source),
        "target_dir": str(target),
        "single_arch_manifest": app_digest,
        "single_arch_layers": [{"digest": d, "size": s} for d, s in app_layers],
        "multi_arch_index": index_digest,
        "multi_arch_amd64_manifest": amd_digest,
        "multi_arch_arm64_manifest": arm_digest,
        "blob_count": len(list(writer.blobs.iterdir())),
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
