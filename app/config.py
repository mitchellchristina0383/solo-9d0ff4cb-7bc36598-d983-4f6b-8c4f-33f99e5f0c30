from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} 必须是整数：{raw!r}") from exc
    return max(minimum, min(maximum, value))


@dataclass(frozen=True)
class Settings:
    """Application configuration.

    ``verify_delay_ms`` deliberately opens a window between the snapshot
    capture and the final commit so that concurrent tag re-pointing or policy
    edits are observable in the UI and covered by tests.
    """

    db_path: Path = BASE_DIR / "data" / "admission.db"
    verify_delay_ms: int = 500
    app_title: str = "镜像发布准入"
    default_actor: str = "ops"
    handover_source_dir: Path = BASE_DIR / "volumes" / "source"
    handover_target_dir: Path = BASE_DIR / "volumes" / "handover"
    handover_platform_os: str = "linux"
    handover_platform_arch: str = "amd64"

    @classmethod
    def from_env(cls) -> "Settings":
        db_path = os.environ.get("ADMISSION_DB_PATH", "").strip()
        source = os.environ.get("ADMISSION_HANDOVER_SOURCE_DIR", "").strip()
        target = os.environ.get("ADMISSION_HANDOVER_TARGET_DIR", "").strip()
        return cls(
            db_path=Path(db_path) if db_path else BASE_DIR / "data" / "admission.db",
            verify_delay_ms=_env_int("ADMISSION_VERIFY_DELAY_MS", 500, 0, 10_000),
            app_title=os.environ.get("ADMISSION_APP_TITLE", "镜像发布准入"),
            default_actor=os.environ.get("ADMISSION_DEFAULT_ACTOR", "ops"),
            handover_source_dir=(
                Path(source) if source else BASE_DIR / "volumes" / "source"
            ),
            handover_target_dir=(
                Path(target) if target else BASE_DIR / "volumes" / "handover"
            ),
            handover_platform_os=os.environ.get("ADMISSION_HANDOVER_PLATFORM_OS", "linux").strip()
            or "linux",
            handover_platform_arch=os.environ.get(
                "ADMISSION_HANDOVER_PLATFORM_ARCH", "amd64"
            ).strip()
            or "amd64",
        )
