from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> str:
    """Return a sortable UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def fmt_ts(value: str | None) -> str:
    if not value:
        return "—"
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return value
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def short_digest(value: str | None, head: int = 19, tail: int = 10) -> str:
    if not value:
        return "—"
    if len(value) <= head + tail + 1:
        return value
    return f"{value[:head]}…{value[-tail:]}"


def clamp_text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    return value[:limit]
