"""Domain rules: validation, snapshots, and policy evaluation.

The core contract implemented here:

* A verification attempt captures *immutable* snapshots at its start:
  the policy row, the tag row (including its digest), and the referenced
  digest record.  All checks read only those snapshot values.
* A release row is written **only** when the snapshot evaluation allowed the
  request, and it copies the snapshot values.  Therefore a later tag update or
  policy change can never retroactively authorize or invalidate a release.
* Failed attempts store the reasons and never produce release rows.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Iterable


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
ENVIRONMENTS = ("dev", "staging", "prod")
SIGNATURE_STATUSES = ("verified", "unverified", "missing", "invalid")
SOURCE_STATUSES = ("verified", "unverified")


class ValidationError(ValueError):
    """Raised for malformed operator input; rendered as a form error."""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


def normalize_repository(value: str) -> str:
    repo = (value or "").strip().lower()
    if not REPOSITORY_RE.match(repo):
        raise ValidationError("仓库名格式不合法（例如 registry.example.com/team/app）", "repository")
    if "//" in repo or repo.startswith("/") or repo.endswith("/") or ".." in repo:
        raise ValidationError("仓库名格式不合法（不允许空路径段或相对路径）", "repository")
    return repo


def normalize_digest(value: str) -> str:
    digest = (value or "").strip().lower()
    if not DIGEST_RE.match(digest):
        raise ValidationError("digest 必须是 sha256: 加 64 位小写十六进制", "digest")
    return digest


def normalize_tag(value: str) -> str:
    tag = (value or "").strip()
    if not TAG_RE.match(tag):
        raise ValidationError("标签只能包含字母、数字、点、下划线和连字符，且以字母数字开头", "tag")
    return tag


def normalize_environment(value: str) -> str:
    env = (value or "").strip().lower()
    if env not in ENVIRONMENTS:
        raise ValidationError(f"环境必须是 {', '.join(ENVIRONMENTS)} 之一", "environment")
    return env


def normalize_actor(value: str | None, default: str = "ops") -> str:
    actor = (value or "").strip() or default
    if len(actor) > 80:
        raise ValidationError("操作人名称过长", "actor")
    return actor


def normalize_build_source(value: str) -> str:
    source = (value or "").strip()
    if not source:
        raise ValidationError("构建来源不能为空", "build_source")
    if len(source) > 400:
        raise ValidationError("构建来源过长（最多 400 字符）", "build_source")
    return source


def normalize_status(value: str, allowed: Iterable[str], field: str) -> str:
    status = (value or "").strip().lower()
    options = tuple(allowed)
    if status not in options:
        raise ValidationError(f"状态必须是 {', '.join(options)} 之一", field)
    return status


@dataclass(frozen=True)
class DigestRecord:
    id: int
    repository: str
    digest: str
    build_source: str
    source_status: str
    signature_status: str
    signer: str | None
    signature_ref: str | None
    note: str | None
    registered_by: str
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "DigestRecord":
        return cls(**dict(row))

    def snapshot(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class TagRecord:
    id: int
    repository: str
    tag: str
    digest: str
    revision: int
    updated_by: str
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "TagRecord":
        return cls(**dict(row))

    def snapshot(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class Policy:
    id: int
    version: int
    require_provenance: bool
    require_signature: bool
    required_signer: str | None
    note: str | None
    created_by: str
    created_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Policy":
        return cls(
            id=row["id"],
            version=row["version"],
            require_provenance=bool(row["require_provenance"]),
            require_signature=bool(row["require_signature"]),
            required_signer=row["required_signer"],
            note=row["note"],
            created_by=row["created_by"],
            created_at=row["created_at"],
        )

    def snapshot(self) -> dict[str, Any]:
        return dict(self.__dict__)

    @property
    def label(self) -> str:
        return f"v{self.version}"


def latest_policy(conn: sqlite3.Connection) -> Policy:
    row = conn.execute("SELECT * FROM policies ORDER BY version DESC LIMIT 1").fetchone()
    if row is None:
        raise RuntimeError("策略缺失：数据库未初始化")
    return Policy.from_row(row)


def policy_expectations(policy: Policy) -> list[str]:
    """Human-readable summary of the active policy."""
    out: list[str] = ["放行前必须引用不可变 digest"]
    if policy.require_provenance:
        out.append("构建来源必须为 verified")
    if policy.require_signature:
        signer = f"，签名者必须为 {policy.required_signer}" if policy.required_signer else ""
        out.append(f"签名必须为 verified{signer}")
    if not policy.require_provenance:
        out.append("构建来源状态不作强制（仅记录）")
    if not policy.require_signature:
        out.append("签名状态不作强制（仅记录）")
    return [line for line in out if line]


@dataclass(frozen=True)
class Check:
    key: str
    label: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    checks: tuple[Check, ...]
    reasons: tuple[Check, ...]

    def checks_json(self) -> str:
        return json.dumps([c.as_dict() for c in self.checks], ensure_ascii=False)

    def reasons_json(self) -> str:
        return json.dumps([c.as_dict() for c in self.reasons], ensure_ascii=False)


def evaluate(
    *,
    repository: str,
    tag_name: str,
    tag_snapshot: dict[str, Any] | None,
    digest_snapshot: dict[str, Any] | None,
    policy_snapshot: dict[str, Any],
    expected_digest: str | None = None,
) -> Decision:
    """Evaluate a request strictly against captured snapshot dictionaries.

    Nothing here reads the live database.  The tag snapshot pins the digest;
    ``digest_snapshot`` is the record resolved for *that* snapshot digest.  A
    missing record means the tag points at an unregistered digest, which fails
    closed.
    """

    checks: list[Check] = []

    tag_exists = tag_snapshot is not None
    checks.append(
        Check(
            "tag_exists",
            "标签存在",
            tag_exists,
            f"开始校验时标签 {repository}:{tag_name} 已登记" if tag_exists
            else f"开始校验时标签 {repository}:{tag_name} 未登记，无法解析镜像",
        )
    )

    tag_digest = (tag_snapshot or {}).get("digest")
    pin_ok = tag_exists and isinstance(tag_digest, str) and tag_digest.startswith("sha256:")
    checks.append(
        Check(
            "digest_reference",
            "引用不可变 digest",
            pin_ok,
            f"标签快照指向 {tag_digest}" if pin_ok else "标签快照未记录不可变 digest",
        )
    )

    digest_match = True
    if expected_digest:
        digest_match = bool(tag_digest) and tag_digest == expected_digest
        checks.append(
            Check(
                "requested_digest",
                "请求声明的 digest",
                digest_match,
                f"声明 {expected_digest}，快照标签指向 {tag_digest or '（无）'}",
            )
        )

    digest_snapshot = digest_snapshot or {}
    registered = bool(digest_snapshot.get("digest"))
    checks.append(
        Check(
            "digest_registered",
            "digest 已登记",
            registered,
            "digest 存在登记记录，构建来源与签名状态可追溯"
            if registered
            else "快照引用的 digest 没有登记记录，无法核验来源与签名",
        )
    )

    if pin_ok and digest_match and not registered:
        reasons = tuple(c for c in checks if not c.passed)
        return Decision(False, tuple(checks), reasons)
    if not pin_ok or not digest_match:
        reasons = tuple(c for c in checks if not c.passed)
        return Decision(False, tuple(checks), reasons)

    policy = Policy(
        id=int(policy_snapshot.get("id", 0)),
        version=int(policy_snapshot.get("version", 0)),
        require_provenance=bool(policy_snapshot.get("require_provenance")),
        require_signature=bool(policy_snapshot.get("require_signature")),
        required_signer=policy_snapshot.get("required_signer"),
        note=policy_snapshot.get("note"),
        created_by=policy_snapshot.get("created_by", ""),
        created_at=policy_snapshot.get("created_at", ""),
    )

    source_status = digest_snapshot.get("source_status")
    build_source = digest_snapshot.get("build_source") or "（未记录）"
    source_ok = (not policy.require_provenance) or source_status == "verified"
    checks.append(
        Check(
            "provenance",
            "构建来源",
            source_ok,
            (
                f"来源已核验：{build_source}"
                if source_status == "verified"
                else f"来源未核验（状态：{source_status}），来源：{build_source}"
            )
            + ("" if policy.require_provenance else "；快照策略仅记录不强制"),
        )
    )

    signature_status = digest_snapshot.get("signature_status")
    signer = digest_snapshot.get("signer")
    signature_ok = (not policy.require_signature) or signature_status == "verified"
    signer_detail = f"签名者：{signer}" if signer else "未记录签名者"
    checks.append(
        Check(
            "signature",
            "签名状态",
            signature_ok,
            (
                f"签名已验证（{signer_detail}）"
                if signature_status == "verified"
                else f"签名状态为 {signature_status}（{signer_detail}）"
            )
            + ("" if policy.require_signature else "；快照策略仅记录不强制"),
        )
    )

    if policy.require_signature and policy.required_signer:
        signer_ok = (signer or "").strip() == policy.required_signer
        checks.append(
            Check(
                "signer_identity",
                "签名者身份",
                signer_ok,
                f"要求签名者为 {policy.required_signer}，实际为 {signer or '（空）'}",
            )
        )

    reasons = tuple(c for c in checks if not c.passed)
    return Decision(not reasons, tuple(checks), reasons)


def read_snapshot(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        data = json.loads(value)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None
