from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import Settings
from .db import init_db
from .rules import (
    ENVIRONMENTS,
    SIGNATURE_STATUSES,
    SOURCE_STATUSES,
    ValidationError,
)
from .service import ConflictError, Service
from .util import fmt_ts, short_digest
from . import __version__


TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def get_settings() -> Settings:
    return Settings.from_env()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    init_db(settings.db_path)
    service = Service(settings)
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["fmt_ts"] = fmt_ts
    templates.env.filters["short_digest"] = short_digest

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_db(settings.db_path)
        yield

    app = FastAPI(title=settings.app_title, version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.service = service
    app.mount("/static", StaticFiles(directory=str(TEMPLATES_DIR.parent / "static")), name="static")

    def page(request: Request, name: str, context: dict[str, Any], status_code: int = 200) -> HTMLResponse:
        ctx: dict[str, Any] = {
            "request": request,
            "app_title": settings.app_title,
            "default_actor": settings.default_actor,
            "environments": ENVIRONMENTS,
            "source_statuses": SOURCE_STATUSES,
            "signature_statuses": SIGNATURE_STATUSES,
            "version": __version__,
        }
        ctx.update(context)
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def redirect(path: str, *, error: str | None = None, notice: str | None = None) -> RedirectResponse:
        if error:
            path = f"{path}?{('&' if '?' in path else '')}error={quote(error)}"
        elif notice:
            path = f"{path}?{('&' if '?' in path else '')}notice={quote(notice)}"
        return RedirectResponse(path, status_code=303)

    # ------------------------------------------------------------------ pages
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        stats = service.stats()
        policy = service.current_policy()
        recent_requests = service.list_requests(limit=8)
        recent_releases = service.list_releases()[:6]
        return page(
            request,
            "dashboard.html",
            {
                "nav": "dashboard",
                "stats": stats,
                "policy": policy,
                "recent_requests": recent_requests,
                "recent_releases": recent_releases,
            },
        )

    @app.get("/digests", response_class=HTMLResponse)
    def digests_page(request: Request, error: str | None = None, notice: str | None = None) -> HTMLResponse:
        return page(
            request,
            "digests.html",
            {"nav": "digests", "digests": service.list_digests(), "error": error, "notice": notice},
        )

    @app.post("/digests")
    def create_digest(
        repository: str = Form(...),
        digest: str = Form(...),
        build_source: str = Form(...),
        source_status: str = Form("unverified"),
        signature_status: str = Form("unverified"),
        signer: str = Form(""),
        signature_ref: str = Form(""),
        note: str = Form(""),
        actor: str = Form(""),
    ) -> RedirectResponse:
        try:
            record, created = service.upsert_digest(
                repository=repository,
                digest=digest,
                build_source=build_source,
                source_status=source_status,
                signature_status=signature_status,
                signer=signer,
                signature_ref=signature_ref,
                note=note,
                actor=actor,
            )
        except ValidationError as exc:
            return redirect("/digests", error=str(exc))
        action = "已登记" if created else "已更新登记"
        return redirect(
            "/digests",
            notice=f"{action} {record['repository']} {short_digest(record['digest'])}",
        )

    @app.get("/digests/{digest_id}", response_class=HTMLResponse)
    def digest_detail(request: Request, digest_id: int) -> HTMLResponse:
        digest = None
        for item in service.list_digests():
            if item["id"] == digest_id:
                digest = item
                break
        if digest is None:
            return page(
                request,
                "not_found.html",
                {"nav": "digests", "title": "digest 记录不存在"},
                status_code=404,
            )
        history = service.digest_history(digest["repository"], digest["digest"])
        tags = [t for t in service.list_tags() if t["digest"] == digest["digest"] and t["repository"] == digest["repository"]]
        return page(
            request,
            "digest_detail.html",
            {"nav": "digests", "digest": digest, "history": history, "tags": tags},
        )

    @app.post("/digests/{digest_id}/delete")
    def delete_digest(digest_id: int, actor: str = Form("")) -> RedirectResponse:
        try:
            service.delete_digest(digest_id, actor)
        except (ValidationError, ConflictError) as exc:
            return redirect("/digests", error=str(exc))
        return redirect("/digests", notice="已删除未被引用的 digest 登记")

    @app.get("/tags", response_class=HTMLResponse)
    def tags_page(request: Request, error: str | None = None, notice: str | None = None) -> HTMLResponse:
        return page(
            request,
            "tags.html",
            {
                "nav": "tags",
                "tags": service.list_tags(),
                "digests": service.list_digests(),
                "history": service.tag_history()[:25],
                "error": error,
                "notice": notice,
            },
        )

    @app.post("/tags")
    def upsert_tag(
        repository: str = Form(...),
        tag: str = Form(...),
        digest: str = Form(...),
        actor: str = Form(""),
    ) -> RedirectResponse:
        try:
            record = service.set_tag(repository=repository, tag=tag, digest=digest, actor=actor)
        except (ValidationError, ConflictError) as exc:
            return redirect("/tags", error=str(exc))
        if not record.get("changed"):
            return redirect("/tags", notice="标签已指向该 digest，无需变更")
        return redirect(
            "/tags",
            notice=f"{record['repository']}:{record['tag']} → {short_digest(record['digest'])}（修订 {record['revision']}）",
        )

    @app.get("/policies", response_class=HTMLResponse)
    def policies_page(request: Request, error: str | None = None, notice: str | None = None) -> HTMLResponse:
        return page(
            request,
            "policies.html",
            {
                "nav": "policies",
                "policies": service.list_policies(),
                "current": service.current_policy(),
                "error": error,
                "notice": notice,
            },
        )

    @app.post("/policies")
    def create_policy(
        require_provenance: str = Form(""),
        require_signature: str = Form(""),
        required_signer: str = Form(""),
        note: str = Form(""),
        actor: str = Form(""),
    ) -> RedirectResponse:
        try:
            created = service.create_policy(
                require_provenance=require_provenance.strip().lower() in ("1", "true", "on", "yes"),
                require_signature=require_signature.strip().lower() in ("1", "true", "on", "yes"),
                required_signer=required_signer,
                note=note,
                actor=actor,
            )
        except ValidationError as exc:
            return redirect("/policies", error=str(exc))
        return redirect("/policies", notice=f"已发布策略 v{created['version']}，仅影响之后开始的校验")

    @app.get("/requests", response_class=HTMLResponse)
    def requests_page(
        request: Request,
        status: str | None = None,
        error: str | None = None,
        notice: str | None = None,
    ) -> HTMLResponse:
        return page(
            request,
            "requests.html",
            {
                "nav": "requests",
                "requests": service.list_requests(status=status),
                "status_filter": status or "",
                "tags": service.list_tags(),
                "error": error,
                "notice": notice,
            },
        )

    @app.post("/requests")
    def create_request(
        repository: str = Form(...),
        tag: str = Form(...),
        expected_digest: str = Form(""),
        environment: str = Form(...),
        requested_by: str = Form(""),
        note: str = Form(""),
    ) -> RedirectResponse:
        try:
            created = service.create_request(
                repository=repository,
                tag=tag,
                expected_digest=expected_digest,
                environment=environment,
                requested_by=requested_by,
                note=note,
            )
        except ValidationError as exc:
            return redirect("/requests", error=str(exc))
        return redirect(f"/requests/{created['id']}", notice="已创建部署请求，尚未校验")

    @app.get("/requests/{request_id}", response_class=HTMLResponse)
    def request_detail(
        request: Request, request_id: str, error: str | None = None, notice: str | None = None
    ) -> HTMLResponse:
        item = service.get_request(request_id)
        if item is None:
            return page(
                request,
                "not_found.html",
                {"nav": "requests", "title": "部署请求不存在"},
                status_code=404,
            )
        return page(
            request,
            "request_detail.html",
            {"nav": "requests", "item": item, "error": error, "notice": notice},
        )

    @app.post("/requests/{request_id}/verify")
    def verify_request(request_id: str, actor: str = Form("")) -> RedirectResponse:
        try:
            attempt = service.verify(request_id, actor=actor)
        except ConflictError as exc:
            return redirect(f"/requests/{request_id}", error=str(exc))
        except ValidationError as exc:
            return redirect(f"/requests/{request_id}", error=str(exc))
        if attempt["status"] == "allowed":
            return redirect(
                f"/requests/{request_id}",
                notice=f"第 {attempt['attempt_no']} 次校验通过，已生成放行记录（绑定快照 digest）",
            )
        reason = "；".join(r["detail"] for r in attempt["reasons_obj"]) or "策略未通过"
        return redirect(
            f"/requests/{request_id}",
            error=f"第 {attempt['attempt_no']} 次校验拒绝：{reason}",
        )

    @app.get("/requests/{request_id}/attempts/{attempt_no}", response_class=HTMLResponse)
    def attempt_detail(request: Request, request_id: str, attempt_no: int) -> HTMLResponse:
        item = service.get_request(request_id)
        if item is None:
            return page(
                request, "not_found.html", {"nav": "requests", "title": "部署请求不存在"}, status_code=404
            )
        attempt = next((a for a in item["attempts"] if a["attempt_no"] == attempt_no), None)
        if attempt is None:
            return page(
                request, "not_found.html", {"nav": "requests", "title": "校验记录不存在"}, status_code=404
            )
        return page(
            request,
            "attempt_detail.html",
            {"nav": "requests", "item": item, "attempt": attempt},
        )

    @app.get("/releases", response_class=HTMLResponse)
    def releases_page(
        request: Request, error: str | None = None, notice: str | None = None
    ) -> HTMLResponse:
        releases = service.list_releases()
        handovers = service.list_handovers()
        latest: dict[str, dict[str, Any]] = {}
        for item in handovers:
            latest.setdefault(item["release_id"], item)
        return page(
            request,
            "releases.html",
            {
                "nav": "releases",
                "releases": releases,
                "handovers": latest,
                "error": error,
                "notice": notice,
            },
        )

    @app.post("/releases/{release_id}/handover")
    def create_handover(release_id: str, actor: str = Form("")) -> RedirectResponse:
        try:
            item = service.handover_release(release_id, actor=actor)
        except ConflictError as exc:
            return redirect("/releases", error=str(exc))
        if item["status"] == "failed":
            return redirect(
                "/releases",
                error=f"交接失败（未新增索引项，已放行镜像不受影响）：{item.get('error')}",
            )
        detail = item.get("detail_obj") or {}
        if detail.get("already_listed"):
            notice = (
                f"目标索引已含该镜像（{item['manifest_digest']}），"
                f"复用 {item['reused_blobs']} 个 blob，未重复列项"
            )
        else:
            notice = (
                f"已交接 {item['manifest_digest']}：{item['blob_count']} 个 blob、"
                f"{item['total_bytes']} 字节，复用 {item['reused_blobs']} 个 blob，索引已更新"
            )
        return redirect("/handovers", notice=notice)

    @app.get("/handovers", response_class=HTMLResponse)
    def handovers_page(
        request: Request, error: str | None = None, notice: str | None = None
    ) -> HTMLResponse:
        return page(
            request,
            "handovers.html",
            {
                "nav": "handovers",
                "handovers": service.list_handovers(),
                "source_dir": settings.handover_source_dir,
                "target_dir": settings.handover_target_dir,
                "platform": f"{settings.handover_platform_os}/{settings.handover_platform_arch}",
                "error": error,
                "notice": notice,
            },
        )

    @app.get("/handovers/{handover_id}", response_class=HTMLResponse)
    def handover_detail(request: Request, handover_id: int) -> HTMLResponse:
        item = service.get_handover(handover_id)
        if item is None:
            return page(
                request,
                "not_found.html",
                {"nav": "handovers", "title": "交接记录不存在"},
                status_code=404,
            )
        return page(
            request,
            "handover_detail.html",
            {"nav": "handovers", "item": item},
        )

    @app.get("/healthz", response_class=HTMLResponse)
    def healthz() -> HTMLResponse:
        return HTMLResponse("ok")

    return app
