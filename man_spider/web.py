"""Optional, loopback-only viewer. This module never starts a scanner.

Install ``man-spider[web]`` and run ``manspider-web`` independently of scans.
Scan data stays read-only; operator review marks use a separate local store.
There is no remote-file API or authentication. Browser-origin checks are not
user authentication: other local users and processes can access saved findings
and change review marks.
"""

import argparse
import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path


SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'none'; font-src 'none'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'none'"
    ),
}


def create_app(store, *, port: int = 8765):
    """Build the optional web app without importing any network scan code."""

    import anyio
    from fastapi import FastAPI, Request
    from fastapi.responses import FileResponse, JSONResponse
    from starlette.concurrency import run_in_threadpool

    from man_spider.web_data import ANALYSIS_STATUSES, ViewerError
    from man_spider.rules import CONTENT_REPRESENTATIONS, INSPECTION_DETECTORS

    if not 1 <= port <= 65535:
        raise ValueError("A valid local port is required")
    authority = f"127.0.0.1:{port}"
    origin = f"http://{authority}"
    assets = Path(__file__).with_name("web_static")

    @asynccontextmanager
    async def lifespan(_app):
        # Bound concurrent SQLite work across multiple tabs. Uvicorn also
        # caps accepted requests; there is only one server worker.
        limiter = anyio.to_thread.current_default_thread_limiter()
        previous = limiter.total_tokens
        limiter.total_tokens = 2
        try:
            yield
        finally:
            limiter.total_tokens = previous

    app = FastAPI(
        title="MANSPIDER local viewer", docs_url=None, redoc_url=None,
        openapi_url=None, lifespan=lifespan,
    )

    def error(message, status=400, *, code=None):
        payload = {"detail": message}
        if code is not None:
            payload["code"] = code
        return JSONResponse(payload, status_code=status, headers=SECURITY_HEADERS)

    @app.middleware("http")
    async def protect(request: Request, call_next):
        # Require the literal advertised authority (including its port).
        # DNS rebinding, proxy-forwarded hosts and sibling origins have no role.
        if request.headers.getlist("host") != [authority]:
            return error("Недопустимый адрес локального интерфейса", 400)
        origins = request.headers.getlist("origin")
        if origins and origins != [origin]:
            return error("Запрос с другого сайта запрещён", 403)
        sites = request.headers.getlist("sec-fetch-site")
        if sites and (len(sites) != 1 or sites[0] not in {"same-origin", "none"}):
            return error("Запрос с другого сайта запрещён", 403)
        if len(request.url.query) > 8192:
            return error("Слишком длинный запрос", 400)
        if len(request.url.path) > 4096:
            return error("Слишком длинный путь запроса", 414)
        try:
            response = await call_next(request)
        except Exception:
            # Unexpected database/framework errors must not leak local paths,
            # credentials or submitted queries through debug pages/logs.
            return error("Ошибка локального просмотрщика; сканирование не остановлено", 500)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(ViewerError)
    async def viewer_error(_request, exc):
        return error(str(exc), getattr(exc, "status", 400), code=getattr(exc, "code", None))

    @app.get("/")
    async def index():
        return FileResponse(assets / "index.html", media_type="text/html")

    @app.get("/assets/{name}")
    async def asset(name: str):
        media = {"app.js": "text/javascript", "style.css": "text/css"}
        if name not in media:
            return error("Ресурс не найден", 404)
        return FileResponse(assets / name, media_type=media[name])

    def params(request, *, fields=(), enums=None, default_limit=100, max_limit=200, extras=None):
        enums = enums or {}
        extras = extras or {}
        allowed = {"limit", "after", *fields, *enums, *extras}
        result = {}
        for key, value in request.query_params.multi_items():
            if key not in allowed or key in result:
                raise ViewerError("Неизвестный или повторяющийся параметр", status=400)
            if len(value) > 1024 or "\x00" in value:
                raise ViewerError("Недопустимая длина или содержимое фильтра", status=400)
            result[key] = value
        for key, default, minimum, maximum in (
            ("limit", default_limit, 1, max_limit), ("after", 0, 0, 2**63 - 1),
        ):
            value = str(result.get(key, default))
            if not value.isascii() or not value.isdecimal() or not minimum <= int(value) <= maximum:
                raise ViewerError("Некорректная граница страницы", status=400)
            result[key] = int(value)
        for key, permitted in enums.items():
            if key in result and result[key] not in {"", *permitted}:
                raise ViewerError("Недопустимое значение фильтра", status=400)
        for key, convert in extras.items():
            if key in result:
                result[key] = convert(result[key])
        return result

    def size(value):
        if not value.isascii() or not value.isdecimal() or int(value) > 2**63 - 1:
            raise ViewerError("Некорректный размер файла", status=400)
        return int(value)

    def clean_id(value):
        if not value or len(value) > 128 or not all(c.isascii() and (c.isalnum() or c in "-_") for c in value):
            raise ViewerError("Сканирование или находка не найдены", status=404)
        return value

    @app.get("/api/scans")
    async def scans(request: Request):
        if request.query_params:
            return error("Неизвестный параметр")
        return await run_in_threadpool(store.scans)

    @app.get("/api/scans/{scan_id}/summary")
    async def summary(scan_id: str, request: Request):
        if request.query_params:
            return error("Неизвестный параметр")
        return await run_in_threadpool(store.summary, clean_id(scan_id))

    @app.get("/api/scans/{scan_id}/findings")
    async def findings(scan_id: str, request: Request):
        filters = params(
            request, fields=("rule", "target", "share", "path", "extension", "q", "category"),
            enums={
                "severity": {"info", "low", "medium", "high", "critical"},
                "confidence": {"low", "medium", "high"},
                "analysis_status": ANALYSIS_STATUSES,
                "review_status": {"reviewed", "unreviewed"},
                "representation": {
                    "metadata", "unknown", *CONTENT_REPRESENTATIONS,
                    *(f"inspect:{detector}" for detector in INSPECTION_DETECTORS),
                },
            }, extras={"min_size": size, "max_size": size},
        )
        if filters.get("min_size", 0) > filters.get("max_size", 2**63 - 1):
            raise ViewerError("Минимальный размер больше максимального", status=400)
        return await run_in_threadpool(store.findings, clean_id(scan_id), **filters)

    @app.get("/api/scans/{scan_id}/objects")
    async def objects(scan_id: str, request: Request):
        filters = params(request, fields=("q",), enums={
            "status": {"pending", "in_progress", "processed", "skipped", "error"},
            "analysis_status": ANALYSIS_STATUSES,
            "kind": {"file", "directory", "target", "share", "share_enumeration"},
        })
        return await run_in_threadpool(store.objects, clean_id(scan_id), **filters)

    @app.get("/api/scans/{scan_id}/objects/{object_id}/findings")
    async def object_findings(scan_id: str, object_id: str, request: Request):
        if len(object_id) > 19 or not object_id.isascii() or not object_id.isdecimal() or not 0 < int(object_id) < 2**63:
            return error("Объект не найден", 404)
        filters = params(
            request, fields=("page_token",), default_limit=50,
            enums={"review_status": {"reviewed", "unreviewed"}},
        )
        return await run_in_threadpool(store.object_findings, clean_id(scan_id), int(object_id), **filters)

    @app.patch("/api/scans/{scan_id}/findings/{finding_id}/review")
    async def review(scan_id: str, finding_id: str, request: Request):
        # This is a local annotation, never a mutation of scanner evidence.
        # Require an explicit same-origin JSON request. No form, cross-origin
        # preflight, or ambient browser credentials can authorize a write.
        if request.headers.getlist("origin") != [origin] or request.headers.getlist("x-manspider-review") != ["1"]:
            return error("Отметка требует явного запроса из локального интерфейса", 403)
        if request.query_params:
            return error("Неизвестный параметр")
        scan_id, finding_id = clean_id(scan_id), clean_id(finding_id)
        content_types = request.headers.getlist("content-type")
        if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
            return error("Требуется application/json", 415)
        lengths = request.headers.getlist("content-length")
        if lengths and (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal()):
            return error("Некорректный размер запроса")
        if lengths and int(lengths[0]) > 256:
            return error("Слишком большой запрос", 413)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 256:
                return error("Слишком большой запрос", 413)
            body.extend(chunk)
        try:
            # Reject duplicate keys as well as unknown fields and non-booleans.
            def unique_object(pairs):
                if len({key for key, _value in pairs}) != len(pairs):
                    raise ValueError("Duplicate field")
                return dict(pairs)

            value = json.loads(body, object_pairs_hook=unique_object)
            if not isinstance(value, dict) or set(value) != {"reviewed"} or type(value["reviewed"]) is not bool:
                return error("Укажите единственное поле reviewed: true или false")
        except (ValueError, UnicodeError, TypeError, IndexError):
            return error("Некорректный JSON отметки")
        return await run_in_threadpool(store.set_finding_review, scan_id, finding_id, value["reviewed"])

    @app.get("/api/scans/{scan_id}/findings/{finding_id}/evidence")
    async def evidence(scan_id: str, finding_id: str, request: Request):
        if "after" in request.query_params:
            return error("Для текста используется offset")
        filters = params(
            request, default_limit=65536, max_limit=65536,
            enums={"field": {"value", "context"}}, fields=("offset",),
        )
        filters.pop("after")
        offset = filters.pop("offset", "0")
        if not offset.isascii() or not offset.isdecimal() or int(offset) > 2**63 - 1:
            return error("Некорректное смещение текста")
        filters["offset"] = int(offset)
        if filters.get("field") == "":
            return error("Укажите value или context")
        return await run_in_threadpool(store.evidence, clean_id(scan_id), clean_id(finding_id), **filters)

    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description="Локальный просмотр результатов MANSPIDER без запуска сканирования")
    parser.add_argument("--state-dir", action="append", type=Path, default=[],
                        help="каталог с сессиями; можно повторять (по умолчанию каталоги MANSPIDER)")
    parser.add_argument("--state", action="append", type=Path, default=[], help="конкретный файл сессии; можно повторять")
    parser.add_argument("--port", type=int, default=8765, help="локальный порт (по умолчанию 8765)")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("порт должен быть в диапазоне 1024–65535")
    try:
        import uvicorn
        from man_spider.state import resume_search_directories
        from man_spider.web_data import ViewerStore

        directories = args.state_dir or ([] if args.state else list(resume_search_directories()))
        store = ViewerStore(directories, files=args.state)
        app = create_app(store, port=args.port)
    except ImportError:
        print("Установите веб-компонент: uv sync --extra web (или pip install 'man-spider[web]')", file=sys.stderr)
        return 2
    print("MANSPIDER: локальный просмотрщик; не запускает сканирование и не обращается к SMB.", flush=True)
    print("Откройте в браузере:", flush=True)
    print(f"http://127.0.0.1:{args.port}/", flush=True)
    print("Без авторизации: другие пользователи и процессы этого хоста могут читать немаскированные находки и менять отметки проверки.", flush=True)
    print("Остановка интерфейса: Ctrl+C. Работа сканера от этого не зависит.", flush=True)
    # Explicitly disable proxy trust, auto reload, websocket support, access
    # logging and multi-process workers. No host override can expose evidence.
    uvicorn.run(
        app, host="127.0.0.1", port=args.port, workers=1, reload=False,
        access_log=False, proxy_headers=False, server_header=False,
        ws="none", limit_concurrency=8, backlog=16, timeout_keep_alive=2,
        timeout_graceful_shutdown=3, log_level="warning",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
