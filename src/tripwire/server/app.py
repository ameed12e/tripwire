"""Beacon server.

Routes:

* ``GET /t/{token}[.ext]`` - beacon endpoint. Always answers with a 1x1 GIF
  (whether the token is valid or not, so scanners learn nothing). Valid tokens
  create a ``beacon_hit`` incident with the requester's IP, user agent and a
  few headers. Nothing is sent back except the image.
* ``GET /r/{incident_id}?exp=..&sig=..`` - full JSON report behind a signed,
  expiring link (the link included in alerts).
* ``GET /healthz`` - liveness probe.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response

from tripwire.core.engine import Engine
from tripwire.core.events import Event, EventKind, Severity
from tripwire.core.logging import get_logger
from tripwire.server.security import RateLimiter, verify_beacon_token, verify_report

log = get_logger(__name__)

PIXEL_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
_NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "X-Robots-Tag": "noindex, nofollow",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
_CAPTURED_HEADERS = ("user-agent", "referer", "accept-language", "accept", "via", "x-forwarded-for")
MAX_HEADER_CHARS = 512


def client_ip(request: Request, trust_forwarded_for: bool) -> str:
    if trust_forwarded_for:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def create_app(engine: Engine, manage_engine: bool = True) -> FastAPI:
    config = engine.config
    srv = config.server
    signing_key = config.signing_key().get_secret_value()
    limiter = RateLimiter(srv.max_hits_per_minute_per_ip)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if manage_engine:
            await engine.start()
        try:
            yield
        finally:
            if manage_engine:
                await engine.stop()

    app = FastAPI(
        title="Tripwire beacon server",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    def pixel() -> Response:
        return Response(PIXEL_GIF, media_type="image/gif", headers=_NO_CACHE)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/t/{token}")
    async def beacon(token: str, request: Request) -> Response:
        ip = client_ip(request, srv.trust_forwarded_for)
        if not limiter.allow(ip):
            return pixel()
        decoy_id = verify_beacon_token(signing_key, token.split(".", 1)[0])
        if decoy_id is None:
            return pixel()
        label = engine.db.beacon_label(decoy_id) or f"beacon {decoy_id}"
        headers = {
            h: request.headers[h][:MAX_HEADER_CHARS]
            for h in _CAPTURED_HEADERS
            if h in request.headers
        }
        ua = headers.get("user-agent", "unknown client")
        engine.emit(
            Event(
                kind=EventKind.BEACON_HIT,
                source="beacon-server",
                summary=f"Beacon opened: {label} from {ip} ({ua[:60]})",
                severity=Severity.CRITICAL,
                host=config.host_name,
                decoy_id=decoy_id,
                details={"client_ip": ip, "headers": headers, "path": request.url.path},
            )
        )
        return pixel()

    @app.get("/r/{incident_id}")
    async def report(
        incident_id: str,
        exp: int = Query(...),
        sig: str = Query(..., max_length=128),
    ) -> JSONResponse:
        if not verify_report(signing_key, incident_id, exp, sig):
            raise HTTPException(status_code=404, detail="not found")
        incident = engine.db.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="not found")
        return JSONResponse(incident.report(), headers=_NO_CACHE)

    return app
