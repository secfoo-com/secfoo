from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from secfoo.config import STORE_DIR
from secfoo.web.routes import (
    activities,
    agents,
    assessments,
    overview,
    projects,
    responsible_ai,
    runs,
    third_party,
)

STATIC_DIR = Path(__file__).parent / "static"

# Mermaid is an optional asset (~3.6MB), deliberately not shipped in the
# wheel -- `secfoo vendor mermaid` fetches it on demand. It lives in the
# user's store rather than inside the installed package so it survives
# upgrades and works where site-packages is read-only (containers, system
# installs). Reports render diagrams when it's present and fall back to
# readable Mermaid source when it isn't.
VENDOR_DIR = STORE_DIR / "vendor"
MERMAID_BUNDLE = VENDOR_DIR / "mermaid.min.js"


def mermaid_bundle_available() -> bool:
    return MERMAID_BUNDLE.is_file()


def create_app() -> FastAPI:
    app = FastAPI(title="secfoo dashboard")

    @app.middleware("http")
    async def revalidate_static(request, call_next):
        # Make the browser re-check stylesheets/scripts on each load (a cheap
        # 304 via ETag when unchanged). Without this, heuristic caching can
        # keep serving an old design-system.css -- and its @import-ed
        # component files -- after an upgrade, so a new UI looks broken.
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response
    # Mounted BEFORE /static: Starlette matches mounts in registration
    # order, so the broader /static would otherwise swallow /static/vendor.
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static/vendor", StaticFiles(directory=str(VENDOR_DIR)), name="vendor")
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(overview.router)
    app.include_router(activities.router)
    app.include_router(agents.router)
    app.include_router(assessments.router)
    app.include_router(third_party.router)
    app.include_router(responsible_ai.router)
    app.include_router(projects.router)
    app.include_router(runs.router)
    return app
