from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.routes.analyze import router as analyze_router
from app.services.db import init_db

settings = get_settings()
init_db()

app = FastAPI(
    title=settings.app_name,
    description="An AI - Powered Threat Detection, Geolocation & Forensic Intelligence",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False if "*" in settings.cors_origin_list else True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Keep internal exception details in server logs rather than returning
    # an unhandled stack trace to the frontend.
    import logging
    logging.getLogger("trinetra").exception("Unhandled API exception", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error."},
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(analyze_router)
