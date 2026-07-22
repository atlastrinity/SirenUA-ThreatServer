"""
HTTP Middleware and Exception Handlers.
Registers request logging, HTTP error, validation, and global exception handlers on the app.
"""

import asyncio
import time
import traceback

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from core.config import logger
from database.analytics_db import log_error_to_db, safe_run_task
from database.db_helpers import backup_sqlite_to_firestore


def register_middleware(app: FastAPI):
    """Attach HTTP logging middleware to *app*."""

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start_time = time.time()
        client_host = request.client.host if request.client else "unknown"
        logger.info(f"⬇️ Incoming request: {request.method} {request.url.path} from {client_host}")
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            logger.info(
                f"⬆️ Response: {request.method} {request.url.path} "
                f"- Status: {response.status_code} - Duration: {duration:.3f}s"
            )
            return response
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"❌ Request Failed: {request.method} {request.url.path} "
                f"- Error: {e} - Duration: {duration:.3f}s"
            )
            raise e


def register_exception_handlers(app: FastAPI):
    """Attach all exception handlers to *app*."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code >= 500 or exc.status_code in [401, 403, 429]:
            safe_run_task(asyncio.to_thread(
                log_error_to_db,
                "server",
                str(exc.detail),
                str(request.url.path),
                f"method={request.method}, status={exc.status_code}",
                "auth" if exc.status_code in [401, 403] else ("500_server" if exc.status_code >= 500 else "general")
            ))
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        error_msg = str(exc.errors())
        safe_run_task(asyncio.to_thread(
            log_error_to_db,
            "server", error_msg, str(request.url.path), f"method={request.method}", "general"
        ))
        return JSONResponse(status_code=422, content={"detail": exc.errors()})

    @app.exception_handler(Exception)
    async def custom_global_exception_handler(request: Request, exc: Exception):
        tb = traceback.format_exc()
        error_str = f"{str(exc)}\n{tb}"
        safe_run_task(asyncio.to_thread(
            log_error_to_db,
            "server", error_str, str(request.url.path), f"method={request.method}", "systemic"
        ))
        try:
            safe_run_task(asyncio.to_thread(backup_sqlite_to_firestore))
        except Exception:
            pass
        return JSONResponse(
            status_code=500,
            content={"detail": "Внутрішня помилка сервера. Помилку записано в системний лог."},
        )
