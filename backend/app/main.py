import time
import uuid
import logging
from contextlib import asynccontextmanager
from typing import Callable
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app.api.v1 import (
    auth, atm, accounts, transactions, soc, incidents, 
    alerts, audit, simulations, admin, ws, rules,
    certificates, keys, protocols, security_center
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securevault")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds enterprise HTTP security headers to all responses."""
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attaches a unique Request-ID / Correlation-ID to every request for SOC traceability."""
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        corr_id = request.headers.get("X-Correlation-ID") or uuid.uuid4().hex
        request.state.correlation_id = corr_id
        start_time = time.time()
        
        response = await call_next(request)
        
        process_time = (time.time() - start_time) * 1000.0
        response.headers["X-Correlation-ID"] = corr_id
        response.headers["X-Response-Time-Ms"] = f"{process_time:.2f}"
        return response


from app.db.migrate import run_auto_migrations
from app.db.seed_rules import seed_rules_and_indicators
from app.db.session import AsyncSessionLocal
from app.engines.telemetry_worker import telemetry_engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure database schema exists (creates tables automatically for zero-config SQLite or MySQL)
    logger.info("Initializing SecureVault ATM Database Engine...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await run_auto_migrations(engine)
    async with AsyncSessionLocal() as session:
        await seed_rules_and_indicators(session)
    logger.info("Database schemas, migrations, rules, and threat indicators verified.")
    
    # Synchronize to local MongoDB Compass database
    try:
        from app.db.mongo_sync import sync_all_to_mongodb
        mongo_res = sync_all_to_mongodb()
        logger.info(f"MongoDB Compass initial synchronization: {mongo_res.get('status')}")
    except Exception as e:
        logger.warning(f"Optional MongoDB initial sync note: {e}")

    # Start Real-Time Fleet Telemetry & Live Event Engine
    telemetry_engine.start()
    
    yield
    # Shutdown
    logger.info("Shutting down SecureVault ATM.")
    await telemetry_engine.stop()
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Cybersecurity ATM Banking & SIEM Operations Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Direct WebSocket mounts for real-time live SIEM and telemetry stream
from app.api.v1.ws import websocket_endpoint
app.add_api_websocket_route("/ws", websocket_endpoint)
app.add_api_websocket_route("/ws/", websocket_endpoint)
app.add_api_websocket_route(f"{settings.API_V1_STR}/ws", websocket_endpoint)
app.add_api_websocket_route(f"{settings.API_V1_STR}/ws/", websocket_endpoint)

# Custom Middlewares
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    corr_id = getattr(request.state, "correlation_id", "unknown")
    logger.error(f"Unhandled exception [CorrID: {corr_id}]: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred while processing your request.",
            "correlation_id": corr_id
        }
    )


# Root Health Check
@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "HEALTHY",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT
    }


# Include V1 Routers
api_prefix = settings.API_V1_STR
app.include_router(auth.router, prefix=api_prefix)
app.include_router(atm.router, prefix=api_prefix)
app.include_router(accounts.router, prefix=api_prefix)
app.include_router(transactions.router, prefix=api_prefix)
app.include_router(soc.router, prefix=api_prefix)
app.include_router(incidents.router, prefix=api_prefix)
app.include_router(alerts.router, prefix=api_prefix)
app.include_router(audit.router, prefix=api_prefix)
app.include_router(simulations.router, prefix=api_prefix)
app.include_router(admin.router, prefix=api_prefix)
app.include_router(ws.router, prefix=api_prefix)
app.include_router(ws.router)  # Direct /ws support
app.include_router(rules.router, prefix=api_prefix)
app.include_router(certificates.router, prefix=api_prefix)
app.include_router(keys.router, prefix=api_prefix)
app.include_router(protocols.router, prefix=api_prefix)
app.include_router(security_center.router, prefix=api_prefix)
