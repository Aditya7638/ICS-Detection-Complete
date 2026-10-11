"""
ICS Anomaly Detection Platform — FastAPI Application
"""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, text

# Ensure backend root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import get_settings
from app.db.models import Base
from app.db.session import engine
from app.detection.model_engine import init_model_engine
from app.detection.fusion_engine import init_fusion_engine

from app.api.routes import (
    auth, inference, alarms, analytics, monitoring,
    system, chat, simulator, ws, config, optimizer, events,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)
settings = get_settings()


def _ensure_column(connection, table: str, column: str, definition: str):
    """Add a column to a table if it doesn't already exist."""
    existing = {col["name"] for col in inspect(engine).get_columns(table)}
    if column not in existing:
        connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}"))
        logger.info(f"Added column {table}.{column}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables (use Alembic for tracked migrations in production)
    Base.metadata.create_all(bind=engine)

    # --- Backwards-compatible column additions for predictions ---
    with engine.begin() as conn:
        _ensure_column(conn, "predictions", "user_id", "VARCHAR")
        _ensure_column(conn, "predictions", "explanation", "TEXT")
        _ensure_column(conn, "predictions", "data_fingerprint", "VARCHAR(64)")
        _ensure_column(conn, "predictions", "detection_context", "JSON")

    # Backfill fingerprints for records created before duplicate protection existed.
    from app.db.session import SessionLocal
    from app.db.models import Prediction
    from app.detection.detection_service import build_data_fingerprint
    db = SessionLocal()
    try:
        for prediction in db.query(Prediction).filter(Prediction.data_fingerprint.is_(None)).all():
            if prediction.user_id and prediction.reading:
                prediction.data_fingerprint = build_data_fingerprint(
                    prediction.user_id,
                    prediction.reading.source or "api",
                    prediction.timestamp,
                    prediction.reading.sensor_data,
                )
        db.commit()
    finally:
        db.close()

    # --- Load ML model and fusion engine ---
    model_path = Path(__file__).parent.parent / settings.MODEL_PATH
    fusion_path = Path(__file__).parent.parent / settings.FUSION_CONFIG_PATH
    logger.info(f"Loading model from {model_path}")
    init_model_engine(str(model_path), threshold=0.70)
    init_fusion_engine(str(fusion_path))
    logger.info("Model and fusion engine ready")

    # --- Ensure baseline config exists and is active in DB ---
    db2 = SessionLocal()
    try:
        from app.db.models import DetectionConfig
        from app.detection.detection_service import set_active_config

        baseline = db2.query(DetectionConfig).filter(DetectionConfig.is_baseline == True).first()
        if baseline:
            # Restore active config to in-memory state on startup
            active = db2.query(DetectionConfig).filter(DetectionConfig.is_active == True).first()
            if active:
                asset_crits = {a.asset_tag: a.criticality_level for a in active.critical_assets}
                set_active_config(config_id=active.id, version=active.version,
                                  asset_criticalities=asset_crits)
                logger.info(f"Restored active config: {active.name} (id={active.id})")
    finally:
        db2.close()

    yield
    logger.info("Shutdown")


app = FastAPI(
    title="ICS Anomaly Detection Platform",
    version="2.0.0",
    description=(
        "Risk-aware ICS/SCADA anomaly and cyberattack detection "
        "(SWaT dataset, RF + Rule Engine fusion, adaptive configuration)"
    ),
    lifespan=lifespan,
)

# CORS
origins = [o.strip() for o in settings.CORS_ORIGINS.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins + ["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
PREFIX = "/api/v1"
app.include_router(auth.router, prefix=PREFIX)
app.include_router(system.router, prefix=PREFIX)
app.include_router(inference.router, prefix=PREFIX)
app.include_router(alarms.router, prefix=PREFIX)
app.include_router(analytics.router, prefix=PREFIX)
app.include_router(monitoring.router, prefix=PREFIX)
app.include_router(chat.router, prefix=PREFIX)
app.include_router(simulator.router, prefix=PREFIX)
app.include_router(ws.router, prefix=PREFIX)
# New risk-aware routes
app.include_router(config.router, prefix=PREFIX)
app.include_router(optimizer.router, prefix=PREFIX)
app.include_router(events.router, prefix=PREFIX)


@app.get("/")
def root():
    return {"service": "ICS Anomaly Detection Platform v2.0", "docs": "/docs"}
