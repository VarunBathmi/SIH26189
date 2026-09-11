import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import settings
from app.database import init_db, get_db
from app.graph.neo4j_connection import is_neo4j_available, close_neo4j_driver
from app.api.auth_routes import router as auth_router
from app.api.case_routes import router as case_router
from app.api.ingestion_routes import router as ingestion_router
from app.api.evidence_routes import router as evidence_router
from app.api.graph_routes import router as graph_router
from app.api.analytics_routes import router as analytics_router
from app.api.alert_routes import router as alert_router
from app.api.secure_routes import router as secure_router
from app.api.audit_routes import router as audit_router
from app.api.forensics_routes import router as forensics_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    logger.info("Initializing database schema...")
    try:
        init_db()
        logger.info("Database schema initialized successfully.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")

    # Check Neo4j availability
    if is_neo4j_available():
        logger.info("Neo4j graph database is connected and active.")
    else:
        logger.warning("Neo4j is not reachable. Platform active in dual NetworkX standalone mode.")

    yield

    # Shutdown
    close_neo4j_driver()
    logger.info("Backend shutdown complete.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "AI-Powered Criminal Network Analysis Platform Master Backend — PS 26189 & v4.0.0 Aligned. "
        "Featuring Raw-Report NLP Event Extraction, Dual-Authorization Identity Reveal, "
        "Digital Chain of Custody (Hash Chain), and Professional SHA-256 Cryptographic Evidence Integrity."
    ),
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if settings.CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Healthcheck endpoint (Public)
@app.get("/health", tags=["Health & Diagnostics"], summary="Comprehensive DB & Graph Health Check")
def health_check(db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    neo_status = "connected" if is_neo4j_available() else "offline (using NetworkX engine)"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "neo4j": neo_status,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }

# Mount all feature routers
app.include_router(auth_router)
app.include_router(case_router)
app.include_router(ingestion_router)
app.include_router(evidence_router)
app.include_router(graph_router)
app.include_router(analytics_router)
app.include_router(alert_router)
app.include_router(secure_router)
app.include_router(audit_router)
app.include_router(forensics_router)
