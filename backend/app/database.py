import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger(__name__)

database_url = settings.DATABASE_URL
connect_args = {}

if database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

def create_active_engine(db_url: str):
    if db_url.startswith("sqlite"):
        return create_engine(db_url, connect_args={"check_same_thread": False})
    
    # Try PostgreSQL connection
    try:
        eng = create_engine(
            db_url,
            connect_args=connect_args,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20
        )
        # Test connection immediately
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Connected to PostgreSQL database.")
        return eng
    except Exception as e:
        logger.warning(
            f"PostgreSQL connection to '{db_url}' failed: {e}. "
            "Falling back to local SQLite database (./data/crime_network_dev.db)."
        )
        fallback_url = "sqlite:///./data/crime_network_dev.db"
        return create_engine(fallback_url, connect_args={"check_same_thread": False})

engine = create_active_engine(database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)
