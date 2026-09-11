import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load .env file from project root if present
root_dir = Path(__file__).resolve().parent.parent.parent
env_path = root_dir / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Powered Criminal Network Analysis Platform"
    VERSION: str = "4.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # Security (Shared with Auth Microservice)
    SECRET_KEY: str = os.getenv("JWT_SECRET", os.getenv("SECRET_KEY", "sih_master_secret_key_jwt_2026_investigation_platform_secure"))
    FERNET_KEY: str = os.getenv("FERNET_KEY", "jdVLIGwIosNtWQubOxj2ZznPQdOVf89Q0t-K729uNb0=")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")) # 1 hour default
    OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://sih_user:sih_pass@localhost:5432/crime_network_db")
    
    # Neo4j Graph Database
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "sih_pass123")
    
    # CORS (Allows Vite :5173, Next.js :3000, Nginx :8080, and FastAPI :8000)
    CORS_ORIGINS_RAW: str = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173,http://localhost:8080,http://localhost:8000,http://127.0.0.1:3000,http://127.0.0.1:5173,http://127.0.0.1:8080")
    
    # Evidence & Reports Storage
    BASE_DATA_DIR: Path = root_dir / "data"
    EVIDENCE_STORAGE_DIR: Path = Path(os.getenv("EVIDENCE_STORAGE_DIR", str(root_dir / "data" / "evidence")))
    REPORTS_STORAGE_DIR: Path = root_dir / "data" / "reports"
    UPLOADS_STORAGE_DIR: Path = root_dir / "data" / "uploads"
    
    # Financial thresholds
    DEFAULT_REPORTING_THRESHOLD: float = 50000.0
    DEFAULT_LARGE_AMOUNT_THRESHOLD: float = 200000.0

    @property
    def CORS_ORIGINS(self) -> list[str]:
        return [
            origin.strip() 
            for origin in self.CORS_ORIGINS_RAW.split(",")
            if origin.strip()
        ]

    model_config = {
        "case_sensitive": True,
        "extra": "allow"
    }

settings = Settings()

# Ensure directories exist
settings.EVIDENCE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.UPLOADS_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
