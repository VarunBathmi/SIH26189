import sys
import asyncio
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.types import ASGIApp
import httpx

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.database import Base, get_db
from app.main import app

# Use in-memory SQLite database for isolated fast unit testing
TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def init_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

class SyncASGIClient:
    """Synchronous test client wrapper executing against ASGI application via httpx.ASGITransport."""
    def __init__(self, asgi_app: ASGIApp, base_url: str = "http://testserver"):
        self.asgi_app = asgi_app
        self.base_url = base_url
        self.transport = httpx.ASGITransport(app=asgi_app)

    def request(self, method: str, url: str, **kwargs):
        async def _call():
            async with httpx.AsyncClient(transport=self.transport, base_url=self.base_url) as client:
                return await client.request(method, url, **kwargs)
        return asyncio.run(_call())

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs):
        return self.request("POST", url, **kwargs)

    def patch(self, url: str, **kwargs):
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs):
        return self.request("DELETE", url, **kwargs)

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield SyncASGIClient(app)
    app.dependency_overrides.clear()

@pytest.fixture
def investigator_headers():
    return {
        "X-Role": "investigator",
        "X-User": "inspector_verma@investigation.gov.in"
    }

@pytest.fixture
def admin_headers():
    return {
        "X-Role": "administrator",
        "X-User": "admin_sharma@investigation.gov.in"
    }
