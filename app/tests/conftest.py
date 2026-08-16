import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import create_app
from app.db.session import Base, get_db
from app.models import Company, User, UserRole
from app.services.password import hash_password


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestAsyncSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def override_get_db() -> AsyncSession:
    async with TestAsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@pytest_asyncio.fixture(scope="function")
async def db_session():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestAsyncSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session):
    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_company(db_session):
    company = Company(name="Test Company")
    db_session.add(company)
    await db_session.flush()
    await db_session.refresh(company)
    return company


@pytest_asyncio.fixture
async def test_user(db_session, test_company):
    user = User(
        name="Test User",
        email="test@example.com",
        phone="9876543210",
        password_hash=hash_password("Password@123"),
        role=UserRole.HR_ADMIN,
        company_id=test_company.id,
        is_active=True,
        is_verified=False,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user