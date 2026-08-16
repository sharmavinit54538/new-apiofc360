import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import User, UserRole
from app.services.jwt import get_user_id_from_token, get_user_role_from_token


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_after_registration(self, client: AsyncClient):
        # Register
        register_payload = {
            "name": "Rahul Sharma",
            "email": "rahul@company.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Acme Corp",
        }
        await client.post("/api/v1/auth/register", json=register_payload)
        
        # Login
        login_payload = {
            "email": "rahul@company.com",
            "password": "Password@123",
        }
        response = await client.post("/api/v1/auth/login", json=login_payload)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        
        # Verify token contents
        user_id = get_user_id_from_token(data["access_token"])
        role = get_user_role_from_token(data["access_token"])
        
        assert user_id is not None
        assert role == UserRole.HR_ADMIN

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client: AsyncClient):
        login_payload = {
            "email": "nonexistent@example.com",
            "password": "Password@123",
        }
        response = await client.post("/api/v1/auth/login", json=login_payload)
        
        assert response.status_code == 401
        assert "invalid credentials" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient, db_session: AsyncSession):
        from app.services.password import hash_password
        from app.models import Company
        
        company = Company(name="Test Company")
        db_session.add(company)
        await db_session.flush()
        
        user = User(
            name="Test User",
            email="test@example.com",
            phone="9876543210",
            password_hash=hash_password("CorrectPassword@123"),
            role=UserRole.HR_ADMIN,
            company_id=company.id,
        )
        db_session.add(user)
        await db_session.flush()
        
        login_payload = {
            "email": "test@example.com",
            "password": "WrongPassword@123",
        }
        response = await client.post("/api/v1/auth/login", json=login_payload)
        
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client: AsyncClient, db_session: AsyncSession):
        from app.services.password import hash_password
        from app.models import Company
        
        company = Company(name="Test Company")
        db_session.add(company)
        await db_session.flush()
        
        user = User(
            name="Test User",
            email="test@example.com",
            phone="9876543210",
            password_hash=hash_password("Password@123"),
            role=UserRole.HR_ADMIN,
            company_id=company.id,
            is_active=False,
        )
        db_session.add(user)
        await db_session.flush()
        
        login_payload = {
            "email": "test@example.com",
            "password": "Password@123",
        }
        response = await client.post("/api/v1/auth/login", json=login_payload)
        
        assert response.status_code == 401
        assert "deactivated" in response.json()["detail"].lower()