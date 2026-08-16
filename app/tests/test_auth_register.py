import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import User, Company, UserRole
from app.services.password import verify_password


class TestRegisterSuccess:
    @pytest.mark.asyncio
    async def test_successful_hr_admin_registration(self, client: AsyncClient):
        payload = {
            "name": "Rahul Sharma",
            "email": "rahul@company.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Acme Corp",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        data = response.json()
        assert data["message"] == "HR Admin registered successfully"
        assert data["user"]["name"] == "Rahul Sharma"
        assert data["user"]["email"] == "rahul@company.com"
        assert data["user"]["phone"] == "9876543210"
        assert data["user"]["company_name"] == "Acme Corp"
        assert data["user"]["role"] == "hr_admin"
        assert "id" in data["user"]
        assert "password" not in data["user"]
        assert "password_hash" not in data["user"]
        assert "confirm_password" not in data["user"]

    @pytest.mark.asyncio
    async def test_user_created_in_db_with_correct_role(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Rahul Sharma",
            "email": "rahul@company.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Acme Corp",
        }
        await client.post("/api/v1/auth/register", json=payload)
        
        result = await db_session.execute(select(User).where(User.email == "rahul@company.com"))
        user = result.scalar_one()
        
        assert user.role == UserRole.HR_ADMIN
        assert user.name == "Rahul Sharma"
        assert user.email == "rahul@company.com"
        assert user.phone == "9876543210"
        assert verify_password("Password@123", user.password_hash)
        assert user.is_active is True
        assert user.is_verified is False

    @pytest.mark.asyncio
    async def test_company_created_and_associated(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Rahul Sharma",
            "email": "rahul@company.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Acme Corp",
        }
        await client.post("/api/v1/auth/register", json=payload)
        
        result = await db_session.execute(select(Company).where(Company.name == "Acme Corp"))
        company = result.scalar_one()
        
        user_result = await db_session.execute(select(User).where(User.email == "rahul@company.com"))
        user = user_result.scalar_one()
        
        assert user.company_id == company.id
        assert company.name == "Acme Corp"
        assert company.is_active is True


class TestRegisterRoleInjection:
    @pytest.mark.asyncio
    async def test_super_admin_role_injection_rejected(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Attacker",
            "email": "attacker@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Evil Corp",
            "role": "super_admin",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        
        result = await db_session.execute(select(User).where(User.email == "attacker@example.com"))
        user = result.scalar_one()
        assert user.role == UserRole.HR_ADMIN
        assert user.role != UserRole.SUPER_ADMIN

    @pytest.mark.asyncio
    async def test_employee_role_injection_rejected(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Attacker",
            "email": "attacker2@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Evil Corp",
            "role": "employee",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        
        result = await db_session.execute(select(User).where(User.email == "attacker2@example.com"))
        user = result.scalar_one()
        assert user.role == UserRole.HR_ADMIN
        assert user.role != UserRole.EMPLOYEE

    @pytest.mark.asyncio
    async def test_manager_role_injection_rejected(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Attacker",
            "email": "attacker3@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Evil Corp",
            "role": "manager",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        
        result = await db_session.execute(select(User).where(User.email == "attacker3@example.com"))
        user = result.scalar_one()
        assert user.role == UserRole.HR_ADMIN

    @pytest.mark.asyncio
    async def test_executive_role_injection_rejected(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Attacker",
            "email": "attacker4@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Evil Corp",
            "role": "executive",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        
        result = await db_session.execute(select(User).where(User.email == "attacker4@example.com"))
        user = result.scalar_one()
        assert user.role == UserRole.HR_ADMIN

    @pytest.mark.asyncio
    async def test_it_executive_role_injection_rejected(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Attacker",
            "email": "attacker5@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Evil Corp",
            "role": "it_executive",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        
        result = await db_session.execute(select(User).where(User.email == "attacker5@example.com"))
        user = result.scalar_one()
        assert user.role == UserRole.HR_ADMIN

    @pytest.mark.asyncio
    async def test_is_admin_field_injection_rejected(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Attacker",
            "email": "attacker6@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Evil Corp",
            "is_admin": True,
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        
        result = await db_session.execute(select(User).where(User.email == "attacker6@example.com"))
        user = result.scalar_one()
        assert user.role == UserRole.HR_ADMIN

    @pytest.mark.asyncio
    async def test_is_super_admin_field_injection_rejected(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Attacker",
            "email": "attacker7@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Evil Corp",
            "is_super_admin": True,
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        
        result = await db_session.execute(select(User).where(User.email == "attacker7@example.com"))
        user = result.scalar_one()
        assert user.role == UserRole.HR_ADMIN


class TestRegisterDuplicateEmail:
    @pytest.mark.asyncio
    async def test_duplicate_email_returns_409(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Rahul Sharma",
            "email": "rahul@company.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Acme Corp",
        }
        await client.post("/api/v1/auth/register", json=payload)
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 409
        assert "already registered" in response.json()["detail"].lower()


class TestRegisterInvalidEmail:
    @pytest.mark.asyncio
    async def test_invalid_email_format_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "not-an-email",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_email_normalized_to_lowercase(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Test User",
            "email": "TEST@COMPANY.COM",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        assert response.json()["user"]["email"] == "test@company.com"
        
        result = await db_session.execute(select(User).where(User.email == "test@company.com"))
        user = result.scalar_one()
        assert user.email == "test@company.com"


class TestRegisterPasswordValidation:
    @pytest.mark.asyncio
    async def test_password_mismatch_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Different@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 422
        assert "password" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_weak_password_too_short_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Pass@1",
            "confirm_password": "Pass@1",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_weak_password_no_uppercase_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "password@123",
            "confirm_password": "password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_weak_password_no_lowercase_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "PASSWORD@123",
            "confirm_password": "PASSWORD@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_weak_password_no_digit_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@",
            "confirm_password": "Password@",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_weak_password_no_special_char_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password123",
            "confirm_password": "Password123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 422


class TestRegisterMissingFields:
    @pytest.mark.asyncio
    async def test_missing_name_returns_422(self, client: AsyncClient):
        payload = {
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_email_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_password_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_confirm_password_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_phone_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_company_name_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422


class TestRegisterPasswordNotExposed:
    @pytest.mark.asyncio
    async def test_response_does_not_contain_password(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        
        assert response.status_code == 201
        response_text = str(response.json())
        assert "Password@123" not in response_text
        assert "password" not in response.json()["user"]

    @pytest.mark.asyncio
    async def test_database_password_is_hashed(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        await client.post("/api/v1/auth/register", json=payload)
        
        result = await db_session.execute(select(User).where(User.email == "test@example.com"))
        user = result.scalar_one()
        
        assert user.password_hash != "Password@123"
        assert verify_password("Password@123", user.password_hash)
        assert user.password_hash.startswith("$argon2")


class TestRegisterCompanyAssociation:
    @pytest.mark.asyncio
    async def test_user_associated_with_company(self, client: AsyncClient, db_session: AsyncSession):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        await client.post("/api/v1/auth/register", json=payload)
        
        result = await db_session.execute(select(User).where(User.email == "test@example.com"))
        user = result.scalar_one()
        
        company_result = await db_session.execute(select(Company).where(Company.id == user.company_id))
        company = company_result.scalar_one()
        
        assert company.name == "Test Company"
        assert user.company_id == company.id

    @pytest.mark.asyncio
    async def test_existing_company_reused(self, client: AsyncClient, db_session: AsyncSession, test_company: Company):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": test_company.name,
        }
        await client.post("/api/v1/auth/register", json=payload)
        
        result = await db_session.execute(select(User).where(User.email == "test@example.com"))
        user = result.scalar_one()
        
        assert user.company_id == test_company.id
        
        companies = await db_session.execute(select(Company).where(Company.name == test_company.name))
        company_count = len(companies.scalars().all())
        assert company_count == 1


class TestRegisterTransactionRollback:
    @pytest.mark.asyncio
    async def test_rollback_on_failure(self, client: AsyncClient, db_session: AsyncSession):
        # This test verifies that partial records are not created on failure
        # First create a user
        payload1 = {
            "name": "User One",
            "email": "user1@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Company One",
        }
        await client.post("/api/v1/auth/register", json=payload1)
        
        # Try to register with same email (should fail)
        payload2 = {
            "name": "User Two",
            "email": "user1@example.com",  # duplicate email
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Company Two",
        }
        response = await client.post("/api/v1/auth/register", json=payload2)
        
        assert response.status_code == 409
        
        # Verify only one user exists
        users = await db_session.execute(select(User))
        user_count = len(users.scalars().all())
        assert user_count == 1
        
        # Verify only one company exists
        companies = await db_session.execute(select(Company))
        company_count = len(companies.scalars().all())
        assert company_count == 1


class TestRegisterPhoneValidation:
    @pytest.mark.asyncio
    async def test_invalid_phone_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "invalid-phone",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_empty_phone_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "   ",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422


class TestRegisterNameValidation:
    @pytest.mark.asyncio
    async def test_empty_name_returns_422(self, client: AsyncClient):
        payload = {
            "name": "   ",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "Test Company",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422


class TestRegisterCompanyNameValidation:
    @pytest.mark.asyncio
    async def test_empty_company_name_returns_422(self, client: AsyncClient):
        payload = {
            "name": "Test",
            "email": "test@example.com",
            "password": "Password@123",
            "confirm_password": "Password@123",
            "phone": "9876543210",
            "company_name": "   ",
        }
        response = await client.post("/api/v1/auth/register", json=payload)
        assert response.status_code == 422