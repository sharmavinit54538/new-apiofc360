from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from app.models.user import User, UserRole
from app.models.company import Company
from app.schemas.auth import RegisterRequest, LoginRequest, TokenResponse
from app.services import hash_password, verify_password, create_tokens


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def register(self, data: RegisterRequest) -> tuple[User, Company]:
        normalized_email = data.email.lower().strip()

        existing_user = await self._get_user_by_email(normalized_email)
        if existing_user:
            raise ValueError("Email already registered")

        company = await self._get_or_create_company(data.company_name.strip())

        password_hash = hash_password(data.password)

        user = User(
            name=data.name.strip(),
            email=normalized_email,
            phone=data.phone.strip(),
            password_hash=password_hash,
            role=UserRole.HR_ADMIN,
            company_id=company.id,
            is_active=True,
            is_verified=False,
        )

        self.db.add(user)
        try:
            await self.db.flush()
            await self.db.refresh(user, attribute_names=["company"])
        except IntegrityError as e:
            await self.db.rollback()
            if "uq_users_email" in str(e.orig) or "duplicate key" in str(e.orig).lower():
                raise ValueError("Email already registered")
            raise

        return user, company

    async def login(self, data: LoginRequest) -> TokenResponse:
        normalized_email = data.email.lower().strip()
        user = await self._get_user_by_email(normalized_email)

        if not user:
            raise ValueError("Invalid credentials")

        if not user.is_active:
            raise ValueError("Account is deactivated")

        if not verify_password(data.password, user.password_hash):
            raise ValueError("Invalid credentials")

        access_token, refresh_token = create_tokens(
            user_id=str(user.id),
            email=user.email,
            role=user.role,
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    async def _get_user_by_email(self, email: str) -> User | None:
        result = await self.db.execute(
            select(User).where(User.email == email).options(selectinload(User.company))
        )
        return result.scalar_one_or_none()

    async def _get_or_create_company(self, company_name: str) -> Company:
        result = await self.db.execute(
            select(Company).where(Company.name == company_name)
        )
        company = result.scalar_one_or_none()

        if company:
            return company

        company = Company(name=company_name)
        self.db.add(company)
        await self.db.flush()
        await self.db.refresh(company)
        return company