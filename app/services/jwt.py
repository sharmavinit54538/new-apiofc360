from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt, JWTError
from app.core.config import get_settings
from app.models.user import UserRole

settings = get_settings()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_tokens(user_id: str, email: str, role: UserRole) -> tuple[str, str]:
    token_data = {
        "sub": str(user_id),
        "email": email,
        "role": role.value,
    }
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    return access_token, refresh_token


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        raise ValueError("Invalid token")


def verify_token_type(token: str, expected_type: str) -> dict:
    payload = decode_token(token)
    if payload.get("type") != expected_type:
        raise ValueError(f"Invalid token type. Expected {expected_type}")
    return payload


def get_user_id_from_token(token: str) -> str:
    payload = verify_token_type(token, "access")
    user_id = payload.get("sub")
    if not user_id:
        raise ValueError("Invalid token: missing subject")
    return user_id


def get_user_role_from_token(token: str) -> UserRole:
    payload = verify_token_type(token, "access")
    role_str = payload.get("role")
    if not role_str:
        raise ValueError("Invalid token: missing role")
    try:
        return UserRole(role_str)
    except ValueError:
        raise ValueError(f"Invalid role in token: {role_str}")