from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, HashingError
from argon2.low_level import Type
from app.core.config import get_settings

settings = get_settings()

ph = PasswordHasher(
    memory_cost=settings.PASSWORD_HASH_MEMORY_COST,
    time_cost=settings.PASSWORD_HASH_TIME_COST,
    parallelism=settings.PASSWORD_HASH_PARALLELISM,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    try:
        return ph.hash(password)
    except HashingError as e:
        raise ValueError(f"Password hashing failed: {str(e)}")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        ph.verify(password_hash, plain_password)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return ph.check_needs_rehash(password_hash)
    except Exception:
        return True