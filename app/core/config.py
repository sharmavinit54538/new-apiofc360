import os
from typing import List
from pydantic import BaseModel


class Settings(BaseModel):
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-super-secret-jwt-key-change-in-production")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    
    PASSWORD_HASH_ALGORITHM: str = os.getenv("PASSWORD_HASH_ALGORITHM", "argon2")
    PASSWORD_HASH_MEMORY_COST: int = int(os.getenv("PASSWORD_HASH_MEMORY_COST", "65536"))
    PASSWORD_HASH_TIME_COST: int = int(os.getenv("PASSWORD_HASH_TIME_COST", "3"))
    PASSWORD_HASH_PARALLELISM: int = int(os.getenv("PASSWORD_HASH_PARALLELISM", "4"))
    
    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.getenv("APP_PORT", "8000"))
    
    CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")


def get_settings() -> Settings:
    return Settings()