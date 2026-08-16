from pydantic import BaseModel, EmailStr, field_validator, model_validator
from typing import Optional
import re


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirm_password: str
    phone: str
    company_name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name cannot be empty or whitespace only")
        if len(v) > 255:
            raise ValueError("Name cannot exceed 255 characters")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Phone cannot be empty or whitespace only")
        if not re.match(r"^[\d\s\-\+\(\)]{10,15}$", v):
            raise ValueError("Invalid phone number format")
        return v

    @field_validator("company_name")
    @classmethod
    def validate_company_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Company name cannot be empty or whitespace only")
        if len(v) > 255:
            raise ValueError("Company name cannot exceed 255 characters")
        return v

    @model_validator(mode="after")
    def validate_passwords_match(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Password and confirm password do not match")
        return self

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Rahul Sharma",
                "email": "rahul@company.com",
                "password": "Password@123",
                "confirm_password": "Password@123",
                "phone": "9876543210",
                "company_name": "Acme Corp"
            }
        }


class RegisterResponse(BaseModel):
    message: str
    user: "UserResponse"

    class Config:
        from_attributes = True


class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    phone: str
    company_name: str
    role: str

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Rahul Sharma",
                "email": "rahul@company.com",
                "phone": "9876543210",
                "company_name": "Acme Corp",
                "role": "hr_admin"
            }
        }


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return v.lower().strip()


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer"
            }
        }


class ErrorResponse(BaseModel):
    detail: str

    class Config:
        json_schema_extra = {
            "example": {"detail": "Email already registered"}
        }