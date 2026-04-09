"""
Authentication and Authorization for Shadow AI Hunter
- JWT-based authentication
- Role-based access control (RBAC)
- MongoDB user lookup (injected at startup)
"""

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, List

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
SUPER_ADMIN_USERS = {
    u.strip() for u in os.getenv("SUPER_ADMIN_USERS", "admin").split(",") if u.strip()
}

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme - tokenUrl matches the actual route after router prefix
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# MongoDB collection injected at startup via init_db()
_users_collection = None


def init_db(users_collection) -> None:
    """
    Inject the MongoDB users collection into the auth module.
    Must be called once during application startup before any auth operations.
    """
    global _users_collection
    _users_collection = users_collection


class UserRole(str, Enum):
    """RBAC Roles"""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    WORKER = "worker"


class Token(BaseModel):
    """JWT Token response"""
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Decoded token payload"""
    sub: str  # username
    role: UserRole
    tenant_id: str = "default"
    exp: Optional[datetime] = None


class User(BaseModel):
    """Public user model"""
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    disabled: bool = False
    tenant_id: str = "default"


class UserInDB(User):
    """User with hashed password (never returned to clients)"""
    hashed_password: str
    refresh_token_hash: Optional[str] = None
    refresh_expires_at: Optional[datetime] = None


# Role permissions
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        "scan:read", "scan:write", "scan:delete",
        "device:read", "device:write", "device:delete",
        "alert:read", "alert:write", "alert:delete",
        "policy:read", "policy:write", "policy:delete",
        "user:read", "user:write", "user:delete",
        "report:read", "report:write",
        "admin:all",
    ],
    UserRole.ANALYST: [
        "scan:read", "scan:write",
        "device:read", "device:write",
        "alert:read", "alert:write",
        "policy:read", "policy:write",
        "report:read",
    ],
    UserRole.VIEWER: [
        "scan:read",
        "device:read",
        "alert:read",
        "policy:read",
        "report:read",
    ],
    UserRole.WORKER: [
        "scan:read", "scan:write",
        "device:read", "device:write",
        "alert:read", "alert:write",
    ],
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password with bcrypt."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed refresh JWT."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def _token_hash(token: str) -> str:
    return hmac.new(SECRET_KEY.encode(), token.encode(), hashlib.sha256).hexdigest()


def store_refresh_token(username: str, refresh_token: str, expires_at: datetime) -> None:
    """Store hashed refresh token for a user (single active token)."""
    if _users_collection is None:
        return
    _users_collection.update_one(
        {"username": username},
        {"$set": {
            "refresh_token_hash": _token_hash(refresh_token),
            "refresh_expires_at": expires_at,
        }},
    )


def clear_refresh_token(username: str) -> None:
    """Clear refresh token fields for a user."""
    if _users_collection is None:
        return
    _users_collection.update_one(
        {"username": username},
        {"$unset": {
            "refresh_token_hash": "",
            "refresh_expires_at": "",
        }},
    )


def is_super_admin(username: str) -> bool:
    return username in SUPER_ADMIN_USERS


def get_user(username: str) -> Optional[UserInDB]:
    """
    Look up a user in MongoDB.
    Returns None if the user does not exist or the DB is not initialized.
    """
    if _users_collection is None:
        return None
    doc = _users_collection.find_one({"username": username})
    if doc is None:
        return None
    return UserInDB(
        username=doc["username"],
        email=doc.get("email"),
        full_name=doc.get("full_name"),
        role=UserRole(doc.get("role", "viewer")),
        disabled=doc.get("disabled", False),
        hashed_password=doc["hashed_password"],
        refresh_token_hash=doc.get("refresh_token_hash"),
        refresh_expires_at=doc.get("refresh_expires_at"),
        tenant_id=doc.get("tenant_id", "default"),
    )


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
) -> User:
    """Validate JWT from Authorization header or HttpOnly cookie."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if token is None:
        token = request.cookies.get("access_token")
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency: require an active (non-disabled) user."""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_role(allowed_roles: List[UserRole]):
    """Dependency factory: require one of the specified roles."""
    async def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{current_user.role.value}' not authorized. "
                    f"Required: {[r.value for r in allowed_roles]}"
                ),
            )
        return current_user

    return role_checker


def has_permission(user: User, permission: str) -> bool:
    """Check if a user has a specific granular permission."""
    role_perms = ROLE_PERMISSIONS.get(user.role, [])
    return permission in role_perms or "admin:all" in role_perms


# Convenience dependencies
require_admin = require_role([UserRole.ADMIN])
require_analyst = require_role([UserRole.ADMIN, UserRole.ANALYST])
require_viewer = require_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
