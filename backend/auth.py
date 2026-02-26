"""
Authentication and Authorization for Shadow AI Hunter
- JWT-based authentication
- Role-based access control (RBAC)
"""

from datetime import datetime, timedelta
from typing import Optional, List
from enum import Enum

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


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
    exp: Optional[datetime] = None


class User(BaseModel):
    """User model"""
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    disabled: bool = False


class UserInDB(User):
    """User with hashed password"""
    hashed_password: str


# Role permissions
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        "scan:read", "scan:write", "scan:delete",
        "device:read", "device:write", "device:delete",
        "alert:read", "alert:write", "alert:delete",
        "policy:read", "policy:write", "policy:delete",
        "user:read", "user:write", "user:delete",
        "report:read", "report:write",
        "admin:all"
    ],
    UserRole.ANALYST: [
        "scan:read", "scan:write",
        "device:read", "device:write",
        "alert:read", "alert:write",
        "policy:read", "policy:write",
        "report:read"
    ],
    UserRole.VIEWER: [
        "scan:read",
        "device:read",
        "alert:read",
        "policy:read",
        "report:read"
    ],
    UserRole.WORKER: [
        "scan:read", "scan:write",
        "device:read", "device:write",
        "alert:read", "alert:write"
    ]
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # Get user from database (mock for now)
    user = get_user(username)
    if user is None:
        raise credentials_exception
    
    return user


def get_user(username: str) -> Optional[UserInDB]:
    """Get user from database"""
    # TODO: Implement actual DB lookup
    # For now, return None (users must be provisioned)
    return None


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get current active user"""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_role(allowed_roles: List[UserRole]):
    """Dependency for role-based access control"""
    async def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role.value}' not authorized. Required: {[r.value for r in allowed_roles]}"
            )
        return current_user
    return role_checker


def has_permission(user: User, permission: str) -> bool:
    """Check if user has a specific permission"""
    role_perms = ROLE_PERMISSIONS.get(user.role, [])
    return permission in role_perms or "admin:all" in role_perms


# Convenience dependencies
require_admin = require_role([UserRole.ADMIN])
require_analyst = require_role([UserRole.ADMIN, UserRole.ANALYST])
require_viewer = require_role([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
