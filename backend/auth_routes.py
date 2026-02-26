"""
Authentication routes for Shadow AI Hunter
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from auth import (
    Token, User, UserInDB, get_user, verify_password, 
    create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES,
    UserRole, ROLE_PERMISSIONS, get_password_hash
)

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout():
    """Logout (client should discard token)"""
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user info"""
    return current_user


@router.get("/permissions")
async def get_permissions(current_user: User = Depends(get_current_active_user)):
    """Get permissions for current user"""
    return {
        "role": current_user.role.value,
        "permissions": ROLE_PERMISSIONS.get(current_user.role, [])
    }


# Helper functions (would be in database module)
def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate user with username and password"""
    user = get_user_from_db(username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def get_user_from_db(username: str) -> Optional[UserInDB]:
    """
    Get user from database
    TODO: Implement actual DB lookup
    """
    # Mock users for development
    # In production, these would be in MongoDB
    mock_users = {
        "admin": UserInDB(
            username="admin",
            email="admin@shadowai.local",
            full_name="Admin User",
            role=UserRole.ADMIN,
            hashed_password=get_password_hash("admin123")
        ),
        "analyst": UserInDB(
            username="analyst",
            email="analyst@shadowai.local",
            full_name="Security Analyst",
            role=UserRole.ANALYST,
            hashed_password=get_password_hash("analyst123")
        ),
        "viewer": UserInDB(
            username="viewer",
            email="viewer@shadowai.local",
            full_name="Read Only User",
            role=UserRole.VIEWER,
            hashed_password=get_password_hash("viewer123")
        ),
        "worker": UserInDB(
            username="worker",
            email="worker@shadowai.local",
            full_name="Background Worker",
            role=UserRole.WORKER,
            hashed_password=get_password_hash("worker123")
        )
    }
    
    return mock_users.get(username)


# Import for circular dependency
from auth import get_current_active_user
