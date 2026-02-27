"""
Authentication routes for Shadow AI Hunter.

Users are stored in MongoDB and looked up via auth.get_user().
No credentials are hard-coded here.
"""

from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from auth import (
    Token,
    User,
    UserInDB,
    get_user,
    verify_password,
    create_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    UserRole,
    ROLE_PERMISSIONS,
    get_current_active_user,
)

# Prefix must be /api/auth so that nginx's /api/ block routes requests here
router = APIRouter(prefix="/api/auth", tags=["authentication"])


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """
    Verify username + password against MongoDB.
    Returns the UserInDB on success, None on failure.
    """
    user = get_user(username)
    if user is None:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if user.disabled:
        return None
    return user


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth2 compatible token login."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout():
    """Logout — client is responsible for discarding the token."""
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Return the current authenticated user's profile."""
    return current_user


@router.get("/permissions")
async def get_permissions(current_user: User = Depends(get_current_active_user)):
    """Return the role and permission set for the current user."""
    return {
        "role": current_user.role.value,
        "permissions": ROLE_PERMISSIONS.get(current_user.role, []),
    }
