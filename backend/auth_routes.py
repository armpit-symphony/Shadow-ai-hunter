"""
Authentication routes for Shadow AI Hunter.

Users are stored in MongoDB and looked up via auth.get_user().
No credentials are hard-coded here.
"""

from datetime import timedelta, datetime, timezone
import secrets
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm

from auth import (
    Token,
    User,
    UserInDB,
    get_user,
    verify_password,
    create_access_token,
    create_refresh_token,
    store_refresh_token,
    clear_refresh_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    UserRole,
    ROLE_PERMISSIONS,
    get_current_active_user,
    SECRET_KEY,
    ALGORITHM,
)
from jose import JWTError, jwt

# Prefix must be /api/auth so that nginx's /api/ block routes requests here
router = APIRouter(prefix="/api/auth", tags=["authentication"])
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"


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
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """OAuth2 compatible token login."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value, "tenant_id": user.tenant_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(
        data={"sub": user.username, "role": user.role.value, "tenant_id": user.tenant_id, "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    csrf_token = secrets.token_urlsafe(32)
    store_refresh_token(
        user.username,
        refresh_token,
        datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/api/auth/refresh",
    )
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/refresh", response_model=Token)
async def refresh_token(request: Request, response: Response):
    """Rotate access token using refresh token cookie."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user = get_user(username)
    if not user or user.disabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # Validate stored refresh token hash
    from auth import _token_hash  # local import to avoid export
    if getattr(user, "refresh_token_hash", None) != _token_hash(refresh_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value, "tenant_id": user.tenant_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Logout — clears auth cookies and refresh token."""
    token = request.cookies.get("access_token")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username:
                clear_refresh_token(username)
        except JWTError:
            pass
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/auth/refresh")
    response.delete_cookie("csrf_token", path="/")
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
