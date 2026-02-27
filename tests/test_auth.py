"""
Unit tests for backend/auth.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from datetime import timedelta

import auth as auth_module
from auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_user,
    init_db,
    has_permission,
    UserRole,
    User,
    UserInDB,
    SECRET_KEY,
    ALGORITHM,
    ROLE_PERMISSIONS,
)


class TestPasswordHashing:
    def test_hash_is_different_from_plain(self):
        plain = "super-secret-password"
        hashed = get_password_hash(plain)
        assert hashed != plain

    def test_verify_correct_password(self):
        plain = "correct-password-123"
        hashed = get_password_hash(plain)
        assert verify_password(plain, hashed) is True

    def test_verify_wrong_password(self):
        hashed = get_password_hash("right-password")
        assert verify_password("wrong-password", hashed) is False

    def test_hash_different_each_time(self):
        # bcrypt uses a salt, so the same password produces different hashes
        h1 = get_password_hash("password")
        h2 = get_password_hash("password")
        assert h1 != h2
        # But both should still verify
        assert verify_password("password", h1)
        assert verify_password("password", h2)


class TestCreateAccessToken:
    def test_token_is_string(self):
        token = create_access_token({"sub": "testuser", "role": "viewer"})
        assert isinstance(token, str)
        assert len(token) > 10

    def test_token_decodes_correctly(self):
        from jose import jwt

        token = create_access_token({"sub": "alice", "role": "analyst"})
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "alice"
        assert payload["role"] == "analyst"
        assert "exp" in payload

    def test_custom_expiry(self):
        from jose import jwt
        from datetime import datetime

        before = datetime.utcnow()
        token = create_access_token({"sub": "bob"}, expires_delta=timedelta(hours=2))
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = datetime.utcfromtimestamp(payload["exp"])
        # Should expire roughly 2 hours from now
        delta = exp - before
        assert 6000 < delta.total_seconds() < 7300  # ~2 hours with some tolerance


class TestGetUser:
    def test_returns_none_before_init(self):
        # Reset the collection to None
        auth_module._users_collection = None
        result = get_user("anyone")
        assert result is None

    def test_returns_none_for_missing_user(self):
        # Inject a mock collection that returns None for find_one
        class MockCollection:
            def find_one(self, query):
                return None

        init_db(MockCollection())
        result = get_user("nonexistent")
        assert result is None
        auth_module._users_collection = None  # reset

    def test_returns_user_from_mock_db(self):
        hashed = get_password_hash("test123")

        class MockCollection:
            def find_one(self, query):
                if query.get("username") == "testadmin":
                    return {
                        "username": "testadmin",
                        "email": "testadmin@example.com",
                        "full_name": "Test Admin",
                        "role": "admin",
                        "disabled": False,
                        "hashed_password": hashed,
                    }
                return None

        init_db(MockCollection())
        user = get_user("testadmin")
        assert user is not None
        assert user.username == "testadmin"
        assert user.role == UserRole.ADMIN
        assert user.disabled is False
        auth_module._users_collection = None  # reset

    def test_disabled_user_returned_but_flagged(self):
        hashed = get_password_hash("pass")

        class MockCollection:
            def find_one(self, query):
                return {
                    "username": "disableduser",
                    "role": "viewer",
                    "disabled": True,
                    "hashed_password": hashed,
                }

        init_db(MockCollection())
        user = get_user("disableduser")
        assert user is not None
        assert user.disabled is True
        auth_module._users_collection = None


class TestRolePermissions:
    def test_admin_has_admin_all(self):
        perms = ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "admin:all" in perms

    def test_viewer_read_only(self):
        perms = ROLE_PERMISSIONS[UserRole.VIEWER]
        write_perms = [p for p in perms if ":write" in p or ":delete" in p]
        assert write_perms == [], f"Viewer has write permissions: {write_perms}"

    def test_analyst_can_write_scans(self):
        perms = ROLE_PERMISSIONS[UserRole.ANALYST]
        assert "scan:write" in perms

    def test_analyst_cannot_manage_users(self):
        perms = ROLE_PERMISSIONS[UserRole.ANALYST]
        assert "user:delete" not in perms


class TestHasPermission:
    def test_admin_has_all(self):
        user = User(username="u", role=UserRole.ADMIN)
        assert has_permission(user, "scan:delete") is True
        assert has_permission(user, "policy:delete") is True
        assert has_permission(user, "user:write") is True

    def test_viewer_has_read(self):
        user = User(username="u", role=UserRole.VIEWER)
        assert has_permission(user, "scan:read") is True
        assert has_permission(user, "device:read") is True

    def test_viewer_does_not_have_write(self):
        user = User(username="u", role=UserRole.VIEWER)
        assert has_permission(user, "scan:write") is False
        assert has_permission(user, "device:delete") is False

    def test_worker_operational_access(self):
        user = User(username="u", role=UserRole.WORKER)
        assert has_permission(user, "scan:write") is True
        assert has_permission(user, "user:delete") is False
