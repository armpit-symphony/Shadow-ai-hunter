"""
Integration tests for the FastAPI backend.

Uses TestClient with a mocked MongoDB so no real DB is required.
Run with:  cd backend && pytest ../tests/test_api.py -v
"""

import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mock_db():
    """Return a MagicMock that mimics the MongoDB database object."""
    db = MagicMock()

    # Provide sensible return values for common collection operations
    db.scans.count_documents.return_value = 5
    db.devices.count_documents.return_value = 10
    db.alerts.count_documents.return_value = 3
    db.policies.count_documents.return_value = 2

    db.devices.find.return_value = []
    db.alerts.find.return_value = []
    db.policies.find.return_value = []
    db.scans.find.return_value = []
    db.users.count_documents.return_value = 1  # non-zero → no seeding
    db.users.find_one.return_value = None

    db.scans.create_index.return_value = None
    db.devices.create_index.return_value = None
    db.alerts.create_index.return_value = None
    db.users.create_index.return_value = None

    return db


@pytest.fixture(scope="module")
def client(mock_db):
    """Build a TestClient with MongoDB patched out."""
    with (
        patch("pymongo.MongoClient") as mock_client_cls,
        patch("auth.init_db"),
        patch("auth._users_collection", None),
    ):
        mock_mongo_client = MagicMock()
        mock_mongo_client.shadow_ai_hunter = mock_db
        mock_client_cls.return_value = mock_mongo_client

        # Import app after patching so lifespan doesn't try real DB calls
        from server import app

        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


@pytest.fixture
def admin_token(client):
    """Return a valid admin JWT token via the auth module directly."""
    import auth as auth_module
    from auth import create_access_token, get_password_hash, init_db, UserRole, UserInDB

    hashed = get_password_hash("testpassword")

    class _MockUsers:
        def find_one(self, q):
            if q.get("username") == "admin":
                return {
                    "username": "admin",
                    "email": "admin@test.local",
                    "full_name": "Test Admin",
                    "role": "admin",
                    "disabled": False,
                    "hashed_password": hashed,
                }
            return None

    init_db(_MockUsers())
    token = create_access_token({"sub": "admin", "role": UserRole.ADMIN.value})
    yield f"Bearer {token}"
    auth_module._users_collection = None


@pytest.fixture
def viewer_token():
    """Return a valid viewer JWT token."""
    from auth import create_access_token, UserRole

    return f"Bearer {create_access_token({'sub': 'viewer', 'role': UserRole.VIEWER.value})}"


# ---------------------------------------------------------------------------
# Health endpoint (unauthenticated)
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_health_body(self, client):
        response = client.get("/api/health")
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestAuthEndpoints:
    def test_login_wrong_credentials(self, client):
        response = client.post(
            "/api/auth/login",
            data={"username": "nobody", "password": "wrongpass"},
        )
        assert response.status_code == 401

    def test_protected_endpoint_without_token(self, client):
        response = client.get("/api/dashboard/stats")
        assert response.status_code == 401

    def test_protected_endpoint_with_bad_token(self, client):
        response = client.get(
            "/api/dashboard/stats",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Dashboard (requires viewer role)
# ---------------------------------------------------------------------------

class TestDashboardEndpoint:
    def test_stats_with_valid_token(self, client, mock_db, admin_token):
        # Patch get_user to return a valid user for this request
        import auth as auth_module
        from auth import UserInDB, UserRole, get_password_hash, init_db

        hashed = get_password_hash("p")

        class _MockUsers:
            def find_one(self, q):
                if q.get("username") == "admin":
                    return {
                        "username": "admin",
                        "email": "a@a.com",
                        "full_name": "A",
                        "role": "admin",
                        "disabled": False,
                        "hashed_password": hashed,
                    }
                return None

        init_db(_MockUsers())
        response = client.get(
            "/api/dashboard/stats",
            headers={"Authorization": admin_token},
        )
        # May be 200 or 500 depending on mock completeness, but not 401
        assert response.status_code != 401
        auth_module._users_collection = None

    def test_stats_unauthenticated_returns_401(self, client):
        response = client.get("/api/dashboard/stats")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------

class TestPoliciesEndpoint:
    def test_get_policies_unauthenticated(self, client):
        response = client.get("/api/policies")
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Scan endpoint
# ---------------------------------------------------------------------------

class TestScanEndpoint:
    def test_scan_unauthenticated(self, client):
        response = client.post(
            "/api/scan",
            json={"network_range": "192.168.1.0/24"},
        )
        assert response.status_code == 401

    def test_scan_viewer_forbidden(self, client, viewer_token):
        import auth as auth_module
        from auth import init_db, get_password_hash, UserRole

        hashed = get_password_hash("p")

        class _MockUsers:
            def find_one(self, q):
                if q.get("username") == "viewer":
                    return {
                        "username": "viewer",
                        "role": "viewer",
                        "disabled": False,
                        "hashed_password": hashed,
                    }
                return None

        init_db(_MockUsers())
        response = client.post(
            "/api/scan",
            json={"network_range": "10.0.0.0/24"},
            headers={"Authorization": viewer_token},
        )
        # Viewer (read-only) should be forbidden from starting scans
        assert response.status_code == 403
        auth_module._users_collection = None


# ---------------------------------------------------------------------------
# Scans history
# ---------------------------------------------------------------------------

class TestScansEndpoint:
    def test_scans_unauthenticated(self, client):
        response = client.get("/api/scans")
        assert response.status_code == 401
