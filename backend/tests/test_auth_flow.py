import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes.auth import router as auth_router
from app.db.models import Base
from app.db.session import get_db


class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine)

        def override_get_db():
            db = self.session_factory()
            try:
                yield db
            finally:
                db.close()

        app = FastAPI()
        app.include_router(auth_router, prefix="/api/v1")
        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        self.engine.dispose()

    def test_register_login_and_current_user_flow(self):
        registration = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "new-operator",
                "email": "operator@example.invalid",
                "password": "Strong#Password123",
            },
        )

        self.assertEqual(registration.status_code, 200, registration.text)
        self.assertEqual(registration.json()["role"], "OPERATOR")

        login = self.client.post(
            "/api/v1/auth/login",
            data={"username": "new-operator", "password": "Strong#Password123"},
        )

        self.assertEqual(login.status_code, 200, login.text)
        token = login.json()["access_token"]
        current_user = self.client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(current_user.status_code, 200, current_user.text)
        self.assertEqual(current_user.json()["username"], "new-operator")

    def test_duplicate_username_is_reported(self):
        payload = {
            "username": "duplicate",
            "email": "first@example.invalid",
            "password": "Strong#Password123",
        }
        self.assertEqual(self.client.post("/api/v1/auth/register", json=payload).status_code, 200)
        duplicate = self.client.post(
            "/api/v1/auth/register",
            json={**payload, "email": "second@example.invalid"},
        )
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(duplicate.json()["detail"], "Username already exists")

    def test_invalid_password_is_reported_as_validation_error(self):
        response = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "weak-password",
                "email": "weak@example.invalid",
                "password": "allletters",
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_invalid_credentials_are_rejected(self):
        response = self.client.post(
            "/api/v1/auth/login",
            data={"username": "missing", "password": "Wrong#Password123"},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
