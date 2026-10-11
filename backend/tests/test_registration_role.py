import unittest
from unittest.mock import MagicMock, patch

from app.api.routes.auth import register
from app.db.models import UserRole
from app.schemas.schemas import RegisterRequest


class RegistrationRoleTests(unittest.TestCase):
    def test_registration_cannot_assign_a_privileged_role(self):
        request = RegisterRequest(
            username="new-operator",
            email="operator@example.invalid",
            password="secure-pass!",
            role="ADMIN",
        )
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        with patch("app.api.routes.auth.hash_password", return_value="hashed-password"):
            created_user = register(request, db)

        self.assertEqual(created_user.role, UserRole.OPERATOR)


if __name__ == "__main__":
    unittest.main()
