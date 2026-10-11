import unittest
from unittest.mock import MagicMock

from fastapi import HTTPException

from app.api.routes.auth import update_user_role
from app.auth.security import admin_only
from app.db.models import UserRole
from app.schemas.schemas import UserRoleUpdateRequest


class UserRoleManagementTests(unittest.TestCase):
    def setUp(self):
        self.admin = MagicMock(id="admin-1", role=UserRole.ADMIN)
        self.target = MagicMock(
            id="operator-1",
            username="operator",
            role=UserRole.OPERATOR,
            is_active=True,
        )
        self.db = MagicMock()
        self.db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = self.target

    def test_admin_can_promote_operator_and_change_is_audited(self):
        result = update_user_role(
            self.target.id,
            UserRoleUpdateRequest(role=UserRole.ADMIN),
            self.db,
            self.admin,
        )

        self.assertIs(result, self.target)
        self.assertEqual(self.target.role, UserRole.ADMIN)
        self.db.add.assert_called_once()
        audit_log = self.db.add.call_args.args[0]
        self.assertEqual(audit_log.action, "user_role_updated")
        self.assertEqual(audit_log.detail["previous_role"], UserRole.OPERATOR)
        self.assertEqual(audit_log.detail["new_role"], UserRole.ADMIN.value)
        self.db.commit.assert_called_once()

    def test_admin_cannot_change_own_role(self):
        self.target.id = self.admin.id
        self.target.role = UserRole.ADMIN

        with self.assertRaisesRegex(HTTPException, "cannot change your own role"):
            update_user_role(
                self.target.id,
                UserRoleUpdateRequest(role=UserRole.OPERATOR),
                self.db,
                self.admin,
            )

        self.db.commit.assert_not_called()

    def test_last_active_admin_cannot_be_demoted(self):
        self.target.role = UserRole.ADMIN
        self.db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = self.target
        self.db.query.return_value.filter.return_value.count.return_value = 1

        with self.assertRaisesRegex(HTTPException, "last active administrator"):
            update_user_role(
                self.target.id,
                UserRoleUpdateRequest(role=UserRole.OPERATOR),
                self.db,
                self.admin,
            )

        self.db.commit.assert_not_called()

    def test_operator_is_rejected_by_admin_role_dependency(self):
        operator = MagicMock(id="operator-1", role=UserRole.OPERATOR)
        with self.assertRaises(HTTPException) as error:
            admin_only(user=operator)

        self.assertEqual(error.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
