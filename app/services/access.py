from __future__ import annotations

from dataclasses import dataclass

from app.core.errors import PermissionDeniedError
from app.core.security import Principal


@dataclass(frozen=True, slots=True)
class DataScope:
    mode: str
    # all/self 时为 None；department/departments 时为允许访问的部门集合
    department_ids: frozenset[int] | None

    @classmethod
    def from_principal(cls, principal: Principal, permission: str) -> "DataScope":
        if principal.is_administrator or "*" in principal.own_permissions:
            return cls("all", None)
        if principal.permission_via_delegation(permission):
            delegation = principal.delegation
            assert delegation is not None
            if delegation.all_departments:
                return cls("all", None)
            if not delegation.department_ids:
                return cls("self", None)
            return cls("departments", frozenset(delegation.department_ids))
        if permission not in principal.permissions:
            raise PermissionDeniedError(f"缺少权限：{permission}")
        if principal.department_id is None:
            return cls("self", None)
        return cls("department", frozenset({principal.department_id}))

    def allowed_department_ids(self) -> frozenset[int] | None:
        """列表过滤用：None 表示不限制部门。"""
        if self.mode == "all":
            return None
        return self.department_ids or frozenset()

    def restrict_department(self, requested_department_id: int | None) -> int | None:
        if self.mode == "all":
            return requested_department_id
        if self.mode == "self":
            if requested_department_id is not None:
                raise PermissionDeniedError("当前账号没有部门数据范围")
            return None
        allowed = self.department_ids or frozenset()
        if requested_department_id is not None:
            if requested_department_id not in allowed:
                raise PermissionDeniedError("不能访问授权业务范围之外的部门数据")
            return requested_department_id
        if self.mode == "department":
            return next(iter(allowed))
        raise PermissionDeniedError("请明确指定授权业务范围内的部门")

    def require_owned_department(self, resource_department_id: int | None) -> None:
        if self.mode == "all":
            return
        if resource_department_id is not None and self.department_ids and resource_department_id in self.department_ids:
            return
        raise PermissionDeniedError("该业务记录不在当前账号的数据范围内")
