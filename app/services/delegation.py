from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import DelegationContext, Principal
from app.repositories.delegation import DelegationRepository
from app.repositories.identity import UserRepository
from app.services.audit import AuditContext, AuditService

# 代理授权不得携带授权管理类能力，从机制上杜绝二次转授。
NON_DELEGABLE_PERMISSIONS = {"users.write", "roles.write", "delegations.write"}


class DelegationService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = DelegationRepository(connection)
        self.users = UserRepository(connection)
        self.audit = AuditService(connection, self.clock)
        self.max_days = int(os.getenv("TOWNSHIP_DELEGATION_MAX_DAYS", "180"))

    # ------------------------------------------------------------------ 创建
    def create_delegation(self, principal: Principal, data: dict) -> dict:
        principal.require("delegations.write")
        granter = self.users.require(int(data["granter_user_id"]))
        agent = self.users.require(int(data["agent_user_id"]))
        if granter["id"] == agent["id"]:
            raise ValidationError("授权人与代理人不能为同一人")
        if granter["status"] != "active" or agent["status"] != "active":
            raise ValidationError("授权人与代理人均须为在职启用状态")
        starts_at = from_storage(data["starts_at"])
        ends_at = from_storage(data["ends_at"])
        now = self.clock.now()
        if starts_at is None or ends_at is None:
            raise ValidationError("生效时间与截止时间不能为空")
        if ends_at <= starts_at:
            raise ValidationError("截止时间必须晚于生效时间")
        if ends_at <= now:
            raise ValidationError("截止时间必须晚于当前时间")
        if ends_at - starts_at > timedelta(days=self.max_days):
            raise ValidationError(f"单次代理授权最长不能超过 {self.max_days} 天")

        permission_codes = list(dict.fromkeys(data.get("permission_codes") or []))
        if not permission_codes:
            raise ValidationError("至少选择一项代理权限")
        granter_permissions = self._granter_permission_codes(granter["id"])
        missing = [code for code in permission_codes if code not in granter_permissions]
        if missing:
            raise PermissionDeniedError(f"授权人不具备以下能力，不能转授：{', '.join(sorted(missing))}")
        forbidden = sorted(set(permission_codes) & NON_DELEGABLE_PERMISSIONS)
        if forbidden:
            raise ValidationError(f"以下权限不得代理：{', '.join(forbidden)}")

        department_ids = list(dict.fromkeys(data.get("department_ids") or []))
        allowed_departments = self._accessible_departments(granter["id"], to_storage(now))
        if allowed_departments is not None:
            if not department_ids:
                raise ValidationError("授权人数据范围受限，必须明确指定代理业务部门")
            for dept_id in department_ids:
                if dept_id not in allowed_departments:
                    raise PermissionDeniedError("授权人对指定部门没有数据范围，不能转授")
        for dept_id in department_ids:
            department = self.connection.execute(
                "SELECT id FROM departments WHERE id=? AND is_active=1", (dept_id,)
            ).fetchone()
            if department is None:
                raise NotFoundError(f"业务部门不存在或已停用：{dept_id}")

        if self.repository.find_overlapping_pair(granter["id"], agent["id"], to_storage(starts_at), to_storage(ends_at)):
            raise ConflictError("授权人与代理人之间已存在时间重叠的有效代理授权")

        try:
            delegation = self.repository.create(
                granter_user_id=granter["id"],
                agent_user_id=agent["id"],
                permission_codes=permission_codes,
                department_ids=department_ids,
                reason=str(data.get("reason", "")).strip(),
                starts_at=to_storage(starts_at),
                ends_at=to_storage(ends_at),
                created_at=to_storage(now),
                created_by_user_id=principal.user_id,
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("代理授权重复提交或时间窗口冲突") from exc
        self.audit.record(
            AuditContext.from_principal(principal),
            action="delegation.create",
            resource_type="delegation",
            resource_id=delegation["id"],
            after=delegation,
            metadata={"granter": granter["username"], "agent": agent["username"]},
        )
        return self.detail(delegation["id"])

    # ------------------------------------------------------------------ 上岗/离岗
    def activate(self, principal: Principal, delegation_id: int) -> dict:
        delegation = self.require_active(delegation_id)
        if delegation["agent_user_id"] != principal.user_id:
            raise PermissionDeniedError("只有指定代理人可以启用该授权")
        context = self._effective_context(delegation, principal.user_id)
        if context is None:
            raise ConflictError("代理授权当前不可用")
        self.repository.set_session_delegation(principal.session_id, delegation_id)
        granter = self.users.require(delegation["granter_user_id"])
        self.audit.record(
            AuditContext.from_principal(principal),
            action="delegation.activate",
            resource_type="delegation",
            resource_id=delegation_id,
            metadata={"granter": granter["display_name"]},
        )
        return self.detail(delegation_id)

    def deactivate(self, principal: Principal) -> dict:
        if principal.delegation is None:
            raise ConflictError("当前会话没有启用中的代理授权")
        delegation_id = principal.delegation.delegation_id
        self.repository.set_session_delegation(principal.session_id, None)
        self.audit.record(
            AuditContext.from_principal(principal),
            action="delegation.deactivate",
            resource_type="delegation",
            resource_id=delegation_id,
        )
        return {"message": "已结束代理上岗", "delegation_id": delegation_id}

    # ------------------------------------------------------------------ 撤销
    def revoke(self, principal: Principal, delegation_id: int, reason: str) -> dict:
        principal.require("delegations.write")
        before = self.repository.get(delegation_id)
        if before is None:
            raise NotFoundError("代理授权不存在")
        if before["status"] != "active":
            raise ConflictError("只能撤销处于生效中的代理授权")
        now = to_storage(self.clock.now())
        self.repository.revoke(delegation_id, now, principal.user_id, reason.strip())
        detached = self.repository.clear_sessions_for_delegation(delegation_id)
        after = self.require_detail(delegation_id)
        self.audit.record(
            AuditContext.from_principal(principal),
            action="delegation.revoke",
            resource_type="delegation",
            resource_id=delegation_id,
            before=before,
            after=after,
            metadata={"reason": reason, "detached_sessions": detached},
        )
        return after

    # ------------------------------------------------------------------ 查询
    def list(self, principal: Principal, *, granter_user_id: int | None, agent_user_id: int | None,
             status: str | None, active_at: str | None, limit: int, offset: int) -> dict:
        principal.require("delegations.read")
        moment = to_storage(from_storage(active_at) or self.clock.now()) if active_at is not None else None
        rows = self.repository.list_for_view(
            granter_user_id=granter_user_id,
            agent_user_id=agent_user_id,
            status=status,
            active_at=moment,
            limit=limit,
            offset=offset,
        )
        total = self.repository.count_for_view(
            granter_user_id=granter_user_id,
            agent_user_id=agent_user_id,
            status=status,
            active_at=moment,
        )
        return {"total": total, "data": rows}

    def detail(self, delegation_id: int) -> dict:
        delegation = self.repository.get(delegation_id)
        if delegation is None:
            raise NotFoundError("代理授权不存在")
        return self._decorate(delegation)

    def require_detail(self, delegation_id: int) -> dict:
        return self.detail(delegation_id)

    def available_for_agent(self, principal: Principal) -> list[dict]:
        moment = to_storage(self.clock.now())
        rows = self.repository.active_for_agent_at(principal.user_id, moment)
        result = []
        for row in rows:
            context = self._effective_context(row, principal.user_id)
            item = self._decorate(row)
            item["usable"] = context is not None
            result.append(item)
        return result

    def require_active(self, delegation_id: int) -> dict:
        delegation = self.repository.get(delegation_id)
        if delegation is None:
            raise NotFoundError("代理授权不存在")
        return delegation

    # -------------------------------------------------- 账号/任期联动终止
    def terminate_for_user(self, user_id: int, reason: str) -> int:
        ids = [
            int(row[0])
            for row in self.connection.execute(
                "SELECT id FROM delegations WHERE status='active' AND (granter_user_id=? OR agent_user_id=?)",
                (user_id, user_id),
            ).fetchall()
        ]
        self._terminate_ids(ids, reason)
        return len(ids)

    def terminate_for_lost_department(self, granter_user_id: int, department_id: int, reason: str) -> int:
        """授权人失去某部门访问途径（任期结束/部门停用）时，终止依赖该部门的授权。"""
        moment = to_storage(self.clock.now())
        accessible = self._accessible_departments(granter_user_id, moment)
        if accessible is not None and department_id in accessible:
            return 0
        rows = self.connection.execute(
            "SELECT id, department_ids_json FROM delegations WHERE status='active' AND granter_user_id=?",
            (granter_user_id,),
        ).fetchall()
        ids = []
        for row in rows:
            scoped = json.loads(row[1] or "[]")
            if department_id in scoped:
                ids.append(int(row[0]))
        self._terminate_ids(ids, reason)
        return len(ids)

    def terminate_for_disabled_department(self, department_id: int, reason: str) -> int:
        rows = self.connection.execute(
            "SELECT DISTINCT granter_user_id FROM delegations WHERE status='active'"
        ).fetchall()
        total = 0
        for row in rows:
            total += self.terminate_for_lost_department(int(row[0]), department_id, reason)
        return total

    def sweep_invalid(self, *, reason: str = "grant_scope_changed") -> int:
        """角色权限、用户角色或部门归属调整后，回收授权人已不再具备授予条件的授权。"""
        moment = to_storage(self.clock.now())
        rows = self.connection.execute(
            "SELECT id,granter_user_id,permission_codes_json,department_ids_json "
            "FROM delegations WHERE status='active'"
        ).fetchall()
        invalid_ids: list[int] = []
        for row in rows:
            granter = self.users.get(int(row["granter_user_id"]))
            if granter is None or granter["status"] != "active":
                invalid_ids.append(int(row["id"]))
                continue
            owned_permissions = self._granter_permission_codes(granter["id"])
            codes = json.loads(row["permission_codes_json"] or "[]")
            if any(code not in owned_permissions or code in NON_DELEGABLE_PERMISSIONS for code in codes):
                invalid_ids.append(int(row["id"]))
                continue
            allowed_departments = self._accessible_departments(granter["id"], moment)
            if allowed_departments is not None:
                scoped = json.loads(row["department_ids_json"] or "[]")
                if any(dept_id not in allowed_departments for dept_id in scoped):
                    invalid_ids.append(int(row["id"]))
        self._terminate_ids(invalid_ids, reason)
        return len(invalid_ids)

    def _terminate_ids(self, ids: list[int], reason: str) -> None:
        for delegation_id in dict.fromkeys(ids):
            self.connection.execute(
                "UPDATE delegations SET status='terminated',terminate_reason=? WHERE id=? AND status='active'",
                (reason, delegation_id),
            )
            self.repository.clear_sessions_for_delegation(delegation_id)

    # -------------------------------------------------- 会话实时鉴权支持
    def session_context(self, session_id: int) -> DelegationContext | None:
        """每次请求实时计算会话上的代理上下文；失效即解绑，杜绝幽灵授权。"""
        moment = to_storage(self.clock.now())
        delegation = self.repository.active_for_session(session_id, moment)
        if delegation is None:
            self.connection.execute(
                "UPDATE sessions SET active_delegation_id=NULL WHERE id=? AND active_delegation_id IS NOT NULL",
                (session_id,),
            )
            return None
        agent_id = int(self.connection.execute("SELECT user_id FROM sessions WHERE id=?", (session_id,)).fetchone()[0])
        context = self._effective_context(delegation, agent_id)
        if context is None:
            self.repository.set_session_delegation(session_id, None)
            return None
        return context

    def _effective_context(self, delegation: dict, agent_user_id: int) -> DelegationContext | None:
        now_value = to_storage(self.clock.now())
        if delegation["status"] != "active":
            return None
        if delegation["starts_at"] > now_value or delegation["ends_at"] <= now_value:
            return None
        granter = self.users.get(delegation["granter_user_id"])
        agent = self.users.get(agent_user_id)
        if granter is None or agent is None:
            return None
        if granter["status"] != "active" or agent["status"] != "active":
            return None
        granter_permissions = self._granter_permission_codes(granter["id"])
        effective_permissions = frozenset(
            code for code in delegation["permission_codes"]
            if code in granter_permissions and code not in NON_DELEGABLE_PERMISSIONS
        )
        if not effective_permissions:
            return None
        allowed_departments = self._accessible_departments(granter["id"], now_value)
        requested = list(delegation["department_ids"])
        if allowed_departments is None:
            all_departments = len(requested) == 0
            effective_departments = frozenset(requested)
        else:
            all_departments = False
            effective_departments = frozenset(dept_id for dept_id in requested if dept_id in allowed_departments)
        return DelegationContext(
            delegation_id=delegation["id"],
            granter_user_id=granter["id"],
            granter_name=granter["display_name"],
            permissions=effective_permissions,
            department_ids=effective_departments,
            all_departments=all_departments,
        )

    # -------------------------------------------------- 辅助
    def _granter_permission_codes(self, granter_user_id: int) -> set[str]:
        """授权人可转授的权限：其角色直接拥有的权限；系统管理员角色展开为全部已登记权限码。"""
        owned = self.users.permissions(granter_user_id)
        if "administrator" in self.users.role_codes(granter_user_id) or "*" in owned:
            return {str(row[0]) for row in self.connection.execute("SELECT code FROM permissions").fetchall()}
        return set(owned)

    def _accessible_departments(self, user_id: int, moment: str) -> set[int] | None:
        """None 表示不限部门（系统管理员）；否则为本人主任职与有效任期部门集合。"""
        owned = self.users.permissions(user_id)
        if "administrator" in self.users.role_codes(user_id) or "*" in owned:
            return None
        user = self.users.require(user_id)
        accessible: set[int] = set()
        if user["department_id"] is not None:
            active = self.connection.execute(
                "SELECT 1 FROM departments WHERE id=? AND is_active=1", (user["department_id"],)
            ).fetchone()
            if active:
                accessible.add(int(user["department_id"]))
        rows = self.connection.execute(
            "SELECT DISTINCT m.department_id FROM department_memberships m "
            "JOIN departments d ON d.id=m.department_id AND d.is_active=1 "
            "WHERE m.user_id=? AND m.starts_at<=? AND (m.ends_at IS NULL OR m.ends_at>?)",
            (user_id, moment, moment),
        ).fetchall()
        accessible.update(int(row[0]) for row in rows)
        return accessible

    def _decorate(self, delegation: dict) -> dict:
        granter = self.users.require(delegation["granter_user_id"])
        agent = self.users.require(delegation["agent_user_id"])
        delegation["granter"] = {"user_id": granter["id"], "username": granter["username"], "display_name": granter["display_name"]}
        delegation["agent"] = {"user_id": agent["id"], "username": agent["username"], "display_name": agent["display_name"]}
        return delegation
