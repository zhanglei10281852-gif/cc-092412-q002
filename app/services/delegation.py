from __future__ import annotations

import json
import sqlite3

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError
from app.core.security import ActiveDelegation, Principal
from app.repositories.delegation import DelegationRepository
from app.repositories.identity import UserRepository
from app.services.audit import AuditContext, AuditService

MAX_ACTIVITY_EVENTS_PER_GRANT = 200


def _canonical_codes(codes: list[str]) -> list[str]:
    return sorted({code.strip() for code in codes})


def delegation_contexts(grants: list[dict]) -> tuple[ActiveDelegation, ...]:
    return tuple(
        ActiveDelegation(
            grant_id=int(grant["id"]),
            grantor_user_id=int(grant["grantor_user_id"]),
            grantor_name=str(grant["grantor_name"]),
            department_id=grant["department_id"],
            permission_codes=frozenset(json.loads(grant["permission_codes_json"])),
            starts_at=str(grant["starts_at"]),
            ends_at=str(grant["ends_at"]),
        )
        for grant in grants
    )


def delegated_permissions(grants: list[dict]) -> set[str]:
    permissions: set[str] = set()
    for grant in grants:
        permissions.update(json.loads(grant["permission_codes_json"]))
    return permissions


class DelegationService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.users = UserRepository(connection)
        self.delegations = DelegationRepository(connection)
        self.audit = AuditService(connection, self.clock)

    def create(self, principal: Principal, data: dict) -> tuple[dict, bool]:
        """创建临时代理授权，返回 (授权详情, 是否新建)。完全相同的活跃授权重复提交时幂等返回已有记录。"""
        principal.require("delegations.write")
        grantor_id = int(data.get("grantor_user_id") or principal.user_id)
        delegate_id = int(data["delegate_user_id"])
        if grantor_id == delegate_id:
            raise ValidationError("不能将权限代理给自己")
        grantor = self.users.require(grantor_id)
        if grantor["status"] != "active":
            raise ValidationError("授权人账号不可用")
        delegate = self.users.require(delegate_id)
        if delegate["status"] != "active":
            raise ValidationError("代理人账号不可用")

        try:
            starts_at = from_storage(data.get("starts_at"))
            ends_at = from_storage(data.get("ends_at"))
        except ValueError:
            raise ValidationError("生效或截止时间格式无效") from None
        if starts_at is None or ends_at is None:
            raise ValidationError("生效时间与截止时间不能为空")
        if ends_at <= starts_at:
            raise ValidationError("截止时间必须晚于生效时间")
        now = self.clock.now()
        if ends_at <= now:
            raise ValidationError("截止时间必须晚于当前时间")

        codes = _canonical_codes(list(data.get("permission_codes") or []))
        if not codes:
            raise ValidationError("业务范围至少包含一项权限")
        known = {str(row[0]) for row in self.connection.execute("SELECT code FROM permissions").fetchall()}
        missing = [code for code in codes if code not in known]
        if missing:
            raise NotFoundError(f"权限不存在：{', '.join(missing)}")
        # 授权人只能转授自己角色拥有的能力；通过代理获得的权限不计入，防止层层转授。
        grantor_permissions = self.users.permissions(grantor_id)
        overreach = [code for code in codes if code not in grantor_permissions]
        if overreach:
            raise PermissionDeniedError(
                "授权人不能转授自己没有的能力",
                context={"overreach": overreach},
            )

        department_id = data.get("department_id")
        if department_id is not None:
            department = self.connection.execute(
                "SELECT id FROM departments WHERE id=? AND is_active=1", (department_id,)
            ).fetchone()
            if department is None:
                raise NotFoundError("部门不存在或已停用")
            membership = self.connection.execute(
                "SELECT 1 FROM department_memberships WHERE user_id=? AND department_id=?"
                " AND starts_at<=? AND (ends_at IS NULL OR ends_at>?) LIMIT 1",
                (grantor_id, department_id, to_storage(now), to_storage(now)),
            ).fetchone()
            if membership is None:
                raise ValidationError("授权人在该部门没有有效任期，不能授予该部门范围的代理")

        starts_text = to_storage(starts_at)
        ends_text = to_storage(ends_at)
        codes_json = json.dumps(codes, ensure_ascii=False)
        duplicate = self.delegations.find_duplicate(
            grantor_user_id=grantor_id,
            delegate_user_id=delegate_id,
            department_id=department_id,
            permission_codes_json=codes_json,
            starts_at=starts_text,
            ends_at=ends_text,
        )
        if duplicate is not None:
            return self.detail(duplicate["id"]), False
        overlap = self.delegations.find_overlap(
            grantor_user_id=grantor_id,
            delegate_user_id=delegate_id,
            starts_at=starts_text,
            ends_at=ends_text,
        )
        if overlap is not None:
            raise ConflictError("同一授权人与代理人之间已存在时间重叠的代理授权")

        now_text = to_storage(now)
        cursor = self.connection.execute(
            "INSERT INTO delegation_grants(grantor_user_id,delegate_user_id,department_id,permission_codes_json,"
            "reason,status,starts_at,ends_at,created_by,created_at,updated_at) VALUES(?,?,?,?,?,'active',?,?,?,?,?)",
            (
                grantor_id,
                delegate_id,
                department_id,
                codes_json,
                (data.get("reason") or "").strip(),
                starts_text,
                ends_text,
                principal.user_id,
                now_text,
                now_text,
            ),
        )
        delegation_id = int(cursor.lastrowid)
        created = self.detail(delegation_id)
        self.audit.record(
            AuditContext.from_principal(principal),
            action="delegation.create",
            resource_type="delegation",
            resource_id=delegation_id,
            after=created,
            metadata={"grantor": grantor["username"], "delegate": delegate["username"]},
        )
        return created, True

    def revoke(self, principal: Principal, delegation_id: int, reason: str) -> dict:
        grant = self.delegations.require(delegation_id)
        if principal.user_id != int(grant["grantor_user_id"]):
            principal.require("delegations.write")
        if grant["status"] != "active":
            raise ConflictError("代理授权已撤销")
        now_text = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE delegation_grants SET status='revoked',revoked_at=?,revoked_by=?,revoke_reason=?,updated_at=? WHERE id=?",
            (now_text, principal.user_id, reason.strip(), now_text, delegation_id),
        )
        revoked = self.detail(delegation_id)
        self.audit.record(
            AuditContext.from_principal(principal),
            action="delegation.revoke",
            resource_type="delegation",
            resource_id=delegation_id,
            before=grant,
            after=revoked,
        )
        return revoked

    def detail(self, delegation_id: int) -> dict:
        grant = self.delegations.detail(delegation_id)
        if grant is None:
            raise NotFoundError("代理授权不存在")
        return self.present(grant)

    def list(
        self,
        principal: Principal,
        *,
        grantor_user_id: int | None,
        delegate_user_id: int | None,
        status: str | None,
        active_at: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[dict], int]:
        principal.require("delegations.read")
        rows, total = self.delegations.list(
            grantor_user_id=grantor_user_id,
            delegate_user_id=delegate_user_id,
            status=status,
            active_at=active_at,
            limit=limit,
            offset=offset,
        )
        return [self.present(row) for row in rows], total

    def active_grants_for(self, delegate_user_id: int, moment=None) -> list[dict]:
        moment_text = to_storage(moment or self.clock.now())
        return self.delegations.active_for_delegate(delegate_user_id, moment_text)

    def activity(
        self,
        principal: Principal,
        *,
        moment_text: str,
        grantor_user_id: int | None,
        delegate_user_id: int | None,
        limit: int,
        offset: int,
    ) -> dict:
        """查询某一时间点谁代表谁办理了哪些业务：先生效授权，再关联代理期间留下的审计事件。"""
        principal.require("delegations.read")
        grants, total = self.delegations.effective_at(
            moment=moment_text,
            grantor_user_id=grantor_user_id,
            delegate_user_id=delegate_user_id,
            limit=limit,
            offset=offset,
        )
        items = []
        for grant in grants:
            # 元数据中的 grant_id 是精确判据：授权失效后新事件不可能再携带它；
            # 时间窗只是辅助边界，上界取闭区间以覆盖与撤销同秒发生的办理记录。
            window_end = min(grant["ends_at"], grant["revoked_at"] or grant["ends_at"])
            rows = self.connection.execute(
                "SELECT id,action,resource_type,resource_id,outcome,actor_name,metadata_json,created_at "
                "FROM audit_events WHERE actor_user_id=? AND created_at>=? AND created_at<=? ORDER BY id LIMIT ?",
                (grant["delegate_user_id"], grant["starts_at"], window_end, MAX_ACTIVITY_EVENTS_PER_GRANT),
            ).fetchall()
            events = []
            for row in rows:
                metadata = json.loads(row["metadata_json"] or "{}")
                if any(int(item.get("grant_id", -1)) == grant["id"] for item in metadata.get("delegations", [])):
                    events.append(
                        {
                            "id": row["id"],
                            "action": row["action"],
                            "resource_type": row["resource_type"],
                            "resource_id": row["resource_id"],
                            "outcome": row["outcome"],
                            "actor_name": row["actor_name"],
                            "created_at": row["created_at"],
                        }
                    )
            items.append({"grant": self.present(grant), "events": events})
        return {"moment": moment_text, "total": total, "data": items}

    def present(self, grant: dict) -> dict:
        presented = dict(grant)
        presented["permission_codes"] = json.loads(presented.pop("permission_codes_json"))
        presented["is_effective"] = self.delegations.is_effective(int(presented["id"]), to_storage(self.clock.now()))
        return presented
