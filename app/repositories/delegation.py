from __future__ import annotations

from typing import Any

from app.repositories.base import Repository, row_dict, rows_dict

_DETAIL_SELECT = (
    "SELECT g.*, grantor.username AS grantor_username, grantor.display_name AS grantor_name, "
    "delegate.username AS delegate_username, delegate.display_name AS delegate_name, "
    "d.name AS department_name "
    "FROM delegation_grants g "
    "JOIN users grantor ON grantor.id=g.grantor_user_id "
    "JOIN users delegate ON delegate.id=g.delegate_user_id "
    "LEFT JOIN departments d ON d.id=g.department_id"
)


class DelegationRepository(Repository):
    table = "delegation_grants"
    entity_name = "代理授权"

    def detail(self, delegation_id: int) -> dict[str, Any] | None:
        return row_dict(self.connection.execute(_DETAIL_SELECT + " WHERE g.id=?", (delegation_id,)).fetchone())

    def is_effective(self, delegation_id: int, moment: str) -> bool:
        """完整生效判定：时间窗内、未撤销、双方账号可用，部门级授权要求授权人任期覆盖该时刻。"""
        row = self.connection.execute(
            "SELECT 1 FROM delegation_grants g "
            "JOIN users grantor ON grantor.id=g.grantor_user_id "
            "JOIN users delegate ON delegate.id=g.delegate_user_id "
            "WHERE g.id=? AND g.status='active' AND g.starts_at<=? AND g.ends_at>?"
            " AND grantor.status='active' AND delegate.status='active'"
            " AND (g.department_id IS NULL OR EXISTS ("
            "SELECT 1 FROM department_memberships m WHERE m.user_id=g.grantor_user_id"
            " AND m.department_id=g.department_id AND m.starts_at<=? AND (m.ends_at IS NULL OR m.ends_at>?)))",
            (delegation_id, moment, moment, moment, moment),
        ).fetchone()
        return row is not None

    def active_for_delegate(self, delegate_user_id: int, moment: str) -> list[dict]:
        """返回某时刻对代理人实际生效的授权：时间窗内、未撤销、双方账号可用，
        且部门级授权要求授权人在该部门的任期覆盖该时刻。"""
        return rows_dict(self.connection.execute(
            _DETAIL_SELECT +
            " WHERE g.delegate_user_id=? AND g.status='active' AND g.starts_at<=? AND g.ends_at>?"
            " AND grantor.status='active' AND delegate.status='active'"
            " AND (g.department_id IS NULL OR EXISTS ("
            "SELECT 1 FROM department_memberships m WHERE m.user_id=g.grantor_user_id"
            " AND m.department_id=g.department_id AND m.starts_at<=? AND (m.ends_at IS NULL OR m.ends_at>?)))"
            " ORDER BY g.id",
            (delegate_user_id, moment, moment, moment, moment),
        ).fetchall())

    def find_duplicate(
        self,
        *,
        grantor_user_id: int,
        delegate_user_id: int,
        department_id: int | None,
        permission_codes_json: str,
        starts_at: str,
        ends_at: str,
    ) -> dict[str, Any] | None:
        """查找内容完全一致且仍活跃的授权，用于重复提交的幂等命中。"""
        return row_dict(self.connection.execute(
            "SELECT * FROM delegation_grants WHERE grantor_user_id=? AND delegate_user_id=?"
            " AND IFNULL(department_id,-1)=IFNULL(?,-1) AND permission_codes_json=?"
            " AND starts_at=? AND ends_at=? AND status='active' ORDER BY id LIMIT 1",
            (grantor_user_id, delegate_user_id, department_id, permission_codes_json, starts_at, ends_at),
        ).fetchone())

    def find_overlap(self, *, grantor_user_id: int, delegate_user_id: int, starts_at: str, ends_at: str) -> dict[str, Any] | None:
        """查找同一授权人、代理人之间时间窗重叠的活跃授权。"""
        return row_dict(self.connection.execute(
            "SELECT * FROM delegation_grants WHERE grantor_user_id=? AND delegate_user_id=?"
            " AND status='active' AND starts_at<? AND ends_at>? ORDER BY id LIMIT 1",
            (grantor_user_id, delegate_user_id, ends_at, starts_at),
        ).fetchone())

    def list(
        self,
        *,
        grantor_user_id: int | None,
        delegate_user_id: int | None,
        status: str | None,
        active_at: str | None,
        limit: int,
        offset: int,
    ) -> tuple[list[dict], int]:
        conditions: list[str] = []
        params: list[Any] = []
        if grantor_user_id is not None:
            conditions.append("g.grantor_user_id=?")
            params.append(grantor_user_id)
        if delegate_user_id is not None:
            conditions.append("g.delegate_user_id=?")
            params.append(delegate_user_id)
        if status:
            conditions.append("g.status=?")
            params.append(status)
        if active_at is not None:
            conditions.append("g.starts_at<=? AND g.ends_at>? AND (g.revoked_at IS NULL OR g.revoked_at>?)")
            params.extend([active_at, active_at, active_at])
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        total = int(self.connection.execute(
            "SELECT COUNT(*) FROM delegation_grants g" + where, tuple(params)
        ).fetchone()[0])
        rows = rows_dict(self.connection.execute(
            _DETAIL_SELECT + where + " ORDER BY g.id DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall())
        return rows, total

    def effective_at(
        self,
        *,
        moment: str,
        grantor_user_id: int | None,
        delegate_user_id: int | None,
        limit: int,
        offset: int,
    ) -> tuple[list[dict], int]:
        """时间回溯查询：在指定时刻处于生效状态（时间窗内且当时未撤销）的授权。"""
        conditions = ["g.starts_at<=?", "g.ends_at>?", "(g.revoked_at IS NULL OR g.revoked_at>?)"]
        params: list[Any] = [moment, moment, moment]
        if grantor_user_id is not None:
            conditions.append("g.grantor_user_id=?")
            params.append(grantor_user_id)
        if delegate_user_id is not None:
            conditions.append("g.delegate_user_id=?")
            params.append(delegate_user_id)
        where = " WHERE " + " AND ".join(conditions)
        total = int(self.connection.execute(
            "SELECT COUNT(*) FROM delegation_grants g" + where, tuple(params)
        ).fetchone()[0])
        rows = rows_dict(self.connection.execute(
            _DETAIL_SELECT + where + " ORDER BY g.id LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall())
        return rows, total
