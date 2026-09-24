from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.repositories.base import Repository, row_dict, rows_dict


class DelegationRepository(Repository):
    table = "delegations"
    entity_name = "代理授权"

    def get(self, entity_id: int) -> dict[str, Any] | None:
        row = row_dict(self.connection.execute(
            "SELECT * FROM delegations WHERE id=?", (entity_id,)
        ).fetchone())
        return self._hydrate(row)

    def _hydrate(self, row: dict[str, Any] | None) -> dict[str, Any] | None:
        if row is None:
            return None
        row["permission_codes"] = json.loads(row.pop("permission_codes_json") or "[]")
        row["department_ids"] = json.loads(row.pop("department_ids_json") or "[]")
        return row

    def _hydrate_many(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self._hydrate(row) for row in rows]

    def create(
        self,
        *,
        granter_user_id: int,
        agent_user_id: int,
        permission_codes: list[str],
        department_ids: list[int],
        reason: str,
        starts_at: str,
        ends_at: str,
        created_at: str,
        created_by_user_id: int,
    ) -> dict[str, Any]:
        cursor = self.connection.execute(
            "INSERT INTO delegations(granter_user_id,agent_user_id,permission_codes_json,department_ids_json,"
            "reason,status,starts_at,ends_at,created_at,created_by_user_id) VALUES(?,?,?,?,?,'active',?,?,?,?)",
            (
                granter_user_id,
                agent_user_id,
                json.dumps(permission_codes, ensure_ascii=False),
                json.dumps(department_ids),
                reason,
                starts_at,
                ends_at,
                created_at,
                created_by_user_id,
            ),
        )
        item = self.get(int(cursor.lastrowid))
        assert item is not None
        return item

    def find_overlapping_pair(self, granter_user_id: int, agent_user_id: int, starts_at: str, ends_at: str, *, exclude_id: int | None = None) -> dict[str, Any] | None:
        sql = (
            "SELECT * FROM delegations WHERE granter_user_id=? AND agent_user_id=? AND status='active' "
            "AND starts_at<? AND ends_at>? "
        )
        params: list[Any] = [granter_user_id, agent_user_id, ends_at, starts_at]
        if exclude_id is not None:
            sql += "AND id<>? "
            params.append(exclude_id)
        sql += "LIMIT 1"
        return self._hydrate(row_dict(self.connection.execute(sql, tuple(params)).fetchone()))

    def list_for_view(
        self,
        *,
        granter_user_id: int | None,
        agent_user_id: int | None,
        status: str | None,
        active_at: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        if granter_user_id is not None:
            conditions.append("d.granter_user_id=?")
            params.append(granter_user_id)
        if agent_user_id is not None:
            conditions.append("d.agent_user_id=?")
            params.append(agent_user_id)
        if status:
            conditions.append("d.status=?")
            params.append(status)
        if active_at is not None:
            conditions.append("d.starts_at<=? AND d.ends_at>? AND d.status='active'")
            params.extend([active_at, active_at])
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])
        rows = rows_dict(self.connection.execute(
            "SELECT d.*, gu.username AS granter_username, gu.display_name AS granter_display_name,"
            "au.username AS agent_username, au.display_name AS agent_display_name,"
            "gd.name AS granter_department_name "
            "FROM delegations d "
            "JOIN users gu ON gu.id=d.granter_user_id "
            "JOIN users au ON au.id=d.agent_user_id "
            "LEFT JOIN departments gd ON gd.id=gu.department_id"
            + where + " ORDER BY d.id DESC LIMIT ? OFFSET ?",
            tuple(params),
        ).fetchall())
        return self._hydrate_many(rows)

    def count_for_view(
        self,
        *,
        granter_user_id: int | None,
        agent_user_id: int | None,
        status: str | None,
        active_at: str | None,
    ) -> int:
        conditions: list[str] = []
        params: list[Any] = []
        if granter_user_id is not None:
            conditions.append("granter_user_id=?")
            params.append(granter_user_id)
        if agent_user_id is not None:
            conditions.append("agent_user_id=?")
            params.append(agent_user_id)
        if status:
            conditions.append("status=?")
            params.append(status)
        if active_at is not None:
            conditions.append("starts_at<=? AND ends_at>? AND status='active'")
            params.extend([active_at, active_at])
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        return int(self.connection.execute("SELECT COUNT(*) FROM delegations" + where, tuple(params)).fetchone()[0])

    def active_for_agent_at(self, agent_user_id: int, moment: str) -> list[dict[str, Any]]:
        rows = rows_dict(self.connection.execute(
            "SELECT d.*, gu.username AS granter_username, gu.display_name AS granter_display_name,"
            "gu.department_id AS granter_department_id, gu.status AS granter_status "
            "FROM delegations d JOIN users gu ON gu.id=d.granter_user_id "
            "WHERE d.agent_user_id=? AND d.status='active' AND d.starts_at<=? AND d.ends_at>? "
            "ORDER BY d.id",
            (agent_user_id, moment, moment),
        ).fetchall())
        return self._hydrate_many(rows)

    def active_for_session(self, session_id: int, moment: str) -> dict[str, Any] | None:
        row = row_dict(self.connection.execute(
            "SELECT d.* FROM sessions s JOIN delegations d ON d.id=s.active_delegation_id "
            "WHERE s.id=? AND d.status='active' AND d.starts_at<=? AND d.ends_at>?",
            (session_id, moment, moment),
        ).fetchone())
        return self._hydrate(row)

    def set_session_delegation(self, session_id: int, delegation_id: int | None) -> None:
        self.connection.execute("UPDATE sessions SET active_delegation_id=? WHERE id=?", (delegation_id, session_id))

    def clear_sessions_for_delegation(self, delegation_id: int) -> int:
        cursor = self.connection.execute(
            "UPDATE sessions SET active_delegation_id=NULL WHERE active_delegation_id=?",
            (delegation_id,),
        )
        return cursor.rowcount

    def revoke(self, delegation_id: int, revoked_at: str, revoked_by_user_id: int, reason: str) -> None:
        self.connection.execute(
            "UPDATE delegations SET status='revoked',revoked_at=?,revoked_by_user_id=?,revoke_reason=? WHERE id=?",
            (revoked_at, revoked_by_user_id, reason, delegation_id),
        )
