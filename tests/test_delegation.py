from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.core.clock import FrozenClock
from app.database import close_connection, get_connection
from app.main import app
from app.services.auth import AuthService
from app.services.delegation import DelegationService


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _create_department(client: TestClient, headers: dict, name: str) -> int:
    response = client.post(
        "/api/departments",
        headers=headers,
        json={"name": name, "manager": "主任", "phone": "010-12345678"},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _create_role(client: TestClient, headers: dict, code: str, permissions: list[str]) -> None:
    response = client.post(
        "/api/roles",
        headers=headers,
        json={"code": code, "name": code, "permission_codes": permissions},
    )
    assert response.status_code == 201, response.text


def _create_user(client: TestClient, headers: dict, username: str, role_codes: list[str], department_id: int | None = None) -> dict:
    response = client.post(
        "/api/users",
        headers=headers,
        json={
            "username": username,
            "password": "Clerk!23456",
            "display_name": username,
            "role_codes": role_codes,
            "department_id": department_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _login(client: TestClient, username: str) -> dict:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": "Clerk!23456", "client_label": "tests"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"token": body["token"], "headers": {"Authorization": f"Bearer {body['token']}"}}


def _make_petition_in_department(client: TestClient, admin_headers: dict, department_id: int) -> int:
    created = client.post(
        "/petitions",
        json={"type": "意见建议", "target": "路灯", "content": "需要维修", "contact": "13800000000"},
    )
    assert created.status_code == 201, created.text
    petition_id = created.json()["id"]
    first = client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=admin_headers,
        json={"target_status": "待分派"},
    )
    assert first.status_code == 200, first.text
    second = client.post(
        f"/api/petition-workflow/{petition_id}/transition",
        headers=admin_headers,
        json={"target_status": "办理中", "department_id": department_id},
    )
    assert second.status_code == 200, second.text
    return petition_id


def _setup_officer_and_agent(client: TestClient, admin_headers: dict) -> tuple[int, int, int, dict, dict]:
    department_one = _create_department(client, admin_headers, "党政办公室")
    department_two = _create_department(client, admin_headers, "民政办公室")
    _create_role(client, admin_headers, "petition.officer", ["petitions.read", "petitions.write"])
    granter = _create_user(client, admin_headers, "officer.wang", ["petition.officer"], department_one)
    agent = _create_user(client, admin_headers, "deputy.li", [])
    granter_session = _login(client, "officer.wang")
    agent_session = _login(client, "deputy.li")
    return department_one, department_two, granter["id"], granter_session, agent_session, agent["id"]


def _create_delegation(client: TestClient, admin_headers: dict, granter_id: int, agent_id: int,
                       permissions: list[str], department_ids: list[int], *, hours: int = 2) -> dict:
    now = datetime.now(UTC)
    response = client.post(
        "/api/delegations",
        headers=admin_headers,
        json={
            "granter_user_id": granter_id,
            "agent_user_id": agent_id,
            "permission_codes": permissions,
            "department_ids": department_ids,
            "reason": "负责人请假",
            "starts_at": _iso(now - timedelta(minutes=1)),
            "ends_at": _iso(now + timedelta(hours=hours)),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_delegation_grants_scoped_permission_and_records_both_actors(client, admin):
    department_one, department_two, granter_id, granter_session, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write", "petitions.read"], [department_one]
    )

    me_before = client.get("/api/auth/me", headers=agent_session["headers"])
    assert "petitions.write" not in me_before.json()["permissions"]

    activate = client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])
    assert activate.status_code == 200, activate.text
    me_after = client.get("/api/auth/me", headers=agent_session["headers"]).json()
    assert "petitions.write" in me_after["permissions"]
    assert me_after["delegation"]["granter_user_id"] == granter_id
    assert me_after["delegation"]["department_ids"] == [department_one]

    petition_d1 = _make_petition_in_department(client, admin["headers"], department_one)
    response = client.post(
        f"/api/petition-workflow/{petition_d1}/transition",
        headers=agent_session["headers"],
        json={"target_status": "待审核", "result": "代理期间已处理完毕"},
    )
    assert response.status_code == 200, response.text

    events = client.get(
        f"/api/audit?on_behalf_of_user_id={granter_id}&action=petition.transition",
        headers=admin["headers"],
    ).json()
    assert events["total"] == 1
    event = events["data"][0]
    assert event["actor_user_id"] == agent_id
    assert event["on_behalf_of_user_id"] == granter_id
    assert event["on_behalf_of_name"] == "officer.wang"
    assert event["delegation_id"] == delegation["id"]

    petition_d2 = _make_petition_in_department(client, admin["headers"], department_two)
    cross_scope = client.post(
        f"/api/petition-workflow/{petition_d2}/transition",
        headers=agent_session["headers"],
        json={"target_status": "待审核", "result": "越权尝试"},
    )
    assert cross_scope.status_code == 403


def test_cannot_delegate_permission_granter_does_not_have(client, admin):
    department_one = _create_department(client, admin["headers"], "党政办公室")
    _create_role(client, admin["headers"], "petition.officer", ["petitions.read"])
    granter = _create_user(client, admin["headers"], "officer.wang", ["petition.officer"], department_one)
    agent = _create_user(client, admin["headers"], "deputy.li", [])
    now = datetime.now(UTC)
    response = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json={
            "granter_user_id": granter["id"],
            "agent_user_id": agent["id"],
            "permission_codes": ["residents.write"],
            "department_ids": [department_one],
            "reason": "尝试转授没有的能力",
            "starts_at": _iso(now - timedelta(minutes=1)),
            "ends_at": _iso(now + timedelta(hours=2)),
        },
    )
    assert response.status_code == 403


def test_non_delegable_permissions_are_rejected(client, admin):
    granter = _create_user(client, admin["headers"], "boss.wu", ["administrator"])
    agent = _create_user(client, admin["headers"], "deputy.li", [])
    now = datetime.now(UTC)
    response = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json={
            "granter_user_id": granter["id"],
            "agent_user_id": agent["id"],
            "permission_codes": ["users.write"],
            "department_ids": [],
            "reason": "尝试转授用户管理权",
            "starts_at": _iso(now - timedelta(minutes=1)),
            "ends_at": _iso(now + timedelta(hours=2)),
        },
    )
    assert response.status_code == 422


def test_duplicate_submission_is_rejected(client, admin):
    department_one, _, granter_id, _, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    payload = {
        "granter_user_id": granter_id,
        "agent_user_id": agent_id,
        "permission_codes": ["petitions.write"],
        "department_ids": [department_one],
        "reason": "重复提交",
        "starts_at": _iso(datetime.now(UTC) - timedelta(minutes=1)),
        "ends_at": _iso(datetime.now(UTC) + timedelta(hours=2)),
    }
    first = client.post("/api/delegations", headers=admin["headers"], json=payload)
    assert first.status_code == 201
    second = client.post("/api/delegations", headers=admin["headers"], json=payload)
    assert second.status_code == 409
    listed = client.get("/api/delegations", headers=admin["headers"]).json()
    assert listed["total"] == 1


def test_revoke_detaches_existing_sessions_immediately(client, admin):
    department_one, _, granter_id, _, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write"], [department_one]
    )
    client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])
    assert "petitions.write" in client.get("/api/auth/me", headers=agent_session["headers"]).json()["permissions"]

    revoke = client.post(
        f"/api/delegations/{delegation['id']}/revoke",
        headers=admin["headers"],
        json={"reason": "负责人提前返岗"},
    )
    assert revoke.status_code == 200
    me = client.get("/api/auth/me", headers=agent_session["headers"]).json()
    assert "petitions.write" not in me["permissions"]
    assert me["delegation"] is None

    reactivate = client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])
    assert reactivate.status_code in (404, 409)


def test_delegation_survives_service_restart_but_revocation_is_immediate(client, admin):
    department_one, _, granter_id, _, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write"], [department_one]
    )
    client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])

    close_connection()
    with TestClient(app) as restarted:
        me = restarted.get("/api/auth/me", headers=agent_session["headers"]).json()
        assert me["delegation"] is not None
        assert "petitions.write" in me["permissions"]

    client.post(
        f"/api/delegations/{delegation['id']}/revoke",
        headers=admin["headers"],
        json={"reason": "收回"},
    )
    close_connection()
    with TestClient(app) as restarted:
        me = restarted.get("/api/auth/me", headers=agent_session["headers"]).json()
        assert me["delegation"] is None
        assert "petitions.write" not in me["permissions"]


def test_expired_delegation_cannot_power_existing_session(client, admin):
    department_one, _, granter_id, granter_session, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    now = datetime.now(UTC)
    response = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json={
            "granter_user_id": granter_id,
            "agent_user_id": agent_id,
            "permission_codes": ["petitions.write"],
            "department_ids": [department_one],
            "reason": "极短授权",
            "starts_at": _iso(now - timedelta(minutes=1)),
            "ends_at": _iso(now + timedelta(seconds=1)),
        },
    )
    assert response.status_code == 201
    delegation_id = response.json()["id"]
    client.post(f"/api/delegations/mine/activate/{delegation_id}", headers=agent_session["headers"])

    me = client.get("/api/auth/me", headers=agent_session["headers"]).json()
    session_id = me["session_id"]

    future = FrozenClock(datetime.now(UTC) + timedelta(hours=1))
    service = DelegationService(get_connection(), future)
    assert service.session_context(session_id) is None
    stored = get_connection().execute(
        "SELECT active_delegation_id FROM sessions WHERE id=?", (session_id,)
    ).fetchone()
    assert stored[0] is None

    principal = AuthService(get_connection(), future).principal(agent_session["token"])
    assert "petitions.write" not in principal.permissions
    assert principal.delegation is None


def test_disabling_granter_terminates_delegation_and_clears_sessions(client, admin):
    department_one, _, granter_id, _, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write"], [department_one]
    )
    client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])

    changed = client.patch(f"/api/users/{granter_id}", headers=admin["headers"], json={"status": "disabled"})
    assert changed.status_code == 200
    me = client.get("/api/auth/me", headers=agent_session["headers"]).json()
    assert "petitions.write" not in me["permissions"]
    detail = client.get(f"/api/delegations/{delegation['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "terminated"
    assert detail["terminate_reason"] == "user_disabled"


def test_membership_end_terminates_department_scoped_delegation(client, admin):
    department_one, _, granter_id, granter_session, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write"], [department_one]
    )
    client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])

    memberships = client.get(f"/api/departments/{department_one}/members", headers=admin["headers"]).json()
    if not any(item["user_id"] == granter_id for item in memberships):
        added = client.post(
            f"/api/departments/users/{granter_id}/memberships",
            headers=admin["headers"],
            json={
                "department_id": department_one,
                "title": "主任",
                "is_primary": True,
                "starts_at": _iso(datetime.now(UTC) - timedelta(days=1)),
            },
        )
        assert added.status_code == 201, added.text
        memberships = client.get(f"/api/departments/{department_one}/members", headers=admin["headers"]).json()
    membership_id = next(item["id"] for item in memberships if item["user_id"] == granter_id)
    end = client.post(
        f"/api/departments/memberships/{membership_id}/end",
        headers=admin["headers"],
        json={"ends_at": _iso(datetime.now(UTC) - timedelta(seconds=1))},
    )
    assert end.status_code == 200, end.text
    me = client.get("/api/auth/me", headers=agent_session["headers"]).json()
    assert "petitions.write" not in me["permissions"]
    detail = client.get(f"/api/delegations/{delegation['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "terminated"
    assert detail["terminate_reason"] == "membership_ended"


def test_permission_revoked_from_granter_stops_flowing_to_agent(client, admin):
    department_one, _, granter_id, _, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write", "petitions.read"], [department_one]
    )
    client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])
    assert "petitions.write" in client.get("/api/auth/me", headers=agent_session["headers"]).json()["permissions"]

    client.post(
        "/api/roles",
        headers=admin["headers"],
        json={"code": "empty.role", "name": "无权限角色", "permission_codes": []},
    )
    client.put(f"/api/users/{granter_id}/roles", headers=admin["headers"], json={"role_codes": ["empty.role"]})
    me = client.get("/api/auth/me", headers=agent_session["headers"]).json()
    assert "petitions.write" not in me["permissions"]
    assert me["delegation"] is None
    detail = client.get(f"/api/delegations/{delegation['id']}", headers=admin["headers"]).json()
    assert detail["status"] == "terminated"
    assert detail["terminate_reason"] == "granter_roles_changed"


def test_only_named_agent_may_activate(client, admin):
    department_one, _, granter_id, granter_session, _, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write"], [department_one]
    )
    response = client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=granter_session["headers"])
    assert response.status_code == 403


def test_deactivation_returns_agent_to_own_permissions(client, admin):
    department_one, _, granter_id, _, agent_session, agent_id = _setup_officer_and_agent(client, admin["headers"])
    delegation = _create_delegation(
        client, admin["headers"], granter_id, agent_id, ["petitions.write"], [department_one]
    )
    client.post(f"/api/delegations/mine/activate/{delegation['id']}", headers=agent_session["headers"])
    ended = client.post("/api/delegations/mine/deactivate", headers=agent_session["headers"])
    assert ended.status_code == 200, ended.text
    me = client.get("/api/auth/me", headers=agent_session["headers"]).json()
    assert me["delegation"] is None
    assert "petitions.write" not in me["permissions"]


def test_delegation_listing_filters_by_time_point(client, admin):
    department_one, _, granter_id, _, _, agent_id = _setup_officer_and_agent(client, admin["headers"])
    now = datetime.now(UTC)
    created = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json={
            "granter_user_id": granter_id,
            "agent_user_id": agent_id,
            "permission_codes": ["petitions.write"],
            "department_ids": [department_one],
            "reason": "请假窗口",
            "starts_at": _iso(now + timedelta(days=1)),
            "ends_at": _iso(now + timedelta(days=3)),
        },
    )
    assert created.status_code == 201, created.text

    before_window = client.get(
        f"/api/delegations?active_at={_iso(now)}&granter_user_id={granter_id}",
        headers=admin["headers"],
    ).json()
    assert before_window["total"] == 0

    in_window = client.get(
        f"/api/delegations?active_at={_iso(now + timedelta(days=2))}&granter_user_id={granter_id}",
        headers=admin["headers"],
    ).json()
    assert in_window["total"] == 1
    assert in_window["data"][0]["reason"] == "请假窗口"


def test_legacy_database_is_upgraded_with_delegation_columns(tmp_path, monkeypatch):
    import sqlite3

    from app.database import database_path, init_db

    legacy_path = tmp_path / "legacy.db"
    raw = sqlite3.connect(legacy_path)
    raw.executescript(
        """
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_digest TEXT NOT NULL UNIQUE,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            revoked_at TEXT,
            revoke_reason TEXT,
            client_label TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            actor_name TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            outcome TEXT NOT NULL,
            before_json TEXT,
            after_json TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            correlation_id TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    raw.commit()
    raw.close()

    monkeypatch.setenv("TOWNSHIP_DATABASE_PATH", str(legacy_path))
    close_connection()
    init_db()

    connection = sqlite3.connect(legacy_path)
    session_columns = {row[1] for row in connection.execute("PRAGMA table_info(sessions)").fetchall()}
    audit_columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)").fetchall()}
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    connection.close()
    assert "delegations" in tables
    assert "active_delegation_id" in session_columns
    assert {"on_behalf_of_user_id", "on_behalf_of_name", "delegation_id"} <= audit_columns
    close_connection()
    assert database_path() == legacy_path.resolve()
