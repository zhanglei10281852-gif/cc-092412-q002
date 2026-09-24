from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.core.clock import to_storage
from app.database import close_connection, get_connection


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def _make_user(client, admin, username: str, display_name: str, role_codes: list[str]) -> int:
    response = client.post(
        "/api/users",
        headers=admin["headers"],
        json={"username": username, "password": "Clerk!23456", "display_name": display_name, "role_codes": role_codes},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _login(client, username: str) -> dict:
    response = client.post("/api/auth/login", json={"username": username, "password": "Clerk!23456", "client_label": "tests"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def _grant_payload(deputy_id: int, **overrides) -> dict:
    now = datetime.now(UTC)
    payload = {
        "delegate_user_id": deputy_id,
        "permission_codes": ["petitions.read", "petitions.write"],
        "starts_at": _iso(now - timedelta(minutes=5)),
        "ends_at": _iso(now + timedelta(hours=1)),
        "reason": "负责人请假替岗",
    }
    payload.update(overrides)
    return payload


@pytest.fixture()
def office(client, admin) -> dict:
    """党政办场景：负责人拥有信访与代理管理权限，替岗人员没有任何角色。"""
    role = client.post(
        "/api/roles",
        headers=admin["headers"],
        json={
            "code": "office.head",
            "name": "党政办负责人",
            "permission_codes": ["petitions.read", "petitions.write", "delegations.read", "delegations.write"],
        },
    )
    assert role.status_code == 201, role.text
    chief_id = _make_user(client, admin, "office.chief", "负责人", ["office.head"])
    deputy_id = _make_user(client, admin, "office.deputy", "替岗人员", [])
    return {"chief_id": chief_id, "deputy_id": deputy_id}


@pytest.fixture()
def grant(client, admin, office) -> dict:
    response = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"]),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_petition(client) -> int:
    response = client.post("/petitions", json={"type": "意见建议", "target": "村道照明", "content": "建议增设照明"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _receive_petition(client, petition_id: int, headers: dict):
    return client.post(f"/api/petition-workflow/{petition_id}/transition", headers=headers, json={"target_status": "待分派"})


def test_delegation_grants_timeboxed_permissions(client, admin, office, grant):
    assert grant["status"] == "active"
    assert grant["grantor_user_id"] == office["chief_id"]
    assert grant["delegate_user_id"] == office["deputy_id"]
    assert grant["permission_codes"] == ["petitions.read", "petitions.write"]
    assert grant["is_effective"] is True

    deputy_headers = _login(client, "office.deputy")
    me = client.get("/api/auth/me", headers=deputy_headers)
    assert me.status_code == 200
    assert "petitions.write" in me.json()["permissions"]

    petition_id = _create_petition(client)
    assert _receive_petition(client, petition_id, deputy_headers).status_code == 200


def test_delegated_operation_records_both_operator_and_position(client, admin, office, grant):
    deputy_headers = _login(client, "office.deputy")
    petition_id = _create_petition(client)
    assert _receive_petition(client, petition_id, deputy_headers).status_code == 200

    events = client.get("/api/audit?action=petition.transition", headers=admin["headers"])
    assert events.status_code == 200
    assert events.json()["total"] == 1
    record = events.json()["data"][0]
    assert record["actor_name"] == "替岗人员"
    metadata = json.loads(record["metadata_json"])
    assert metadata["delegations"][0]["grant_id"] == grant["id"]
    assert metadata["delegations"][0]["grantor_user_id"] == office["chief_id"]
    assert metadata["delegations"][0]["grantor_name"] == "负责人"


def test_grantor_cannot_delegate_missing_capability(client, admin, office):
    response = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"], permission_codes=["users.write"]),
    )
    assert response.status_code == 403
    assert "不能转授" in response.json()["error"]["message"]

    unknown = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"], permission_codes=["petitions.fly"]),
    )
    assert unknown.status_code == 404

    self_delegation = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(office["chief_id"], grantor_user_id=office["chief_id"]),
    )
    assert self_delegation.status_code == 422


def test_delegate_cannot_redelegate(client, admin, office):
    # 负责人把代理管理权限授予替岗人员，但替岗人员自身角色没有任何能力，仍不能继续转授。
    grant = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"], permission_codes=["delegations.write"]),
    )
    assert grant.status_code == 201, grant.text
    deputy_headers = _login(client, "office.deputy")
    third_id = _make_user(client, admin, "office.third", "第三人", [])
    response = client.post(
        "/api/delegations",
        headers=deputy_headers,
        json=_grant_payload(third_id, permission_codes=["petitions.write"]),
    )
    assert response.status_code == 403
    assert "不能转授" in response.json()["error"]["message"]


def test_create_requires_delegation_permission(client, admin, office):
    deputy_headers = _login(client, "office.deputy")
    response = client.post("/api/delegations", headers=deputy_headers, json=_grant_payload(office["chief_id"]))
    assert response.status_code == 403


def test_duplicate_submission_is_idempotent(client, admin, office):
    payload = _grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"])
    first = client.post("/api/delegations", headers=admin["headers"], json=payload)
    assert first.status_code == 201, first.text
    second = client.post("/api/delegations", headers=admin["headers"], json=payload)
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]

    listing = client.get("/api/delegations", headers=admin["headers"])
    assert listing.status_code == 200
    assert listing.json()["total"] == 1

    now_text = _iso(datetime.now(UTC))
    active_now = client.get("/api/delegations", params={"active_at": now_text}, headers=admin["headers"])
    assert active_now.json()["total"] == 1
    active_past = client.get(
        "/api/delegations", params={"active_at": _iso(datetime.now(UTC) - timedelta(hours=2))}, headers=admin["headers"]
    )
    assert active_past.json()["total"] == 0

    now = datetime.now(UTC)
    overlapping = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(
            office["deputy_id"],
            grantor_user_id=office["chief_id"],
            starts_at=_iso(now + timedelta(minutes=30)),
            ends_at=_iso(now + timedelta(hours=2)),
        ),
    )
    assert overlapping.status_code == 409


def test_revoke_stops_old_session_immediately(client, admin, office, grant):
    deputy_headers = _login(client, "office.deputy")
    assert "petitions.write" in client.get("/api/auth/me", headers=deputy_headers).json()["permissions"]

    revoked = client.post(f"/api/delegations/{grant['id']}/revoke", headers=admin["headers"], json={"reason": "负责人提前返岗"})
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revoked_at"] is not None

    me = client.get("/api/auth/me", headers=deputy_headers)
    assert "petitions.write" not in me.json()["permissions"]
    petition_id = _create_petition(client)
    assert _receive_petition(client, petition_id, deputy_headers).status_code == 403

    again = client.post(f"/api/delegations/{grant['id']}/revoke", headers=admin["headers"], json={})
    assert again.status_code == 409


def test_grantor_can_revoke_own_delegation(client, admin, office, grant):
    chief_headers = _login(client, "office.chief")
    revoked = client.post(f"/api/delegations/{grant['id']}/revoke", headers=chief_headers, json={"reason": "提前返岗"})
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"


def test_expired_grant_stops_old_session(client, admin, office, grant):
    deputy_headers = _login(client, "office.deputy")
    assert "petitions.write" in client.get("/api/auth/me", headers=deputy_headers).json()["permissions"]

    now = datetime.now(UTC)
    connection = get_connection()
    connection.execute(
        "UPDATE delegation_grants SET starts_at=?,ends_at=? WHERE id=?",
        (to_storage(now - timedelta(hours=2)), to_storage(now - timedelta(hours=1)), grant["id"]),
    )

    me = client.get("/api/auth/me", headers=deputy_headers)
    assert "petitions.write" not in me.json()["permissions"]
    petition_id = _create_petition(client)
    assert _receive_petition(client, petition_id, deputy_headers).status_code == 403


def test_disabled_accounts_stop_delegation(client, admin, office, grant):
    deputy_headers = _login(client, "office.deputy")
    assert "petitions.write" in client.get("/api/auth/me", headers=deputy_headers).json()["permissions"]

    # 授权人账号停用：代理立即失效，但授权仍在时间窗内，账号恢复后应复原。
    assert client.patch(f"/api/users/{office['chief_id']}", headers=admin["headers"], json={"status": "disabled"}).status_code == 200
    me = client.get("/api/auth/me", headers=deputy_headers)
    assert "petitions.write" not in me.json()["permissions"]
    assert client.patch(f"/api/users/{office['chief_id']}", headers=admin["headers"], json={"status": "active"}).status_code == 200
    me = client.get("/api/auth/me", headers=deputy_headers)
    assert "petitions.write" in me.json()["permissions"]

    # 代理人账号停用：旧会话直接失效。
    assert client.patch(f"/api/users/{office['deputy_id']}", headers=admin["headers"], json={"status": "disabled"}).status_code == 200
    assert client.get("/api/auth/me", headers=deputy_headers).status_code == 401


def test_department_tenure_end_stops_delegation(client, admin, office):
    department = client.post("/api/departments", headers=admin["headers"], json={"name": "党政办", "manager": "负责人", "phone": "010-0001"})
    assert department.status_code == 201, department.text
    department_id = department.json()["id"]
    now = datetime.now(UTC)
    membership = client.post(
        f"/api/departments/users/{office['chief_id']}/memberships",
        headers=admin["headers"],
        json={"department_id": department_id, "title": "负责人", "is_primary": True, "starts_at": _iso(now - timedelta(days=30))},
    )
    assert membership.status_code == 201, membership.text

    grant = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"], department_id=department_id),
    )
    assert grant.status_code == 201, grant.text
    deputy_headers = _login(client, "office.deputy")
    assert "petitions.write" in client.get("/api/auth/me", headers=deputy_headers).json()["permissions"]

    ended = client.post(
        f"/api/departments/memberships/{membership.json()['id']}/end",
        headers=admin["headers"],
        json={"ends_at": _iso(now - timedelta(seconds=1))},
    )
    assert ended.status_code == 200, ended.text
    me = client.get("/api/auth/me", headers=deputy_headers)
    assert "petitions.write" not in me.json()["permissions"]


def test_department_scope_requires_grantor_membership(client, admin, office):
    department = client.post("/api/departments", headers=admin["headers"], json={"name": "民政办", "manager": "某人", "phone": "010-0002"})
    assert department.status_code == 201
    response = client.post(
        "/api/delegations",
        headers=admin["headers"],
        json=_grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"], department_id=department.json()["id"]),
    )
    assert response.status_code == 422


def test_restart_leaves_no_ghost_or_duplicate_grants(client, admin, office):
    from app.main import app

    payload = _grant_payload(office["deputy_id"], grantor_user_id=office["chief_id"])
    created = client.post("/api/delegations", headers=admin["headers"], json=payload)
    assert created.status_code == 201
    grant_id = created.json()["id"]
    deputy_headers = _login(client, "office.deputy")

    close_connection()
    with TestClient(app) as restarted:
        # 重启后：生效中的授权继续有效，重复提交仍命中同一条记录。
        assert "petitions.write" in restarted.get("/api/auth/me", headers=deputy_headers).json()["permissions"]
        replay = restarted.post("/api/delegations", headers=admin["headers"], json=payload)
        assert replay.status_code == 200
        assert replay.json()["id"] == grant_id
        assert restarted.get("/api/delegations", headers=admin["headers"]).json()["total"] == 1

        revoked = restarted.post(f"/api/delegations/{grant_id}/revoke", headers=admin["headers"], json={"reason": "交接完成"})
        assert revoked.status_code == 200

    close_connection()
    with TestClient(app) as restarted_again:
        # 再次重启：已撤销的授权不会复活，旧会话不再拥有代理权限。
        me = restarted_again.get("/api/auth/me", headers=deputy_headers)
        assert "petitions.write" not in me.json()["permissions"]
        assert restarted_again.get("/api/delegations", headers=admin["headers"]).json()["total"] == 1
        detail = restarted_again.get(f"/api/delegations/{grant_id}", headers=admin["headers"])
        assert detail.json()["status"] == "revoked"


def test_activity_query_reports_who_acted_for_whom(client, admin, office, grant):
    deputy_headers = _login(client, "office.deputy")
    for _ in range(2):
        petition_id = _create_petition(client)
        assert _receive_petition(client, petition_id, deputy_headers).status_code == 200

    moment = _iso(datetime.now(UTC))
    activity = client.get("/api/delegations/activity", params={"moment": moment}, headers=admin["headers"])
    assert activity.status_code == 200, activity.text
    body = activity.json()
    assert body["total"] == 1
    item = body["data"][0]
    assert item["grant"]["id"] == grant["id"]
    assert item["grant"]["grantor_name"] == "负责人"
    assert item["grant"]["delegate_name"] == "替岗人员"
    assert {event["action"] for event in item["events"]} == {"petition.transition"}
    assert all(event["actor_name"] == "替岗人员" for event in item["events"])

    before_window = _iso(datetime.now(UTC) - timedelta(hours=2))
    empty = client.get("/api/delegations/activity", params={"moment": before_window}, headers=admin["headers"])
    assert empty.json()["total"] == 0

    filtered = client.get(
        "/api/delegations/activity",
        params={"moment": moment, "delegate_user_id": office["deputy_id"]},
        headers=admin["headers"],
    )
    assert filtered.json()["total"] == 1
    nobody = client.get(
        "/api/delegations/activity",
        params={"moment": moment, "delegate_user_id": office["chief_id"]},
        headers=admin["headers"],
    )
    assert nobody.json()["total"] == 0

    deputy_headers_no_read = _login(client, "office.deputy")
    assert client.get("/api/delegations/activity", params={"moment": moment}, headers=deputy_headers_no_read).status_code == 403


def test_activity_after_revoke_reports_only_pre_revocation_events(client, admin, office, grant):
    deputy_headers = _login(client, "office.deputy")
    petition_id = _create_petition(client)
    assert _receive_petition(client, petition_id, deputy_headers).status_code == 200
    assert client.post(f"/api/delegations/{grant['id']}/revoke", headers=admin["headers"], json={}).status_code == 200

    moment = _iso(datetime.now(UTC))
    activity = client.get("/api/delegations/activity", params={"moment": moment}, headers=admin["headers"])
    # 撤销后该授权在当前时刻不再生效，但撤销时间点之前仍可回溯到办理记录。
    assert activity.json()["total"] == 0
    history = client.get(
        "/api/delegations/activity",
        params={"moment": _iso(datetime.now(UTC) - timedelta(minutes=1))},
        headers=admin["headers"],
    )
    assert history.json()["total"] == 1
    assert len(history.json()["data"][0]["events"]) == 1
