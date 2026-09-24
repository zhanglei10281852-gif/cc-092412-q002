from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.pagination import Page, page_result
from app.core.security import Principal
from app.database import get_connection
from app.repositories.audit import AuditRepository

router = APIRouter(prefix="/api/audit", tags=["审计记录"])


@router.get("")
def list_audit_events(
    actor_user_id: int | None = None,
    resource_type: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    on_behalf_of_user_id: int | None = Query(default=None, description="被代理岗位用户 ID"),
    delegation_id: int | None = Query(default=None, description="代理授权 ID"),
    created_from: str | None = Query(default=None, description="起始时间（含，ISO 时间）"),
    created_to: str | None = Query(default=None, description="截止时间（含，ISO 时间）"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    principal.require("audit.read")
    pagination = Page(page, size)
    repository = AuditRepository(get_connection())
    rows = repository.list(
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        action=action,
        outcome=outcome,
        on_behalf_of_user_id=on_behalf_of_user_id,
        delegation_id=delegation_id,
        created_from=created_from,
        created_to=created_to,
        limit=size,
        offset=pagination.offset,
    )
    conditions: list[str] = []
    params: list = []
    for column, value in (
        ("actor_user_id", actor_user_id),
        ("resource_type", resource_type),
        ("action", action),
        ("outcome", outcome),
        ("on_behalf_of_user_id", on_behalf_of_user_id),
        ("delegation_id", delegation_id),
    ):
        if value is not None:
            conditions.append(f"{column}=?")
            params.append(value)
    if created_from is not None:
        conditions.append("created_at>=?")
        params.append(created_from)
    if created_to is not None:
        conditions.append("created_at<=?")
        params.append(created_to)
    query = "SELECT COUNT(*) FROM audit_events" + (" WHERE " + " AND ".join(conditions) if conditions else "")
    total = int(get_connection().execute(query, tuple(params)).fetchone()[0])
    return page_result(total=total, page=pagination, rows=rows)
