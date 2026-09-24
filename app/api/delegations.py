from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Response

from app.api.dependencies import current_principal
from app.core.clock import from_storage, to_storage, utc_now
from app.core.errors import ValidationError
from app.core.pagination import Page, page_result
from app.core.security import Principal
from app.database import get_connection, transaction
from app.schemas.identity import DelegationCreate, DelegationRevokeRequest
from app.services.delegation import DelegationService

router = APIRouter(prefix="/api/delegations", tags=["代理授权"])


@router.post("", status_code=201)
def create_delegation(data: DelegationCreate, response: Response, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        grant, created = DelegationService(connection).create(principal, data.model_dump())
    if not created:
        response.status_code = 200
    return grant


@router.get("")
def list_delegations(
    grantor_user_id: int | None = None,
    delegate_user_id: int | None = None,
    status: str | None = None,
    active_at: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    if status is not None and status not in {"active", "revoked"}:
        raise ValidationError("状态只能是 active 或 revoked")
    moment = None
    if active_at:
        try:
            parsed_active = from_storage(active_at)
        except ValueError:
            parsed_active = None
        if parsed_active is None:
            raise ValidationError("active_at 时间格式无效")
        moment = to_storage(parsed_active)
    pagination = Page(page, size)
    rows, total = DelegationService(get_connection()).list(
        principal,
        grantor_user_id=grantor_user_id,
        delegate_user_id=delegate_user_id,
        status=status,
        active_at=moment,
        limit=size,
        offset=pagination.offset,
    )
    return page_result(total=total, page=pagination, rows=rows)


@router.get("/activity")
def delegation_activity(
    moment: str | None = None,
    grantor_user_id: int | None = None,
    delegate_user_id: int | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    try:
        parsed = from_storage(moment) if moment else utc_now()
    except ValueError:
        parsed = None
    if parsed is None:
        raise ValidationError("moment 时间格式无效")
    pagination = Page(page, size)
    result = DelegationService(get_connection()).activity(
        principal,
        moment_text=to_storage(parsed),
        grantor_user_id=grantor_user_id,
        delegate_user_id=delegate_user_id,
        limit=size,
        offset=pagination.offset,
    )
    return {
        "moment": result["moment"],
        "total": result["total"],
        "page": pagination.number,
        "size": pagination.size,
        "pages": (result["total"] + pagination.size - 1) // pagination.size,
        "data": result["data"],
    }


@router.get("/{delegation_id}")
def get_delegation(delegation_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("delegations.read")
    return DelegationService(get_connection()).detail(delegation_id)


@router.post("/{delegation_id}/revoke")
def revoke_delegation(delegation_id: int, data: DelegationRevokeRequest, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return DelegationService(connection).revoke(principal, delegation_id, data.reason)
