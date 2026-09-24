from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.pagination import Page
from app.core.security import Principal
from app.database import get_connection, transaction
from app.schemas.identity import DelegationCreate, DelegationRevokeRequest
from app.services.delegation import DelegationService

router = APIRouter(prefix="/api/delegations", tags=["临时代理授权"])


@router.post("", status_code=201)
def create_delegation(data: DelegationCreate, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return DelegationService(connection).create_delegation(principal, data.model_dump())


@router.get("/mine/available")
def my_available_delegations(principal: Principal = Depends(current_principal)) -> dict:
    rows = DelegationService(get_connection()).available_for_agent(principal)
    return {
        "data": rows,
        "active_delegation_id": principal.delegation.delegation_id if principal.delegation else None,
    }


@router.post("/mine/activate/{delegation_id}", status_code=200)
def activate_delegation(delegation_id: int, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return DelegationService(connection).activate(principal, delegation_id)


@router.post("/mine/deactivate")
def deactivate_delegation(principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return DelegationService(connection).deactivate(principal)


@router.get("")
def list_delegations(
    granter_user_id: int | None = None,
    agent_user_id: int | None = None,
    status: str | None = Query(default=None, pattern="^(active|revoked|terminated)$"),
    active_at: str | None = Query(default=None, description="按指定时间点查询仍有效的授权（ISO 时间）"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(current_principal),
) -> dict:
    pagination = Page(page, size)
    service = DelegationService(get_connection())
    result = service.list(
        principal,
        granter_user_id=granter_user_id,
        agent_user_id=agent_user_id,
        status=status,
        active_at=active_at,
        limit=size,
        offset=pagination.offset,
    )
    result["page"] = page
    result["size"] = size
    result["pages"] = (result["total"] + size - 1) // size
    return result


@router.get("/{delegation_id}")
def get_delegation(delegation_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("delegations.read")
    return DelegationService(get_connection()).detail(delegation_id)


@router.post("/{delegation_id}/revoke")
def revoke_delegation(delegation_id: int, data: DelegationRevokeRequest, principal: Principal = Depends(current_principal)) -> dict:
    with transaction(immediate=True) as connection:
        return DelegationService(connection).revoke(principal, delegation_id, data.reason)
