from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from app.core.clock import Clock, SystemClock, to_storage
from app.core.security import Principal
from app.repositories.audit import AuditRepository


@dataclass(slots=True)
class AuditContext:
    actor_user_id: int | None
    actor_name: str
    correlation_id: str | None = None
    on_behalf_of_user_id: int | None = None
    on_behalf_of_name: str | None = None
    delegation_id: int | None = None

    @classmethod
    def from_principal(cls, principal: Principal) -> "AuditContext":
        delegation = principal.delegation
        return cls(
            actor_user_id=principal.user_id,
            actor_name=principal.display_name,
            on_behalf_of_user_id=delegation.granter_user_id if delegation else None,
            on_behalf_of_name=delegation.granter_name if delegation else None,
            delegation_id=delegation.delegation_id if delegation else None,
        )


class AuditService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.repository = AuditRepository(connection)
        self.clock = clock or SystemClock()

    def record(
        self,
        context: AuditContext,
        *,
        action: str,
        resource_type: str,
        resource_id: str | int | None = None,
        outcome: str = "success",
        before: dict | None = None,
        after: dict | None = None,
        metadata: dict | None = None,
    ) -> int:
        return self.repository.append(
            actor_user_id=context.actor_user_id,
            actor_name=context.actor_name,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            before=before,
            after=after,
            metadata=metadata,
            correlation_id=context.correlation_id,
            on_behalf_of_user_id=context.on_behalf_of_user_id,
            on_behalf_of_name=context.on_behalf_of_name,
            delegation_id=context.delegation_id,
            created_at=to_storage(self.clock.now()),
        )
