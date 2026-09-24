from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from app.core.clock import Clock, SystemClock, to_storage
from app.core.security import ActiveDelegation, Principal
from app.repositories.audit import AuditRepository


@dataclass(slots=True)
class AuditContext:
    actor_user_id: int | None
    actor_name: str
    correlation_id: str | None = None
    delegations: tuple[ActiveDelegation, ...] = field(default_factory=tuple)

    @classmethod
    def from_principal(cls, principal: Principal) -> "AuditContext":
        return cls(principal.user_id, principal.display_name, delegations=principal.delegations)


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
        merged = dict(metadata or {})
        if context.delegations:
            merged["delegations"] = [
                {
                    "grant_id": delegation.grant_id,
                    "grantor_user_id": delegation.grantor_user_id,
                    "grantor_name": delegation.grantor_name,
                    "department_id": delegation.department_id,
                }
                for delegation in context.delegations
            ]
        return self.repository.append(
            actor_user_id=context.actor_user_id,
            actor_name=context.actor_name,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            before=before,
            after=after,
            metadata=merged,
            correlation_id=context.correlation_id,
            created_at=to_storage(self.clock.now()),
        )
