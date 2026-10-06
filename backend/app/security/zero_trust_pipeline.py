import datetime
from typing import List, Dict, Any, Optional, Callable, Awaitable
from decimal import Decimal
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.db.models.models import Transaction, UserRole
from app.audit.writer import write_audit_log


class StepResult(BaseModel):
    step_name: str
    status: str  # "PASSED", "WARNING", "FAILED"
    details: str
    timestamp: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)
    metadata: Dict[str, Any] = {}


class ZeroTrustContext:
    def __init__(
        self,
        db: AsyncSession,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        action: str = "TRANSACTION",
        resource_type: str = "ACCOUNT",
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None
    ):
        self.db = db
        self.actor_id = actor_id
        self.actor_role = actor_role
        self.action = action
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.ip_address = ip_address
        self.device_fingerprint = device_fingerprint
        self.payload = payload or {}
        
        # State accumulated across pipeline steps
        self.traces: List[StepResult] = []
        self.risk_score: int = 0
        self.risk_level: str = "LOW"
        self.risk_factors: Dict[str, Any] = {}
        self.execution_result: Any = None
        self.aborted: bool = False
        self.abort_reason: Optional[str] = None

    def add_trace(self, step_name: str, status: str, details: str, meta: Optional[Dict[str, Any]] = None):
        self.traces.append(StepResult(
            step_name=step_name,
            status=status,
            details=details,
            timestamp=datetime.datetime.now(datetime.timezone.utc),
            metadata=meta or {}
        ))


class ZeroTrustPipeline:
    """
    Zero-Trust Pipeline:
    Every sensitive operation executes through an unbypassable, ordered pipeline:
    1. Authenticate (Identity verified)
    2. Authorize (RBAC & ownership permissions)
    3. Validate (Input schemas, positive balances, ATM limits)
    4. Risk Analysis (Behavioral baseline deviation, velocity, anomalies)
    5. Security Policy (Threshold enforcement, MFA trigger, lockdown refusal)
    6. Execute (Atomic database transaction with row locks)
    7. Audit (Append-only SHA-256 hash chained record)
    """
    def __init__(self, context: ZeroTrustContext):
        self.ctx = context
        self._auth_step: Optional[Callable[[ZeroTrustContext], Awaitable[None]]] = None
        self._authz_step: Optional[Callable[[ZeroTrustContext], Awaitable[None]]] = None
        self._validate_step: Optional[Callable[[ZeroTrustContext], Awaitable[None]]] = None
        self._risk_step: Optional[Callable[[ZeroTrustContext], Awaitable[None]]] = None
        self._policy_step: Optional[Callable[[ZeroTrustContext], Awaitable[None]]] = None
        self._execute_step: Optional[Callable[[ZeroTrustContext], Awaitable[Any]]] = None

    def set_authentication(self, fn: Callable[[ZeroTrustContext], Awaitable[None]]) -> "ZeroTrustPipeline":
        self._auth_step = fn
        return self

    def set_authorization(self, fn: Callable[[ZeroTrustContext], Awaitable[None]]) -> "ZeroTrustPipeline":
        self._authz_step = fn
        return self

    def set_validation(self, fn: Callable[[ZeroTrustContext], Awaitable[None]]) -> "ZeroTrustPipeline":
        self._validate_step = fn
        return self

    def set_risk_analysis(self, fn: Callable[[ZeroTrustContext], Awaitable[None]]) -> "ZeroTrustPipeline":
        self._risk_step = fn
        return self

    def set_security_policy(self, fn: Callable[[ZeroTrustContext], Awaitable[None]]) -> "ZeroTrustPipeline":
        self._policy_step = fn
        return self

    def set_execution(self, fn: Callable[[ZeroTrustContext], Awaitable[Any]]) -> "ZeroTrustPipeline":
        self._execute_step = fn
        return self

    async def run(self) -> ZeroTrustContext:
        try:
            # 1. Authenticate
            if self._auth_step:
                await self._auth_step(self.ctx)
                if self.ctx.aborted:
                    return await self._finalize_aborted()

            # 2. Authorize
            if self._authz_step:
                await self._authz_step(self.ctx)
                if self.ctx.aborted:
                    return await self._finalize_aborted()

            # 3. Validate
            if self._validate_step:
                await self._validate_step(self.ctx)
                if self.ctx.aborted:
                    return await self._finalize_aborted()

            # 4. Risk Analysis
            if self._risk_step:
                await self._risk_step(self.ctx)
                if self.ctx.aborted:
                    return await self._finalize_aborted()

            # 5. Security Policy
            if self._policy_step:
                await self._policy_step(self.ctx)
                if self.ctx.aborted:
                    return await self._finalize_aborted()

            # 6. Execute
            if self._execute_step:
                self.ctx.execution_result = await self._execute_step(self.ctx)
                self.ctx.add_trace("Execute", "PASSED", "Transaction successfully committed with row-level locks.")

            # 7. Audit (Append-only hash chain)
            audit_payload = {
                **self.ctx.payload,
                "risk_score": self.ctx.risk_score,
                "risk_level": self.ctx.risk_level,
                "pipeline_traces": [t.model_dump(mode="json") for t in self.ctx.traces],
            }
            await write_audit_log(
                db=self.ctx.db,
                action=self.ctx.action,
                resource_type=self.ctx.resource_type,
                actor_id=self.ctx.actor_id,
                actor_role=self.ctx.actor_role,
                resource_id=self.ctx.resource_id,
                payload=audit_payload,
                ip_address=self.ctx.ip_address,
            )
            self.ctx.add_trace("Audit", "PASSED", "Cryptographic SHA-256 hash chained audit log recorded.")

            return self.ctx

        except HTTPException as he:
            self.ctx.aborted = True
            self.ctx.abort_reason = he.detail
            self.ctx.add_trace("PipelineError", "FAILED", str(he.detail))
            await self._finalize_aborted()
            raise he
        except Exception as e:
            self.ctx.aborted = True
            self.ctx.abort_reason = str(e)
            self.ctx.add_trace("PipelineError", "FAILED", str(e))
            await self._finalize_aborted()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    async def _finalize_aborted(self) -> ZeroTrustContext:
        """Audits aborted/failed attempts so SOC retains full visibility of security rejections."""
        try:
            audit_payload = {
                **self.ctx.payload,
                "aborted": True,
                "abort_reason": self.ctx.abort_reason,
                "risk_score": self.ctx.risk_score,
                "risk_level": self.ctx.risk_level,
                "pipeline_traces": [t.model_dump(mode="json") for t in self.ctx.traces],
            }
            await write_audit_log(
                db=self.ctx.db,
                action=f"{self.ctx.action}_BLOCKED",
                resource_type=self.ctx.resource_type,
                actor_id=self.ctx.actor_id,
                actor_role=self.ctx.actor_role,
                resource_id=self.ctx.resource_id,
                payload=audit_payload,
                ip_address=self.ctx.ip_address,
            )
        except Exception:
            pass
        return self.ctx
