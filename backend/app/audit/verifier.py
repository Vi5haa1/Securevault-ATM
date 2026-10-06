import datetime
from typing import Dict, Any, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.db.models.models import AuditLog
from app.audit.hash_chain import compute_audit_hash


async def verify_audit_chain(db: AsyncSession) -> Dict[str, Any]:
    """
    Traverses the entire audit log chain sequentially from the genesis block.
    Verifies that:
    1. Every sequence_no is strictly sequential (1, 2, 3...)
    2. The first log's prev_hash matches AUDIT_GENESIS_HASH
    3. Each log's prev_hash exactly matches the prior log's hash
    4. Each log's hash matches the recomputed SHA-256 over its own content
    """
    stmt = select(AuditLog).order_by(AuditLog.sequence_no.asc())
    result = await db.execute(stmt)
    logs = result.scalars().all()

    total_logs = len(logs)
    if total_logs == 0:
        return {
            "total_logs": 0,
            "verified_logs": 0,
            "tampered": False,
            "broken_sequence_no": None,
            "broken_log_id": None,
            "status": "VALID",
            "details": "Audit log chain is empty. Genesis seed intact.",
            "verified_at": datetime.datetime.now(datetime.timezone.utc),
        }

    expected_prev_hash = settings.AUDIT_GENESIS_HASH
    expected_sequence = 1
    verified_count = 0

    for log in logs:
        # Check sequence continuity
        if log.sequence_no != expected_sequence:
            return {
                "total_logs": total_logs,
                "verified_logs": verified_count,
                "tampered": True,
                "broken_sequence_no": log.sequence_no,
                "broken_log_id": log.id,
                "status": "BROKEN",
                "details": f"Broken sequence at record ID {log.id}. Expected seq {expected_sequence}, found {log.sequence_no}.",
                "verified_at": datetime.datetime.now(datetime.timezone.utc),
            }

        # Check prev_hash pointer integrity
        if log.prev_hash != expected_prev_hash:
            return {
                "total_logs": total_logs,
                "verified_logs": verified_count,
                "tampered": True,
                "broken_sequence_no": log.sequence_no,
                "broken_log_id": log.id,
                "status": "BROKEN",
                "details": f"Cryptographic link broken at record #{log.sequence_no} (ID {log.id}). Prev hash does not match preceding record's digest.",
                "verified_at": datetime.datetime.now(datetime.timezone.utc),
            }

        # Recompute hash
        timestamp_str = log.created_at.strftime("%Y-%m-%dT%H:%M:%S")
        computed = compute_audit_hash(
            prev_hash=log.prev_hash,
            sequence_no=log.sequence_no,
            actor_id=log.actor_id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            payload=log.payload,
            timestamp_str=timestamp_str,
        )

        if log.hash != computed:
            return {
                "total_logs": total_logs,
                "verified_logs": verified_count,
                "tampered": True,
                "broken_sequence_no": log.sequence_no,
                "broken_log_id": log.id,
                "status": "BROKEN",
                "details": f"Payload tampering detected at record #{log.sequence_no} (ID {log.id}). Stored hash {log.hash[:16]}... does not match recalculated digest {computed[:16]}...",
                "verified_at": datetime.datetime.now(datetime.timezone.utc),
            }

        expected_prev_hash = log.hash
        expected_sequence += 1
        verified_count += 1

    return {
        "total_logs": total_logs,
        "verified_logs": verified_count,
        "tampered": False,
        "broken_sequence_no": None,
        "broken_log_id": None,
        "status": "VALID",
        "details": f"All {total_logs} audit log entries cryptographically verified against SHA-256 hash chain.",
        "verified_at": datetime.datetime.now(datetime.timezone.utc),
    }
