import os
import json
import asyncio
import datetime
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.config import settings
from app.db.models.models import AuditLog
from app.audit.hash_chain import compute_audit_hash

# In-memory lock to guarantee strict sequence ordering across concurrent writes
_audit_lock = asyncio.Lock()


async def write_audit_log(
    db: AsyncSession,
    action: str,
    resource_type: str,
    actor_id: Optional[str] = None,
    actor_role: Optional[str] = None,
    resource_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """
    Appends an immutable, hash-chained record to the audit table and writes a CEF/JSON SIEM record.
    Uses an asyncio lock and database sequence lookup to ensure sequence continuity.
    """
    async with _audit_lock:
        if payload is None:
            payload = {}

        # Fetch last audit record to chain previous hash and sequence
        stmt = select(AuditLog).order_by(AuditLog.sequence_no.desc()).limit(1)
        res = await db.execute(stmt)
        last_log = res.scalar_one_or_none()

        if last_log is None:
            sequence_no = 1
            prev_hash = settings.AUDIT_GENESIS_HASH
        else:
            sequence_no = last_log.sequence_no + 1
            prev_hash = last_log.hash

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        timestamp_str = now_utc.strftime("%Y-%m-%dT%H:%M:%S")

        record_hash = compute_audit_hash(
            prev_hash=prev_hash,
            sequence_no=sequence_no,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
            timestamp_str=timestamp_str,
        )

        audit_entry = AuditLog(
            sequence_no=sequence_no,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
            ip_address=ip_address,
            created_at=now_utc,
            prev_hash=prev_hash,
            hash=record_hash,
        )

        db.add(audit_entry)
        await db.flush()

        # Write to SIEM export file asynchronously without blocking
        _export_to_siem_file(audit_entry, timestamp_str)

        # Synchronize in real-time to local MongoDB Compass collection
        try:
            from app.db.mongodb import mongo_insert_event
            asyncio.create_task(mongo_insert_event("audit_logs", {
                "sequence_no": audit_entry.sequence_no,
                "action": audit_entry.action,
                "actor_id": audit_entry.actor_id,
                "actor_role": audit_entry.actor_role,
                "resource_type": audit_entry.resource_type,
                "resource_id": audit_entry.resource_id,
                "payload": audit_entry.payload,
                "ip_address": audit_entry.ip_address,
                "created_at": timestamp_str,
                "prev_hash": audit_entry.prev_hash,
                "hash": audit_entry.hash
            }))
        except Exception:
            pass

        return audit_entry


def _export_to_siem_file(log_entry: AuditLog, timestamp_str: str) -> None:
    """Appends CEF/JSON format log to SIEM export file for ingestion demos."""
    try:
        export_dir = os.path.dirname(settings.SIEM_EXPORT_PATH)
        if export_dir and not os.path.exists(export_dir):
            os.makedirs(export_dir, exist_ok=True)

        siem_record = {
            "@timestamp": timestamp_str,
            "cef_version": "0",
            "device_vendor": "SecureVault",
            "device_product": "ATM-Defense",
            "device_version": "1.0",
            "device_event_class_id": log_entry.action,
            "name": f"Audit: {log_entry.action}",
            "severity": "Informational",
            "sequence_no": log_entry.sequence_no,
            "actor_id": log_entry.actor_id,
            "actor_role": log_entry.actor_role,
            "resource_type": log_entry.resource_type,
            "resource_id": log_entry.resource_id,
            "ip_address": log_entry.ip_address,
            "hash": log_entry.hash,
            "prev_hash": log_entry.prev_hash,
            "payload": log_entry.payload,
        }

        with open(settings.SIEM_EXPORT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(siem_record) + "\n")
    except Exception:
        # Never fail a transaction because SIEM export failed
        pass
