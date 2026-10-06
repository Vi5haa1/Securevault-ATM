import hashlib
import datetime
from typing import Dict, Any, Optional
from app.audit.canonical import canonical_json


def compute_audit_hash(
    prev_hash: str,
    sequence_no: int,
    actor_id: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    payload: Dict[str, Any],
    timestamp_str: str,
) -> str:
    """
    Computes a cryptographic SHA-256 hash for an audit log record:
    hash = SHA-256(prev_hash || sequence_no || actor_id || action || resource_type || resource_id || canonical_json(payload) || timestamp)
    """
    actor_str = actor_id or "ANONYMOUS"
    resource_id_str = resource_id or "NONE"
    payload_str = canonical_json(payload)

    chain_input = (
        f"{prev_hash}|"
        f"{sequence_no}|"
        f"{actor_str}|"
        f"{action}|"
        f"{resource_type}|"
        f"{resource_id_str}|"
        f"{payload_str}|"
        f"{timestamp_str}"
    )

    return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
