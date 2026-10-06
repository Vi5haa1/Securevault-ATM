import logging
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.models.models import DetectionRule, SeverityLevel, ThreatIndicator

logger = logging.getLogger("securevault.seed_rules")

DEFAULT_DETECTION_RULES = [
    {
        "rule_id": "RULE-SV-001",
        "name": "Multiple Failed PIN Attempts (Brute Force)",
        "description": "Triggered when 5 or more consecutive invalid PIN entries occur within 5 minutes on the same card or terminal.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["FAILED_PIN", "FAILED_PIN_ATTEMPT"],
        "conditions": {"field": "count", "op": ">=", "threshold": 5, "window_seconds": 300, "group_by": "card_id"},
        "actions": ["LOCK_ACCOUNT", "LOCK_CARD", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 60,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
    },
    {
        "rule_id": "RULE-SV-002",
        "name": "High-Value Transaction Anomaly",
        "description": "Triggered when a requested cash withdrawal exceeds 4x the customer's typical statistical baseline.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["SUSPICIOUS_TXN", "LARGE_WITHDRAWAL"],
        "conditions": {"field": "risk_score", "op": ">=", "threshold": 70, "baseline_multiplier": 4.0},
        "actions": ["REQUIRE_MFA", "INCREASE_RISK", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 30,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078 - Valid Accounts",
    },
    {
        "rule_id": "RULE-SV-003",
        "name": "ATM Physical Tamper Breach",
        "description": "Zero-tolerance alarm triggered when physical cabinet, door, or tilt sensors indicate chassis breach.",
        "severity": SeverityLevel.CRITICAL,
        "event_types": ["ATM_TAMPER", "ATM_PHYSICAL_TAMPER"],
        "conditions": {"field": "sensor_state", "op": "==", "value": "ALERT"},
        "actions": ["LOCKDOWN_ATM", "TERMINATE_SESSIONS", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 0,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1200 - Hardware Additions",
    },
    {
        "rule_id": "RULE-SV-004",
        "name": "API Rate Limit & Burst Abuse",
        "description": "Triggered when incoming HTTP transaction requests from a single client IP exceed maximum threshold.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["API_RATE_LIMIT", "API_ABUSE"],
        "conditions": {"field": "count", "op": ">=", "threshold": 50, "window_seconds": 5},
        "actions": ["BLOCK_REQUEST", "CREATE_ALERT", "NOTIFY_SOC"],
        "cooldown_seconds": 120,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499 - Endpoint DoS",
    },
    {
        "rule_id": "RULE-SV-005",
        "name": "OAuth / Refresh Token Replay Attempt",
        "description": "Detects reuse of an already-invalidated refresh token. Executes automatic token family revocation.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["TOKEN_REPLAY", "SESSION_ABUSE"],
        "conditions": {"field": "immediate", "op": "==", "value": True},
        "actions": ["REVOKE_TOKEN_FAMILY", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 60,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1550 - Alternate Auth Material",
    },
    {
        "rule_id": "RULE-SV-006",
        "name": "Unauthorized Privilege Escalation Probe",
        "description": "Detects unprivileged customer or operator roles attempting to access administrative endpoints.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["PRIVILEGE_ESCALATION", "UNAUTHORIZED_ACCESS"],
        "conditions": {"field": "immediate", "op": "==", "value": True},
        "actions": ["BLOCK_REQUEST", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 60,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078 - Valid Accounts",
    },
    {
        "rule_id": "RULE-SV-007",
        "name": "ATM Firmware Cryptographic Hash Failure",
        "description": "Triggered during secure boot or periodic agent heartbeat when firmware manifest SHA-256 does not match signed gold image.",
        "severity": SeverityLevel.CRITICAL,
        "event_types": ["FIRMWARE_TAMPER"],
        "conditions": {"field": "immediate", "op": "==", "value": True},
        "actions": ["LOCKDOWN_ATM", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 0,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1542 - Pre-OS Boot",
    },
    {
        "rule_id": "RULE-SV-008",
        "name": "ATM mTLS Client Certificate Expired or Revoked",
        "description": "Triggered when an ATM terminal attempts to establish an mTLS session using an invalid or revoked X.509 certificate.",
        "severity": SeverityLevel.CRITICAL,
        "event_types": ["CERT_FAILURE"],
        "conditions": {"field": "immediate", "op": "==", "value": True},
        "actions": ["REVOKE_CERT_SESSION", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 60,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1556 - Modify Auth Process",
    },
    {
        "rule_id": "RULE-SV-009",
        "name": "Duplicate Transaction Replay (Idempotency Collision)",
        "description": "Detects repeated submission of identical transaction payload, STAN, or nonce within replay window.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["DUPLICATE_TXN", "REPLAY_ATTEMPT"],
        "conditions": {"field": "immediate", "op": "==", "value": True},
        "actions": ["BLOCK_REQUEST", "CREATE_ALERT", "NOTIFY_SOC"],
        "cooldown_seconds": 30,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1550 - Alternate Auth Material",
    },
    {
        "rule_id": "RULE-SV-010",
        "name": "Impossible Travel Velocity Anomaly",
        "description": "Detects transactions on the same account across physically distant cities in an unfeasible timeframe.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["IMPOSSIBLE_TRAVEL"],
        "conditions": {"field": "risk_score", "op": ">=", "threshold": 75},
        "actions": ["REQUIRE_MFA", "CREATE_ALERT", "CREATE_INCIDENT", "NOTIFY_SOC"],
        "cooldown_seconds": 300,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1078.004 - Cloud Accounts",
    },
    {
        "rule_id": "RULE-SV-011",
        "name": "Known Malicious Threat Actor IP Hit",
        "description": "Correlates request client IP against offline synthetic threat intelligence feed of compromised relays and botnets.",
        "severity": SeverityLevel.HIGH,
        "event_types": ["MALICIOUS_IP"],
        "conditions": {"field": "immediate", "op": "==", "value": True},
        "actions": ["INCREASE_RISK", "CREATE_ALERT", "NOTIFY_SOC"],
        "cooldown_seconds": 60,
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071 - Application Protocol",
    },
    {
        "rule_id": "RULE-SV-012",
        "name": "ATM Network Disconnection / Heartbeat Timeout",
        "description": "Detects missed heartbeats exceeding 90 seconds. Flags terminal as OFFLINE and raises network incident.",
        "severity": SeverityLevel.MEDIUM,
        "event_types": ["NETWORK_TIMEOUT"],
        "conditions": {"field": "heartbeat_lag_seconds", "op": ">=", "threshold": 90},
        "actions": ["MARK_ATM_OFFLINE", "CREATE_ALERT", "NOTIFY_SOC"],
        "cooldown_seconds": 180,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498 - Network DoS",
    }
]

DEFAULT_THREAT_INDICATORS = [
    {"type": "IP", "value": "198.51.100.22", "category": "API_RATE_ABUSER", "confidence": 95, "severity": SeverityLevel.HIGH, "tags": ["automated-scanner", "denial-of-service"]},
    {"type": "IP", "value": "198.51.100.45", "category": "UNAUTHORIZED_ADMIN_PROBER", "confidence": 90, "severity": SeverityLevel.HIGH, "tags": ["credential-stuffing", "privilege-escalation"]},
    {"type": "IP", "value": "203.0.113.88", "category": "SKIMMER_RELAY_NODE", "confidence": 88, "severity": SeverityLevel.CRITICAL, "tags": ["card-skimming", "pos-malware"]},
    {"type": "IP", "value": "192.0.2.14", "category": "TOR_EXIT_NODE", "confidence": 75, "severity": SeverityLevel.MEDIUM, "tags": ["anonymization", "suspicious-proxy"]},
    {"type": "IP", "value": "198.51.100.99", "category": "DISTRIBUTED_BRUTE_FORCE_BOTNET", "confidence": 92, "severity": SeverityLevel.HIGH, "tags": ["pin-harvesting", "botnet"]},
    {"type": "DOMAIN", "value": "c2-relay.synthetic-threat.net", "category": "ATM_MALWARE_C2", "confidence": 99, "severity": SeverityLevel.CRITICAL, "tags": ["blackbox-attack", "command-and-control"]},
]

async def seed_rules_and_indicators(db: AsyncSession):
    """Seeds default detection rules and threat intelligence indicators if they don't exist."""
    # 1. Detection Rules
    for r in DEFAULT_DETECTION_RULES:
        stmt = select(DetectionRule).where(DetectionRule.rule_id == r["rule_id"])
        res = await db.execute(stmt)
        if not res.scalar_one_or_none():
            rule = DetectionRule(
                rule_id=r["rule_id"],
                name=r["name"],
                description=r["description"],
                enabled=True,
                severity=r["severity"],
                event_types=r["event_types"],
                conditions=r["conditions"],
                actions=r["actions"],
                cooldown_seconds=r["cooldown_seconds"],
                mitre_tactic=r["mitre_tactic"],
                mitre_technique=r["mitre_technique"],
                version=1,
                hit_count=0,
                updated_by="SYSTEM"
            )
            db.add(rule)

    # 2. Threat Indicators
    for ti in DEFAULT_THREAT_INDICATORS:
        stmt_ti = select(ThreatIndicator).where(ThreatIndicator.value == ti["value"])
        res_ti = await db.execute(stmt_ti)
        if not res_ti.scalar_one_or_none():
            ind = ThreatIndicator(
                indicator_type=ti["type"],
                value=ti["value"],
                threat_category=ti["category"],
                confidence=ti["confidence"],
                severity=ti["severity"],
                first_seen=datetime.datetime.now(datetime.timezone.utc),
                last_seen=datetime.datetime.now(datetime.timezone.utc),
                is_active=True,
                tags=ti["tags"]
            )
            db.add(ind)

    await db.commit()
    logger.info("Default detection rules and threat intelligence indicators seeded successfully.")
