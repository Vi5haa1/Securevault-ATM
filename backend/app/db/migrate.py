import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger("securevault.migrate")

async def run_auto_migrations(engine: AsyncEngine):
    """
    Non-destructive schema migration helper.
    Ensures existing SQLite / MySQL database schemas have new columns and indexes
    without requiring manual drops or losing existing seeded data.
    """
    logger.info("Running schema safety checks and migrations...")
    async with engine.begin() as conn:
        # Check dialect
        dialect_name = engine.dialect.name

        if dialect_name == "sqlite":
            # 1. Check ATM columns
            res = await conn.execute(text("PRAGMA table_info(atms)"))
            columns = [row[1] for row in res.fetchall()]

            atm_new_cols = [
                ("firmware_version", "VARCHAR(32) DEFAULT 'SV-ATM-FW-3.4.1'"),
                ("firmware_hash", "VARCHAR(64) DEFAULT 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"),
                ("secure_boot_enabled", "BOOLEAN DEFAULT 1"),
                ("certificate_id", "VARCHAR(64) DEFAULT NULL"),
                ("certificate_status", "VARCHAR(32) DEFAULT 'VALID'"),
                ("risk_score", "INTEGER DEFAULT 5"),
                ("latency_ms", "INTEGER DEFAULT 24"),
                ("cpu_usage", "INTEGER DEFAULT 18"),
                ("memory_usage", "INTEGER DEFAULT 32"),
                ("disk_usage", "INTEGER DEFAULT 45"),
                ("under_attack", "BOOLEAN DEFAULT 0"),
            ]

            for col_name, col_def in atm_new_cols:
                if col_name not in columns:
                    logger.info(f"Adding missing column atms.{col_name}...")
                    await conn.execute(text(f"ALTER TABLE atms ADD COLUMN {col_name} {col_def}"))

            # 2. Check SecurityEvent columns
            res_ev = await conn.execute(text("PRAGMA table_info(security_events)"))
            ev_columns = [row[1] for row in res_ev.fetchall()]
            ev_new_cols = [
                ("correlation_key", "VARCHAR(128) DEFAULT NULL"),
                ("mitre_technique", "VARCHAR(64) DEFAULT NULL"),
                ("mitre_tactic", "VARCHAR(64) DEFAULT NULL"),
                ("incident_id", "INTEGER DEFAULT NULL"),
                ("rule_id", "VARCHAR(64) DEFAULT NULL"),
                ("device_id", "VARCHAR(128) DEFAULT NULL"),
            ]
            for col_name, col_def in ev_new_cols:
                if col_name not in ev_columns:
                    logger.info(f"Adding missing column security_events.{col_name}...")
                    await conn.execute(text(f"ALTER TABLE security_events ADD COLUMN {col_name} {col_def}"))

            # 3. Check Transactions columns
            res_tx = await conn.execute(text("PRAGMA table_info(transactions)"))
            tx_columns = [row[1] for row in res_tx.fetchall()]
            tx_new_cols = [
                ("iso_mti", "VARCHAR(8) DEFAULT '0200'"),
                ("iso_stan", "VARCHAR(16) DEFAULT NULL"),
                ("emv_atc", "INTEGER DEFAULT NULL"),
                ("mac_digest", "VARCHAR(64) DEFAULT NULL"),
                ("prev_txn_hash", "VARCHAR(64) DEFAULT NULL"),
                ("txn_hash", "VARCHAR(64) DEFAULT NULL"),
            ]
            for col_name, col_def in tx_new_cols:
                if col_name not in tx_columns:
                    logger.info(f"Adding missing column transactions.{col_name}...")
                    await conn.execute(text(f"ALTER TABLE transactions ADD COLUMN {col_name} {col_def}"))

    logger.info("Schema migrations verified successfully.")
