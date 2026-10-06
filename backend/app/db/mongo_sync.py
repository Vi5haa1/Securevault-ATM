import logging
import datetime
import decimal
from typing import Dict, Any, List
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pymongo import MongoClient

from app.core.config import settings
from app.db.models.models import (
    User, Customer, Account, Card, Atm, AtmSensor,
    Transaction, SecurityEvent, Alert, Incident,
    AuditLog, DetectionRule, ThreatIndicator
)

logger = logging.getLogger("securevault.mongo_sync")


def serialize_model(instance: Any) -> Dict[str, Any]:
    """Converts a SQLAlchemy model instance into a clean BSON dictionary for MongoDB."""
    data = {}
    for column in instance.__table__.columns:
        val = getattr(instance, column.name)
        if isinstance(val, (datetime.datetime, datetime.date)):
            val = val.isoformat()
        elif isinstance(val, decimal.Decimal):
            val = float(val)
        elif hasattr(val, "value"):  # Enums
            val = val.value
        data[column.name] = val
    if "id" in data:
        data["_id"] = str(data["id"])
    return data


def sync_all_to_mongodb() -> Dict[str, Any]:
    """
    Reads all core entities from SQLite and synchronizes them
    into local MongoDB collections in MongoDB Compass database 'securevault_db'.
    """
    try:
        client = MongoClient(settings.MONGODB_URL, serverSelectionTimeoutMS=3000)
        db = client[settings.MONGODB_DB_NAME]

        sync_url = settings.DATABASE_URL.replace("+aiosqlite", "")
        sync_engine = create_engine(sync_url)
        SyncSession = sessionmaker(bind=sync_engine)

        synced_counts = {}

        with SyncSession() as session:
            # 1. Users
            users = session.query(User).all()
            if users:
                db.users.drop()
                docs = [serialize_model(u) for u in users]
                db.users.insert_many(docs)
                synced_counts["users"] = len(docs)

            # 2. Customers
            customers = session.query(Customer).all()
            if customers:
                db.customers.drop()
                docs = [serialize_model(c) for c in customers]
                db.customers.insert_many(docs)
                synced_counts["customers"] = len(docs)

            # 3. Accounts
            accounts = session.query(Account).all()
            if accounts:
                db.accounts.drop()
                docs = [serialize_model(a) for a in accounts]
                db.accounts.insert_many(docs)
                synced_counts["accounts"] = len(docs)

            # 4. Cards
            cards = session.query(Card).all()
            if cards:
                db.cards.drop()
                docs = [serialize_model(cd) for cd in cards]
                db.cards.insert_many(docs)
                synced_counts["cards"] = len(docs)

            # 5. ATMs
            atms = session.query(Atm).all()
            if atms:
                db.atms.drop()
                docs = [serialize_model(atm) for atm in atms]
                db.atms.insert_many(docs)
                synced_counts["atms"] = len(docs)

            # 6. ATM Sensors
            sensors = session.query(AtmSensor).all()
            if sensors:
                db.atm_sensors.drop()
                docs = [serialize_model(s) for s in sensors]
                db.atm_sensors.insert_many(docs)
                synced_counts["atm_sensors"] = len(docs)

            # 7. Transactions
            txns = session.query(Transaction).all()
            if txns:
                db.transactions.drop()
                docs = [serialize_model(t) for t in txns]
                db.transactions.insert_many(docs)
                synced_counts["transactions"] = len(docs)

            # 8. Security Events
            events = session.query(SecurityEvent).all()
            if events:
                db.security_events.drop()
                docs = [serialize_model(e) for e in events]
                db.security_events.insert_many(docs)
                synced_counts["security_events"] = len(docs)

            # 9. Alerts
            alerts = session.query(Alert).all()
            if alerts:
                db.alerts.drop()
                docs = [serialize_model(al) for al in alerts]
                db.alerts.insert_many(docs)
                synced_counts["alerts"] = len(docs)

            # 10. Incidents
            incidents = session.query(Incident).all()
            if incidents:
                db.incidents.drop()
                docs = [serialize_model(inc) for inc in incidents]
                db.incidents.insert_many(docs)
                synced_counts["incidents"] = len(docs)

            # 11. Audit Logs
            audit_logs = session.query(AuditLog).all()
            if audit_logs:
                db.audit_logs.drop()
                docs = [serialize_model(lg) for lg in audit_logs]
                db.audit_logs.insert_many(docs)
                synced_counts["audit_logs"] = len(docs)

            # 12. Detection Rules
            rules = session.query(DetectionRule).all()
            if rules:
                db.detection_rules.drop()
                docs = [serialize_model(r) for r in rules]
                db.detection_rules.insert_many(docs)
                synced_counts["detection_rules"] = len(docs)

            # 13. Threat Indicators
            indicators = session.query(ThreatIndicator).all()
            if indicators:
                db.threat_indicators.drop()
                docs = [serialize_model(ti) for ti in indicators]
                db.threat_indicators.insert_many(docs)
                synced_counts["threat_indicators"] = len(docs)

        logger.info(f"MongoDB Sync successfully completed! Synced collections: {synced_counts}")
        return {
            "success": True,
            "status": "SYNCED",
            "database": settings.MONGODB_DB_NAME,
            "connection_url": settings.MONGODB_URL,
            "synced_counts": synced_counts,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to sync data to MongoDB: {e}")
        return {
            "success": False,
            "status": "ERROR",
            "error": str(e)
        }
