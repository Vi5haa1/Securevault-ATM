import logging
from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import MongoClient
from app.core.config import settings

logger = logging.getLogger("securevault.mongodb")

_motor_client: Optional[AsyncIOMotorClient] = None
_sync_client: Optional[MongoClient] = None


def get_sync_mongo_client() -> MongoClient:
    """Returns a synchronous PyMongo client."""
    global _sync_client
    if _sync_client is None:
        _sync_client = MongoClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=3000
        )
    return _sync_client


def get_motor_client() -> AsyncIOMotorClient:
    """Returns an asynchronous Motor client."""
    global _motor_client
    if _motor_client is None:
        _motor_client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            serverSelectionTimeoutMS=3000
        )
    return _motor_client


def get_mongo_db() -> AsyncIOMotorDatabase:
    """Returns the main SecureVault MongoDB database instance."""
    client = get_motor_client()
    return client[settings.MONGODB_DB_NAME]


async def check_mongo_connection() -> Dict[str, Any]:
    """Checks MongoDB connection health and returns database info."""
    try:
        client = get_motor_client()
        await client.admin.command("ping")
        db = get_mongo_db()
        collections = await db.list_collection_names()
        return {
            "connected": True,
            "url": settings.MONGODB_URL,
            "database": settings.MONGODB_DB_NAME,
            "collections": collections,
            "status": "ONLINE"
        }
    except Exception as e:
        logger.warning(f"MongoDB connection check failed: {e}")
        return {
            "connected": False,
            "url": settings.MONGODB_URL,
            "database": settings.MONGODB_DB_NAME,
            "error": str(e),
            "status": "OFFLINE"
        }


async def mongo_save_document(collection_name: str, doc_id: Any, doc_data: Dict[str, Any]) -> bool:
    """Saves or updates a document in MongoDB collection (upsert)."""
    if not settings.ENABLE_MONGODB_SYNC:
        return False
    try:
        db = get_mongo_db()
        coll = db[collection_name]
        doc_data["_id"] = str(doc_id)
        await coll.replace_one({"_id": str(doc_id)}, doc_data, upsert=True)
        return True
    except Exception as e:
        logger.debug(f"MongoDB sync error on collection '{collection_name}': {e}")
        return False


async def mongo_insert_event(collection_name: str, event_data: Dict[str, Any]) -> bool:
    """Inserts a new event or transaction document into MongoDB."""
    if not settings.ENABLE_MONGODB_SYNC:
        return False
    try:
        db = get_mongo_db()
        coll = db[collection_name]
        await coll.insert_one(event_data)
        return True
    except Exception as e:
        logger.debug(f"MongoDB insert error on collection '{collection_name}': {e}")
        return False
