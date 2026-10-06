import json
from decimal import Decimal
from typing import Any
import datetime


class AuditJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for audit payloads ensuring canonical representation."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Decimal):
            return str(obj)
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        return super().default(obj)


def canonical_json(data: Any) -> str:
    """Produces deterministic, canonical JSON with sorted keys and compact delimiters."""
    if data is None:
        return "{}"
    return json.dumps(data, cls=AuditJSONEncoder, sort_keys=True, separators=(',', ':'))
