from __future__ import annotations

import hashlib
from datetime import datetime, timezone


def timestamp_bucket(timestamp: datetime, bucket_seconds: int = 300) -> int:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return int(timestamp.timestamp() // bucket_seconds)


def watermark_fingerprint(
    organization_id: str,
    workspace_id: str,
    device_id: str,
    session_id: str,
    incident_id: str | None,
    timestamp: datetime,
) -> str:
    bucket = timestamp_bucket(timestamp)
    material = "|".join([organization_id, workspace_id, device_id, session_id, incident_id or "no-incident", str(bucket)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
