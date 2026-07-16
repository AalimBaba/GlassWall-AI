from datetime import datetime, timezone

from backend.app.watermark import timestamp_bucket, watermark_fingerprint


def test_watermark_fingerprint_is_stable_within_timestamp_bucket() -> None:
    first = watermark_fingerprint("org", "workspace", "device", "session", "incident", datetime(2026, 7, 16, 10, 0, tzinfo=timezone.utc))
    second = watermark_fingerprint("org", "workspace", "device", "session", "incident", datetime(2026, 7, 16, 10, 4, tzinfo=timezone.utc))
    assert first == second
    assert len(first) == 64


def test_timestamp_bucket_changes_over_time() -> None:
    assert timestamp_bucket(datetime(2026, 7, 16, 10, 0, tzinfo=timezone.utc)) != timestamp_bucket(datetime(2026, 7, 16, 10, 6, tzinfo=timezone.utc))
