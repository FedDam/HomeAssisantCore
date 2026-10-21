"""Tests for the Cloud Bridge connection helpers."""

from homeassistant.components.cloud_bridge.cloud_client import backoff_delay
from homeassistant.components.cloud_bridge.const import (
    RECONNECT_MAX_DELAY,
    RECONNECT_MIN_DELAY,
)


def test_backoff_delay_grows_with_jitter_and_cap() -> None:
    """Test reconnection delays are exponential, jittered and capped."""
    first = [backoff_delay(0) for _ in range(50)]
    late = [backoff_delay(40) for _ in range(50)]

    assert all(
        RECONNECT_MIN_DELAY / 2 <= delay <= RECONNECT_MIN_DELAY for delay in first
    )
    assert all(
        RECONNECT_MAX_DELAY / 2 <= delay <= RECONNECT_MAX_DELAY for delay in late
    )
    assert len(set(late)) > 1
