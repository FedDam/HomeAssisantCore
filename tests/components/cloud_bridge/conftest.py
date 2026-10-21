"""Fixtures for the Cloud Bridge tests."""

from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import patch

from aiohttp.test_utils import TestServer
import pytest

from homeassistant.auth.models import User
from homeassistant.components.cloud_bridge.bridge import CloudBridge
from homeassistant.components.cloud_bridge.const import (
    DATA_BRIDGE,
    DOMAIN,
    STORAGE_KEY,
    STORAGE_VERSION,
    SYSTEM_USER_NAME,
)
from homeassistant.const import EVENT_HOMEASSISTANT_FINAL_WRITE
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component

from .fake_backend import PAIRING_CODE, FakeBackend


def identity_record(
    *,
    phase: str | None = None,
    system_user_id: str | None = None,
    nonce: str | None = None,
    disabled: bool = False,
) -> dict[str, Any]:
    """Return a stored identity record."""
    return {
        "version": STORAGE_VERSION,
        "minor_version": 1,
        "key": STORAGE_KEY,
        "data": {
            "phase": phase,
            "system_user_id": system_user_id,
            "nonce": nonce,
            "disabled": disabled,
        },
    }


async def bridge_users(hass: HomeAssistant) -> list[User]:
    """Return all users carrying a Cloud Bridge name."""
    return [
        user
        for user in await hass.auth.async_get_users()
        if user.name is not None and user.name.startswith(SYSTEM_USER_NAME)
    ]


@pytest.fixture
async def fake_backend(socket_enabled: None) -> AsyncGenerator[FakeBackend]:
    """Run a fake backend on 127.0.0.1."""
    backend = FakeBackend()
    server = TestServer(backend.app, host="127.0.0.1")
    await server.start_server()
    backend.url = str(server.make_url("")).rstrip("/")
    yield backend
    await backend.drop_connections()
    await server.close()


@pytest.fixture(autouse=True)
def fast_reconnect() -> Generator[None]:
    """Make reconnection delays short."""
    with patch(
        "homeassistant.components.cloud_bridge.cloud_client.backoff_delay",
        return_value=0.01,
    ):
        yield


async def setup_bridge(hass: HomeAssistant) -> CloudBridge:
    """Set up the integration and return the bridge."""
    assert await async_setup_component(hass, DOMAIN, {})
    await hass.async_block_till_done()
    return hass.data[DATA_BRIDGE]


async def pair_bridge(bridge: CloudBridge, backend: FakeBackend) -> None:
    """Pair with the fake backend and wait for the session."""
    await bridge.async_pair(PAIRING_CODE, backend.url)
    await backend.wait_for(lambda: bridge.connected and bool(backend.sockets))


async def restart_bridge(hass: HomeAssistant, bridge: CloudBridge) -> CloudBridge:
    """Simulate a restart of the bridge using the persisted storage."""
    await bridge.async_stop()
    # Flush delayed writes so the old instance cannot overwrite the new one.
    hass.bus.async_fire(EVENT_HOMEASSISTANT_FINAL_WRITE)
    await hass.async_block_till_done()
    new_bridge = CloudBridge(hass)
    await new_bridge.async_setup()
    hass.data[DATA_BRIDGE] = new_bridge
    await new_bridge.async_start()
    return new_bridge
