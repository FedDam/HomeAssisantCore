"""Tests for the Cloud Bridge administrator WebSocket API."""

import pytest

from homeassistant.components.cloud_bridge.const import LinkState
from homeassistant.core import HomeAssistant

from .conftest import setup_bridge
from .fake_backend import PAIRING_CODE, FakeBackend

from tests.typing import WebSocketGenerator

COMMANDS = [
    {"type": "cloud_bridge/status"},
    {"type": "cloud_bridge/pair", "pairing_code": PAIRING_CODE},
    {"type": "cloud_bridge/suspend"},
    {"type": "cloud_bridge/resume"},
    {"type": "cloud_bridge/revoke"},
    {"type": "cloud_bridge/reset"},
    {"type": "cloud_bridge/rotate_key"},
    {"type": "cloud_bridge/set_exposed_entities", "entity_ids": []},
]


@pytest.mark.parametrize("message", COMMANDS, ids=[c["type"] for c in COMMANDS])
@pytest.mark.usefixtures("hass_storage")
async def test_commands_require_admin(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    hass_read_only_access_token: str,
    message: dict[str, str],
) -> None:
    """Test a non-administrator cannot use any command."""
    await setup_bridge(hass)
    client = await hass_ws_client(hass, hass_read_only_access_token)

    await client.send_json_auto_id(message)
    response = await client.receive_json()

    assert not response["success"]
    assert response["error"]["code"] == "unauthorized"


@pytest.mark.usefixtures("hass_storage")
async def test_admin_flow(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    fake_backend: FakeBackend,
) -> None:
    """Test pairing, sharing, status and revocation from the API."""
    hass.states.async_set("light.kitchen", "off")
    bridge = await setup_bridge(hass)
    client = await hass_ws_client(hass)

    await client.send_json_auto_id(
        {
            "type": "cloud_bridge/set_exposed_entities",
            "entity_ids": ["light.kitchen"],
        }
    )
    assert (await client.receive_json())["success"]

    await client.send_json_auto_id(
        {
            "type": "cloud_bridge/pair",
            "pairing_code": PAIRING_CODE,
            "cloud_url": fake_backend.url,
        }
    )
    assert (await client.receive_json())["success"]
    await fake_backend.wait_for(lambda: bridge.connected)

    await client.send_json_auto_id({"type": "cloud_bridge/status"})
    status = (await client.receive_json())["result"]
    assert status["identity"]["status"] == "ready"
    assert status["link"]["state"] == LinkState.ACTIVE
    assert status["link"]["installation_id"] == "ha-001"
    assert status["connected"] is True
    assert status["exposed_entities"] == ["light.kitchen"]
    assert "private_key" not in str(status)

    await client.send_json_auto_id({"type": "cloud_bridge/revoke"})
    assert (await client.receive_json())["success"]

    await client.send_json_auto_id({"type": "cloud_bridge/resume"})
    response = await client.receive_json()
    assert response["error"]["code"] == "invalid_state"


@pytest.mark.usefixtures("hass_storage")
async def test_errors_are_reported(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator
) -> None:
    """Test operation errors carry a stable code."""
    await setup_bridge(hass)
    client = await hass_ws_client(hass)

    await client.send_json_auto_id({"type": "cloud_bridge/rotate_key"})
    assert (await client.receive_json())["error"]["code"] == "not_connected"

    await client.send_json_auto_id(
        {
            "type": "cloud_bridge/pair",
            "pairing_code": PAIRING_CODE,
            "cloud_url": "http://cloud.example.com",
        }
    )
    assert (await client.receive_json())["error"]["code"] == "insecure_cloud_url"
