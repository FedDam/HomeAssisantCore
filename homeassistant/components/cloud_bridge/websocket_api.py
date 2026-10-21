"""Administrator WebSocket commands for the Cloud Bridge.

Every command requires an administrator: pairing, revocation and the choice of
shared entities change what the cloud can do in this home.
"""

from collections.abc import Awaitable
from typing import Any

import probatio

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from .cloud_client import CloudClientError
from .const import DATA_BRIDGE
from .provisioning import LinkError


@callback
def async_register(hass: HomeAssistant) -> None:
    """Register the commands."""
    for handler in (
        ws_status,
        ws_pair,
        ws_suspend,
        ws_resume,
        ws_revoke,
        ws_reset,
        ws_rotate_key,
        ws_set_exposed_entities,
    ):
        websocket_api.async_register_command(hass, handler)


async def _async_run(
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
    operation: Awaitable[None],
) -> None:
    try:
        await operation
    except (LinkError, CloudClientError) as err:
        connection.send_error(msg["id"], err.code, str(err))
        return
    connection.send_result(msg["id"])


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "cloud_bridge/status"})
@callback
def ws_status(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return the bridge status."""
    connection.send_result(msg["id"], hass.data[DATA_BRIDGE].status())


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        probatio.Required("type"): "cloud_bridge/pair",
        probatio.Required("pairing_code"): str,
        probatio.Optional("cloud_url"): str,
    }
)
@websocket_api.async_response
async def ws_pair(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Pair with the backend."""
    await _async_run(
        connection,
        msg,
        hass.data[DATA_BRIDGE].async_pair(msg["pairing_code"], msg.get("cloud_url")),
    )


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "cloud_bridge/suspend"})
@websocket_api.async_response
async def ws_suspend(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Suspend the link."""
    await _async_run(connection, msg, hass.data[DATA_BRIDGE].async_suspend())


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "cloud_bridge/resume"})
@websocket_api.async_response
async def ws_resume(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Resume the link."""
    await _async_run(connection, msg, hass.data[DATA_BRIDGE].async_resume())


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "cloud_bridge/revoke"})
@websocket_api.async_response
async def ws_revoke(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Revoke the link."""
    await _async_run(connection, msg, hass.data[DATA_BRIDGE].async_revoke())


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "cloud_bridge/reset"})
@websocket_api.async_response
async def ws_reset(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Reset a revoked link."""
    await _async_run(connection, msg, hass.data[DATA_BRIDGE].async_reset_link())


@websocket_api.require_admin
@websocket_api.websocket_command({probatio.Required("type"): "cloud_bridge/rotate_key"})
@websocket_api.async_response
async def ws_rotate_key(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Rotate the installation key."""
    await _async_run(connection, msg, hass.data[DATA_BRIDGE].async_rotate_key())


@websocket_api.require_admin
@websocket_api.websocket_command(
    {
        probatio.Required("type"): "cloud_bridge/set_exposed_entities",
        probatio.Required("entity_ids"): [str],
    }
)
@websocket_api.async_response
async def ws_set_exposed_entities(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Choose the entities shared with the cloud."""
    await _async_run(
        connection,
        msg,
        hass.data[DATA_BRIDGE].async_set_exposed_entities(msg["entity_ids"]),
    )
