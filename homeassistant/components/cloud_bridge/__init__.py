"""The Cloud Bridge integration.

Built-in integration loaded by bootstrap as a default integration. It owns a
technical identity (a system user), installation credentials, the pairing
state machine and an outbound connection to the cloud backend. It never
blocks Home Assistant: any failure only keeps the bridge offline.
"""

import logging

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant
from homeassistant.helpers import config_validation as cv, issue_registry as ir
from homeassistant.helpers.start import async_at_started
from homeassistant.helpers.typing import ConfigType

from . import websocket_api
from .bridge import CloudBridge
from .const import DATA_BRIDGE, DOMAIN, ISSUE_IDENTITY_ERROR, IdentityStatus

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.empty_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the Cloud Bridge.

    Always returns True: a blocked identity only disables the bridge and must
    never prevent Home Assistant from starting.
    """
    bridge = CloudBridge(hass)
    hass.data[DATA_BRIDGE] = bridge
    state = await bridge.async_setup()
    websocket_api.async_register(hass)

    if state.status is IdentityStatus.ERROR:
        assert state.error is not None
        _LOGGER.error(
            "Cloud Bridge identity is blocked (%s); remote access is disabled",
            state.error,
        )
        ir.async_create_issue(
            hass,
            DOMAIN,
            ISSUE_IDENTITY_ERROR,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_IDENTITY_ERROR,
            translation_placeholders={"reason": state.error.value},
        )
    else:
        ir.async_delete_issue(hass, DOMAIN, ISSUE_IDENTITY_ERROR)
        if state.status is IdentityStatus.DISABLED:
            _LOGGER.info("Cloud Bridge is disabled")

    async def _async_started(hass: HomeAssistant) -> None:
        await bridge.async_start()

    async def _async_stop(event: Event) -> None:
        await bridge.async_stop()

    async_at_started(hass, _async_started)
    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_stop)
    return True
