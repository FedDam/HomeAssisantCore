"""Tests for the Cloud Bridge command handler."""

import asyncio
from datetime import timedelta
from typing import Any
from unittest.mock import patch
import uuid

import pytest

from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.auth.permissions.const import POLICY_CONTROL
from homeassistant.components.cloud_bridge.command_handler import CommandHandler
from homeassistant.components.cloud_bridge.const import (
    COMMANDS_STORAGE_KEY,
    CommandStatus,
)
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util

from tests.common import async_mock_service

INSTALLATION_ID = "ha-001"
LIGHT = "light.kitchen"
LOCK = "lock.front_door"
GARAGE = "cover.garage"


class Harness:
    """Command handler with controllable collaborators."""

    def __init__(self, hass: HomeAssistant, user_id: str | None) -> None:
        """Initialize the harness."""
        self.exposed = [LIGHT, LOCK, GARAGE, "cover.blinds"]
        self.user_id = user_id
        self.audit: list[tuple[str, dict[str, Any]]] = []
        self.handler = CommandHandler(
            hass,
            get_exposed_entities=lambda: self.exposed,
            get_user_id=lambda: self.user_id,
            audit=lambda event, detail: self.audit.append((event, detail)),
        )


@pytest.fixture
async def harness(hass: HomeAssistant, hass_storage: dict[str, Any]) -> Harness:
    """Return a loaded harness with a few entities."""
    user = await hass.auth.async_create_system_user(
        "cloud_bridge", group_ids=[GROUP_ID_USER]
    )
    hass.states.async_set(LIGHT, "off")
    hass.states.async_set(LOCK, "locked")
    hass.states.async_set(GARAGE, "closed", {"device_class": "garage"})
    hass.states.async_set("cover.blinds", "open", {"device_class": "blind"})
    hass.states.async_set("light.not_shared", "off")
    harness = Harness(hass, user.id)
    await harness.handler.async_load()
    return harness


def command(**overrides: Any) -> dict[str, Any]:
    """Return a valid command, optionally altered."""
    message = {
        "type": "command",
        "command_id": str(uuid.uuid4()),
        "action": "light.turn_on",
        "entity_id": LIGHT,
        "expires_at": (dt_util.utcnow() + timedelta(seconds=30)).isoformat(),
    }
    message.update(overrides)
    return message


async def test_executes_allowed_command(hass: HomeAssistant, harness: Harness) -> None:
    """Test a valid command runs as the system user."""
    calls = async_mock_service(hass, "light", "turn_on")
    message = command(data={"brightness_pct": 40})

    result = await harness.handler.async_handle(message, INSTALLATION_ID)

    assert result["status"] == CommandStatus.EXECUTED
    assert result["command_id"] == message["command_id"]
    (call,) = calls
    assert call.data == {"entity_id": LIGHT, "brightness_pct": 40}
    assert call.context.user_id == harness.user_id
    assert result["context_id"] == call.context.id
    assert harness.audit[0][0] == "command"


async def test_system_user_permissions(hass: HomeAssistant, harness: Harness) -> None:
    """Test Home Assistant authorizes entity control but not admin actions."""
    assert harness.user_id is not None
    user = await hass.auth.async_get_user(harness.user_id)
    assert user is not None

    assert user.permissions.check_entity(LIGHT, POLICY_CONTROL)
    assert not user.is_admin


async def test_duplicate_is_not_executed_twice(
    hass: HomeAssistant, hass_storage: dict[str, Any], harness: Harness
) -> None:
    """Test the same command_id never executes twice, also after a restart."""
    calls = async_mock_service(hass, "light", "turn_on")
    message = command()

    first = await harness.handler.async_handle(message, INSTALLATION_ID)
    second = await harness.handler.async_handle(message, INSTALLATION_ID)
    restarted = Harness(hass, harness.user_id)
    await restarted.handler.async_load()
    third = await restarted.handler.async_handle(message, INSTALLATION_ID)

    assert first["status"] == CommandStatus.EXECUTED
    assert second["status"] == CommandStatus.DUPLICATE
    assert third["status"] == CommandStatus.DUPLICATE
    assert len(calls) == 1
    assert message["command_id"] in hass_storage[COMMANDS_STORAGE_KEY]["data"]["seen"]


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        pytest.param(
            {"expires_at": (dt_util.utcnow() - timedelta(seconds=1)).isoformat()},
            "expired",
            id="expired",
        ),
        pytest.param(
            {"expires_at": (dt_util.utcnow() + timedelta(hours=1)).isoformat()},
            "invalid_expiry",
            id="too_far",
        ),
        pytest.param(
            {"expires_at": "2026-10-16T09:00:00"}, "invalid_command", id="naive_time"
        ),
        pytest.param(
            {"installation_id": "ha-002"}, "installation_mismatch", id="tenant"
        ),
        pytest.param(
            {"entity_id": "light.not_shared"}, "entity_not_allowed", id="not_shared"
        ),
        pytest.param(
            {"action": "lock.unlock", "entity_id": LOCK},
            "invalid_command",
            id="lock_action",
        ),
        pytest.param(
            {"action": "cover.open_cover", "entity_id": GARAGE},
            "sensitive_entity",
            id="garage",
        ),
        pytest.param(
            {"action": "switch.turn_on"}, "action_not_allowed", id="cross_domain"
        ),
        pytest.param(
            {"action": "homeassistant.restart"}, "invalid_command", id="restart"
        ),
        pytest.param({"action": "shell_command.run"}, "invalid_command", id="shell"),
        pytest.param(
            {"domain": "light", "service": "turn_on"},
            "invalid_command",
            id="free_service",
        ),
        pytest.param({"url": "http://x"}, "invalid_command", id="extra_field"),
        pytest.param({"command_id": "not-a-uuid"}, "invalid_command", id="bad_id"),
        pytest.param({"entity_id": "all"}, "invalid_command", id="all_entities"),
        pytest.param(
            {"data": {"brightness_pct": True}}, "invalid_data", id="bool_as_int"
        ),
        pytest.param({"data": {"brightness_pct": 101}}, "invalid_data", id="range"),
        pytest.param(
            {"data": {"entity_id": "light.x"}}, "invalid_data", id="data_target"
        ),
        pytest.param({"data": "x"}, "invalid_command", id="data_not_dict"),
    ],
)
async def test_rejected_commands(
    hass: HomeAssistant,
    harness: Harness,
    overrides: dict[str, Any],
    error: str,
) -> None:
    """Test untrusted commands are rejected and never executed."""
    calls = async_mock_service(hass, "light", "turn_on")
    async_mock_service(hass, "cover", "open_cover")

    result = await harness.handler.async_handle(command(**overrides), INSTALLATION_ID)

    assert result["status"] == CommandStatus.REJECTED
    assert result["error"] == error
    assert calls == []


async def test_entity_missing(hass: HomeAssistant, harness: Harness) -> None:
    """Test a shared entity that does not exist."""
    harness.exposed.append("light.gone")

    result = await harness.handler.async_handle(
        command(entity_id="light.gone"), INSTALLATION_ID
    )

    assert result["error"] == "entity_not_found"


async def test_rate_limit(hass: HomeAssistant, harness: Harness) -> None:
    """Test bursts beyond the limit are rejected."""
    async_mock_service(hass, "light", "turn_on")

    results = [
        (await harness.handler.async_handle(command(), INSTALLATION_ID))["status"]
        for _ in range(15)
    ]

    assert results.count(CommandStatus.EXECUTED) == 10
    assert results.count(CommandStatus.REJECTED) == 5


async def test_inactive_identity_is_unauthorized(
    hass: HomeAssistant, harness: Harness
) -> None:
    """Test no command runs without a usable system user."""
    calls = async_mock_service(hass, "light", "turn_on")
    harness.user_id = None

    result = await harness.handler.async_handle(command(), INSTALLATION_ID)

    assert result["error"] == "unauthorized"
    assert calls == []


async def test_storage_failure_prevents_execution(
    hass: HomeAssistant, harness: Harness
) -> None:
    """Test a command whose ID cannot be persisted is not executed."""
    calls = async_mock_service(hass, "light", "turn_on")

    with patch(
        "homeassistant.components.cloud_bridge.command_handler.Store.async_save",
        side_effect=OSError("disk full"),
    ):
        result = await harness.handler.async_handle(command(), INSTALLATION_ID)

    assert result["status"] == CommandStatus.FAILED
    assert calls == []


async def test_service_error(hass: HomeAssistant, harness: Harness) -> None:
    """Test a failing service call is reported."""

    async def fail(call: ServiceCall) -> None:
        raise HomeAssistantError("device offline")

    hass.services.async_register("light", "turn_on", fail)

    result = await harness.handler.async_handle(command(), INSTALLATION_ID)

    assert result["status"] == CommandStatus.FAILED
    assert result["error"] == "service_error"


async def test_service_missing(hass: HomeAssistant, harness: Harness) -> None:
    """Test a command for a service that is not registered."""
    result = await harness.handler.async_handle(command(), INSTALLATION_ID)

    assert result["status"] == CommandStatus.FAILED
    assert result["error"] == "service_not_found"


async def test_service_timeout(hass: HomeAssistant, harness: Harness) -> None:
    """Test a slow service reports a timeout, not success."""
    never = asyncio.Event()

    async def slow(call: ServiceCall) -> None:
        await never.wait()

    hass.services.async_register("light", "turn_on", slow)

    with patch(
        "homeassistant.components.cloud_bridge.command_handler.COMMAND_TIMEOUT", 0.01
    ):
        result = await harness.handler.async_handle(command(), INSTALLATION_ID)

    assert result["status"] == CommandStatus.TIMEOUT


async def test_seen_ids_expire(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test stored command IDs are pruned after expiry."""
    hass_storage[COMMANDS_STORAGE_KEY] = {
        "version": 1,
        "data": {"seen": {"old": 0, "recent": 4102444800, "bad": "x"}},
    }
    harness = Harness(hass, None)

    await harness.handler.async_load()

    assert harness.handler._seen == {"recent": 4102444800}


async def test_corrupt_seen_store_raises(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an unreadable replay record keeps the bridge offline."""
    hass_storage[COMMANDS_STORAGE_KEY] = {"version": 1, "data": {"seen": []}}

    with pytest.raises(HomeAssistantError):
        await Harness(hass, None).handler.async_load()
