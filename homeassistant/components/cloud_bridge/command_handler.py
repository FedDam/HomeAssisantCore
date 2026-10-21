"""Validation and execution of cloud commands.

A command is untrusted until validated. Only a fixed set of actions is
supported; the backend never chooses a free ``domain/service``. The target
entity must have been shared by the owner. Sensitive entities (locks, alarm
panels, doors, gates, garage doors) are never controllable in this version.

``command_id`` is persisted before execution so a replay, also after a
restart, is never executed twice. Commands expire after at most
``COMMAND_MAX_TTL``; expired commands are not executed.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging
import time
from typing import Any

import probatio

from homeassistant.const import ATTR_DEVICE_CLASS, ATTR_ENTITY_ID
from homeassistant.core import Context, HomeAssistant, split_entity_id, valid_entity_id
from homeassistant.exceptions import HomeAssistantError, ServiceNotFound, Unauthorized
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import (
    COMMAND_MAX_TTL,
    COMMAND_TIMEOUT,
    COMMANDS_STORAGE_KEY,
    RATE_LIMIT_BURST,
    RATE_LIMIT_PER_SECOND,
    STORAGE_VERSION,
    CommandStatus,
)

_LOGGER = logging.getLogger(__name__)

SENSITIVE_DOMAINS = frozenset({"lock", "alarm_control_panel"})
SENSITIVE_DEVICE_CLASSES = frozenset({"door", "garage", "gate"})
# Seen command IDs are kept a little longer than their expiry to absorb skew.
SEEN_RETENTION_MARGIN = 60


def _strict_int(minimum: int, maximum: int) -> Callable[[Any], int]:
    def validate(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise probatio.Invalid("expected an integer")
        if not minimum <= value <= maximum:
            raise probatio.Invalid("value out of range")
        return value

    return validate


def _strict_number(minimum: float, maximum: float) -> Callable[[Any], float]:
    def validate(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise probatio.Invalid("expected a number")
        if not minimum <= value <= maximum:
            raise probatio.Invalid("value out of range")
        return float(value)

    return validate


def _entity_id(value: Any) -> str:
    if not isinstance(value, str) or not valid_entity_id(value):
        raise probatio.Invalid("invalid entity_id")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or (parsed := dt_util.parse_datetime(value)) is None:
        raise probatio.Invalid("invalid timestamp")
    if parsed.tzinfo is None:
        raise probatio.Invalid("timestamp must include a timezone")
    return parsed


NO_DATA = probatio.Schema({})


@dataclass(frozen=True, slots=True)
class Action:
    """A supported cloud action."""

    domain: str
    service: str
    data_schema: probatio.Schema = field(default_factory=lambda: NO_DATA)


ACTIONS: dict[str, Action] = {
    "light.turn_on": Action(
        "light",
        "turn_on",
        probatio.Schema(
            {
                probatio.Optional("brightness_pct"): _strict_int(0, 100),
                probatio.Optional("color_temp_kelvin"): _strict_int(1500, 10000),
            }
        ),
    ),
    "light.turn_off": Action("light", "turn_off"),
    "light.toggle": Action("light", "toggle"),
    "switch.turn_on": Action("switch", "turn_on"),
    "switch.turn_off": Action("switch", "turn_off"),
    "switch.toggle": Action("switch", "toggle"),
    "fan.turn_on": Action("fan", "turn_on"),
    "fan.turn_off": Action("fan", "turn_off"),
    "fan.set_percentage": Action(
        "fan",
        "set_percentage",
        probatio.Schema({probatio.Required("percentage"): _strict_int(0, 100)}),
    ),
    "cover.open_cover": Action("cover", "open_cover"),
    "cover.close_cover": Action("cover", "close_cover"),
    "cover.stop_cover": Action("cover", "stop_cover"),
    "cover.set_cover_position": Action(
        "cover",
        "set_cover_position",
        probatio.Schema({probatio.Required("position"): _strict_int(0, 100)}),
    ),
    "climate.turn_on": Action("climate", "turn_on"),
    "climate.turn_off": Action("climate", "turn_off"),
    "climate.set_temperature": Action(
        "climate",
        "set_temperature",
        probatio.Schema({probatio.Required("temperature"): _strict_number(5, 35)}),
    ),
    "climate.set_hvac_mode": Action(
        "climate",
        "set_hvac_mode",
        probatio.Schema(
            {
                probatio.Required("hvac_mode"): probatio.In(
                    ["off", "heat", "cool", "heat_cool", "auto", "dry", "fan_only"]
                )
            }
        ),
    ),
}

COMMAND_SCHEMA = probatio.Schema(
    {
        probatio.Required("type"): "command",
        probatio.Required("command_id"): probatio.UUID(),
        probatio.Required("action"): probatio.In(list(ACTIONS)),
        probatio.Required("entity_id"): _entity_id,
        probatio.Required("expires_at"): _timestamp,
        probatio.Optional("data", default={}): dict,
        probatio.Optional("installation_id"): str,
    }
)


def is_sensitive(hass: HomeAssistant, entity_id: str) -> bool:
    """Return True if the entity needs a stronger policy than this bridge has."""
    domain = split_entity_id(entity_id)[0]
    if domain in SENSITIVE_DOMAINS:
        return True
    state = hass.states.get(entity_id)
    return (
        state is not None
        and state.attributes.get(ATTR_DEVICE_CLASS) in SENSITIVE_DEVICE_CLASSES
    )


class RateLimiter:
    """Token bucket."""

    def __init__(self, burst: int, per_second: float) -> None:
        """Initialize the bucket."""
        self._burst = burst
        self._rate = per_second
        self._tokens = float(burst)
        self._last = time.monotonic()

    def allow(self) -> bool:
        """Consume a token if available."""
        now = time.monotonic()
        self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
        self._last = now
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True


class CommandHandler:
    """Validate and execute commands received from the authenticated backend."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        get_exposed_entities: Callable[[], list[str]],
        get_user_id: Callable[[], str | None],
        audit: Callable[[str, dict[str, Any]], None],
    ) -> None:
        """Initialize the handler."""
        self.hass = hass
        self._get_exposed_entities = get_exposed_entities
        self._get_user_id = get_user_id
        self._audit = audit
        self._store: Store[dict[str, Any]] = Store(
            hass,
            STORAGE_VERSION,
            COMMANDS_STORAGE_KEY,
            private=True,
            atomic_writes=True,
        )
        self._seen: dict[str, float] = {}
        self._rate_limiter = RateLimiter(RATE_LIMIT_BURST, RATE_LIMIT_PER_SECOND)

    async def async_load(self) -> None:
        """Load the IDs of already processed commands.

        An unreadable record raises, so the bridge stays offline rather than
        risk executing a replayed command.
        """
        data = await self._store.async_load()
        seen = data.get("seen") if isinstance(data, dict) else None
        if data is not None and not isinstance(seen, dict):
            raise HomeAssistantError("Invalid command record")
        self._seen = {
            command_id: expiry
            for command_id, expiry in (seen or {}).items()
            if isinstance(command_id, str) and isinstance(expiry, (int, float))
        }
        self._prune()

    async def async_handle(
        self, message: dict[str, Any], installation_id: str
    ) -> dict[str, Any]:
        """Process one command and return the result message."""
        raw_id = message.get("command_id")
        command_id = raw_id if isinstance(raw_id, str) and len(raw_id) <= 64 else None

        try:
            command = COMMAND_SCHEMA(message)
        except probatio.Invalid:
            return self._result(command_id, CommandStatus.REJECTED, "invalid_command")

        command_id = command["command_id"]
        action: Action = ACTIONS[command["action"]]
        entity_id: str = command["entity_id"]

        # The payload never identifies the installation: the session does.
        if command.get("installation_id", installation_id) != installation_id:
            return self._result(
                command_id, CommandStatus.REJECTED, "installation_mismatch"
            )

        now = dt_util.utcnow()
        expires_at: datetime = command["expires_at"]
        if expires_at <= now:
            return self._result(command_id, CommandStatus.REJECTED, "expired")
        if expires_at > now + COMMAND_MAX_TTL:
            return self._result(command_id, CommandStatus.REJECTED, "invalid_expiry")

        if command_id in self._seen:
            return self._result(command_id, CommandStatus.DUPLICATE)

        if not self._rate_limiter.allow():
            return self._result(command_id, CommandStatus.REJECTED, "rate_limited")

        if entity_id not in self._get_exposed_entities():
            return self._result(
                command_id, CommandStatus.REJECTED, "entity_not_allowed"
            )
        if is_sensitive(self.hass, entity_id):
            return self._result(command_id, CommandStatus.REJECTED, "sensitive_entity")
        if split_entity_id(entity_id)[0] != action.domain:
            return self._result(
                command_id, CommandStatus.REJECTED, "action_not_allowed"
            )
        if self.hass.states.get(entity_id) is None:
            return self._result(command_id, CommandStatus.REJECTED, "entity_not_found")

        try:
            data = action.data_schema(command["data"])
        except probatio.Invalid:
            return self._result(command_id, CommandStatus.REJECTED, "invalid_data")

        if (user_id := self._get_user_id()) is None:
            return self._result(command_id, CommandStatus.REJECTED, "unauthorized")

        self._prune()
        self._seen[command_id] = expires_at.timestamp() + SEEN_RETENTION_MARGIN
        try:
            await self._store.async_save({"seen": dict(self._seen)})
        except Exception:  # noqa: BLE001
            # Never execute a command whose ID could not be made durable.
            del self._seen[command_id]
            _LOGGER.error("Unable to persist the command ID; command not executed")
            return self._result(command_id, CommandStatus.FAILED, "storage_error")

        context = Context(user_id=user_id)
        status, error = await self._async_execute(action, entity_id, data, context)
        self._audit(
            "command",
            {
                "command_id": command_id,
                "action": command["action"],
                "entity_id": entity_id,
                "status": status,
                "error": error,
                "context_id": context.id,
            },
        )
        return self._result(command_id, status, error, context_id=context.id)

    async def _async_execute(
        self,
        action: Action,
        entity_id: str,
        data: dict[str, Any],
        context: Context,
    ) -> tuple[CommandStatus, str | None]:
        try:
            async with asyncio.timeout(COMMAND_TIMEOUT):
                await self.hass.services.async_call(
                    action.domain,
                    action.service,
                    {ATTR_ENTITY_ID: entity_id, **data},
                    blocking=True,
                    context=context,
                )
        except TimeoutError:
            # The call may still complete; the state stream reports the outcome.
            return CommandStatus.TIMEOUT, None
        except Unauthorized:
            return CommandStatus.REJECTED, "unauthorized"
        except ServiceNotFound:
            return CommandStatus.FAILED, "service_not_found"
        except HomeAssistantError, probatio.Invalid:
            return CommandStatus.FAILED, "service_error"
        return CommandStatus.EXECUTED, None

    def _prune(self) -> None:
        now = time.time()
        self._seen = {
            command_id: expiry
            for command_id, expiry in self._seen.items()
            if expiry > now
        }

    @staticmethod
    def _result(
        command_id: str | None,
        status: CommandStatus,
        error: str | None = None,
        *,
        context_id: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": "command_result",
            "command_id": command_id,
            "status": status,
        }
        if error is not None:
            result["error"] = error
        if context_id is not None:
            result["context_id"] = context_id
        return result
