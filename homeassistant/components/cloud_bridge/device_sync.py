"""State synchronisation towards the backend.

Only entities explicitly shared by the owner are sent, and only an allowlist
of attributes: no entity, device or area data leaks by default.
"""

from collections.abc import Callable
from typing import Any

from homeassistant.core import (
    CALLBACK_TYPE,
    Event,
    EventStateChangedData,
    HomeAssistant,
    State,
    callback,
)
from homeassistant.helpers.event import async_track_state_change_event

from .command_handler import is_sensitive

SHARED_ATTRIBUTES = frozenset(
    {
        "friendly_name",
        "device_class",
        "unit_of_measurement",
        "supported_features",
        "supported_color_modes",
        "color_mode",
        "brightness",
        "color_temp_kelvin",
        "min_color_temp_kelvin",
        "max_color_temp_kelvin",
        "percentage",
        "current_position",
        "current_temperature",
        "temperature",
        "target_temp_step",
        "min_temp",
        "max_temp",
        "hvac_mode",
        "hvac_modes",
        "hvac_action",
    }
)


def state_payload(state: State) -> dict[str, Any]:
    """Return the shareable representation of a state."""
    return {
        "entity_id": state.entity_id,
        "state": state.state,
        "attributes": {
            key: value
            for key, value in state.attributes.items()
            if key in SHARED_ATTRIBUTES
        },
        "last_changed": state.last_changed.isoformat(),
        "last_updated": state.last_updated.isoformat(),
    }


class DeviceSync:
    """Send a snapshot and state updates of the shared entities."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        send: Callable[[dict[str, Any]], None],
        get_exposed_entities: Callable[[], list[str]],
    ) -> None:
        """Initialize the synchroniser."""
        self.hass = hass
        self._send = send
        self._get_exposed_entities = get_exposed_entities
        self._unsub: CALLBACK_TYPE | None = None
        self._revision = 0

    @callback
    def async_start(self) -> None:
        """Subscribe to the shared entities and send a full snapshot."""
        self.async_stop()
        entity_ids = self._shared_entities()
        if entity_ids:
            self._unsub = async_track_state_change_event(
                self.hass, entity_ids, self._async_state_changed
            )
        self._send(
            {
                "type": "snapshot",
                "revision": self._next_revision(),
                "entities": [
                    state_payload(state)
                    for entity_id in entity_ids
                    if (state := self.hass.states.get(entity_id)) is not None
                ],
            }
        )

    @callback
    def async_stop(self) -> None:
        """Unsubscribe."""
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    def _shared_entities(self) -> list[str]:
        return [
            entity_id
            for entity_id in self._get_exposed_entities()
            if not is_sensitive(self.hass, entity_id)
        ]

    def _next_revision(self) -> int:
        self._revision += 1
        return self._revision

    @callback
    def _async_state_changed(self, event: Event[EventStateChangedData]) -> None:
        new_state = event.data["new_state"]
        if new_state is not None and is_sensitive(self.hass, new_state.entity_id):
            # Device class changed to a sensitive one: stop sharing it.
            self._send(
                {
                    "type": "state_removed",
                    "revision": self._next_revision(),
                    "entity_id": new_state.entity_id,
                }
            )
            return
        if new_state is None:
            self._send(
                {
                    "type": "state_removed",
                    "revision": self._next_revision(),
                    "entity_id": event.data["entity_id"],
                }
            )
            return
        self._send(
            {
                "type": "state",
                "revision": self._next_revision(),
                **state_payload(new_state),
            }
        )
