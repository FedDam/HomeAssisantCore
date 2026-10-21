"""Cloud Bridge orchestration.

The bridge only connects when the identity is ready, the link is ACTIVE and
every persisted record could be read. Any doubt keeps it offline (fail
closed); Home Assistant keeps working locally in every case.
"""

import asyncio
import logging
from typing import Any

from homeassistant.core import HomeAssistant, callback, valid_entity_id
from homeassistant.exceptions import HomeAssistantError

from .cloud_client import CloudClient, CloudClientError
from .command_handler import CommandHandler, is_sensitive
from .const import DEFAULT_CLOUD_URL, IdentityStatus, LinkState
from .credentials import CredentialsError, InstallationCredentials
from .device_sync import DeviceSync
from .provisioning import (
    LinkError,
    LinkManager,
    async_request_pairing,
    validate_cloud_url,
    websocket_url,
)
from .system_user import CloudBridgeIdentity, IdentityState

_LOGGER = logging.getLogger(__name__)

MAX_EXPOSED_ENTITIES = 500


class CloudBridge:
    """Own every Cloud Bridge component."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the bridge."""
        self.hass = hass
        self.identity = CloudBridgeIdentity(hass)
        self.credentials = InstallationCredentials(hass)
        self.link = LinkManager(hass)
        self.commands = CommandHandler(
            hass,
            get_exposed_entities=lambda: self.link.exposed_entities,
            get_user_id=self._user_id,
            audit=self.link.audit,
        )
        self.sync = DeviceSync(
            hass,
            send=self._send,
            get_exposed_entities=lambda: self.link.exposed_entities,
        )
        self.client: CloudClient | None = None
        self.blocked_reason: str | None = None
        self._lock = asyncio.Lock()
        self._started = False

    @property
    def can_operate(self) -> bool:
        """Return True if the bridge may pair or connect."""
        return (
            self.identity.state.status is IdentityStatus.READY
            and self.blocked_reason is None
        )

    @property
    def connected(self) -> bool:
        """Return True when authenticated with the backend."""
        return self.client is not None and self.client.connected

    async def async_setup(self) -> IdentityState:
        """Load every record. Never raises."""
        state = await self.identity.async_initialize()
        for name, load in (
            ("link", self.link.async_load),
            ("credentials", self.credentials.async_load),
            ("commands", self.commands.async_load),
        ):
            try:
                await load()
            except LinkError, CredentialsError, HomeAssistantError:
                self.blocked_reason = f"{name}_storage_invalid"
            except Exception:
                _LOGGER.exception("Unable to load the Cloud Bridge %s record", name)
                self.blocked_reason = f"{name}_storage_error"
            if self.blocked_reason is not None:
                _LOGGER.error("Cloud Bridge blocked: %s", self.blocked_reason)
                return state
        try:
            await self._async_reconcile_boot()
        except Exception:
            _LOGGER.exception("Unable to reconcile the Cloud Bridge link")
            self.blocked_reason = "reconcile_error"
        return state

    async def _async_reconcile_boot(self) -> None:
        link_state = self.link.state
        if link_state is LinkState.PAIRING:
            # Interrupted pairing: drop the key, the owner pairs again.
            await self.credentials.async_destroy()
            await self.link.async_transition(
                LinkState.UNPROVISIONED, "pairing_interrupted", cloud_url=None
            )
        elif link_state in (LinkState.UNPROVISIONED, LinkState.REVOKED):
            if self.credentials.has_key:
                # Revoked or leftover credentials are never reused.
                await self.credentials.async_destroy()
        elif not self.credentials.has_key:
            self.blocked_reason = "credentials_missing"
            _LOGGER.error("Cloud Bridge credentials are missing; revoke and pair again")

    async def async_start(self) -> None:
        """Connect if the link is active."""
        self._started = True
        self._async_maybe_connect()

    async def async_stop(self) -> None:
        """Disconnect."""
        self._started = False
        await self._async_disconnect()

    async def async_pair(self, pairing_code: str, cloud_url: str | None) -> None:
        """Pair with the backend using a code issued to the owner."""
        async with self._lock:
            self._require_operational()
            if self.link.state is not LinkState.UNPROVISIONED:
                raise LinkError("invalid_state", "Already paired; revoke first")
            if (url := cloud_url or DEFAULT_CLOUD_URL) is None:
                raise LinkError("missing_cloud_url", "No backend URL configured")
            url = validate_cloud_url(url)

            await self.link.async_transition(
                LinkState.PAIRING, "pairing_started", cloud_url=url
            )
            try:
                public_key = await self.credentials.async_generate()
                installation_id = await async_request_pairing(
                    self.hass, url, pairing_code, public_key, self.credentials.sign
                )
            except Exception as err:
                await self.credentials.async_destroy()
                await self.link.async_transition(
                    LinkState.UNPROVISIONED,
                    "pairing_failed",
                    cloud_url=None,
                    detail={"reason": getattr(err, "code", "error")},
                )
                raise
            await self.link.async_transition(
                LinkState.ACTIVE, "paired", installation_id=installation_id
            )
            self._async_maybe_connect()

    async def async_suspend(self) -> None:
        """Pause the link; it stays paused across restarts."""
        async with self._lock:
            if self.link.state not in (LinkState.ACTIVE, LinkState.SUSPENDED):
                raise LinkError("invalid_state", "The link is not active")
            await self.link.async_transition(LinkState.SUSPENDED, "suspended")
            await self._async_disconnect()

    async def async_resume(self) -> None:
        """Resume a suspended link."""
        async with self._lock:
            if self.link.state not in (LinkState.ACTIVE, LinkState.SUSPENDED):
                raise LinkError("invalid_state", "The link is not suspended")
            self._require_operational()
            await self.link.async_transition(LinkState.ACTIVE, "resumed")
            self._async_maybe_connect()

    async def async_revoke(self, source: str = "local") -> None:
        """Revoke the link and destroy the installation key."""
        async with self._lock:
            if self.link.state is LinkState.REVOKED:
                return
            if self.link.state is LinkState.UNPROVISIONED:
                raise LinkError("invalid_state", "The link is not provisioned")
            # Persist REVOKED first: a crash before the key is destroyed is
            # completed at the next start.
            await self.link.async_transition(LinkState.REVOKED, f"revoked_{source}")
            notice = {"type": "revoke"} if source == "local" else None
            await self._async_disconnect(notice)
            await self.credentials.async_destroy()

    async def async_reset_link(self) -> None:
        """Return a revoked link to UNPROVISIONED so the owner can pair again."""
        async with self._lock:
            if self.link.state is not LinkState.REVOKED:
                raise LinkError("invalid_state", "Only a revoked link can be reset")
            await self.credentials.async_destroy()
            await self.link.async_transition(
                LinkState.UNPROVISIONED, "reset", installation_id=None, cloud_url=None
            )

    async def async_rotate_key(self) -> None:
        """Rotate the installation key."""
        async with self._lock:
            if (client := self.client) is None:
                raise CloudClientError("not_connected")
            try:
                await client.async_rotate_key()
            except CloudClientError as err:
                self.link.audit("key_rotation_failed", {"reason": err.code})
                raise
            self.link.audit("key_rotated", {})

    async def async_set_exposed_entities(self, entity_ids: list[str]) -> None:
        """Choose the entities shared with the cloud."""
        if len(entity_ids) > MAX_EXPOSED_ENTITIES:
            raise LinkError("too_many_entities", "Too many entities")
        for entity_id in entity_ids:
            if not valid_entity_id(entity_id):
                raise LinkError("invalid_entity_id", f"Invalid entity: {entity_id}")
            if is_sensitive(self.hass, entity_id):
                raise LinkError(
                    "sensitive_entity", f"Entity cannot be shared: {entity_id}"
                )
        async with self._lock:
            await self.link.async_set_exposed_entities(entity_ids)
            if self.connected:
                self.sync.async_start()

    def status(self) -> dict[str, Any]:
        """Return a status safe to show to an administrator."""
        identity = self.identity.state
        return {
            "identity": {
                "status": identity.status,
                "error": identity.error,
                "confirmed": identity.confirmed,
            },
            "link": {
                "state": self.link.state,
                "installation_id": self.link.installation_id,
                "cloud_url": self.link.cloud_url,
            },
            "blocked_reason": self.blocked_reason,
            "connected": self.connected,
            "last_error": self.client.last_error if self.client else None,
            "exposed_entities": self.link.exposed_entities,
            "audit": self.link.audit_log[-50:],
        }

    def _require_operational(self) -> None:
        if not self.can_operate:
            raise LinkError(
                "not_operational",
                "The Cloud Bridge identity or storage is not usable",
            )

    @callback
    def _async_maybe_connect(self) -> None:
        if (
            not self._started
            or self.client is not None
            or self.link.state is not LinkState.ACTIVE
            or not self.can_operate
        ):
            return
        installation_id = self.link.installation_id
        cloud_url = self.link.cloud_url
        assert installation_id is not None
        assert cloud_url is not None
        self.client = CloudClient(
            self.hass,
            url=websocket_url(cloud_url),
            installation_id=installation_id,
            credentials=self.credentials,
            on_connected=self._on_connected,
            on_disconnected=self.sync.async_stop,
            on_message=self._async_on_message,
            on_revoked=self._async_on_revoked,
        )
        self.client.start()

    async def _async_disconnect(self, notice: dict[str, Any] | None = None) -> None:
        if (client := self.client) is None:
            return
        self.client = None
        self.sync.async_stop()
        await client.async_stop(notice)

    def _user_id(self) -> str | None:
        state = self.identity.state
        if state.status is not IdentityStatus.READY or state.user is None:
            return None
        if not state.user.is_active:
            return None
        return state.user.id

    @callback
    def _send(self, message: dict[str, Any]) -> None:
        if self.client is not None:
            self.client.send(message)

    @callback
    def _on_connected(self) -> None:
        self.link.audit("connected", {})
        self.sync.async_start()

    async def _async_on_message(self, message: dict[str, Any]) -> None:
        if message.get("type") != "command":
            _LOGGER.debug("Ignoring unknown Cloud Bridge message")
            return
        installation_id = self.link.installation_id
        assert installation_id is not None
        self._send(await self.commands.async_handle(message, installation_id))

    async def _async_on_revoked(self) -> None:
        await self.async_revoke(source="cloud")
