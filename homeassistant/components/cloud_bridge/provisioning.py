"""Association of the installation with the cloud backend.

State machine (persisted, every transition audited)::

    UNPROVISIONED -> PAIRING -> ACTIVE <-> SUSPENDED
          ^             |         |           |
          |             v         v           v
          +--------- REVOKED <----+-----------+

Transitions are explicit; requesting the current state is a no-op. A tenant
change requires revoke -> reset -> new pairing approved by the owner.
"""

from collections.abc import Callable
import ipaddress
import logging
import re
from typing import Any, TypedDict
from urllib.parse import urlsplit

import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import (
    AUDIT_MAX_ENTRIES,
    LINK_STORAGE_KEY,
    PAIR_PATH,
    PAIR_TIMEOUT,
    PROTOCOL_VERSION,
    SIGN_PAIR,
    STORAGE_VERSION,
    WEBSOCKET_PATH,
    LinkState,
)
from .credentials import signing_payload

_LOGGER = logging.getLogger(__name__)

PAIRING_CODE_RE = re.compile(r"^[A-Za-z0-9-]{6,64}$")
INSTALLATION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

TRANSITIONS: dict[LinkState, set[LinkState]] = {
    LinkState.UNPROVISIONED: {LinkState.PAIRING},
    LinkState.PAIRING: {LinkState.ACTIVE, LinkState.UNPROVISIONED, LinkState.REVOKED},
    LinkState.ACTIVE: {LinkState.SUSPENDED, LinkState.REVOKED},
    LinkState.SUSPENDED: {LinkState.ACTIVE, LinkState.REVOKED},
    LinkState.REVOKED: {LinkState.UNPROVISIONED},
}

AUDIT_SAVE_DELAY = 10


class LinkError(Exception):
    """Raised when a link operation is not allowed."""

    def __init__(self, code: str, message: str) -> None:
        """Initialize the error."""
        super().__init__(message)
        self.code = code


class PairingError(LinkError):
    """Raised when pairing fails."""


class LinkData(TypedDict):
    """Persisted link record."""

    state: str
    installation_id: str | None
    cloud_url: str | None
    exposed_entities: list[str]
    audit: list[dict[str, Any]]


def _default_data() -> LinkData:
    return {
        "state": LinkState.UNPROVISIONED,
        "installation_id": None,
        "cloud_url": None,
        "exposed_entities": [],
        "audit": [],
    }


def validate_cloud_url(url: str) -> str:
    """Return the normalized backend base URL or raise LinkError.

    HTTPS is required; plain HTTP is accepted only for a loopback host, to
    develop against a local backend.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as err:
        raise LinkError("invalid_cloud_url", "Invalid backend URL") from err
    host = parts.hostname
    if (
        not host
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.scheme not in ("https", "http")
    ):
        raise LinkError("invalid_cloud_url", "Invalid backend URL")
    if parts.scheme == "http" and not _is_loopback(host):
        raise LinkError("insecure_cloud_url", "The backend URL must use HTTPS")
    netloc = host if ":" not in host else f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return f"{parts.scheme}://{netloc}{parts.path.rstrip('/')}"


def websocket_url(cloud_url: str) -> str:
    """Return the WebSocket URL for a validated backend URL."""
    scheme, rest = cloud_url.split("://", 1)
    return f"{'wss' if scheme == 'https' else 'ws'}://{rest}{WEBSOCKET_PATH}"


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_data(raw: Any) -> LinkData | None:
    if not isinstance(raw, dict) or set(raw) != set(_default_data()):
        return None
    if raw["state"] not in iter(LinkState):
        return None
    for key in ("installation_id", "cloud_url"):
        if raw[key] is not None and not isinstance(raw[key], str):
            return None
    if not isinstance(raw["exposed_entities"], list) or not all(
        isinstance(entity_id, str) for entity_id in raw["exposed_entities"]
    ):
        return None
    if not isinstance(raw["audit"], list):
        return None
    if raw["state"] in (LinkState.ACTIVE, LinkState.SUSPENDED) and (
        raw["installation_id"] is None or raw["cloud_url"] is None
    ):
        return None
    return LinkData(
        state=LinkState(raw["state"]),
        installation_id=raw["installation_id"],
        cloud_url=raw["cloud_url"],
        exposed_entities=list(raw["exposed_entities"]),
        audit=list(raw["audit"])[-AUDIT_MAX_ENTRIES:],
    )


class LinkManager:
    """Persist the link state machine, the shared entities and the audit log."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the manager."""
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, LINK_STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: LinkData = _default_data()

    @property
    def state(self) -> LinkState:
        """Return the link state."""
        return LinkState(self._data["state"])

    @property
    def installation_id(self) -> str | None:
        """Return the installation ID assigned by the backend."""
        return self._data["installation_id"]

    @property
    def cloud_url(self) -> str | None:
        """Return the backend URL."""
        return self._data["cloud_url"]

    @property
    def exposed_entities(self) -> list[str]:
        """Return the entities shared with the cloud."""
        return list(self._data["exposed_entities"])

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Return the audit log, oldest first."""
        return list(self._data["audit"])

    async def async_load(self) -> None:
        """Load the record. Raises LinkError on a corrupt record."""
        if (raw := await self._store.async_load()) is None:
            return
        if (data := _validate_data(raw)) is None:
            raise LinkError("storage_invalid", "Invalid link record")
        self._data = data

    async def async_transition(
        self,
        new_state: LinkState,
        event: str,
        *,
        detail: dict[str, Any] | None = None,
        **changes: Any,
    ) -> bool:
        """Move to a new state; return False if already in it."""
        current = self.state
        if new_state is current:
            return False
        if new_state not in TRANSITIONS[current]:
            raise LinkError(
                "invalid_transition",
                f"Cannot go from {current} to {new_state}",
            )
        data = LinkData(**self._data)
        data["state"] = new_state
        for key, value in changes.items():
            if key not in ("installation_id", "cloud_url"):
                raise KeyError(key)
            data[key] = value  # type: ignore[literal-required]
        data["audit"] = self._with_audit(
            event, {"from": current, "to": new_state, **(detail or {})}
        )
        await self._store.async_save(dict(data))
        self._data = data
        _LOGGER.info("Cloud Bridge link %s -> %s (%s)", current, new_state, event)
        return True

    async def async_set_exposed_entities(self, entity_ids: list[str]) -> None:
        """Persist the entities shared with the cloud."""
        data = LinkData(**self._data)
        data["exposed_entities"] = sorted(set(entity_ids))
        data["audit"] = self._with_audit(
            "exposed_entities_changed", {"count": len(data["exposed_entities"])}
        )
        await self._store.async_save(dict(data))
        self._data = data

    def audit(self, event: str, detail: dict[str, Any]) -> None:
        """Record an audit event, saved with a short delay."""
        self._data["audit"] = self._with_audit(event, detail)
        self._store.async_delay_save(lambda: dict(self._data), AUDIT_SAVE_DELAY)

    def _with_audit(self, event: str, detail: dict[str, Any]) -> list[dict[str, Any]]:
        entry = {"time": dt_util.utcnow().isoformat(), "event": event, **detail}
        return [*self._data["audit"], entry][-AUDIT_MAX_ENTRIES:]


async def async_request_pairing(
    hass: HomeAssistant,
    cloud_url: str,
    pairing_code: str,
    public_key: str,
    sign: Callable[[bytes], str],
) -> str:
    """Register the public key with the backend and return the installation ID.

    The pairing code is a short-lived, single-use code issued by the backend to
    an authenticated owner session; the backend derives the tenant from it.
    The signature proves possession of the private key.
    """
    if not PAIRING_CODE_RE.match(pairing_code):
        raise PairingError("invalid_pairing_code", "Invalid pairing code format")
    timestamp = dt_util.utcnow().isoformat()
    payload = {
        "protocol": PROTOCOL_VERSION,
        "pairing_code": pairing_code,
        "public_key": public_key,
        "timestamp": timestamp,
        "proof": sign(signing_payload(SIGN_PAIR, pairing_code, public_key, timestamp)),
    }
    session = async_get_clientsession(hass)
    try:
        async with session.post(
            f"{cloud_url}{PAIR_PATH}",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=PAIR_TIMEOUT),
            allow_redirects=False,
        ) as resp:
            if resp.status in (400, 401, 403, 404, 409, 410):
                raise PairingError("pairing_rejected", "The backend rejected pairing")
            if resp.status != 200:
                raise PairingError("cloud_error", "Unexpected backend response")
            body = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError, ValueError) as err:
        raise PairingError("cloud_unreachable", "Backend unreachable") from err

    installation_id = body.get("installation_id") if isinstance(body, dict) else None
    if not isinstance(installation_id, str) or not INSTALLATION_ID_RE.match(
        installation_id
    ):
        raise PairingError("cloud_error", "Invalid installation ID from backend")
    return installation_id
