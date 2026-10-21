"""Installation credentials of the Cloud Bridge.

Each installation owns an Ed25519 key pair generated locally at pairing time.
Only the public key ever leaves Home Assistant. No Home Assistant refresh or
access token is created for the cloud: commands are executed in process.

The private key is kept in a private, atomically written store. Home Assistant
has no secret vault, so the key is as protected as the ``.storage`` directory
(and is included in backups).
"""

import base64
import binascii
import logging
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import CREDENTIALS_STORAGE_KEY, STORAGE_VERSION

_LOGGER = logging.getLogger(__name__)


class CredentialsError(Exception):
    """Raised when the installation credentials are unusable."""


def b64encode(data: bytes) -> str:
    """Encode bytes as URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64decode(data: str) -> bytes:
    """Decode URL-safe base64 with or without padding."""
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    except (binascii.Error, ValueError) as err:
        raise ValueError("Invalid base64") from err


def public_key_b64(private_key: Ed25519PrivateKey) -> str:
    """Return the raw public key, base64 encoded."""
    return b64encode(private_key.public_key().public_bytes_raw())


def signing_payload(prefix: str, *parts: str) -> bytes:
    """Build a domain separated payload to sign."""
    return "\n".join((prefix, *parts)).encode()


def verify_signature(public_key: str, signature: str, payload: bytes) -> bool:
    """Verify a signature; used by tests and by reference backends."""
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(public_key)).verify(
            b64decode(signature), payload
        )
    except Exception:  # noqa: BLE001
        return False
    return True


class InstallationCredentials:
    """Hold the installation key pair."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the credentials."""
        self._store: Store[dict[str, Any]] = Store(
            hass,
            STORAGE_VERSION,
            CREDENTIALS_STORAGE_KEY,
            private=True,
            atomic_writes=True,
        )
        self._key: Ed25519PrivateKey | None = None
        self._pending_key: Ed25519PrivateKey | None = None

    @property
    def has_key(self) -> bool:
        """Return True if a key is available."""
        return self._key is not None

    @property
    def has_pending_key(self) -> bool:
        """Return True if a rotation is in progress."""
        return self._pending_key is not None

    @property
    def public_key(self) -> str:
        """Return the current public key."""
        return public_key_b64(self._require_key())

    async def async_load(self) -> None:
        """Load the keys. Raises CredentialsError on a corrupt record."""
        if (data := await self._store.async_load()) is None:
            return
        try:
            self._key = _load_key(data["private_key"])
            self._pending_key = _load_key(data["pending_private_key"])
        except (KeyError, TypeError, ValueError) as err:
            raise CredentialsError("Invalid credentials record") from err

    async def async_generate(self) -> str:
        """Generate the key pair for a new pairing and return the public key."""
        if self._key is not None:
            raise CredentialsError("A key already exists")
        key = Ed25519PrivateKey.generate()
        await self._async_save(key, None)
        self._key = key
        return public_key_b64(key)

    def sign(self, payload: bytes, *, pending: bool = False) -> str:
        """Sign a payload with the current key, or with the pending key."""
        if not pending:
            return b64encode(self._require_key().sign(payload))
        if self._pending_key is None:
            raise CredentialsError("No rotation in progress")
        return b64encode(self._pending_key.sign(payload))

    async def async_begin_rotation(self) -> Ed25519PrivateKey:
        """Create and persist a pending key; the current key stays valid."""
        key = self._require_key()
        pending = Ed25519PrivateKey.generate()
        await self._async_save(key, pending)
        self._pending_key = pending
        return pending

    async def async_commit_rotation(self) -> None:
        """Replace the current key with the pending key."""
        if (pending := self._pending_key) is None:
            raise CredentialsError("No rotation in progress")
        await self._async_save(pending, None)
        self._key = pending
        self._pending_key = None

    async def async_abort_rotation(self) -> None:
        """Drop the pending key."""
        if self._pending_key is None:
            return
        await self._async_save(self._require_key(), None)
        self._pending_key = None

    async def async_destroy(self) -> None:
        """Delete all keys, used on revocation and reset."""
        self._key = None
        self._pending_key = None
        await self._store.async_remove()

    def _require_key(self) -> Ed25519PrivateKey:
        if self._key is None:
            raise CredentialsError("No installation key")
        return self._key

    async def _async_save(
        self, key: Ed25519PrivateKey, pending: Ed25519PrivateKey | None
    ) -> None:
        await self._store.async_save(
            {
                "private_key": b64encode(key.private_bytes_raw()),
                "pending_private_key": (
                    b64encode(pending.private_bytes_raw()) if pending else None
                ),
            }
        )


def _load_key(value: Any) -> Ed25519PrivateKey | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("Key must be a string")
    return Ed25519PrivateKey.from_private_bytes(b64decode(value))
