"""Constants for the Cloud Bridge integration."""

from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from homeassistant.util.hass_dict import HassKey

if TYPE_CHECKING:
    from .bridge import CloudBridge

DOMAIN: Final = "cloud_bridge"

SYSTEM_USER_NAME: Final = "cloud_bridge"
# Temporary name used while the system user is being created. The suffix is a
# random nonce stored in the private identity record, so an orphaned user left
# behind by a crash can be recognised without trusting the name alone.
SYSTEM_USER_PENDING_PREFIX: Final = "cloud_bridge_pending_"

STORAGE_KEY: Final = f"{DOMAIN}.identity"
STORAGE_VERSION: Final = 1
CREDENTIALS_STORAGE_KEY: Final = f"{DOMAIN}.credentials"
LINK_STORAGE_KEY: Final = f"{DOMAIN}.link"
COMMANDS_STORAGE_KEY: Final = f"{DOMAIN}.commands"

DATA_BRIDGE: HassKey[CloudBridge] = HassKey(DOMAIN)

ISSUE_IDENTITY_ERROR: Final = "identity_error"

# Set by the fork build to the production backend. When None, the owner must
# provide the backend URL when pairing.
DEFAULT_CLOUD_URL: Final[str | None] = None

PROTOCOL_VERSION: Final = 1
PAIR_PATH: Final = "/api/bridge/v1/pair"
WEBSOCKET_PATH: Final = "/api/bridge/v1/ws"

# Domain separation prefixes for every signed payload.
SIGN_PAIR: Final = "cloud_bridge/pair/v1"
SIGN_AUTH: Final = "cloud_bridge/auth/v1"
SIGN_ROTATE: Final = "cloud_bridge/rotate/v1"

PAIR_TIMEOUT: Final = 15
CONNECT_TIMEOUT: Final = 15
HANDSHAKE_TIMEOUT: Final = 10
ROTATE_TIMEOUT: Final = 15
HEARTBEAT_INTERVAL: Final = 30
MAX_MESSAGE_SIZE: Final = 64 * 1024
RECONNECT_MIN_DELAY: Final = 1.0
RECONNECT_MAX_DELAY: Final = 300.0

COMMAND_MAX_TTL: Final = timedelta(minutes=5)
COMMAND_TIMEOUT: Final = 10
RATE_LIMIT_BURST: Final = 10
RATE_LIMIT_PER_SECOND: Final = 2.0

AUDIT_MAX_ENTRIES: Final = 200


class IdentityPhase(StrEnum):
    """Lifecycle phase persisted in the identity record."""

    # Nonce saved, system user may or may not exist yet.
    CREATING = "creating"
    # User ID saved, auth store persistence not yet observed after a restart.
    CREATED = "created"
    # User found by ID after a restart: the identity is durable.
    CONFIRMED = "confirmed"


class IdentityStatus(StrEnum):
    """Runtime status of the Cloud Bridge identity."""

    READY = "ready"
    DISABLED = "disabled"
    INACTIVE = "inactive"
    ERROR = "error"


class IdentityError(StrEnum):
    """Reason why the identity was blocked (fail closed)."""

    STORAGE_ERROR = "storage_error"
    STORAGE_INVALID = "storage_invalid"
    NAME_COLLISION = "name_collision"
    USER_MISSING = "user_missing"
    USER_MISMATCH = "user_mismatch"
    RECONCILE_REJECTED = "reconcile_rejected"
    CREATE_FAILED = "create_failed"
    UNEXPECTED = "unexpected"


class LinkState(StrEnum):
    """State of the association with the cloud backend."""

    UNPROVISIONED = "unprovisioned"
    PAIRING = "pairing"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class CommandStatus(StrEnum):
    """Outcome of a cloud command, reported back to the backend."""

    # The service call returned; the physical state is reported separately.
    EXECUTED = "executed"
    REJECTED = "rejected"
    FAILED = "failed"
    TIMEOUT = "timeout"
    DUPLICATE = "duplicate"
