"""Technical identity (system user) of the Cloud Bridge.

The identity record is stored in a private, atomically written store and only
contains the ID of the system user, a lifecycle phase and the disabled flag.
No password, token or key is ever stored in it.

Creation is crash safe:

1. A random nonce is saved (phase ``creating``) before any user is created.
2. The system user is created with a temporary name containing the nonce.
3. The user ID is saved (phase ``created``) and the user is renamed.
4. On the next start, finding the user by ID marks the phase ``confirmed``.

If Home Assistant stops between 2 and 3, the orphaned user is adopted on the
next start only if its name contains the stored nonce and it never received
credentials. A user is never adopted because of its final name alone.

The auth store saves with a delay, so after 3 the user may not be on disk yet.
A ``created`` record whose user is missing therefore restarts the creation,
while a ``confirmed`` record whose user is missing fails closed.
"""

from dataclasses import dataclass
import logging
import secrets
from typing import Any, TypedDict

from homeassistant.auth.const import GROUP_ID_USER
from homeassistant.auth.models import User
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import (
    STORAGE_KEY,
    STORAGE_VERSION,
    SYSTEM_USER_NAME,
    SYSTEM_USER_PENDING_PREFIX,
    IdentityError,
    IdentityPhase,
    IdentityStatus,
)

_LOGGER = logging.getLogger(__name__)


class IdentityData(TypedDict):
    """Persisted identity record."""

    phase: str | None
    system_user_id: str | None
    nonce: str | None
    disabled: bool


@dataclass(frozen=True, slots=True)
class IdentityState:
    """Result of loading the identity."""

    status: IdentityStatus
    user: User | None = None
    error: IdentityError | None = None
    # True once the system user was found by ID after a restart.
    confirmed: bool = False


def _default_data() -> IdentityData:
    return {"phase": None, "system_user_id": None, "nonce": None, "disabled": False}


def _pending_name(nonce: str) -> str:
    return f"{SYSTEM_USER_PENDING_PREFIX}{nonce}"


def _validate_data(raw: Any) -> IdentityData | None:
    """Return the record if it has the expected shape, else None."""
    if not isinstance(raw, dict) or set(raw) != set(_default_data()):
        return None
    phase = raw["phase"]
    user_id = raw["system_user_id"]
    nonce = raw["nonce"]
    if not isinstance(raw["disabled"], bool):
        return None
    if phase is not None and phase not in iter(IdentityPhase):
        return None
    if user_id is not None and not isinstance(user_id, str):
        return None
    if nonce is not None and not isinstance(nonce, str):
        return None
    if phase == IdentityPhase.CREATING and nonce is None:
        return None
    if phase == IdentityPhase.CREATED and (user_id is None or nonce is None):
        return None
    if phase == IdentityPhase.CONFIRMED and user_id is None:
        return None
    return IdentityData(
        phase=phase, system_user_id=user_id, nonce=nonce, disabled=raw["disabled"]
    )


def _group_ids(user: User) -> list[str]:
    return [group.id for group in user.groups]


def _has_expected_shape(user: User, *, allow_no_group: bool = False) -> bool:
    """Return True if the user looks like a Cloud Bridge system user.

    The only group allowed is the non-admin user group, needed for Home
    Assistant to authorize entity service calls made on its behalf.
    """
    allowed_groups = [[GROUP_ID_USER], []] if allow_no_group else [[GROUP_ID_USER]]
    return (
        user.system_generated
        and not user.is_owner
        and not user.credentials
        and _group_ids(user) in allowed_groups
    )


class CloudBridgeIdentity:
    """Manage the Cloud Bridge system user."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the identity manager."""
        self.hass = hass
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: IdentityData = _default_data()
        self.state = IdentityState(IdentityStatus.ERROR, error=IdentityError.UNEXPECTED)

    async def async_initialize(self) -> IdentityState:
        """Load, verify or create the identity. Never raises."""
        try:
            self.state = await self._async_initialize()
        except Exception:
            _LOGGER.exception(
                "Unexpected error while loading the Cloud Bridge identity"
            )
            self.state = self._fail(IdentityError.UNEXPECTED)
        return self.state

    async def async_disable(self) -> None:
        """Persistently disable the Cloud Bridge.

        The flag survives restarts and is never cleared automatically.
        """
        data = IdentityData(**self._data)
        data["disabled"] = True
        await self._store.async_save(dict(data))
        self._data = data
        self.state = IdentityState(IdentityStatus.DISABLED, user=self.state.user)

    async def async_reset(self) -> None:
        """Clear a blocked identity record so the next start creates a new one.

        Explicit recovery step for a failed-closed identity. It does not delete
        or adopt any user, and refuses to run unless the identity is blocked.
        """
        if self.state.status is not IdentityStatus.ERROR:
            raise ValueError("Only a blocked identity can be reset")
        if self.state.error is IdentityError.STORAGE_ERROR:
            raise ValueError("The identity storage is unreadable")
        data = _default_data()
        await self._store.async_save(dict(data))
        self._data = data

    async def _async_initialize(self) -> IdentityState:
        try:
            raw = await self._store.async_load()
        except Exception:  # noqa: BLE001
            _LOGGER.error("Unable to read the Cloud Bridge identity storage")
            return self._fail(IdentityError.STORAGE_ERROR)

        data = _default_data() if raw is None else _validate_data(raw)
        if data is None:
            return self._fail(IdentityError.STORAGE_INVALID)
        self._data = data

        if data["disabled"]:
            user = None
            if data["system_user_id"] is not None:
                user = await self.hass.auth.async_get_user(data["system_user_id"])
            return IdentityState(IdentityStatus.DISABLED, user=user)

        match data["phase"]:
            case None:
                return await self._async_create()
            case IdentityPhase.CREATING:
                return await self._async_reconcile_creating()
            case _:
                return await self._async_verify()

    async def _async_create(self) -> IdentityState:
        """Create the system user on first start."""
        for user in await self.hass.auth.async_get_users():
            if user.name == SYSTEM_USER_NAME:
                _LOGGER.error(
                    "A user named %s already exists and is not the Cloud Bridge "
                    "identity; refusing to adopt it",
                    SYSTEM_USER_NAME,
                )
                return self._fail(IdentityError.NAME_COLLISION)

        nonce = secrets.token_hex(16)
        if not await self._async_save(
            IdentityData(
                phase=IdentityPhase.CREATING,
                system_user_id=None,
                nonce=nonce,
                disabled=False,
            )
        ):
            return self._fail(IdentityError.STORAGE_ERROR)

        try:
            user = await self.hass.auth.async_create_system_user(
                _pending_name(nonce), group_ids=[GROUP_ID_USER], local_only=True
            )
        except Exception:
            _LOGGER.exception("Unable to create the Cloud Bridge system user")
            return self._fail(IdentityError.CREATE_FAILED)

        return await self._async_record_created(user, nonce)

    async def _async_record_created(self, user: User, nonce: str) -> IdentityState:
        """Persist the ID of a freshly created or adopted user."""
        if not await self._async_save(
            IdentityData(
                phase=IdentityPhase.CREATED,
                system_user_id=user.id,
                nonce=nonce,
                disabled=False,
            )
        ):
            # The record still holds the nonce: the next start can reconcile.
            return self._fail(IdentityError.STORAGE_ERROR)

        if user.name != SYSTEM_USER_NAME:
            await self.hass.auth.async_update_user(user, name=SYSTEM_USER_NAME)

        _LOGGER.info("Cloud Bridge system user created")
        return IdentityState(IdentityStatus.READY, user=user)

    async def _async_reconcile_creating(self) -> IdentityState:
        """Resume a creation interrupted before the user ID was saved."""
        nonce = self._data["nonce"]
        assert nonce is not None
        expected_name = _pending_name(nonce)
        candidates = [
            user
            for user in await self.hass.auth.async_get_users()
            if user.name == expected_name
        ]

        if not candidates:
            _LOGGER.info("Resuming interrupted Cloud Bridge identity creation")
            return await self._async_create()

        if len(candidates) > 1 or not (
            _has_expected_shape(user := candidates[0])
            and user.is_active
            and not user.refresh_tokens
        ):
            _LOGGER.error("Orphaned Cloud Bridge system user cannot be adopted safely")
            return self._fail(IdentityError.RECONCILE_REJECTED)

        _LOGGER.info("Adopting orphaned Cloud Bridge system user")
        return await self._async_record_created(user, nonce)

    async def _async_verify(self) -> IdentityState:
        """Verify the stored identity by ID."""
        data = self._data
        phase = data["phase"]
        user_id = data["system_user_id"]
        assert user_id is not None

        user = await self.hass.auth.async_get_user(user_id)

        if user is None:
            if phase == IdentityPhase.CREATED:
                # The auth store did not persist the user before shutdown. It
                # was never confirmed, so no credentials were ever issued.
                _LOGGER.warning(
                    "Unconfirmed Cloud Bridge system user was not persisted; "
                    "creating it again"
                )
                return await self._async_create()
            _LOGGER.error("The stored Cloud Bridge system user no longer exists")
            return self._fail(IdentityError.USER_MISSING)

        allowed_names = {SYSTEM_USER_NAME}
        if phase == IdentityPhase.CREATED and data["nonce"] is not None:
            allowed_names.add(_pending_name(data["nonce"]))

        # Identities created before the user group was required have no group.
        if (
            not _has_expected_shape(user, allow_no_group=True)
            or user.name not in allowed_names
        ):
            _LOGGER.error(
                "The stored Cloud Bridge system user does not match the expected "
                "identity"
            )
            return self._fail(IdentityError.USER_MISMATCH)

        if not user.is_active:
            _LOGGER.warning(
                "The Cloud Bridge system user is deactivated; it will not be "
                "reactivated automatically"
            )
            return IdentityState(IdentityStatus.INACTIVE, user=user)

        if not user.groups:
            _LOGGER.info("Adding the Cloud Bridge system user to the user group")
            await self.hass.auth.async_update_user(user, group_ids=[GROUP_ID_USER])

        if phase == IdentityPhase.CREATED:
            if user.name != SYSTEM_USER_NAME:
                await self.hass.auth.async_update_user(user, name=SYSTEM_USER_NAME)
            if not await self._async_save(
                IdentityData(
                    phase=IdentityPhase.CONFIRMED,
                    system_user_id=user.id,
                    nonce=None,
                    disabled=False,
                )
            ):
                return self._fail(IdentityError.STORAGE_ERROR)

        return IdentityState(IdentityStatus.READY, user=user, confirmed=True)

    async def _async_save(self, data: IdentityData) -> bool:
        try:
            await self._store.async_save(dict(data))
        except Exception:  # noqa: BLE001
            _LOGGER.error("Unable to write the Cloud Bridge identity storage")
            return False
        self._data = data
        return True

    @staticmethod
    def _fail(error: IdentityError) -> IdentityState:
        return IdentityState(IdentityStatus.ERROR, error=error)
