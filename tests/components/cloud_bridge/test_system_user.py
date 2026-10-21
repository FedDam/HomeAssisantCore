"""Tests for the Cloud Bridge system user."""

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import patch

import pytest

from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.auth.models import Credentials, User
from homeassistant.components.cloud_bridge.const import (
    STORAGE_KEY,
    SYSTEM_USER_NAME,
    SYSTEM_USER_PENDING_PREFIX,
    IdentityError,
    IdentityPhase,
    IdentityStatus,
)
from homeassistant.components.cloud_bridge.system_user import CloudBridgeIdentity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .conftest import bridge_users, identity_record

NONCE = "0123456789abcdef0123456789abcdef"
PENDING_NAME = f"{SYSTEM_USER_PENDING_PREFIX}{NONCE}"


async def _start(hass: HomeAssistant) -> CloudBridgeIdentity:
    """Simulate a start of the bridge."""
    identity = CloudBridgeIdentity(hass)
    await identity.async_initialize()
    return identity


def _stored(hass_storage: dict[str, Any]) -> dict[str, Any]:
    return hass_storage[STORAGE_KEY]["data"]


async def test_first_start_creates_one_system_user(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an empty installation creates exactly one minimal system user."""
    users_before = len(await hass.auth.async_get_users())

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.READY
    assert identity.state.confirmed is False
    assert len(await hass.auth.async_get_users()) == users_before + 1
    (user,) = await bridge_users(hass)
    assert identity.state.user is user
    assert user.name == SYSTEM_USER_NAME
    assert user.system_generated
    assert user.is_active
    assert user.local_only
    assert not user.is_owner
    assert [group.id for group in user.groups] == [GROUP_ID_USER]
    assert not user.credentials
    assert not user.refresh_tokens

    stored = _stored(hass_storage)
    assert stored["phase"] == IdentityPhase.CREATED
    assert stored["system_user_id"] == user.id
    assert stored["disabled"] is False
    assert set(stored) == {"phase", "system_user_id", "nonce", "disabled"}


async def test_restart_does_not_duplicate(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test restarts reuse the identity by ID and confirm it."""
    first = await _start(hass)
    second = await _start(hass)
    third = await _start(hass)

    assert len(await bridge_users(hass)) == 1
    assert second.state.status is IdentityStatus.READY
    assert second.state.confirmed is True
    assert third.state.user is first.state.user
    assert _stored(hass_storage)["phase"] == IdentityPhase.CONFIRMED
    assert _stored(hass_storage)["nonce"] is None


async def test_owner_created_after_system_user(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test the system user does not take the owner role."""
    await _start(hass)

    owner = await hass.auth.async_create_user("Owner", group_ids=[GROUP_ID_ADMIN])

    assert owner.is_owner
    assert await hass.auth.async_get_owner() is owner


async def _normal_homonym(hass: HomeAssistant) -> User:
    return await hass.auth.async_create_user(SYSTEM_USER_NAME)


async def _system_homonym(hass: HomeAssistant) -> User:
    return await hass.auth.async_create_system_user(SYSTEM_USER_NAME)


@pytest.mark.parametrize(
    "make_homonym",
    [
        pytest.param(_normal_homonym, id="normal"),
        pytest.param(_system_homonym, id="system"),
    ],
)
async def test_name_collision_fails_closed(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    make_homonym: Callable[[HomeAssistant], Awaitable[User]],
) -> None:
    """Test an existing user with the same name is never adopted."""
    homonym = await make_homonym(hass)

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.NAME_COLLISION
    assert identity.state.user is None
    assert await bridge_users(hass) == [homonym]
    assert STORAGE_KEY not in hass_storage


async def test_saved_id_missing_fails_closed(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a confirmed ID that no longer exists is not regenerated."""
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CONFIRMED, system_user_id="does-not-exist"
    )

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.USER_MISSING
    assert await bridge_users(hass) == []
    assert _stored(hass_storage)["system_user_id"] == "does-not-exist"


async def _normal_user(hass: HomeAssistant) -> User:
    await hass.auth.async_create_user("Owner")
    return await hass.auth.async_create_user(SYSTEM_USER_NAME)


async def _owner(hass: HomeAssistant) -> User:
    return await hass.auth.async_create_user(SYSTEM_USER_NAME)


async def _other_system_user(hass: HomeAssistant) -> User:
    return await hass.auth.async_create_system_user("Other")


async def _admin_system_user(hass: HomeAssistant) -> User:
    return await hass.auth.async_create_system_user(
        SYSTEM_USER_NAME, group_ids=[GROUP_ID_ADMIN]
    )


async def _system_user_with_credentials(hass: HomeAssistant) -> User:
    user = await hass.auth.async_create_system_user(SYSTEM_USER_NAME)
    user.credentials.append(
        Credentials(auth_provider_type="homeassistant", auth_provider_id=None, data={})
    )
    return user


@pytest.mark.parametrize(
    "make_user",
    [
        pytest.param(_normal_user, id="normal_user"),
        pytest.param(_owner, id="owner"),
        pytest.param(_other_system_user, id="other_system_user"),
        pytest.param(_admin_system_user, id="admin_system_user"),
        pytest.param(_system_user_with_credentials, id="with_credentials"),
    ],
)
async def test_saved_id_altered_fails_closed(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    make_user: Callable[[HomeAssistant], Awaitable[User]],
) -> None:
    """Test a stored ID pointing to an unexpected user fails closed."""
    user = await make_user(hass)
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CONFIRMED, system_user_id=user.id
    )
    users_before = len(await hass.auth.async_get_users())

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.USER_MISMATCH
    assert len(await hass.auth.async_get_users()) == users_before


async def test_inactive_user_not_reactivated(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a deactivated system user stays deactivated across restarts."""
    identity = await _start(hass)
    user = identity.state.user
    assert user is not None
    await hass.auth.async_deactivate_user(user)

    for _ in range(2):
        identity = await _start(hass)
        assert identity.state.status is IdentityStatus.INACTIVE
        assert not user.is_active

    assert len(await bridge_users(hass)) == 1


async def test_disabled_flag_prevents_creation(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a disabled bridge never creates its identity."""
    hass_storage[STORAGE_KEY] = identity_record(disabled=True)

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.DISABLED
    assert await bridge_users(hass) == []


async def test_disable_persists_across_restart(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test disabling survives restarts and is never cleared automatically."""
    identity = await _start(hass)
    user = identity.state.user
    await identity.async_disable()

    for _ in range(2):
        identity = await _start(hass)
        assert identity.state.status is IdentityStatus.DISABLED
        assert identity.state.user is user

    assert _stored(hass_storage)["disabled"] is True
    assert len(await bridge_users(hass)) == 1
    assert user is not None
    assert not user.refresh_tokens


async def test_disabled_user_deleted_not_recreated(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a disabled bridge whose user was removed is not recreated."""
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CONFIRMED, system_user_id="removed", disabled=True
    )

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.DISABLED
    assert await bridge_users(hass) == []


async def test_storage_read_error_fails_closed(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an unreadable storage blocks the bridge without creating users."""
    with patch(
        "homeassistant.components.cloud_bridge.system_user.Store.async_load",
        side_effect=HomeAssistantError("corrupt"),
    ):
        identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.STORAGE_ERROR
    assert await bridge_users(hass) == []
    with pytest.raises(ValueError):
        await identity.async_reset()


@pytest.mark.parametrize(
    "data",
    [
        pytest.param([], id="not_a_dict"),
        pytest.param({"system_user_id": "abc"}, id="missing_keys"),
        pytest.param(
            {
                "phase": "bogus",
                "system_user_id": None,
                "nonce": None,
                "disabled": False,
            },
            id="unknown_phase",
        ),
        pytest.param(
            {"phase": None, "system_user_id": None, "nonce": None, "disabled": "no"},
            id="disabled_not_bool",
        ),
        pytest.param(
            {
                "phase": "confirmed",
                "system_user_id": None,
                "nonce": None,
                "disabled": False,
            },
            id="confirmed_without_id",
        ),
        pytest.param(
            {
                "phase": "creating",
                "system_user_id": None,
                "nonce": None,
                "disabled": False,
            },
            id="creating_without_nonce",
        ),
        pytest.param(
            {
                "phase": "created",
                "system_user_id": "abc",
                "nonce": None,
                "disabled": False,
            },
            id="created_without_nonce",
        ),
        pytest.param(
            {
                "phase": None,
                "system_user_id": None,
                "nonce": None,
                "disabled": False,
                "refresh_token": "x",
            },
            id="extra_key",
        ),
        pytest.param(
            {
                "phase": "confirmed",
                "system_user_id": 1,
                "nonce": None,
                "disabled": False,
            },
            id="user_id_not_str",
        ),
        pytest.param(
            {
                "phase": "creating",
                "system_user_id": None,
                "nonce": 1,
                "disabled": False,
            },
            id="nonce_not_str",
        ),
    ],
)
async def test_invalid_storage_fails_closed(
    hass: HomeAssistant, hass_storage: dict[str, Any], data: Any
) -> None:
    """Test a malformed record blocks the bridge without creating users."""
    hass_storage[STORAGE_KEY] = {"version": 1, "key": STORAGE_KEY, "data": data}

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.STORAGE_INVALID
    assert await bridge_users(hass) == []


async def test_storage_write_error_before_creation(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test no user is created if the nonce cannot be persisted."""
    with patch(
        "homeassistant.components.cloud_bridge.system_user.Store.async_save",
        side_effect=OSError("disk full"),
    ):
        identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.STORAGE_ERROR
    assert await bridge_users(hass) == []


async def test_crash_between_create_and_save_reconciles(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an orphan left by a failed ID save is adopted by nonce only."""
    store_save = CloudBridgeIdentity._async_save
    calls = 0

    async def fail_second_save(self: CloudBridgeIdentity, data: Any) -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            return False
        return await store_save(self, data)

    with patch.object(CloudBridgeIdentity, "_async_save", fail_second_save):
        identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.STORAGE_ERROR
    (orphan,) = await bridge_users(hass)
    assert orphan.name is not None
    assert orphan.name.startswith(SYSTEM_USER_PENDING_PREFIX)
    assert _stored(hass_storage)["phase"] == IdentityPhase.CREATING

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.READY
    assert identity.state.user is orphan
    assert orphan.name == SYSTEM_USER_NAME
    assert await bridge_users(hass) == [orphan]
    assert _stored(hass_storage)["system_user_id"] == orphan.id


async def test_creating_without_orphan_creates_user(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a creation interrupted before the user existed is resumed."""
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CREATING, nonce=NONCE
    )

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.READY
    assert len(await bridge_users(hass)) == 1


async def test_creating_does_not_adopt_homonym(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test reconciliation never adopts a user by its final name."""
    homonym = await hass.auth.async_create_system_user(SYSTEM_USER_NAME)
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CREATING, nonce=NONCE
    )

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.NAME_COLLISION
    assert await bridge_users(hass) == [homonym]


async def _orphan_with_refresh_token(hass: HomeAssistant) -> None:
    orphan = await hass.auth.async_create_system_user(
        PENDING_NAME, group_ids=[GROUP_ID_USER]
    )
    await hass.auth.async_create_refresh_token(orphan)


async def _inactive_orphan(hass: HomeAssistant) -> None:
    orphan = await hass.auth.async_create_system_user(
        PENDING_NAME, group_ids=[GROUP_ID_USER]
    )
    await hass.auth.async_deactivate_user(orphan)


async def _normal_orphan(hass: HomeAssistant) -> None:
    await hass.auth.async_create_user(PENDING_NAME)


async def _duplicate_orphans(hass: HomeAssistant) -> None:
    await hass.auth.async_create_system_user(PENDING_NAME, group_ids=[GROUP_ID_USER])
    await hass.auth.async_create_system_user(PENDING_NAME, group_ids=[GROUP_ID_USER])


@pytest.mark.parametrize(
    "make_orphan",
    [
        pytest.param(_orphan_with_refresh_token, id="has_refresh_token"),
        pytest.param(_inactive_orphan, id="inactive"),
        pytest.param(_normal_orphan, id="not_system_generated"),
        pytest.param(_duplicate_orphans, id="duplicate"),
    ],
)
async def test_creating_rejects_unsafe_orphan(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    make_orphan: Callable[[HomeAssistant], Awaitable[None]],
) -> None:
    """Test an orphan that is not pristine is not adopted."""
    await hass.auth.async_create_user("Owner")
    await make_orphan(hass)
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CREATING, nonce=NONCE
    )
    users_before = len(await hass.auth.async_get_users())

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.RECONCILE_REJECTED
    assert len(await hass.auth.async_get_users()) == users_before


async def test_created_with_pending_name_is_confirmed(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a crash before the rename is completed on the next start."""
    user = await hass.auth.async_create_system_user(PENDING_NAME)
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CREATED, system_user_id=user.id, nonce=NONCE
    )

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.READY
    assert identity.state.confirmed is True
    assert user.name == SYSTEM_USER_NAME
    assert _stored(hass_storage)["phase"] == IdentityPhase.CONFIRMED


async def test_confirmed_rejects_pending_name(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test the pending name is only accepted before confirmation."""
    user = await hass.auth.async_create_system_user(PENDING_NAME)
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CONFIRMED, system_user_id=user.id
    )

    identity = await _start(hass)

    assert identity.state.error is IdentityError.USER_MISMATCH


async def test_unconfirmed_user_not_persisted_is_recreated(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a user lost by the delayed auth save is created again."""
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CREATED, system_user_id="lost", nonce=NONCE
    )

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.READY
    (user,) = await bridge_users(hass)
    assert user.id != "lost"
    assert _stored(hass_storage)["system_user_id"] == user.id


async def test_create_failure_fails_closed(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an auth error during creation blocks the bridge."""
    with patch.object(
        hass.auth, "async_create_system_user", side_effect=ValueError("boom")
    ):
        identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.CREATE_FAILED


async def test_unexpected_error_fails_closed(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an unexpected exception is contained."""
    with patch.object(hass.auth, "async_get_users", side_effect=RuntimeError("boom")):
        identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.UNEXPECTED


async def test_reset_allows_explicit_recovery(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a blocked identity is recreated only after an explicit reset."""
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CONFIRMED, system_user_id="does-not-exist"
    )
    identity = await _start(hass)
    assert identity.state.error is IdentityError.USER_MISSING

    await identity.async_reset()
    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.READY
    assert len(await bridge_users(hass)) == 1


async def test_reset_refused_when_ready(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a working identity cannot be reset."""
    identity = await _start(hass)

    with pytest.raises(ValueError):
        await identity.async_reset()


async def test_confirmation_save_error_fails_closed(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test the identity is blocked if the confirmation cannot be saved."""
    await _start(hass)

    with patch(
        "homeassistant.components.cloud_bridge.system_user.Store.async_save",
        side_effect=OSError("disk full"),
    ):
        identity = await _start(hass)

    assert identity.state.status is IdentityStatus.ERROR
    assert identity.state.error is IdentityError.STORAGE_ERROR
    assert _stored(hass_storage)["phase"] == IdentityPhase.CREATED
    assert len(await bridge_users(hass)) == 1


async def test_identity_without_group_is_migrated(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an identity created without the user group receives it."""
    user = await hass.auth.async_create_system_user(SYSTEM_USER_NAME)
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CONFIRMED, system_user_id=user.id
    )

    identity = await _start(hass)

    assert identity.state.status is IdentityStatus.READY
    assert [group.id for group in user.groups] == [GROUP_ID_USER]
    assert not user.is_admin


async def test_orphan_without_group_is_rejected(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test reconciliation only adopts users created exactly as expected."""
    await hass.auth.async_create_system_user(PENDING_NAME)
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CREATING, nonce=NONCE
    )

    identity = await _start(hass)

    assert identity.state.error is IdentityError.RECONCILE_REJECTED
