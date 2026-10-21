"""Tests for the Cloud Bridge installation credentials."""

from typing import Any

import pytest

from homeassistant.components.cloud_bridge.const import (
    CREDENTIALS_STORAGE_KEY,
    SIGN_AUTH,
)
from homeassistant.components.cloud_bridge.credentials import (
    CredentialsError,
    InstallationCredentials,
    public_key_b64,
    signing_payload,
    verify_signature,
)
from homeassistant.core import HomeAssistant

PAYLOAD = signing_payload(SIGN_AUTH, "ha-001", "nonce")


async def _loaded(hass: HomeAssistant) -> InstallationCredentials:
    credentials = InstallationCredentials(hass)
    await credentials.async_load()
    return credentials


async def test_generate_sign_and_persist(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test a generated key signs, persists and is reloaded."""
    credentials = await _loaded(hass)
    assert not credentials.has_key

    public_key = await credentials.async_generate()
    signature = credentials.sign(PAYLOAD)

    assert verify_signature(public_key, signature, PAYLOAD)
    assert not verify_signature(public_key, signature, PAYLOAD + b"x")
    assert set(hass_storage[CREDENTIALS_STORAGE_KEY]["data"]) == {
        "private_key",
        "pending_private_key",
    }
    reloaded = await _loaded(hass)
    assert reloaded.public_key == public_key


async def test_generate_refuses_to_overwrite(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an existing key is never silently replaced."""
    credentials = await _loaded(hass)
    await credentials.async_generate()

    with pytest.raises(CredentialsError):
        await credentials.async_generate()


async def test_keys_are_unique_per_installation(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test two installations never share a key or a valid signature."""
    first = InstallationCredentials(hass)
    second = InstallationCredentials(hass)
    first_key = await first.async_generate()
    await second.async_destroy()
    second_key = await second.async_generate()

    assert first_key != second_key
    assert not verify_signature(second_key, first.sign(PAYLOAD), PAYLOAD)


@pytest.mark.parametrize(
    "data",
    [
        pytest.param({"private_key": 1, "pending_private_key": None}, id="not_str"),
        pytest.param({"private_key": "!!!", "pending_private_key": None}, id="bad"),
        pytest.param({"pending_private_key": None}, id="missing"),
        pytest.param({"private_key": "AAAA", "pending_private_key": None}, id="short"),
    ],
)
async def test_corrupt_record_raises(
    hass: HomeAssistant, hass_storage: dict[str, Any], data: dict[str, Any]
) -> None:
    """Test a corrupt record is reported instead of replaced."""
    hass_storage[CREDENTIALS_STORAGE_KEY] = {"version": 1, "data": data}

    with pytest.raises(CredentialsError):
        await _loaded(hass)


async def test_rotation_commit_and_abort(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test the pending key survives restarts until committed or aborted."""
    credentials = await _loaded(hass)
    old_key = await credentials.async_generate()

    pending = await credentials.async_begin_rotation()
    reloaded = await _loaded(hass)
    assert reloaded.has_pending_key
    assert reloaded.public_key == old_key
    assert verify_signature(
        public_key_b64(pending), reloaded.sign(PAYLOAD, pending=True), PAYLOAD
    )

    await reloaded.async_abort_rotation()
    assert (await _loaded(hass)).public_key == old_key

    pending = await reloaded.async_begin_rotation()
    await reloaded.async_commit_rotation()
    committed = await _loaded(hass)
    assert committed.public_key == public_key_b64(pending)
    assert not committed.has_pending_key
    with pytest.raises(CredentialsError):
        await committed.async_commit_rotation()
    with pytest.raises(CredentialsError):
        committed.sign(PAYLOAD, pending=True)


async def test_destroy_removes_keys(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test destroyed keys are gone from memory and storage."""
    credentials = await _loaded(hass)
    await credentials.async_generate()

    await credentials.async_destroy()

    assert not credentials.has_key
    assert CREDENTIALS_STORAGE_KEY not in hass_storage
    with pytest.raises(CredentialsError):
        credentials.sign(PAYLOAD)


def test_verify_rejects_garbage() -> None:
    """Test signature verification never raises."""
    assert not verify_signature("not-a-key", "not-a-signature", PAYLOAD)
