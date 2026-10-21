"""Tests for the Cloud Bridge setup."""

from typing import Any
from unittest.mock import patch

import pytest

from homeassistant import bootstrap
from homeassistant.components.cloud_bridge.const import (
    DATA_BRIDGE,
    DOMAIN,
    ISSUE_IDENTITY_ERROR,
    STORAGE_KEY,
    SYSTEM_USER_NAME,
    IdentityError,
    IdentityPhase,
    IdentityStatus,
)
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.setup import async_setup_component

from .conftest import bridge_users, identity_record

from tests.common import CLIENT_ID
from tests.typing import ClientSessionGenerator


async def test_setup_creates_identity(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test setup without configuration creates the identity and no token."""
    assert await async_setup_component(hass, DOMAIN, {})

    state = hass.data[DATA_BRIDGE].identity.state
    assert state.status is IdentityStatus.READY
    (user,) = await bridge_users(hass)
    assert state.user is user
    assert not user.refresh_tokens
    assert issue_registry.async_get_issue(DOMAIN, ISSUE_IDENTITY_ERROR) is None


async def test_blocked_identity_does_not_block_startup(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test a failed-closed identity raises a repair issue but setup succeeds."""
    hass_storage[STORAGE_KEY] = identity_record(
        phase=IdentityPhase.CONFIRMED, system_user_id="does-not-exist"
    )

    assert await async_setup_component(hass, DOMAIN, {})
    await hass.async_start()
    await hass.async_block_till_done()

    assert hass.state is CoreState.running
    assert hass.data[DATA_BRIDGE].identity.state.error is IdentityError.USER_MISSING
    issue = issue_registry.async_get_issue(DOMAIN, ISSUE_IDENTITY_ERROR)
    assert issue is not None
    assert issue.severity is ir.IssueSeverity.ERROR
    assert issue.translation_placeholders == {"reason": "user_missing"}


async def test_unexpected_error_does_not_block_startup(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test an unexpected exception only disables the bridge."""
    with patch.object(hass.auth, "async_get_users", side_effect=RuntimeError("boom")):
        assert await async_setup_component(hass, DOMAIN, {})

    assert hass.data[DATA_BRIDGE].identity.state.error is IdentityError.UNEXPECTED
    assert issue_registry.async_get_issue(DOMAIN, ISSUE_IDENTITY_ERROR) is not None


async def test_issue_cleared_after_recovery(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test a previous identity issue is removed once the identity is ready."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        ISSUE_IDENTITY_ERROR,
        is_fixable=False,
        severity=ir.IssueSeverity.ERROR,
        translation_key=ISSUE_IDENTITY_ERROR,
        translation_placeholders={"reason": "user_missing"},
    )

    assert await async_setup_component(hass, DOMAIN, {})

    assert issue_registry.async_get_issue(DOMAIN, ISSUE_IDENTITY_ERROR) is None


async def test_disabled_bridge_setup(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test a disabled bridge sets up without identity or issue."""
    hass_storage[STORAGE_KEY] = identity_record(disabled=True)

    assert await async_setup_component(hass, DOMAIN, {})

    assert hass.data[DATA_BRIDGE].identity.state.status is IdentityStatus.DISABLED
    assert await bridge_users(hass) == []
    assert issue_registry.async_get_issue(DOMAIN, ISSUE_IDENTITY_ERROR) is None


@pytest.mark.usefixtures("hass_storage")
async def test_cloud_unavailable_keeps_home_assistant_running(
    hass: HomeAssistant,
) -> None:
    """Test setup needs no network (sockets are blocked in the test suite)."""
    with patch(
        "homeassistant.helpers.aiohttp_client.async_get_clientsession",
        side_effect=AssertionError("network must not be used"),
    ):
        assert await async_setup_component(hass, DOMAIN, {})
        await hass.async_start()
        await hass.async_block_till_done()

    assert hass.state is CoreState.running
    assert hass.data[DATA_BRIDGE].identity.state.status is IdentityStatus.READY


def test_loaded_as_default_integration() -> None:
    """Test bootstrap loads the bridge after auth, outside recovery mode."""
    assert DOMAIN in bootstrap.DEFAULT_INTEGRATIONS
    # Core integrations are set up before hass.auth exists.
    assert DOMAIN not in bootstrap.CORE_INTEGRATIONS
    assert DOMAIN not in bootstrap.DEFAULT_INTEGRATIONS_RECOVERY_MODE


async def test_yaml_config_not_required(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test bootstrap sets up the bridge from an empty configuration."""
    assert DOMAIN in bootstrap._get_domains(hass, {})


@pytest.mark.usefixtures("local_auth")
async def test_onboarding_owner_after_system_user(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    hass_client_no_auth: ClientSessionGenerator,
) -> None:
    """Test onboarding creates the owner after the system user exists."""
    assert await async_setup_component(hass, DOMAIN, {})
    assert await async_setup_component(hass, "person", {})
    assert await async_setup_component(hass, "onboarding", {})
    await hass.async_block_till_done()
    (system_user,) = await bridge_users(hass)

    client = await hass_client_no_auth()
    resp = await client.post(
        "/api/onboarding/users",
        json={
            "client_id": CLIENT_ID,
            "name": "Owner",
            "username": "owner",
            "password": "owner-pass",
            "language": "en",
        },
    )

    assert resp.status == 200
    owner = await hass.auth.async_get_owner()
    assert owner is not None
    assert owner.name == "Owner"
    assert owner is not system_user
    assert not system_user.is_owner
    assert system_user.name == SYSTEM_USER_NAME
