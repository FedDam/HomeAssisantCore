"""End-to-end tests of the Cloud Bridge against a fake backend."""

from datetime import timedelta
from typing import Any
from unittest.mock import patch
import uuid

import pytest

from homeassistant.components.cloud_bridge.cloud_client import CloudClientError
from homeassistant.components.cloud_bridge.const import (
    CREDENTIALS_STORAGE_KEY,
    LINK_STORAGE_KEY,
    STORAGE_KEY,
    CommandStatus,
    LinkState,
)
from homeassistant.components.cloud_bridge.credentials import public_key_b64
from homeassistant.components.cloud_bridge.provisioning import LinkError
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.util import dt as dt_util

from .conftest import identity_record, pair_bridge, restart_bridge, setup_bridge
from .fake_backend import PAIRING_CODE, FakeBackend

from tests.common import async_mock_service

LIGHT = "light.kitchen"


def _command(**overrides: Any) -> dict[str, Any]:
    message = {
        "type": "command",
        "command_id": str(uuid.uuid4()),
        "action": "light.turn_on",
        "entity_id": LIGHT,
        "expires_at": (dt_util.utcnow() + timedelta(seconds=30)).isoformat(),
    }
    message.update(overrides)
    return message


def _link_record(state: LinkState, url: str) -> dict[str, Any]:
    return {
        "version": 1,
        "data": {
            "state": state,
            "installation_id": "ha-001",
            "cloud_url": url,
            "exposed_entities": [],
            "audit": [],
        },
    }


@pytest.fixture(autouse=True)
def entities(hass: HomeAssistant) -> None:
    """Create a few entities."""
    hass.states.async_set(
        LIGHT,
        "off",
        {"friendly_name": "Kitchen", "brightness": 0, "ip_address": "10.0.0.2"},
    )
    hass.states.async_set("light.private", "off")
    hass.states.async_set("lock.front_door", "locked")


@pytest.mark.usefixtures("hass_storage")
async def test_pair_connect_and_sync(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test pairing, authentication, snapshot and state updates."""
    bridge = await setup_bridge(hass)
    await bridge.async_set_exposed_entities([LIGHT])

    await pair_bridge(bridge, fake_backend)
    await fake_backend.wait_for(lambda: bool(fake_backend.messages("snapshot")))

    assert bridge.link.state is LinkState.ACTIVE
    assert bridge.link.installation_id == "ha-001"
    assert fake_backend.auth_results == ["auth_ok"]
    (snapshot,) = fake_backend.messages("snapshot")
    (entity,) = snapshot["entities"]
    assert entity["entity_id"] == LIGHT
    # Attributes outside the allowlist are never shared.
    assert entity["attributes"] == {"friendly_name": "Kitchen", "brightness": 0}

    hass.states.async_set("light.private", "on")
    hass.states.async_set(LIGHT, "on", {"friendly_name": "Kitchen"})
    await fake_backend.wait_for(lambda: bool(fake_backend.messages("state")))

    (update,) = fake_backend.messages("state")
    assert update["entity_id"] == LIGHT
    assert update["state"] == "on"
    assert update["revision"] > snapshot["revision"]

    hass.states.async_remove(LIGHT)
    await fake_backend.wait_for(lambda: bool(fake_backend.messages("state_removed")))


@pytest.mark.usefixtures("hass_storage")
async def test_command_round_trip(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test commands are executed once and replies are structured."""
    calls = async_mock_service(hass, "light", "turn_on")
    bridge = await setup_bridge(hass)
    await bridge.async_set_exposed_entities([LIGHT])
    await pair_bridge(bridge, fake_backend)

    command = _command()
    await fake_backend.send(command)
    await fake_backend.send(command)
    await fake_backend.send(_command(installation_id="ha-002"))
    await fake_backend.send(_command(entity_id="light.private"))
    await fake_backend.wait_for(
        lambda: len(fake_backend.messages("command_result")) == 4
    )

    results = fake_backend.messages("command_result")
    assert [result["status"] for result in results] == [
        CommandStatus.EXECUTED,
        CommandStatus.DUPLICATE,
        CommandStatus.REJECTED,
        CommandStatus.REJECTED,
    ]
    assert results[2]["error"] == "installation_mismatch"
    assert results[3]["error"] == "entity_not_allowed"
    assert len(calls) == 1
    user = bridge.identity.state.user
    assert user is not None
    assert calls[0].context.user_id == user.id


@pytest.mark.usefixtures("hass_storage")
async def test_replay_after_reconnect_is_not_executed(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test replayed and expired commands are refused after a reconnection."""
    calls = async_mock_service(hass, "light", "turn_on")
    bridge = await setup_bridge(hass)
    await bridge.async_set_exposed_entities([LIGHT])
    await pair_bridge(bridge, fake_backend)
    command = _command()
    await fake_backend.send(command)
    await fake_backend.wait_for(lambda: bool(fake_backend.messages("command_result")))

    bridge = await restart_bridge(hass, bridge)
    await fake_backend.wait_for(lambda: fake_backend.authenticated_sessions == 2)
    await fake_backend.send(command)
    await fake_backend.send(
        _command(expires_at=(dt_util.utcnow() - timedelta(seconds=1)).isoformat())
    )
    await fake_backend.wait_for(
        lambda: len(fake_backend.messages("command_result")) == 3
    )

    results = fake_backend.messages("command_result")
    assert results[1]["status"] == CommandStatus.DUPLICATE
    assert results[2]["error"] == "expired"
    assert len(calls) == 1


async def test_pair_requires_ready_identity(
    hass: HomeAssistant, hass_storage: dict[str, Any], fake_backend: FakeBackend
) -> None:
    """Test no credential is issued while the identity is blocked."""
    hass_storage[STORAGE_KEY] = identity_record(
        phase="confirmed", system_user_id="missing"
    )
    bridge = await setup_bridge(hass)

    with pytest.raises(LinkError) as err:
        await bridge.async_pair(PAIRING_CODE, fake_backend.url)

    assert err.value.code == "not_operational"
    assert fake_backend.pair_requests == []
    assert CREDENTIALS_STORAGE_KEY not in hass_storage


async def test_pairing_failure_rolls_back(
    hass: HomeAssistant, hass_storage: dict[str, Any], fake_backend: FakeBackend
) -> None:
    """Test a refused pairing leaves no credentials behind."""
    bridge = await setup_bridge(hass)

    with pytest.raises(LinkError):
        await bridge.async_pair("WRONG-CODE-1", fake_backend.url)

    assert bridge.link.state is LinkState.UNPROVISIONED
    assert not bridge.credentials.has_key
    assert CREDENTIALS_STORAGE_KEY not in hass_storage
    assert bridge.link.audit_log[-1]["event"] == "pairing_failed"
    assert bridge.link.audit_log[-1]["reason"] == "pairing_rejected"


@pytest.mark.parametrize(
    ("url", "code"),
    [
        (None, "missing_cloud_url"),
        ("http://cloud.example.com", "insecure_cloud_url"),
    ],
)
async def test_pair_rejects_bad_backend_url(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    url: str | None,
    code: str,
) -> None:
    """Test pairing never talks to an unsafe backend."""
    bridge = await setup_bridge(hass)

    with pytest.raises(LinkError) as err:
        await bridge.async_pair(PAIRING_CODE, url)

    assert err.value.code == code
    assert bridge.link.state is LinkState.UNPROVISIONED


@pytest.mark.usefixtures("hass_storage")
async def test_pair_twice_is_refused(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a tenant change requires an explicit revocation first."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    fake_backend.pairing_codes["OTHER-TENANT-1"] = "tenant-b"

    with pytest.raises(LinkError) as err:
        await bridge.async_pair("OTHER-TENANT-1", fake_backend.url)

    assert err.value.code == "invalid_state"
    assert len(fake_backend.installations) == 1


async def test_interrupted_pairing_is_discarded(
    hass: HomeAssistant, hass_storage: dict[str, Any], fake_backend: FakeBackend
) -> None:
    """Test a crash during pairing drops the half-created credentials."""
    bridge = await setup_bridge(hass)
    await bridge.credentials.async_generate()
    await bridge.link.async_transition(
        LinkState.PAIRING, "pairing_started", cloud_url=fake_backend.url
    )

    bridge = await restart_bridge(hass, bridge)

    assert bridge.link.state is LinkState.UNPROVISIONED
    assert not bridge.credentials.has_key
    assert bridge.link.audit_log[-1]["event"] == "pairing_interrupted"


async def test_local_revoke_survives_restart(
    hass: HomeAssistant, hass_storage: dict[str, Any], fake_backend: FakeBackend
) -> None:
    """Test a revoked link never reconnects nor recreates its key."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)

    await bridge.async_revoke()

    assert bridge.link.state is LinkState.REVOKED
    assert not bridge.connected
    assert CREDENTIALS_STORAGE_KEY not in hass_storage
    await fake_backend.wait_for(lambda: fake_backend.installations["ha-001"].revoked)

    bridge = await restart_bridge(hass, bridge)
    await hass.async_block_till_done()

    assert bridge.link.state is LinkState.REVOKED
    assert bridge.client is None
    assert not bridge.credentials.has_key
    assert fake_backend.authenticated_sessions == 1
    with pytest.raises(LinkError):
        await bridge.async_resume()


@pytest.mark.usefixtures("hass_storage")
async def test_backend_revoke_message(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test the backend can revoke the installation."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)

    await fake_backend.send({"type": "revoke"})
    await fake_backend.wait_for(lambda: bridge.link.state is LinkState.REVOKED)
    await hass.async_block_till_done()

    assert bridge.link.audit_log[-1]["event"] == "revoked_cloud"
    assert not bridge.credentials.has_key
    assert bridge.client is None


@pytest.mark.usefixtures("hass_storage")
async def test_revoked_on_authentication(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a key revoked on the backend is not used again."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    fake_backend.installations["ha-001"].revoked = True

    await fake_backend.drop_connections()
    await fake_backend.wait_for(lambda: bridge.link.state is LinkState.REVOKED)
    await hass.async_block_till_done()

    assert fake_backend.auth_results == ["auth_ok", "revoked"]
    assert not bridge.credentials.has_key


@pytest.mark.usefixtures("hass_storage")
async def test_invalid_signature_never_repairs(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a refused key keeps retrying with backoff and is never replaced."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    public_key = bridge.credentials.public_key
    fake_backend.installations["ha-001"].public_key = "someone-else"

    await fake_backend.drop_connections()
    await fake_backend.wait_for(
        lambda: fake_backend.auth_results.count("invalid_signature") >= 3
    )

    assert bridge.link.state is LinkState.ACTIVE
    assert bridge.credentials.public_key == public_key
    assert len(fake_backend.pair_requests) == 1
    assert bridge.client is not None
    assert bridge.client.last_error == "auth_failed:invalid_signature"


@pytest.mark.usefixtures("hass_storage")
async def test_reconnect_resends_snapshot(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a dropped connection reconnects and resynchronises."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    await fake_backend.wait_for(lambda: len(fake_backend.messages("snapshot")) == 1)

    await fake_backend.drop_connections()

    await fake_backend.wait_for(lambda: len(fake_backend.messages("snapshot")) == 2)
    assert fake_backend.authenticated_sessions == 2


@pytest.mark.usefixtures("hass_storage")
async def test_bad_challenge_is_retried(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a protocol violation does not revoke or authenticate."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    fake_backend.challenge = {"type": "challenge", "nonce": "short"}

    await fake_backend.drop_connections()
    await fake_backend.wait_for(
        lambda: bridge.client is not None and bridge.client.last_error is not None
    )

    assert bridge.link.state is LinkState.ACTIVE
    assert bridge.client.last_error == "ProtocolError"


async def test_suspend_and_resume(
    hass: HomeAssistant, hass_storage: dict[str, Any], fake_backend: FakeBackend
) -> None:
    """Test a suspended link stays offline across restarts until resumed."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)

    await bridge.async_suspend()
    await bridge.async_suspend()
    assert not bridge.connected

    bridge = await restart_bridge(hass, bridge)
    assert bridge.link.state is LinkState.SUSPENDED
    assert bridge.client is None

    await bridge.async_resume()
    await fake_backend.wait_for(lambda: bridge.connected)
    assert fake_backend.authenticated_sessions == 2


@pytest.mark.usefixtures("hass_storage")
async def test_reset_only_after_revoke(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test re-pairing needs revoke, reset and a new owner approval."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)

    with pytest.raises(LinkError):
        await bridge.async_reset_link()
    await bridge.async_revoke()
    await bridge.async_reset_link()

    assert bridge.link.state is LinkState.UNPROVISIONED
    assert bridge.link.installation_id is None
    fake_backend.pairing_codes["NEW-CODE-0002"] = "tenant-b"
    await bridge.async_pair("NEW-CODE-0002", fake_backend.url)
    assert bridge.link.installation_id == "ha-002"
    assert fake_backend.installations["ha-002"].tenant == "tenant-b"


async def test_missing_credentials_block_connection(
    hass: HomeAssistant, hass_storage: dict[str, Any], fake_backend: FakeBackend
) -> None:
    """Test an active link without its key stays offline."""
    hass_storage[LINK_STORAGE_KEY] = _link_record(LinkState.ACTIVE, fake_backend.url)

    bridge = await setup_bridge(hass)

    assert bridge.blocked_reason == "credentials_missing"
    assert bridge.client is None
    with pytest.raises(LinkError):
        await bridge.async_pair(PAIRING_CODE, fake_backend.url)


@pytest.mark.parametrize(
    ("key", "data"),
    [
        (LINK_STORAGE_KEY, {"state": "x"}),
        (CREDENTIALS_STORAGE_KEY, {"private_key": 1}),
        ("cloud_bridge.commands", {"seen": "x"}),
    ],
)
async def test_corrupt_records_block_bridge(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    key: str,
    data: dict[str, Any],
) -> None:
    """Test any unreadable record keeps the bridge offline."""
    hass_storage[key] = {"version": 1, "data": data}

    bridge = await setup_bridge(hass)

    assert bridge.blocked_reason is not None
    assert bridge.blocked_reason.endswith("_storage_invalid")
    assert not bridge.can_operate


@pytest.mark.usefixtures("hass_storage")
async def test_rotate_key(hass: HomeAssistant, fake_backend: FakeBackend) -> None:
    """Test the new key is used after a confirmed rotation."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    old_key = bridge.credentials.public_key

    await bridge.async_rotate_key()

    installation = fake_backend.installations["ha-001"]
    assert installation.public_key == bridge.credentials.public_key != old_key
    assert not bridge.credentials.has_pending_key
    await fake_backend.drop_connections()
    await fake_backend.wait_for(lambda: fake_backend.authenticated_sessions == 2)
    assert "invalid_signature" not in fake_backend.auth_results


@pytest.mark.usefixtures("hass_storage")
async def test_rotate_key_rejected(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a refused rotation keeps the current key."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    old_key = bridge.credentials.public_key
    fake_backend.rotation_response = "rotate_key_failed"

    with pytest.raises(CloudClientError) as err:
        await bridge.async_rotate_key()

    assert err.value.code == "rotation_rejected"
    assert bridge.credentials.public_key == old_key
    assert not bridge.credentials.has_pending_key


@pytest.mark.usefixtures("hass_storage")
async def test_rotation_applied_but_unconfirmed(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a rotation the backend applied without confirming is recovered."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    pending = await bridge.credentials.async_begin_rotation()
    # The backend switched keys but the confirmation never arrived.
    fake_backend.installations["ha-001"].public_key = public_key_b64(pending)

    await fake_backend.drop_connections()
    await fake_backend.wait_for(lambda: not bridge.credentials.has_pending_key)

    assert fake_backend.auth_results == ["auth_ok", "invalid_signature", "auth_ok"]
    assert bridge.credentials.public_key == public_key_b64(pending)
    assert not bridge.credentials.has_pending_key


@pytest.mark.usefixtures("hass_storage")
async def test_rotation_unconfirmed_and_not_applied(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test an unanswered rotation falls back to the current key."""
    bridge = await setup_bridge(hass)
    await pair_bridge(bridge, fake_backend)
    old_key = bridge.credentials.public_key
    fake_backend.rotation_response = None

    with (
        patch(
            "homeassistant.components.cloud_bridge.cloud_client.ROTATE_TIMEOUT", 0.05
        ),
        pytest.raises(CloudClientError) as err,
    ):
        await bridge.async_rotate_key()
    assert err.value.code == "rotation_unconfirmed"
    assert bridge.credentials.has_pending_key

    await fake_backend.drop_connections()
    await fake_backend.wait_for(lambda: not bridge.credentials.has_pending_key)
    assert fake_backend.auth_results == ["auth_ok", "auth_ok"]
    assert bridge.credentials.public_key == old_key


@pytest.mark.usefixtures("hass_storage")
async def test_rotate_requires_connection(hass: HomeAssistant) -> None:
    """Test rotation needs an authenticated session."""
    bridge = await setup_bridge(hass)

    with pytest.raises(CloudClientError):
        await bridge.async_rotate_key()


@pytest.mark.usefixtures("hass_storage")
async def test_sensitive_entities_cannot_be_shared(hass: HomeAssistant) -> None:
    """Test locks and similar entities need a separate policy."""
    bridge = await setup_bridge(hass)

    for entity_ids in (["lock.front_door"], ["not an entity"], ["light.x"] * 501):
        with pytest.raises(LinkError):
            await bridge.async_set_exposed_entities(entity_ids)
    assert bridge.link.exposed_entities == []


@pytest.mark.usefixtures("socket_enabled")
async def test_cloud_offline_keeps_home_assistant_running(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test an unreachable backend never affects local control."""
    calls = async_mock_service(hass, "light", "turn_on")
    hass_storage[LINK_STORAGE_KEY] = _link_record(
        LinkState.ACTIVE, "http://127.0.0.1:1"
    )
    hass_storage[CREDENTIALS_STORAGE_KEY] = {
        "version": 1,
        "data": {
            "private_key": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "pending_private_key": None,
        },
    }

    bridge = await setup_bridge(hass)
    await hass.async_start()
    await hass.async_block_till_done()
    assert bridge.client is not None
    client = bridge.client
    await FakeBackend().wait_for(lambda: client.last_error is not None)

    await hass.services.async_call("light", "turn_on", blocking=True)
    assert hass.state is CoreState.running
    assert len(calls) == 1
    assert not bridge.connected


@pytest.mark.usefixtures("hass_storage")
async def test_entity_becoming_sensitive_stops_sharing(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test an entity whose device class turns sensitive is withdrawn."""
    hass.states.async_set("cover.shed", "closed", {"device_class": "shutter"})
    bridge = await setup_bridge(hass)
    await bridge.async_set_exposed_entities(["cover.shed"])
    await pair_bridge(bridge, fake_backend)

    hass.states.async_set("cover.shed", "closed", {"device_class": "garage"})
    await fake_backend.wait_for(lambda: bool(fake_backend.messages("state_removed")))

    assert fake_backend.messages("state") == []
