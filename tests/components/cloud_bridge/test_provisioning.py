"""Tests for the Cloud Bridge link state machine and pairing request."""

from typing import Any

import pytest

from homeassistant.components.cloud_bridge.const import LINK_STORAGE_KEY, LinkState
from homeassistant.components.cloud_bridge.credentials import InstallationCredentials
from homeassistant.components.cloud_bridge.provisioning import (
    LinkError,
    LinkManager,
    PairingError,
    async_request_pairing,
    validate_cloud_url,
    websocket_url,
)
from homeassistant.core import HomeAssistant

from .fake_backend import PAIRING_CODE, TENANT, FakeBackend


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://cloud.example.com", "https://cloud.example.com"),
        ("https://cloud.example.com:8443/base/", "https://cloud.example.com:8443/base"),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://localhost", "http://localhost"),
        ("http://[::1]:9000", "http://[::1]:9000"),
    ],
)
def test_valid_cloud_url(url: str, expected: str) -> None:
    """Test accepted backend URLs."""
    assert validate_cloud_url(url) == expected


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://cloud.example.com", "insecure_cloud_url"),
        ("http://192.168.1.10", "insecure_cloud_url"),
        ("ftp://cloud.example.com", "invalid_cloud_url"),
        ("https://user:pass@cloud.example.com", "invalid_cloud_url"),
        ("https://cloud.example.com/?token=x", "invalid_cloud_url"),
        ("https://cloud.example.com/#x", "invalid_cloud_url"),
        ("https://", "invalid_cloud_url"),
        ("https://cloud.example.com:99999", "invalid_cloud_url"),
    ],
)
def test_invalid_cloud_url(url: str, code: str) -> None:
    """Test rejected backend URLs."""
    with pytest.raises(LinkError) as err:
        validate_cloud_url(url)
    assert err.value.code == code


def test_websocket_url() -> None:
    """Test the WebSocket URL keeps TLS."""
    assert (
        websocket_url("https://c.example.com") == "wss://c.example.com/api/bridge/v1/ws"
    )
    assert websocket_url("http://127.0.0.1:1") == "ws://127.0.0.1:1/api/bridge/v1/ws"


async def test_transitions_are_explicit_and_idempotent(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> None:
    """Test the state machine and its audit trail."""
    link = LinkManager(hass)
    await link.async_load()

    with pytest.raises(LinkError):
        await link.async_transition(LinkState.ACTIVE, "skip_pairing")
    assert await link.async_transition(
        LinkState.PAIRING, "pairing_started", cloud_url="https://c.example.com"
    )
    assert await link.async_transition(
        LinkState.ACTIVE, "paired", installation_id="ha-001"
    )
    assert not await link.async_transition(LinkState.ACTIVE, "paired")
    assert await link.async_transition(LinkState.REVOKED, "revoked_local")
    with pytest.raises(LinkError):
        await link.async_transition(LinkState.ACTIVE, "reactivate")

    reloaded = LinkManager(hass)
    await reloaded.async_load()
    assert reloaded.state is LinkState.REVOKED
    assert [entry["event"] for entry in reloaded.audit_log] == [
        "pairing_started",
        "paired",
        "revoked_local",
    ]
    assert hass_storage[LINK_STORAGE_KEY]["data"]["installation_id"] == "ha-001"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param({"state": "active"}, id="missing_keys"),
        pytest.param(
            {
                "state": "bogus",
                "installation_id": None,
                "cloud_url": None,
                "exposed_entities": [],
                "audit": [],
            },
            id="unknown_state",
        ),
        pytest.param(
            {
                "state": "active",
                "installation_id": None,
                "cloud_url": "https://c.example.com",
                "exposed_entities": [],
                "audit": [],
            },
            id="active_without_installation",
        ),
        pytest.param(
            {
                "state": "unprovisioned",
                "installation_id": None,
                "cloud_url": None,
                "exposed_entities": [1],
                "audit": [],
            },
            id="bad_entities",
        ),
        pytest.param(
            {
                "state": "unprovisioned",
                "installation_id": 5,
                "cloud_url": None,
                "exposed_entities": [],
                "audit": [],
            },
            id="bad_installation_id",
        ),
        pytest.param(
            {
                "state": "unprovisioned",
                "installation_id": None,
                "cloud_url": None,
                "exposed_entities": [],
                "audit": {},
            },
            id="bad_audit",
        ),
    ],
)
async def test_invalid_link_record(
    hass: HomeAssistant, hass_storage: dict[str, Any], data: dict[str, Any]
) -> None:
    """Test a corrupt link record is reported."""
    hass_storage[LINK_STORAGE_KEY] = {"version": 1, "data": data}

    with pytest.raises(LinkError):
        await LinkManager(hass).async_load()


async def _pair(hass: HomeAssistant, backend: FakeBackend, code: str) -> str:
    credentials = InstallationCredentials(hass)
    public_key = await credentials.async_generate()
    return await async_request_pairing(
        hass, backend.url, code, public_key, credentials.sign
    )


@pytest.mark.usefixtures("hass_storage")
async def test_pairing_registers_key_with_proof(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test pairing proves possession and the tenant comes from the code."""
    installation_id = await _pair(hass, fake_backend, PAIRING_CODE)

    installation = fake_backend.installations[installation_id]
    assert installation.tenant == TENANT
    (request,) = fake_backend.pair_requests
    assert set(request) == {
        "protocol",
        "pairing_code",
        "public_key",
        "timestamp",
        "proof",
    }
    # Single-use code.
    with pytest.raises(PairingError) as err:
        await _pair(hass, fake_backend, PAIRING_CODE)
    assert err.value.code == "pairing_rejected"


@pytest.mark.parametrize(
    ("status", "response", "code"),
    [
        (403, {"error": "x"}, "pairing_rejected"),
        (410, {"error": "expired"}, "pairing_rejected"),
        (500, {"error": "x"}, "cloud_error"),
        (302, {}, "cloud_error"),
        (200, {"installation_id": "../../etc"}, "cloud_error"),
        (200, {"installation_id": 5}, "cloud_error"),
        (200, ["not", "a", "dict"], "cloud_error"),
    ],
)
@pytest.mark.usefixtures("hass_storage")
async def test_pairing_backend_errors(
    hass: HomeAssistant,
    fake_backend: FakeBackend,
    status: int,
    response: Any,
    code: str,
) -> None:
    """Test backend failures are reported without trusting the response."""
    fake_backend.pair_status = status
    fake_backend.pair_response = response

    with pytest.raises(PairingError) as err:
        await _pair(hass, fake_backend, PAIRING_CODE)
    assert err.value.code == code


@pytest.mark.usefixtures("hass_storage")
async def test_pairing_rejects_malformed_code(
    hass: HomeAssistant, fake_backend: FakeBackend
) -> None:
    """Test a malformed code is never sent."""
    with pytest.raises(PairingError) as err:
        await _pair(hass, fake_backend, "bad code?")
    assert err.value.code == "invalid_pairing_code"
    assert fake_backend.pair_requests == []


@pytest.mark.usefixtures("hass_storage", "socket_enabled")
async def test_pairing_backend_unreachable(hass: HomeAssistant) -> None:
    """Test an unreachable backend."""
    credentials = InstallationCredentials(hass)
    public_key = await credentials.async_generate()

    with pytest.raises(PairingError) as err:
        await async_request_pairing(
            hass, "http://127.0.0.1:1", PAIRING_CODE, public_key, credentials.sign
        )
    assert err.value.code == "cloud_unreachable"
