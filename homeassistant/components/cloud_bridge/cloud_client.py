r"""Outbound WebSocket connection to the cloud backend.

Protocol v1 (JSON text frames, at most ``MAX_MESSAGE_SIZE`` bytes):

1. backend -> ``{"type": "challenge", "nonce": "<random>"}``
2. bridge  -> ``{"type": "auth", "protocol": 1, "installation_id": ...,
   "signature": sign("cloud_bridge/auth/v1\n<installation_id>\n<nonce>")}``
3. backend -> ``{"type": "auth_ok"}`` or
   ``{"type": "auth_failed", "reason": "revoked" | "invalid_signature" | ...}``

The backend must derive tenant and installation from this authenticated
session only. TLS certificates are always verified.
"""

import asyncio
from collections.abc import Callable, Coroutine
from contextlib import suppress
import logging
import random
from typing import Any

import aiohttp

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.util.json import json_loads

from .const import (
    CONNECT_TIMEOUT,
    HANDSHAKE_TIMEOUT,
    HEARTBEAT_INTERVAL,
    MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
    RECONNECT_MAX_DELAY,
    RECONNECT_MIN_DELAY,
    ROTATE_TIMEOUT,
    SIGN_AUTH,
    SIGN_ROTATE,
)
from .credentials import InstallationCredentials, public_key_b64, signing_payload

_LOGGER = logging.getLogger(__name__)

SEND_QUEUE_SIZE = 1000
AUTH_FAILURE_REASONS = frozenset(
    {"revoked", "invalid_signature", "unknown_installation", "unsupported_protocol"}
)
REVOKE_NOTICE_TIMEOUT = 5


class CloudClientError(Exception):
    """Raised when an operation needs a connection that is not available."""

    def __init__(self, code: str) -> None:
        """Initialize the error."""
        super().__init__(code)
        self.code = code


class ProtocolError(Exception):
    """Raised when the backend violates the protocol."""


class AuthRevokedError(Exception):
    """Raised when the backend reports the installation as revoked."""


class AuthFailedError(Exception):
    """Raised when authentication fails for another reason."""

    def __init__(self, reason: str, *, retry_now: bool = False) -> None:
        """Initialize the error."""
        super().__init__(reason)
        self.reason = reason
        self.retry_now = retry_now


def backoff_delay(attempt: int) -> float:
    """Return an exponential delay with jitter."""
    cap = min(RECONNECT_MAX_DELAY, RECONNECT_MIN_DELAY * 2 ** min(attempt, 16))
    return random.uniform(cap / 2, cap)


class CloudClient:
    """Maintain the authenticated connection."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        url: str,
        installation_id: str,
        credentials: InstallationCredentials,
        on_connected: Callable[[], None],
        on_disconnected: Callable[[], None],
        on_message: Callable[[dict[str, Any]], Coroutine[Any, Any, None]],
        on_revoked: Callable[[], Coroutine[Any, Any, None]],
    ) -> None:
        """Initialize the client."""
        self.hass = hass
        self._url = url
        self._installation_id = installation_id
        self._credentials = credentials
        self._on_connected = on_connected
        self._on_disconnected = on_disconnected
        self._on_message = on_message
        self._on_revoked = on_revoked
        self._task: asyncio.Task[None] | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(SEND_QUEUE_SIZE)
        self._authenticated = False
        self._stopping = False
        self._use_pending_key = False
        self._rotation_future: asyncio.Future[bool | None] | None = None
        self.last_error: str | None = None

    @property
    def connected(self) -> bool:
        """Return True when authenticated."""
        return self._authenticated

    @callback
    def start(self) -> None:
        """Start connecting in the background."""
        self._stopping = False
        self._task = self.hass.async_create_background_task(
            self._async_run(), "cloud_bridge connection"
        )

    async def async_stop(self, notice: dict[str, Any] | None = None) -> None:
        """Disconnect, optionally sending a last message first."""
        self._stopping = True
        if (ws := self._ws) is not None:
            if notice is not None and self._authenticated:
                with suppress(Exception):
                    async with asyncio.timeout(REVOKE_NOTICE_TIMEOUT):
                        await ws.send_json(notice)
            await ws.close()
        if (task := self._task) is not None and task is not asyncio.current_task():
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    @callback
    def send(self, message: dict[str, Any]) -> None:
        """Queue a message for the backend."""
        if not self._authenticated:
            return
        try:
            self._queue.put_nowait(message)
        except asyncio.QueueFull:
            # Dropping states would desynchronise the backend: reconnect, which
            # resends a full snapshot.
            _LOGGER.warning("Cloud Bridge send queue full; reconnecting")
            if (ws := self._ws) is not None:
                self.hass.async_create_task(ws.close())

    async def async_rotate_key(self) -> None:
        """Rotate the installation key over the authenticated session."""
        if not self._authenticated:
            raise CloudClientError("not_connected")
        if self._rotation_future is not None:
            raise CloudClientError("rotation_in_progress")
        credentials = self._credentials
        pending = await credentials.async_begin_rotation()
        new_public_key = public_key_b64(pending)
        payload = signing_payload(SIGN_ROTATE, self._installation_id, new_public_key)
        future: asyncio.Future[bool | None] = self.hass.loop.create_future()
        self._rotation_future = future
        self.send(
            {
                "type": "rotate_key",
                "new_public_key": new_public_key,
                "signature": credentials.sign(payload),
                "proof": credentials.sign(payload, pending=True),
            }
        )
        try:
            async with asyncio.timeout(ROTATE_TIMEOUT):
                accepted = await future
        except TimeoutError:
            accepted = None
        finally:
            self._rotation_future = None

        if accepted is True:
            await credentials.async_commit_rotation()
            return
        if accepted is False:
            await credentials.async_abort_rotation()
            raise CloudClientError("rotation_rejected")
        # Unknown outcome: keep the pending key, the next authentication
        # tells which key the backend holds.
        raise CloudClientError("rotation_unconfirmed")

    async def _async_run(self) -> None:
        attempt = 0
        while not self._stopping:
            try:
                if await self._async_connect_once():
                    attempt = 0
            except AuthRevokedError:
                _LOGGER.warning("The backend revoked this installation")
                self._stopping = True
                self.hass.async_create_task(self._on_revoked())
                return
            except AuthFailedError as err:
                self.last_error = f"auth_failed:{err.reason}"
                _LOGGER.warning("Cloud Bridge authentication failed: %s", err.reason)
                if err.retry_now:
                    continue
            except (aiohttp.ClientError, TimeoutError, ProtocolError) as err:
                self.last_error = type(err).__name__
                _LOGGER.debug("Cloud Bridge connection error: %s", type(err).__name__)
            if self._stopping:
                return
            delay = backoff_delay(attempt)
            attempt += 1
            _LOGGER.debug("Cloud Bridge reconnecting in %.1fs", delay)
            await asyncio.sleep(delay)

    async def _async_connect_once(self) -> bool:
        """Connect and serve the session. Return True if it authenticated."""
        session = async_get_clientsession(self.hass)
        async with asyncio.timeout(CONNECT_TIMEOUT):
            ws = await session.ws_connect(
                self._url,
                heartbeat=HEARTBEAT_INTERVAL,
                max_msg_size=MAX_MESSAGE_SIZE,
            )
        self._ws = ws
        writer: asyncio.Task[None] | None = None
        authenticated = False
        try:
            await self._async_handshake(ws)
            authenticated = self._authenticated = True
            self.last_error = None
            _LOGGER.info("Cloud Bridge connected")
            writer = self.hass.async_create_background_task(
                self._async_writer(ws), "cloud_bridge writer"
            )
            self._on_connected()
            await self._async_reader(ws)
        finally:
            self._authenticated = False
            if writer is not None:
                writer.cancel()
                with suppress(asyncio.CancelledError):
                    await writer
            while not self._queue.empty():
                self._queue.get_nowait()
            if (future := self._rotation_future) is not None and not future.done():
                future.set_result(None)
            self._ws = None
            await ws.close()
            if authenticated:
                _LOGGER.info("Cloud Bridge disconnected")
                self._on_disconnected()
        return authenticated

    async def _async_handshake(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        challenge = await self._async_receive_json(ws)
        nonce = challenge.get("nonce")
        if (
            challenge.get("type") != "challenge"
            or not isinstance(nonce, str)
            or not 16 <= len(nonce) <= 256
        ):
            raise ProtocolError("Invalid challenge")

        use_pending = self._use_pending_key
        await ws.send_json(
            {
                "type": "auth",
                "protocol": PROTOCOL_VERSION,
                "installation_id": self._installation_id,
                "signature": self._credentials.sign(
                    signing_payload(SIGN_AUTH, self._installation_id, nonce),
                    pending=use_pending,
                ),
            }
        )
        response = await self._async_receive_json(ws)

        if response.get("type") == "auth_ok":
            self._use_pending_key = False
            if use_pending:
                # The backend applied a rotation we did not see confirmed.
                await self._credentials.async_commit_rotation()
            elif self._credentials.has_pending_key:
                await self._credentials.async_abort_rotation()
            return

        if response.get("type") != "auth_failed":
            raise ProtocolError("Unexpected authentication response")
        # Server-provided text never reaches the logs verbatim.
        reason = response.get("reason")
        if reason not in AUTH_FAILURE_REASONS:
            reason = "other"
        if reason == "revoked":
            raise AuthRevokedError
        if (
            reason == "invalid_signature"
            and not use_pending
            and self._credentials.has_pending_key
        ):
            self._use_pending_key = True
            raise AuthFailedError(reason, retry_now=True)
        self._use_pending_key = False
        raise AuthFailedError(reason)

    async def _async_reader(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        async for msg in ws:
            if msg.type is not aiohttp.WSMsgType.TEXT:
                continue
            try:
                data = json_loads(msg.data)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            match data.get("type"):
                case "revoke":
                    raise AuthRevokedError
                case "rotate_key_ok" | "rotate_key_failed" as result:
                    if (future := self._rotation_future) is not None and (
                        not future.done()
                    ):
                        future.set_result(result == "rotate_key_ok")
                case _:
                    await self._on_message(data)

    async def _async_writer(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        try:
            while True:
                message = await self._queue.get()
                await ws.send_json(message)
        except aiohttp.ClientError, ConnectionError, RuntimeError:
            # The reader notices the closed socket and reconnects.
            await ws.close()

    @staticmethod
    async def _async_receive_json(
        ws: aiohttp.ClientWebSocketResponse,
    ) -> dict[str, Any]:
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            msg = await ws.receive()
        if msg.type is not aiohttp.WSMsgType.TEXT:
            raise ProtocolError("Expected a text frame")
        try:
            data = json_loads(msg.data)
        except ValueError as err:
            raise ProtocolError("Invalid JSON") from err
        if not isinstance(data, dict):
            raise ProtocolError("Expected an object")
        return data
