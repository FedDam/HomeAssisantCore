"""In-process fake of the Cloud Bridge backend, bound to 127.0.0.1.

It implements the backend side of protocol v1 the way a real backend must:
the tenant comes from the pairing code, the installation from the
authenticated session, and every signature is verified.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
import os
from typing import Any

from aiohttp import WSMsgType, web

from homeassistant.components.cloud_bridge.const import (
    PAIR_PATH,
    SIGN_AUTH,
    SIGN_PAIR,
    SIGN_ROTATE,
    WEBSOCKET_PATH,
)
from homeassistant.components.cloud_bridge.credentials import (
    b64encode,
    signing_payload,
    verify_signature,
)
from homeassistant.util.json import json_loads

PAIRING_CODE = "PAIR-CODE-0001"
TENANT = "tenant-a"


@dataclass
class Installation:
    """An installation registered on the backend."""

    public_key: str
    tenant: str
    revoked: bool = False
    old_keys: list[str] = field(default_factory=list)


class FakeBackend:
    """Fake backend."""

    def __init__(self) -> None:
        """Initialize the backend."""
        self.url = ""
        self.pairing_codes: dict[str, str] = {PAIRING_CODE: TENANT}
        self.pair_status: int | None = None
        self.pair_response: Any = None
        self.pair_requests: list[dict[str, Any]] = []
        self.installations: dict[str, Installation] = {}
        self.auth_results: list[str] = []
        self.received: list[dict[str, Any]] = []
        self.sockets: list[web.WebSocketResponse] = []
        self.rotation_response: str | None = "rotate_key_ok"
        self.challenge: dict[str, Any] | None = None
        self.app = web.Application()
        self.app.router.add_post(PAIR_PATH, self._handle_pair)
        self.app.router.add_get(WEBSOCKET_PATH, self._handle_ws)

    @property
    def authenticated_sessions(self) -> int:
        """Return how many sessions authenticated."""
        return self.auth_results.count("auth_ok")

    def messages(self, message_type: str) -> list[dict[str, Any]]:
        """Return received messages of a type."""
        return [msg for msg in self.received if msg.get("type") == message_type]

    async def send(self, message: dict[str, Any]) -> None:
        """Send a message on the latest session."""
        await self.sockets[-1].send_json(message)

    async def drop_connections(self) -> None:
        """Close every session from the server side."""
        for ws in list(self.sockets):
            await ws.close()

    async def wait_for(self, predicate: Callable[[], bool], timeout: float = 5) -> None:
        """Wait until a condition holds."""
        async with asyncio.timeout(timeout):
            while not predicate():
                await asyncio.sleep(0.01)

    async def _handle_pair(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.pair_requests.append(body)
        if self.pair_status is not None:
            return web.json_response(self.pair_response, status=self.pair_status)
        code = body["pairing_code"]
        public_key = body["public_key"]
        # Single-use code; the tenant is derived from it, never from the body.
        if (tenant := self.pairing_codes.pop(code, None)) is None:
            return web.json_response({"error": "invalid_code"}, status=403)
        if not verify_signature(
            public_key,
            body["proof"],
            signing_payload(SIGN_PAIR, code, public_key, body["timestamp"]),
        ):
            return web.json_response({"error": "invalid_proof"}, status=401)
        installation_id = f"ha-{len(self.installations) + 1:03}"
        self.installations[installation_id] = Installation(public_key, tenant)
        return web.json_response(
            self.pair_response or {"installation_id": installation_id}
        )

    async def _handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        nonce = b64encode(os.urandom(32))
        await ws.send_json(self.challenge or {"type": "challenge", "nonce": nonce})
        auth = await ws.receive_json(timeout=5)
        installation_id = auth.get("installation_id")
        installation = self.installations.get(installation_id)
        result = "auth_ok"
        if installation is None:
            result = "unknown_installation"
        elif installation.revoked:
            result = "revoked"
        elif not verify_signature(
            installation.public_key,
            auth["signature"],
            signing_payload(SIGN_AUTH, installation_id, nonce),
        ):
            result = "invalid_signature"
        self.auth_results.append(result)
        if result != "auth_ok":
            await ws.send_json({"type": "auth_failed", "reason": result})
            await ws.close()
            return ws

        assert installation is not None
        await ws.send_json({"type": "auth_ok"})
        self.sockets.append(ws)
        try:
            async for msg in ws:
                if msg.type is not WSMsgType.TEXT:
                    continue
                data = json_loads(msg.data)
                assert isinstance(data, dict)
                self.received.append(data)
                if data["type"] == "rotate_key":
                    await self._handle_rotate(ws, installation_id, installation, data)
                if data["type"] == "revoke":
                    installation.revoked = True
        finally:
            self.sockets.remove(ws)
        return ws

    async def _handle_rotate(
        self,
        ws: web.WebSocketResponse,
        installation_id: str,
        installation: Installation,
        data: dict[str, Any],
    ) -> None:
        if self.rotation_response is None:
            return
        payload = signing_payload(SIGN_ROTATE, installation_id, data["new_public_key"])
        valid = verify_signature(
            installation.public_key, data["signature"], payload
        ) and verify_signature(data["new_public_key"], data["proof"], payload)
        if valid and self.rotation_response == "rotate_key_ok":
            installation.old_keys.append(installation.public_key)
            installation.public_key = data["new_public_key"]
            await ws.send_json({"type": "rotate_key_ok"})
        else:
            await ws.send_json({"type": "rotate_key_failed"})
