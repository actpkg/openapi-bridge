"""The credential reaches the wire the way the OpenAPI document says it should.

The unit tests pin the two halves separately — which scheme a document
selects (`src/security.rs`) and what header or query parameter a credential
becomes (`src/creds.rs`). Neither can drive `get-secret`, which is a host
import with no host behind it on the test target. This module supplies the
missing middle: a real `act` process with a real credential store, a local
API whose document declares one scheme, and an operation that echoes back
exactly what arrived.

Each parametrised case serves a *different* document from the same server, so
the only thing that varies between them is the security scheme — and the
header the request carries changes with it, which is the property the whole
feature exists to provide.
"""

import asyncio
import base64
import json
import subprocess
import threading
from contextlib import AsyncExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from conftest import CONNECT_TIMEOUT, LOG_FILE

TOKEN = "sentinel-token-value"
USER = "sentinel-user"
PASSWORD = "sentinel-password"

# One document per scheme, keyed by the path it is served from. The
# `servers` URL is filled in once the server has a port.
SCHEMES = {
    "bearer": {"type": "http", "scheme": "bearer"},
    "basic": {"type": "http", "scheme": "basic"},
    "apikey-header": {"type": "apiKey", "name": "X-Custom-Key", "in": "header"},
    "apikey-query": {"type": "apiKey", "name": "access_key", "in": "query"},
    # Declared with no scheme at all: the documented fallback is
    # `Authorization: Bearer`.
    "none": None,
}


class Api(BaseHTTPRequestHandler):
    """An OpenAPI document per scheme, plus one operation that echoes the
    request back."""

    base_url = ""

    def log_message(self, *_args):  # keep pytest output readable
        pass

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        name = parsed.path.removeprefix("/").removesuffix(".json")

        if parsed.path.endswith(".json") and name in SCHEMES:
            document = {
                "openapi": "3.0.3",
                "info": {"title": "Echo", "version": "1.0"},
                "servers": [{"url": self.base_url}],
                "paths": {
                    "/echo": {"get": {"operationId": "echo", "summary": "Echo"}}
                },
            }
            if SCHEMES[name] is not None:
                document["components"] = {"securitySchemes": {name: SCHEMES[name]}}
                document["security"] = [{name: []}]
            self._json(200, document)
            return

        if parsed.path == "/echo":
            self._json(
                200,
                {
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "query": parsed.query,
                },
            )
            return

        self._json(404, {})


@pytest.fixture(scope="module")
def api():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    Api.base_url = f"http://127.0.0.1:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Api.base_url
    server.shutdown()


@pytest.fixture(scope="module")
def credential_store(act_command: list[str], wasm_path: Path, tmp_path_factory) -> str:
    """A `--credentials-backend` argument naming a store holding one
    credential under the key openapi-bridge looks for by default.

    All four field names are written into the one credential on purpose:
    which of them is read is decided by the *scheme*, and a store holding
    them all is what makes that visible — the token cases must not start
    sending Basic, and the Basic case must not start sending the token.
    """
    # The only skip: this CLI has no credential store, so the feature under
    # test does not exist here. Everything past this line is a regression.
    probe = subprocess.run(
        [*act_command, "secret", "--help"], capture_output=True, text=True
    )
    if probe.returncode != 0:
        pytest.skip("this `act` has no credential store (`act secret`); nothing to drive")

    root = tmp_path_factory.mktemp("credentials")
    backend = f"file:{root}"
    written = subprocess.run(
        [*act_command, "secret", "set", str(wasm_path), "--key", "default",
         "--field", "openapi:token",
         "--field", "openapi:username", "--field", "openapi:password",
         "--fields-stdin", "--credentials-backend", backend],
        input=json.dumps({
            "openapi:token": TOKEN,
            "openapi:username": USER,
            "openapi:password": PASSWORD,
        }),
        capture_output=True, text=True,
    )
    if written.returncode != 0:
        # **Not a skip.** The line above already proved the subcommand
        # exists, so a failure here is a store that broke rather than one
        # that is absent — and skipping would turn every test below green
        # while proving nothing.
        pytest.fail(
            f"`act secret set` failed even though `act secret` exists, so the "
            f"credential store is broken rather than missing:\n{written.stderr.strip()}"
        )
    return backend


@pytest.fixture
async def client(act_command: list[str], wasm_path: Path, credential_store: str):
    """Overrides the suite-wide client for this module only: the shared one
    grants the same two classes but names no credential store, so
    `get-secret` would find nothing.
    """
    transport = StdioTransport(
        command=act_command[0],
        args=[*act_command[1:], "run", str(wasm_path), "--mcp",
              "--allow", "wasi:http", "--allow", "act:credentials",
              "--credentials-backend", credential_store],
        keep_alive=False,
        log_file=LOG_FILE,
    )
    async with AsyncExitStack() as stack:
        try:
            async with asyncio.timeout(CONNECT_TIMEOUT):
                connected = await stack.enter_async_context(Client(transport))
        except TimeoutError:
            pytest.fail(f"MCP client did not connect within {CONNECT_TIMEOUT}s")
        yield connected


async def echo(client, api: str, scheme: str, **open_args) -> dict:
    """Open a session against the document for `scheme`, call `echo`, and
    return what the API received."""
    opened = await client.call_tool(
        "open_session", {"spec_url": f"{api}/{scheme}.json", **open_args}
    )
    sid = json.loads(opened.content[0].text)["id"]
    try:
        result = await client.call_tool(
            "echo", {"_meta": {"std:session-id": sid}}, raise_on_error=False
        )
        assert not result.is_error, result.content
        return json.loads(result.content[0].text)
    finally:
        await client.call_tool("close_session", {"session_id": sid})


async def test_bearer_scheme_sends_an_authorization_bearer_header(client, api):
    seen = await echo(client, api, "bearer")
    assert seen["headers"]["authorization"] == f"Bearer {TOKEN}"


async def test_a_document_with_no_scheme_falls_back_to_bearer(client, api):
    seen = await echo(client, api, "none")
    assert seen["headers"]["authorization"] == f"Bearer {TOKEN}"


async def test_basic_scheme_sends_the_username_and_password_pair(client, api):
    seen = await echo(client, api, "basic")
    expected = base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
    assert seen["headers"]["authorization"] == f"Basic {expected}"
    assert TOKEN not in json.dumps(seen), "the string token must not be sent as Basic"


async def test_an_api_key_scheme_uses_the_header_the_document_names(client, api):
    seen = await echo(client, api, "apikey-header")
    assert seen["headers"]["x-custom-key"] == TOKEN
    assert "authorization" not in seen["headers"], seen["headers"]


async def test_an_api_key_in_query_becomes_a_query_parameter(client, api):
    seen = await echo(client, api, "apikey-query")
    assert f"access_key={TOKEN}" in seen["query"], seen["query"]
    assert "authorization" not in seen["headers"], seen["headers"]


async def test_a_per_call_header_override_cannot_displace_the_credential(client, api):
    """The guard that would otherwise be decorative. `open-session` refuses
    `Authorization` in session args; if a per-call `http:header:` override
    could still displace the credential, a caller would simply set it there
    instead.
    """
    opened = await client.call_tool("open_session", {"spec_url": f"{api}/bearer.json"})
    sid = json.loads(opened.content[0].text)["id"]
    try:
        result = await client.call_tool(
            "echo",
            {"_meta": {
                "std:session-id": sid,
                "http:header:authorization": "Bearer forged",
            }},
            raise_on_error=False,
        )
        assert not result.is_error, result.content
        seen = json.loads(result.content[0].text)
        assert seen["headers"]["authorization"] == f"Bearer {TOKEN}", seen["headers"]
    finally:
        await client.call_tool("close_session", {"session_id": sid})


async def test_the_session_headers_survive_beside_the_credential(client, api):
    """The credential merges with `headers` rather than replacing it: the
    non-secret defaults `headers` was kept for are still sent.
    """
    seen = await echo(
        client, api, "bearer", headers={"X-Tenant": "acme", "Accept": "application/json"}
    )
    assert seen["headers"]["x-tenant"] == "acme"
    assert seen["headers"]["accept"] == "application/json"
    assert seen["headers"]["authorization"] == f"Bearer {TOKEN}"


async def test_pinning_a_scheme_changes_how_the_credential_is_presented(client, api):
    """A document declaring several schemes needs a deterministic choice and
    a way to override it. Here the pin is what makes the presentation
    differ, with everything else held constant.
    """
    seen = await echo(client, api, "apikey-header", security_scheme="apikey-header")
    assert seen["headers"]["x-custom-key"] == TOKEN
