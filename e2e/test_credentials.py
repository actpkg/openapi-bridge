"""The credential is not a session argument, and `headers` cannot become one.

Everything here is observed through the same MCP surface an agent sees. No
real API key is used anywhere: the assertions are about the published
open-args schema and about the guest's own refusal paths, all of which
answer before any authenticated request is made.
"""

import json

import pytest
from mcp.shared.exceptions import McpError


async def refusal_text(client, arguments: dict) -> str:
    """The text of an `open_session` that must fail.

    Session-lifecycle failures surface on the JSON-RPC error path rather
    than as a tool result with `isError` — measured, and documented in
    conftest's `expect_error`. Both are handled so the assertions below read
    as assertions rather than as transport handling.
    """
    try:
        result = await client.call_tool("open_session", arguments, raise_on_error=False)
    except McpError as exc:
        return str(exc)
    assert result.is_error, f"expected a refusal, got {result!r}"
    return "".join(c.text for c in result.content if hasattr(c, "text"))


async def test_open_session_schema_offers_nowhere_to_put_a_credential(client):
    """`open_session`'s inputSchema is what an agent reads before deciding
    what to hand over. It must name a credential and carry none.
    """
    tools = await client.list_tools()
    open_session = next(t for t in tools if t.name == "open_session")
    props = open_session.inputSchema.get("properties", {})

    assert set(props) == {"spec_url", "credential_key", "security_scheme", "headers"}
    for forbidden in ("password", "passwd", "pwd", "secret", "token", "auth", "api_key"):
        assert not any(forbidden in name.lower() for name in props), (
            f"a place to put a {forbidden}: {sorted(props)}"
        )


@pytest.mark.parametrize(
    "header",
    ["Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "api-key"],
)
async def test_an_auth_shaped_header_is_refused_at_open(
    client, petstore_spec_url, header
):
    """`headers` survives for non-secret defaults only. A credential
    smuggled through it would bypass the credential store entirely, so the
    refusal happens where the caller supplied it.
    """
    text = await refusal_text(
        client, {"spec_url": petstore_spec_url, "headers": {header: "sentinel-value"}}
    )
    assert "sentinel-value" not in text, f"the refusal echoed the value: {text}"
    assert "credential_key" in text, text


async def test_a_non_secret_header_is_still_accepted(client, petstore_spec_url):
    """The guard is a denylist of credential-bearing names, not a ban on
    headers: an `Accept` or a tenant id is exactly what `headers` is for.
    """
    opened = await client.call_tool(
        "open_session",
        {
            "spec_url": petstore_spec_url,
            "headers": {"Accept": "application/json", "X-Tenant": "acme"},
        },
    )
    sid = json.loads(opened.content[0].text)["id"]
    assert sid.startswith("openapi_")
    await client.call_tool("close_session", {"session_id": sid})


async def test_userinfo_in_the_spec_url_is_refused(client):
    """A URL's spelling of a credential. It also travels: `spec_url` becomes
    `secret-request.resource`, which leaves the component for the host.
    """
    text = await refusal_text(
        client,
        {"spec_url": "https://svc:sentinel-value@petstore3.swagger.io/api/v3/openapi.json"},
    )
    assert "sentinel-value" not in text, f"userinfo echoed: {text}"
    assert "userinfo" in text, text


async def test_pinning_an_undeclared_security_scheme_fails_at_open(
    client, petstore_spec_url
):
    """The pin names a key of `components.securitySchemes`. Naming one the
    document does not declare is a mistake in these args, so it is refused
    here rather than on the first tool call — and the refusal lists what the
    document does declare.
    """
    text = await refusal_text(
        client, {"spec_url": petstore_spec_url, "security_scheme": "nope"}
    )
    assert "nope" in text and "api_key" in text, text


async def test_pinning_a_declared_scheme_opens(client, petstore_spec_url):
    """The petstore declares `api_key` (apiKey in header) and
    `petstore_auth` (oauth2). Both are presentable, so either may be pinned.
    """
    for scheme in ("api_key", "petstore_auth"):
        opened = await client.call_tool(
            "open_session",
            {"spec_url": petstore_spec_url, "security_scheme": scheme},
        )
        sid = json.loads(opened.content[0].text)["id"]
        await client.call_tool("close_session", {"session_id": sid})


async def test_calls_still_work_with_no_credential_stored(client, session_meta):
    """A document declaring a security scheme does not mean every operation
    enforces it. With nothing in the store, the bridge calls the API
    unauthenticated rather than refusing on the document's behalf — and the
    API's own 401/403, not the empty store, is what would fail the call.
    """
    result = await client.call_tool(
        "find_pets_by_status", {"status": "sold", "_meta": session_meta},
        raise_on_error=False,
    )
    assert not result.is_error, result.content
