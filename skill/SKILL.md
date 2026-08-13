---
name: openapi-bridge
description: Dynamically exposes OpenAPI endpoints as ACT tools
metadata:
  act: {}
---

# openapi-bridge

Loads an OpenAPI 3.x document at runtime and exposes each operation as a
local ACT tool. Path/query/header parameters and JSON request bodies are
flattened into a single tool argument schema.

## How sessions work here

This component requires a session. Open one against the API you want to
expose, then thread the returned id into every tool call as
`std:session-id` metadata.

Open-session args:

| field | type | required | description |
| --- | --- | --- | --- |
| `spec_url` | string | yes | URL of the OpenAPI document (JSON or YAML) |
| `credential_key` | string | no | which credential in this component's profile to authenticate with (default `default`) |
| `security_scheme` | string | no | pin one `components.securitySchemes` key instead of letting the bridge choose |
| `headers` | object | no | non-secret default headers — `Accept`, a tenant id, an API-version pin |

`open-session` fetches and parses the document eagerly so `list-tools` is
cheap and bad URLs / unparseable documents / a `security_scheme` that names
nothing surface at open time. `close-session` drops the session; the parsed
document stays cached across sessions targeting the same `spec_url`.

Without `std:session-id`, `list-tools` returns an empty list and `call-tool`
errors with `std:invalid-args`. Calls referencing a closed session-id return
`std:session-not-found`.

## Credentials — do not put one in the args

**There is no argument that takes a secret, and `headers` will refuse one.**
The credential lives in the host credential store; the session only *names*
it. `open-session` rejects `Authorization`, `Proxy-Authorization`, `Cookie`,
the common API-key header spellings, the header name this document's own
`apiKey` scheme declares, and a `spec_url` carrying `user:pass@`.

If a call needs a credential, the answer is a command for the **operator** to
run out of band — never an argument for you to fill in:

```bash
act secret set <component-ref> --key default --field openapi:token --fields-stdin
# {"openapi:token":"<token>"}
```

Field names, by what the API needs: `openapi:token` (bearer token or API
key), `openapi:username` + `openapi:password` (HTTP Basic), `openapi:oauth`
(a `std:oauth2` map, provisioned by `act login`). `openapi:oauth` wins when
both it and `openapi:token` are stored. An expired OAuth token is
**re-acquired** with `act login <ref> --key <key> --force`, not refreshed —
the host does not refresh silently.

The bridge reads `components.securitySchemes` to decide how to present it:
`Authorization: Bearer`, `Authorization: Basic`, the API's own key header, or
a query parameter. A document declaring nothing usable falls back to Bearer.
When several schemes are declared, the top-level `security` list wins, then
alphabetical order — pin one with `security_scheme` to override.

A missing credential is not an error by itself: the request goes out
unauthenticated, and the API's own 401/403 comes back as
`std:credential-required` with the provisioning command in it. The bridge
asks the store once per session, so a credential added mid-session needs a
new session.

The host must grant the class: `act run <ref> --mcp --allow wasi:http --allow
act:credentials`.

## Per-call header overrides

Callers can pass extra headers per call by including `http:header:<name>`
keys in the metadata. They merge on top of the session-level `headers` — but
**not** on top of the credential, which is applied last and cannot be
displaced.

## Example

```text
open_session({"spec_url": "https://petstore3.swagger.io/api/v3/openapi.json"})
→ {"id": "openapi_0", "metadata": {}}

list_tools(_meta = {std:session-id: "openapi_0"})
→ [find_pets_by_status, get_pet_by_id, add_pet, ...]

call_tool("find_pets_by_status", {"status": "sold"},
          _meta = {std:session-id: "openapi_0"})
→ JSON array of pets

close_session("openapi_0")
```

## Tool naming

If an operation has `operationId`, it's snake_cased. Otherwise the bridge
synthesises `<method>_<path>`, snake_casing each segment and prefixing
path-parameter segments with `by_` (e.g. `DELETE /pets/{petId}` →
`delete_pets_by_pet_id`).

## Limitations

- One spec per session; a single bridge can host many sessions.
- One credential per session, presented to every operation — operation-level
  `security` is not consulted.
- `openIdConnect`, `mutualTLS`, `http` + `digest` and `apiKey` in a cookie
  are not presentable; a document declaring only those falls back to Bearer.
- 30-second per-request timeout, 10 MB response cap.
- `Content-Type: application/json` request bodies only.
