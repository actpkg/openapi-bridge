# openapi-bridge

Turn an OpenAPI 3.x document into ACT tools. Point a session at a spec URL and
every operation it declares becomes a callable tool, with path, query, header
and JSON-body parameters flattened into one argument schema.

## Credentials

The API's credential is **not** a session argument. It lives in the host
credential store, is *named* by `credential_key`, and is fetched with
`act:credentials@0.1.0` on the first tool call — so it never passes through the
agent's context, the transcript, or the host's session record.

### Field names

Four names, all in this component's own namespace. No field name is well-known:
`ACT-CONSTANTS.md` §8.2 registers field *types*, not names, so the component
that reads a field is the party that asked for it. Which field is read is
decided by the **name**, never by the value's shape (§8.1–8.2).

| field | type | read for |
| --- | --- | --- |
| `openapi:token` | `std:string` | a bearer token or API key pasted by hand |
| `openapi:oauth` | `std:oauth2` | an access token from an OAuth flow, with its expiry and scopes |
| `openapi:username` | `std:string` | the user half of an HTTP Basic credential |
| `openapi:password` | `std:string` | the password half |

```bash
# a bearer token or API key
act secret set actpkg.dev/library/openapi-bridge --key default \
  --field openapi:token --fields-stdin
# {"openapi:token":"<token>"}

# HTTP Basic
act secret set actpkg.dev/library/openapi-bridge --key default \
  --field openapi:username --field openapi:password --fields-stdin
# {"openapi:username":"...","openapi:password":"..."}

# an OAuth credential — map members per ACT-CONSTANTS §8.3
act secret set actpkg.dev/library/openapi-bridge --key default \
  --field openapi:oauth=std:oauth2 --fields-stdin
# {"openapi:oauth":{"std:access-token":"<token>","std:expires-at":1760000000}}
```

**`openapi:oauth` outranks `openapi:token`** when a credential carries both.
The precedence is fixed rather than "whichever is present", so storing a second
field can never quietly change which one authenticates.

An `openapi:oauth` token past its `std:expires-at` (with 30 seconds of skew) is
refused before the request goes out. ACT does **not** refresh a stored token —
silent refresh is out of scope for the host (`ACT-AUTH.md` §1.1) — so it is
re-acquired with `act login <ref> --key <key> --force`, not renewed.

### How the credential is presented

Read from the document, not configured: OpenAPI already says how the API wants
to be authenticated, so the operator does not have to know whether *this* API
spells its key `Authorization: Bearer`, `X-API-Key` or `?api_key=`.

| `components.securitySchemes` entry | what the request carries |
| --- | --- |
| `http` + `bearer` | `Authorization: Bearer <openapi:token>` |
| `http` + `basic` | `Authorization: Basic base64(user:password)` |
| `apiKey` + `in: header` | the declared header name, with the token as its value |
| `apiKey` + `in: query` | the declared query parameter, appended to the URL |
| `oauth2` | `Authorization: Bearer <std:access-token>`, and the scheme's scopes go into `secret-request.scopes` |
| nothing usable | `Authorization: Bearer` — the documented fallback |

`openIdConnect`, `mutualTLS`, `http` + `digest`, and `apiKey` in a cookie are
**not** presentable. A document declaring only those falls back to Bearer
rather than guessing.

### Choosing between several schemes

The order is fixed and documented, because a bridge that chose differently
between two runs of the same document would authenticate differently between
them:

1. `security_scheme`, when the session pins one. It must name a key of
   `components.securitySchemes` and that entry must be presentable; both
   failures are refused at `open-session`, by name.
2. The document's top-level `security` list, in document order — and within one
   requirement object, the alphabetically first presentable scheme.
3. `components.securitySchemes` alphabetically, when `security` is absent, empty
   or names nothing presentable.
4. `Authorization: Bearer`.

Operation-level `security` is deliberately not consulted: a session holds one
credential and presents it to every operation, so a per-operation override would
make the presentation depend on which tool was called.

`security_scheme` is a **scheme name, not a credential** — it says which
mechanism the stored credential is presented through.

### `headers` is for non-secret defaults

`headers` survives for the things a caller legitimately pins: `Accept`,
`User-Agent`, a tenant id, an API-version header. It **refuses** the header
names that carry a credential — `Authorization`, `Proxy-Authorization`,
`Cookie`, and the common API-key spellings — plus, once the document is
fetched, whatever header name *this* API's own `apiKey` scheme declares. A
`spec_url` carrying userinfo (`https://user:pass@host/...`) is refused for the
same reason, and so is a server URL in the document that carries it.

**Header precedence, lowest to highest:**

1. the session's `headers`
2. the operation's own `in: header` parameters, supplied as tool arguments
3. per-call `http:header:*` metadata overrides
4. **the credential-derived header**, applied last and unconditionally

Layer 4 sits on top of layer 3 on purpose. A per-call override that could
displace the credential would make the session-args guard decorative: a caller
refused `Authorization` at open would simply set it per call instead. The same
holds for an `apiKey` in query, whose parameter replaces any same-named pair the
arguments produced.

### When there is no credential

A missing credential is not fatal on its own. Plenty of documents declare a
security scheme and still serve the operations an agent wants without one, so
`not-found` and `denied` — which are indistinguishable by design
(`ACT-AUTH.md` §1.1.7) — let the request go out unauthenticated. The API's own
**401/403** is what becomes `std:credential-required`, carrying the
`act secret set` command that fixes it.

The answer is cached for the session, negative included: under ask-by-default a
repeat is a repeat prompt in front of a human. A credential provisioned
mid-session is picked up by opening a new session. For a bridge fronting a
public API, `--deny act:credentials` silences the question entirely.

## Session arguments

| field | type | required | description |
| --- | --- | --- | --- |
| `spec_url` | string | yes | URL of the OpenAPI document (JSON or YAML) |
| `credential_key` | string | no | credential to authenticate with (default `default`) |
| `security_scheme` | string | no | pin one `components.securitySchemes` key |
| `headers` | object | no | non-secret default headers |

`open-session` fetches and parses the document eagerly, so a bad URL, an
unparseable document, and a `security_scheme` that names nothing all surface
there rather than on the first call. `get-secret` is **not** called at open and
cannot be: the host marks a session live only after `open-session` returns
(`ACT-AUTH.md` §1.1.4).

## Usage

```bash
act run actpkg.dev/library/openapi-bridge --mcp \
  --allow wasi:http --allow act:credentials
```

```bash
just init       # first time: fetch WIT deps
just build      # build + pack the wasm component
just test-unit  # host-target unit tests
just test       # e2e suite (MCP stdio, real client)
```

`ACT`/`ACT_BUILD` default to `npx @actcore/act`/`npx @actcore/act-build`;
override them to point at a local binary, e.g.
`export ACT=act ACT_BUILD=act-build`. The npx default cannot run `just test`
for this component: it imports `act:credentials/store@0.1.0`, which the released
`act` does not implement yet, so the component fails to instantiate.

The e2e suite drives a local Swagger Petstore by default
(`PETSTORE_SPEC=http://localhost:8080/api/v3/openapi.json` against
`swaggerapi/petstore3:unstable`); the public `petstore3.swagger.io` is
frequently 500-ing and is not a reliable target.
