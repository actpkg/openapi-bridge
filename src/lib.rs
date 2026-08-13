//! openapi-bridge — dynamically expose an OpenAPI spec's endpoints as
//! local ACT tools.
//!
//! Each session corresponds to one upstream API: `open-session` takes
//! `spec_url` plus the name of a credential and optional non-secret default
//! `headers`, the bridge fetches and parses the spec, and subsequent
//! capability calls operate against that session via `std:session-id`. The
//! parsed spec is cached by `spec_url` so multiple sessions targeting the same
//! API share the parse.
//!
//! **The credential is not an argument.** It lives in the host's credential
//! store, is named by `credential_key`, and is fetched through
//! `act:credentials/store` on the first tool call — never inside
//! `open-session`, because the host marks a session live only *after*
//! `open-session` returns and would refuse the request as an unknown session
//! (`ACT-AUTH.md` §1.1.4). How it is presented — `Authorization: Bearer`,
//! `Authorization: Basic`, a custom API-key header, or a query parameter — is
//! read from the document's own `components.securitySchemes` (see
//! `security.rs`), so the operator does not have to know which header this
//! particular API wants.

#![allow(clippy::all)]

mod cache;
mod creds;
mod request;
mod security;
mod spec;
mod tools;

use act_types::cbor;
use security::{Presentation, Selection};
use spec::BridgeConfig;

wit_bindgen::generate!({
    path: "wit",
    world: "component-world",
    generate_all,
});

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use exports::act::sessions::session_provider as session_exports;
use exports::act::tools::tool_provider as tool_exports;
// In act:tools@0.2.0 the data model moved to a function-free `types`
// interface; `localized-string` lives in act:core. The `tool-provider`
// export module no longer re-exports these, so reference them directly.
use act::core::types::LocalizedString;
use act::tools::types::{ContentPart, ToolDefinition};

// ── Per-session state ──────────────────────────────────────────────────────

/// What the first tool call learned from the credential store.
#[derive(Clone)]
enum Credential {
    /// Not asked yet.
    Unfetched,
    /// Fetched and turned into one header or one query parameter.
    Present(Presentation),
    /// The store answered `not-found` or `denied`. Cached so the question is
    /// asked once per session rather than once per call: under ask-by-default
    /// a repeat is a repeat *prompt* in front of a human, and "no" does not
    /// become "yes" by asking again. The cost is that a credential provisioned
    /// mid-session is not picked up until the session is reopened, which is
    /// the trade the SKILL.md and README both state.
    Absent,
}

struct UpstreamSession {
    config: BridgeConfig,
    /// Chosen at open, from the document — so a bad `security_scheme` pin
    /// fails there rather than on the first call.
    selection: Selection,
    credential: Credential,
}

thread_local! {
    static SESSIONS: RefCell<HashMap<String, UpstreamSession>> = RefCell::new(HashMap::new());
    static NEXT_ID: Cell<u64> = const { Cell::new(0) };
}

fn alloc_session_id() -> String {
    NEXT_ID.with(|n| {
        let id = n.get();
        n.set(id + 1);
        format!("openapi_{id}")
    })
}

fn snapshot_session(session_id: &str) -> Option<BridgeConfig> {
    SESSIONS.with(|s| s.borrow().get(session_id).map(|u| u.config.clone()))
}

fn snapshot_selection(session_id: &str) -> Option<Selection> {
    SESSIONS.with(|s| s.borrow().get(session_id).map(|u| u.selection.clone()))
}

fn cached_credential(session_id: &str) -> Option<Credential> {
    SESSIONS.with(|s| s.borrow().get(session_id).map(|u| u.credential.clone()))
}

fn remember_credential(session_id: &str, credential: Credential) {
    SESSIONS.with(|s| {
        if let Some(session) = s.borrow_mut().get_mut(session_id) {
            session.credential = credential;
        }
    });
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn extract_session_id(metadata: &[(String, Vec<u8>)]) -> Option<String> {
    metadata
        .iter()
        .find(|(k, _)| k == "std:session-id")
        .and_then(|(_, v)| {
            ciborium::from_reader::<serde_json::Value, _>(v.as_slice())
                .ok()
                .and_then(|val| match val {
                    serde_json::Value::String(s) => Some(s),
                    _ => None,
                })
        })
}

fn make_error(kind: &str, msg: String) -> tool_exports::Error {
    tool_exports::Error {
        kind: kind.to_string(),
        message: LocalizedString::Plain(msg),
        metadata: vec![],
    }
}

fn invalid_args(msg: impl Into<String>) -> tool_exports::Error {
    make_error(act_types::constants::ERR_INVALID_ARGS, msg.into())
}

fn session_not_found(session_id: &str) -> tool_exports::Error {
    make_error(
        act_types::constants::ERR_SESSION_NOT_FOUND,
        format!("Unknown session-id: {session_id}"),
    )
}

/// `ACT-CONSTANTS.md` §9. **Delete this when `act-types` exports it** — the
/// kind is registered in the specification and only missing from the crate.
const ERR_CREDENTIAL_REQUIRED: &str = "std:credential-required";

fn credential_required(msg: String) -> tool_exports::Error {
    make_error(ERR_CREDENTIAL_REQUIRED, msg)
}

/// Unix seconds, for the OAuth expiry check.
///
/// `wasi:clocks` is ambient in ACT — it is not one of the gated capability
/// classes — so this needs no grant. A clock that cannot answer yields 0,
/// under which no stored expiry is ever in the past: the failure mode is a
/// token that is sent and rejected upstream, not one that is refused locally
/// because the host lost its clock.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fetch the credential for this session, or establish that there is none.
///
/// Runs on the first tool call, never at open (`ACT-AUTH.md` §1.1.4), and
/// caches its answer — including the negative one — for the session's
/// lifetime.
///
/// **A missing credential is not fatal here.** Plenty of OpenAPI documents
/// declare a security scheme and still serve the operations an agent wants
/// without one, and a bridge that refused to call them would be refusing on
/// the document's behalf rather than the API's. So `not-found` and `denied`
/// return `Ok(None)` and the request goes out unauthenticated; the API's own
/// 401/403 is what turns into [`ERR_CREDENTIAL_REQUIRED`], with the same
/// `act secret set` command in it (see [`unauthorized`]). That keeps the two
/// store refusals **indistinguishable** — which is the point of collapsing
/// them (`ACT-AUTH.md` §1.1.7): `denied` is decided before the store is
/// consulted, so telling them apart would invent a difference the host
/// deliberately withholds and hand the agent a way to probe a profile for
/// keys.
async fn ensure_credential(
    session_id: &str,
    config: &BridgeConfig,
    selection: &Selection,
) -> Result<Option<Presentation>, tool_exports::Error> {
    match cached_credential(session_id) {
        Some(Credential::Present(p)) => return Ok(Some(p)),
        Some(Credential::Absent) => return Ok(None),
        Some(Credential::Unfetched) => {}
        None => return Err(session_not_found(session_id)),
    }

    let want = act::credentials::types::SecretRequest {
        key: config.credential_key.clone(),
        // A provisioning hint, not a retrieval filter: retrieval MUST NOT be
        // filtered by shape (`ACT-AUTH.md` §1.1.6). This component reads the
        // fields it declared, by name, and decides for itself.
        kind: None,
        // Host-visible by contract — a host may show it to a human or record
        // it. `spec_url` can be passed verbatim only because `open-session`
        // refuses one carrying userinfo.
        resource: Some(config.spec_url.clone()),
        scopes: selection.scopes.clone(),
        hint: Some(format!(
            "Authenticate calls to this OpenAPI service ({} scheme)",
            selection.name
        )),
    };

    let raw = match act::credentials::store::get_secret(session_id.to_string(), want).await {
        Ok(raw) => raw,
        Err(act::credentials::types::SecretError::NotFound)
        | Err(act::credentials::types::SecretError::Denied) => {
            remember_credential(session_id, Credential::Absent);
            return Ok(None);
        }
        Err(act::credentials::types::SecretError::InvalidSession) => {
            return Err(make_error(
                act_types::constants::ERR_SESSION_NOT_FOUND,
                "the credential store does not recognise this session; open a new one".to_string(),
            ));
        }
        Err(act::credentials::types::SecretError::Unavailable(msg)) => {
            // Host-authored and required to be free of credential material
            // (`ACT-AUTH.md` §1.1.7), which is what makes it safe to pass on.
            // Not cached: an unavailable backend is the one failure here that
            // changes on its own.
            return Err(make_error(
                act_types::constants::ERR_INTERNAL,
                format!("the credential store is unavailable: {msg}"),
            ));
        }
    };

    // Values cross as CBOR; `from_wit` decodes the field map. Its error names
    // the field and never its bytes.
    let secret = act_sdk::credentials::Secret::from_wit(raw.kind, raw.fields).map_err(|e| {
        make_error(
            act_types::constants::ERR_INTERNAL,
            format!("credential field decode failed: {e}"),
        )
    })?;

    // Deliberately not cached as `Absent`: a credential that exists but cannot
    // be read is an operator's provisioning mistake with a named fix, and
    // caching it would silently downgrade every later call in this session to
    // an unauthenticated one.
    let presentation = creds::present(
        &secret,
        &selection.scheme,
        &config.credential_key,
        now_unix(),
    )
    .map_err(credential_required)?;

    remember_credential(session_id, Credential::Present(presentation.clone()));
    Ok(Some(presentation))
}

/// What the agent is told when the API itself rejects the request.
///
/// The one place a missing credential becomes a hard failure — the API said so
/// — and the message differs by whether one was sent, because the fix does:
/// provisioning versus replacing.
async fn unauthorized(status: u16, key: &str, authenticated: bool) -> tool_exports::Error {
    if authenticated {
        return credential_required(format!(
            "The API rejected the stored credential under key '{key}' (HTTP {status}). \
             Replace it:\n  act secret rm <component-ref> --key {key}\n  \
             act secret set <component-ref> --key {key} --field {} --fields-stdin\n\
             For an OAuth credential, re-run the flow instead:\n  \
             act login <component-ref> --key {key} --force",
            creds::FIELD_TOKEN
        ));
    }
    // Best-effort: a policy that denies the store denies the listing too, and
    // then the message simply carries no inventory. Keys are not secret —
    // `list-secrets` exists to hand them to the agent.
    let known: Vec<String> = act::credentials::store::list_secrets(None)
        .await
        .map(|v| v.into_iter().map(|i| i.key).collect())
        .unwrap_or_default();
    let mut msg = format!(
        "The API requires authentication (HTTP {status}) and no usable credential was \
         available under key '{key}'. Either it is not set, or policy denies \
         act:credentials for this component — grant it with `--allow act:credentials`. \
         Set one with:\n  \
         act secret set <component-ref> --key {key} --field {} --fields-stdin\n  \
         {{\"{}\": \"...\"}}\n\
         For HTTP Basic use --field {} --field {}; for OAuth, \
         `act login <component-ref> --key {key}`.",
        creds::FIELD_TOKEN,
        creds::FIELD_TOKEN,
        creds::FIELD_USERNAME,
        creds::FIELD_PASSWORD,
    );
    if !known.is_empty() {
        msg.push_str(&format!(
            "\nThis component's profile has: {}",
            known.join(", ")
        ));
    }
    credential_required(msg)
}

/// Extract the origin (scheme + authority) from a URL.
fn url_origin(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        format!("{scheme}://{authority}")
    } else {
        String::new()
    }
}

/// [`spec::check_no_userinfo`] over a whole URL rather than its
/// post-scheme remainder. A URL with no `://` has no authority to check.
fn check_url_no_userinfo(url: &str, what: &str) -> Result<(), String> {
    match url.split_once("://") {
        Some((_, rest)) => spec::check_no_userinfo(rest, what),
        None => Ok(()),
    }
}

/// Resolve a server base URL against the spec URL. Relative server URLs
/// are anchored to the spec's origin.
fn resolve_base_url(spec_url: &str, server_url: &str) -> String {
    if server_url.contains("://") {
        server_url.to_string()
    } else {
        format!("{}{}", url_origin(spec_url), server_url)
    }
}

/// Fetch the OpenAPI spec from a URL.
async fn fetch_spec(url: &str) -> Result<String, String> {
    let client = hclient::Client::builder(hclient_wasi::WasiHttp::new())
        .build()
        .map_err(|e| format!("Failed to fetch spec: {e}"))?;
    let response = client
        .get(url)
        .header(
            "accept",
            "application/json, application/yaml, text/yaml, */*",
        )
        .send()
        .await
        .map_err(|e| format!("Failed to fetch spec: {e}"))?;

    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("Spec fetch returned HTTP {status}"));
    }

    let collected = response
        .collect()
        .await
        .map_err(|e| format!("Spec response is not valid UTF-8: {e}"))?;
    collected
        .text()
        .map_err(|e| format!("Spec response is not valid UTF-8: {e}"))
}

/// Fetch (or use cached) tools for the given config's spec_url.
async fn get_or_fetch_tools(config: &BridgeConfig) -> Result<Vec<tools::ResolvedTool>, String> {
    if let Some(cached) = cache::get_cached(&config.spec_url) {
        return Ok(cached);
    }

    let body = fetch_spec(&config.spec_url).await?;
    let spec = spec::OpenApiSpec::parse(&body)?;
    let resolved = tools::extract_tools(&spec);

    cache::put_cached(config.spec_url.clone(), spec, resolved.clone());

    Ok(resolved)
}

/// Convert a ResolvedTool to a WIT ToolDefinition.
fn to_wit_tool(tool: &tools::ResolvedTool) -> ToolDefinition {
    let mut metadata = Vec::new();

    if tool.metadata_flags.read_only {
        metadata.push((
            act_types::constants::META_READ_ONLY.to_string(),
            cbor::to_cbor(&true),
        ));
    }
    if tool.metadata_flags.idempotent {
        metadata.push((
            act_types::constants::META_IDEMPOTENT.to_string(),
            cbor::to_cbor(&true),
        ));
    }
    if tool.metadata_flags.destructive {
        metadata.push((
            act_types::constants::META_DESTRUCTIVE.to_string(),
            cbor::to_cbor(&true),
        ));
    }

    let schema = tools::build_parameters_schema(tool);
    let schema_str =
        serde_json::to_string(&schema).unwrap_or_else(|_| r#"{"type":"object"}"#.to_string());

    ToolDefinition {
        name: tool.name.clone(),
        description: LocalizedString::Plain(tool.description.clone()),
        parameters_schema: schema_str,
        metadata,
    }
}

/// Send an HTTP request and stream the response back.
async fn send_api_request(
    prepared: request::PreparedRequest,
    credential_key: &str,
    authenticated: bool,
    writer: &mut wit_bindgen::StreamWriter<tool_exports::ToolEvent>,
) {
    let client = match hclient::Client::builder(hclient_wasi::WasiHttp::new()).build() {
        Ok(c) => c,
        Err(e) => {
            let _ = writer
                .write_all(vec![tool_exports::ToolEvent::Error(make_error(
                    act_types::constants::ERR_INTERNAL,
                    format!("HTTP error: {e}"),
                ))])
                .await;
            return;
        }
    };
    // Redirects stay off, as `redirect_limit(0)` had it: the caller's URL
    // is the API endpoint the session was built around, and following a
    // `Location:` elsewhere would quietly move the credential. `Forbid`
    // hands the 3xx response back rather than erroring — what
    // `redirect_limit(0)` did. (`Limit::new(0)` would turn the first
    // redirect into an error instead.)
    let mut builder = client
        .request(prepared.method, &prepared.url)
        .redirect(hclient::redirect::Forbid);

    for (name, value) in prepared.headers.iter() {
        if let Ok(v) = value.to_str() {
            builder = builder.header(name.as_str(), v);
        }
    }

    if let Some(body) = prepared.body {
        builder = builder.body(hclient::RequestBody::Full(bytes::Bytes::from(body)));
    }

    let mut response = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            let _ = writer
                .write_all(vec![tool_exports::ToolEvent::Error(make_error(
                    act_types::constants::ERR_INTERNAL,
                    format!("HTTP error: {e}"),
                ))])
                .await;
            return;
        }
    };

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 401/403 is the API saying the credential is the problem, and it is the
    // only authority on that — a document's `security` list says what the API
    // declares, not which of its operations actually enforce it. Reported as
    // `std:credential-required` with the provisioning command, rather than as
    // an internal error with a body the agent cannot act on.
    if status == 401 || status == 403 {
        // The body is dropped rather than quoted: a WWW-Authenticate challenge
        // or an upstream error page adds nothing the message below does not
        // already say, and an API that echoes the presented key would put it
        // in the agent's context.
        if let Ok(collected) = response.collect().await {
            let _ = collected.text();
        }
        let _ = writer
            .write_all(vec![tool_exports::ToolEvent::Error(
                unauthorized(status, credential_key, authenticated).await,
            )])
            .await;
        return;
    }

    if status >= 400 {
        let body = response
            .collect()
            .await
            .and_then(|c| c.text())
            .unwrap_or_default();
        let _ = writer
            .write_all(vec![tool_exports::ToolEvent::Error(make_error(
                act_types::constants::ERR_INTERNAL,
                format!("HTTP {status}: {body}"),
            ))])
            .await;
        return;
    }

    // hclient's `chunk` hands back `Option<Result<Bytes, _>>` — a body the
    // transport could not finish reading is reported, not silently
    // swallowed: what the agent has received so far is a partial response,
    // and an error event saying so beats a stream that just stops.
    while let Some(chunk) = response.chunk().await {
        match chunk {
            Ok(data) => {
                let _ = writer
                    .write_all(vec![tool_exports::ToolEvent::Content(ContentPart {
                        data: data.to_vec(),
                        mime_type: content_type.clone(),
                        metadata: vec![],
                    })])
                    .await;
            }
            Err(e) => {
                let _ = writer
                    .write_all(vec![tool_exports::ToolEvent::Error(make_error(
                        act_types::constants::ERR_INTERNAL,
                        format!("HTTP error while reading the response: {e}"),
                    ))])
                    .await;
                return;
            }
        }
    }
}

// ── Component entry point ──────────────────────────────────────────────────

struct OpenApiBridge;

export!(OpenApiBridge);

// ── tool-provider ──────────────────────────────────────────────────────────

impl tool_exports::Guest for OpenApiBridge {
    async fn list_tools(
        metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<tool_exports::ListToolsResponse, tool_exports::Error> {
        let session_id = match extract_session_id(&metadata) {
            Some(id) => id,
            None => {
                return Ok(tool_exports::ListToolsResponse {
                    metadata: vec![],
                    tools: vec![],
                });
            }
        };

        let config = match snapshot_session(&session_id) {
            Some(c) => c,
            None => return Err(session_not_found(&session_id)),
        };

        let resolved = get_or_fetch_tools(&config)
            .await
            .map_err(|e| make_error(act_types::constants::ERR_INTERNAL, e))?;

        let tool_defs: Vec<ToolDefinition> = resolved.iter().map(to_wit_tool).collect();

        Ok(tool_exports::ListToolsResponse {
            metadata: vec![],
            tools: tool_defs,
        })
    }

    async fn call_tool(
        name: String,
        arguments: Vec<u8>,
        metadata: Vec<(String, Vec<u8>)>,
    ) -> tool_exports::ToolResult {
        let session_id = match extract_session_id(&metadata) {
            Some(id) => id,
            None => {
                return tool_exports::ToolResult::Immediate(vec![tool_exports::ToolEvent::Error(
                    invalid_args("Missing required metadata key std:session-id"),
                )]);
            }
        };

        let (config, selection) = match (
            snapshot_session(&session_id),
            snapshot_selection(&session_id),
        ) {
            (Some(c), Some(s)) => (c, s),
            _ => {
                return tool_exports::ToolResult::Immediate(vec![tool_exports::ToolEvent::Error(
                    session_not_found(&session_id),
                )]);
            }
        };

        let (mut writer, reader) = wit_stream::new::<tool_exports::ToolEvent>();

        wit_bindgen::spawn_local(async move {
            // Resolve the operation. open-session pre-fetched the spec,
            // so this should hit the cache; fall through to a refetch if
            // the cache was evicted.
            let tool = match cache::get_cached_tool(&config.spec_url, &name) {
                Some(t) => t,
                None => match get_or_fetch_tools(&config).await {
                    Ok(_) => match cache::get_cached_tool(&config.spec_url, &name) {
                        Some(t) => t,
                        None => {
                            let _ = writer
                                .write_all(vec![tool_exports::ToolEvent::Error(make_error(
                                    act_types::constants::ERR_NOT_FOUND,
                                    format!("Tool '{name}' not found in spec"),
                                ))])
                                .await;
                            return;
                        }
                    },
                    Err(e) => {
                        let _ = writer
                            .write_all(vec![tool_exports::ToolEvent::Error(make_error(
                                act_types::constants::ERR_INTERNAL,
                                e,
                            ))])
                            .await;
                        return;
                    }
                },
            };

            // Decode arguments from CBOR.
            let args: serde_json::Value = if arguments.is_empty() {
                serde_json::json!({})
            } else {
                match cbor::from_cbor(&arguments) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = writer
                            .write_all(vec![tool_exports::ToolEvent::Error(invalid_args(format!(
                                "Invalid arguments: {e}"
                            )))])
                            .await;
                        return;
                    }
                }
            };

            // Per-call header overrides (callers can still pass per-tool
            // headers via metadata). They cannot reach the credential-derived
            // header — `build_request` applies that last, by design.
            let call_headers = request::extract_call_headers(&metadata);

            // The credential, on first use. Never at open: the host marks a
            // session live only after `open-session` returns (ACT-AUTH
            // §1.1.4), so a fetch from inside it is refused, always.
            let credential = match ensure_credential(&session_id, &config, &selection).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = writer
                        .write_all(vec![tool_exports::ToolEvent::Error(e)])
                        .await;
                    return;
                }
            };

            let raw_base = cache::get_base_url(&config.spec_url).unwrap_or_default();
            let base_url = resolve_base_url(&config.spec_url, &raw_base);
            // The resolved base URL is where the credential is about to be
            // sent, and userinfo in it is a second credential riding along —
            // one that came from the *document* rather than from session args,
            // so the open-time guard never saw it.
            if let Err(e) = check_url_no_userinfo(&base_url, "the API's server URL") {
                let _ = writer
                    .write_all(vec![tool_exports::ToolEvent::Error(invalid_args(e))])
                    .await;
                return;
            }

            let prepared = match request::build_request(
                &tool,
                &args,
                &base_url,
                &config.headers,
                &call_headers,
                credential.as_ref(),
            ) {
                Ok(r) => r,
                Err(e) => {
                    let _ = writer
                        .write_all(vec![tool_exports::ToolEvent::Error(invalid_args(e))])
                        .await;
                    return;
                }
            };

            send_api_request(
                prepared,
                &config.credential_key,
                credential.is_some(),
                &mut writer,
            )
            .await;
        });

        tool_exports::ToolResult::Streaming(reader)
    }
}

// ── session-provider ───────────────────────────────────────────────────────

fn open_invalid_args(message: String) -> session_exports::Error {
    session_exports::Error {
        kind: act_types::constants::ERR_INVALID_ARGS.to_string(),
        message: LocalizedString::Plain(message),
        metadata: vec![],
    }
}

impl session_exports::Guest for OpenApiBridge {
    async fn get_open_session_args_schema(
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<String, session_exports::Error> {
        let schema = schemars::schema_for!(BridgeConfig);
        serde_json::to_string(&schema).map_err(|e| session_exports::Error {
            kind: act_types::constants::ERR_INTERNAL.to_string(),
            message: LocalizedString::Plain(format!("Schema serialization failed: {e}")),
            metadata: vec![],
        })
    }

    async fn open_session(
        args: Vec<(String, Vec<u8>)>,
        _metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<session_exports::Session, session_exports::Error> {
        let mut json_map = serde_json::Map::with_capacity(args.len());
        for (k, v) in &args {
            if let Ok(val) = ciborium::from_reader::<serde_json::Value, _>(v.as_slice()) {
                json_map.insert(k.clone(), val);
            }
        }
        let config: BridgeConfig = serde_json::from_value(serde_json::Value::Object(json_map))
            .map_err(|e| session_exports::Error {
                kind: act_types::constants::ERR_INVALID_ARGS.to_string(),
                message: LocalizedString::Plain(format!("Invalid open-session args: {e}")),
                metadata: vec![],
            })?;

        // Refused here rather than at the request that would carry them: a
        // credential smuggled through `headers` or through the URL's userinfo
        // would bypass the credential store entirely, and the caller supplied
        // both right here.
        let config = spec::validate(config).map_err(open_invalid_args)?;

        // Pre-fetch the spec so list-tools is cheap and connect / parse
        // failures surface at open time (per ACT-SESSIONS §2.2).
        get_or_fetch_tools(&config)
            .await
            .map_err(|e| session_exports::Error {
                kind: act_types::constants::ERR_INTERNAL.to_string(),
                message: LocalizedString::Plain(e),
                metadata: vec![],
            })?;

        // Choose the security scheme now, from the document just parsed. A
        // `security_scheme` that names nothing, or names something this bridge
        // cannot present, is a mistake in *these* args — so it is refused
        // where they were supplied rather than on the first tool call.
        //
        // **`get-secret` is deliberately not called here**, and cannot be:
        // the host marks a session live only after this function returns, so
        // the id below has never been seen and the request would be refused as
        // an unknown session (ACT-AUTH §1.1.4).
        let selection = cache::select_scheme(&config.spec_url, config.security_scheme.as_deref())
            .ok_or_else(|| session_exports::Error {
                kind: act_types::constants::ERR_INTERNAL.to_string(),
                message: LocalizedString::Plain(
                    "the OpenAPI document was fetched but is no longer cached".to_string(),
                ),
                metadata: vec![],
            })?
            .map_err(open_invalid_args)?;

        // The half of the header guard that needs the document: this API's own
        // API-key header name, which no static denylist could contain.
        spec::validate_scheme(&config.headers, &selection.scheme).map_err(open_invalid_args)?;

        let id = alloc_session_id();
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                id.clone(),
                UpstreamSession {
                    config,
                    selection,
                    credential: Credential::Unfetched,
                },
            );
        });

        Ok(session_exports::Session {
            id,
            metadata: vec![],
        })
    }

    fn close_session(session_id: String) {
        SESSIONS.with(|s| {
            s.borrow_mut().remove(&session_id);
        });
    }
}
