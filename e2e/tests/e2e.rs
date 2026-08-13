//! Drive the packed component through `act run --mcp` with a real MCP client.
//!
//! Rust translation of the python fastmcp/pytest suite that still lives in
//! this directory (kept for reference); the tests observe exactly what an
//! agent observes, over the same client stack (`rmcp`) the host bridge itself
//! is built on.
//!
//! openapi-bridge is a session-provider like sqlite: each session pins to one
//! upstream OpenAPI spec (`spec_url` + optional default `headers`), and every
//! real tool call needs `std:session-id` in its argument metadata (ACT-MCP
//! §3.2). This suite gets that id via the virtual `open_session`/
//! `close_session` tools rather than the host's `--session-args` session-of-1
//! shortcut — see components/sqlite/e2e/conftest.py for the full rationale;
//! nothing here repeats it.
//!
//! External services: the petstore-derived tests (`// needs: petstore`)
//! speak to `PETSTORE_SPEC` — by default the public
//! `https://petstore3.swagger.io/api/v3/openapi.json`, in CI a local
//! `swaggerapi/petstore3:unstable` sidecar — confirmed reachable by
//! [`petstore_spec_url`] before any test opens a session against it. The
//! credential-presentation tests need nothing outside the machine: they
//! serve their own per-test echo API and provision a throwaway credential
//! store.
//!
//! Env: WASM — path to the packed component (default: the component's
//!      release build output);
//!      ACT  — the act invocation (default `act`; the component justfile's
//!             `npx @actcore/act`, two words, also works — whitespace-split,
//!             like the shlex.split the python conftest did);
//!      PETSTORE_SPEC — the upstream OpenAPI spec URL the petstore tests
//!             drive.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;

/// `().serve(transport)` hands back the client-role service running over the
/// child process: role first, the unit client handler second.
type Client = rmcp::service::RunningService<rmcp::service::RoleClient, ()>;

/// Deliberately loose, carried verbatim from the python conftest:
/// `act run --mcp` instantiates the component before it answers
/// `initialize`, so "connect" includes that cost — for a heavy component
/// (servo embeds a browser engine) it is seconds, and on a loaded runner it
/// varies. 30s tripped servo in CI while its healthy connect was ~8s, so the
/// bound sits well above the worst observed cost. The bound exists to give a
/// clear "did not connect" diagnostic instead of a stalled handshake with
/// none.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

fn wasm_path() -> PathBuf {
    let path = PathBuf::from(std::env::var("WASM").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../target/wasm32-wasip2/release/openapi_bridge.wasm"
        )
        .into()
    }));
    ensure_packed(&path);
    path
}

/// The python `wasm_path` fixture's probe, run once per process. Existence is
/// not enough and neither is a fresh mtime: `cargo build` produces a wasm
/// with no `act:component` custom section, and an unpacked artifact declares
/// no capability ceiling, so every grant is refused as "outside ceiling" and
/// the failures point anywhere but here. This has already bitten three
/// components in this workspace, so the check reads the section rather than
/// the file. The justfile's `test: build` ordering exists so this passes.
fn ensure_packed(path: &Path) {
    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(|| {
        if !path.exists() {
            panic!("{path:?} is missing — run `just build` first");
        }
        let mut cmd = new_std_command();
        cmd.args(["inspect", "component-manifest"]).arg(path);
        let output = cmd.output().expect("run act inspect component-manifest");
        let manifest: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        let name = manifest["std"]["name"].as_str().unwrap_or("unknown");
        if name.is_empty() || name == "unknown" {
            panic!("{path:?} is built but not packed — run `just build`");
        }
    });
}

/// The ACT invocation, honouring the same override the component justfile
/// uses. Its default there is `npx @actcore/act` — two words — which cannot
/// be `argv[0]` for a non-shell spawn, so the value is whitespace-split into
/// program + leading args. Quoted paths with spaces are not a form this
/// fleet passes through `ACT`; a full shlex is deliberately not pulled in.
fn act_argv() -> Vec<String> {
    std::env::var("ACT")
        .unwrap_or_else(|_| "act".into())
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// A per-process credential-store root: the shared `client` fixture names no
/// `--credentials-backend`, so `act run` reads the platform default store —
/// which, without this relocation, would be whatever the machine running the
/// suite happens to hold. "No credential is stored" is a premise three tests
/// stand on (`ACT-AUTH` §1.1.7 makes an empty store and a denied class
/// indistinguishable to the guest, so it must actually be empty); a
/// developer who has provisioned this component's `default` profile would
/// otherwise turn that premise into a property of their laptop.
///
/// Applied to every spawned `act` as env (`XDG_DATA_HOME`/`XDG_CONFIG_HOME`
/// — `act` keeps credentials under `dirs::data_dir()`, which is
/// `$XDG_DATA_HOME` on Linux) rather than to this process: cargo runs tests
/// on parallel threads, where `std::env::set_var` is a data race.
fn store_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("openapi-bridge-e2e-{}", std::process::id()));
        std::fs::create_dir_all(root.join("data")).expect("create suite data dir");
        std::fs::create_dir_all(root.join("config")).expect("create suite config dir");
        root
    })
}

fn apply_store_env(cmd: &mut tokio::process::Command, root: &Path) {
    cmd.env("XDG_DATA_HOME", root.join("data"));
    cmd.env("XDG_CONFIG_HOME", root.join("config"));
}

fn apply_store_env_std(cmd: &mut std::process::Command, root: &Path) {
    cmd.env("XDG_DATA_HOME", root.join("data"));
    cmd.env("XDG_CONFIG_HOME", root.join("config"));
}

fn new_std_command() -> std::process::Command {
    let argv = act_argv();
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    apply_store_env_std(&mut cmd, store_root());
    cmd
}

/// Spawn `act run <wasm> --mcp` with the grants this component needs.
///
/// Grants are NOT optional: the default policy mode is `ask` and a headless
/// run degrades it to deny. `--allow wasi:http` opens the full `wasi:http`
/// ceiling act.toml declares (`host = "*"` — the upstream is chosen per
/// session, so the ceiling is open by nature), carried verbatim from the
/// python conftest's grant. `act:credentials` is granted too, because the
/// component imports the store: a denied class and an empty store are
/// indistinguishable to the guest by design (`ACT-AUTH` §1.1.7), so without
/// this the suite would exercise the "denied" branch while believing it
/// exercised the "no credential stored" one. No secret is provisioned for
/// these runs: the petstore operations they drive need none, and the point
/// is that the bridge reaches them unauthenticated.
fn act_command() -> tokio::process::Command {
    let argv = act_argv();
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.arg("run").arg(wasm_path()).arg("--mcp");
    cmd.args(["--allow", "wasi:http", "--allow", "act:credentials"]);
    apply_store_env(&mut cmd, store_root());
    cmd
}

/// The presentation module's `act run`: the same grants, plus the
/// `--credentials-backend` naming the store that fixture provisioned — the
/// shared one names no store, so `get-secret` would find nothing.
fn act_command_with_backend(backend: &str) -> tokio::process::Command {
    let mut cmd = act_command();
    cmd.args(["--credentials-backend", backend]);
    cmd
}

/// Spawn with stderr captured: the audit trail (refusals, per-call rollup)
/// writes there unconditionally — RUST_LOG never silences it — and the
/// python conftest redirected it to a log file to keep it out of the test
/// output. The [`ActStderr`] guard reprints it when a test fails, which is
/// that suite's `pytest_sessionfinish` hook's job.
fn spawn_with_captured_stderr(cmd: tokio::process::Command) -> (TokioChildProcess, Arc<AsyncMutex<String>>) {
    let (transport, stderr) = TokioChildProcess::builder(cmd)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act run --mcp with piped stderr");

    let captured = Arc::new(AsyncMutex::new(String::new()));
    let sink = captured.clone();
    let mut lines = BufReader::new(stderr.expect("stderr was piped")).lines();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            sink.lock().await.push_str(&line);
            sink.lock().await.push('\n');
        }
    });

    (transport, captured)
}

/// Reprints the captured audit trail if the test is unwinding — on an
/// ephemeral CI runner nothing would otherwise ever read it. Diagnosing a
/// CI-only hang in this fleet cost several rounds of probing that one line
/// of this stream would have answered.
struct ActStderr(Arc<AsyncMutex<String>>);

impl Drop for ActStderr {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        // The drain task holds the lock only per line; a short retry is
        // enough to catch a quiet moment.
        for _ in 0..20 {
            if let Ok(buf) = self.0.try_lock() {
                eprintln!("--- act stderr ---\n{}", buf);
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        eprintln!("--- act stderr: buffer busy, not dumped ---");
    }
}

/// A connected MCP client, one `act` process per test: a session opened in
/// one test must not leak into the next (the python transport set
/// `keep_alive=False` for the same reason). The connect — not the test body
/// — is bounded, so a stalled handshake produces a diagnostic of its own
/// instead of consuming the whole test timeout silently.
async fn connect() -> (Client, ActStderr) {
    let (transport, captured) = spawn_with_captured_stderr(act_command());
    let client = tokio::time::timeout(CONNECT_TIMEOUT, ().serve(transport))
        .await
        .expect("MCP client did not connect; act's stderr is dumped by the failure guard")
        .expect("rmcp handshake with act run --mcp");
    (client, ActStderr(captured))
}

async fn connect_with_backend(backend: &str) -> (Client, ActStderr) {
    let (transport, captured) = spawn_with_captured_stderr(act_command_with_backend(backend));
    let client = tokio::time::timeout(CONNECT_TIMEOUT, ().serve(transport))
        .await
        .expect("MCP client did not connect; act's stderr is dumped by the failure guard")
        .expect("rmcp handshake with act run --mcp");
    (client, ActStderr(captured))
}

fn text_blocks(result: &rmcp::model::CallToolResult) -> Vec<String> {
    result
        .content
        .iter()
        .filter_map(|b| match b {
            rmcp::model::ContentBlock::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect()
}

fn first_text_block(result: &rmcp::model::CallToolResult) -> &rmcp::model::TextContent {
    match result.content.first() {
        Some(rmcp::model::ContentBlock::Text(t)) => t,
        other => panic!("expected the first content block to be Text, got: {other:?}"),
    }
}

/// A tool-call request. The session id rides in the *argument* channel — a
/// `_meta` key inside `arguments` (ACT-MCP §3.2), which the host pops before
/// the guest sees it — the same channel fastmcp's `{"_meta": …}` argument
/// used. `std:session-id` keeps its `std:` spelling there: the argument
/// channel is deliberately exempt from the `dev.actcore/` respelling that
/// governs MCP's transport-level `_meta` field (§3.1). Per-call header
/// overrides (`http:header:*`) ride the same channel, which is exactly what
/// `test_a_per_call_header_override_cannot_displace_the_credential` probes.
fn args_with_meta(arguments: Value, meta: Value) -> Value {
    let mut obj = arguments.as_object().cloned().unwrap_or_default();
    obj.insert("_meta".to_string(), meta);
    Value::Object(obj)
}

/// The python `session_meta` fixture: the `_meta` payload every real bridge
/// tool call needs.
fn session_meta(session_id: &str) -> Value {
    json!({ "std:session-id": session_id })
}

fn session_args(arguments: Value, session_id: &str) -> Value {
    args_with_meta(arguments, session_meta(session_id))
}

async fn call_tool(client: &Client, tool: &str, arguments: Value) -> rmcp::model::CallToolResult {
    client
        .call_tool(
            CallToolRequestParams::new(tool.to_string())
                .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
        )
        .await
        .unwrap_or_else(|e| panic!("call_tool {tool} failed at the transport: {e:?}"))
}

/// The kind and message of a failed call may arrive on either path: as a
/// JSON-RPC error response (`ErrorData.data` / `message`) or as an isError
/// result (`_meta` / first text content). The python conftest's
/// `expect_error` fixture handled both; so does this. `call-tool` has no
/// `result<>` wrapper, so a guest reporting a failed call can only do it
/// through `tool-event::error` — the isError path — while the JSON-RPC path
/// exists for failures that are not the guest's tool body: `list-tools`, the
/// session operations themselves, a wasmtime trap, an unreachable actor.
async fn error_kind_of(
    client: &Client,
    tool: &str,
    arguments: Value,
) -> Option<(String, String)> {
    match client
        .call_tool(
            CallToolRequestParams::new(tool.to_string())
                .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
        )
        .await
    {
        Err(rmcp::ServiceError::McpError(e)) => {
            let kind = e
                .data
                .as_ref()
                .and_then(|d| d.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            kind.map(|k| (k, e.message.to_string()))
        }
        Ok(result) => {
            assert_eq!(result.is_error, Some(true), "call must fail: {result:?}");
            let kind = result
                .meta
                .as_ref()
                .and_then(|m| m.0.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let message = text_blocks(&result).into_iter().next().unwrap_or_default();
            kind.map(|k| (k, message))
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    }
}

/// The python conftest's `expect_error` fixture: assert a call fails with a
/// specific ACT error kind.
async fn expect_error(client: &Client, tool: &str, arguments: Value, kind: &str) {
    let Some((actual_kind, message)) = error_kind_of(client, tool, arguments).await else {
        panic!("expected {tool} to fail with {kind}, but no named error kind came back");
    };
    assert_eq!(
        actual_kind, kind,
        "expected {kind}, got {actual_kind} ({message:?})"
    );
}

async fn open_session(client: &Client, arguments: Value) -> String {
    let result = call_tool(&client, "open_session", arguments).await;
    assert_ne!(result.is_error, Some(true), "open_session failed: {result:?}");
    let reply: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("reply is JSON");
    reply["id"]
        .as_str()
        .expect("open_session reply carries an id")
        .to_string()
}

async fn close_session(client: &Client, session_id: &str) {
    let result = call_tool(
        client,
        "close_session",
        json!({ "session_id": session_id }),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "close_session failed: {result:?}");
}

/// The python `session` fixture: a per-test session against the
/// (reachability-confirmed) petstore spec, opened via the virtual
/// `open_session` tool — the path an agent actually uses.
/// `open-session` pre-fetches and parses the spec, so connect/parse failures
/// surface here rather than on the first real call.
///
/// Closing: the python fixture closed on teardown, even mid-panic; here each
/// test owns one `act` process, so a session a panicking test leaves behind
/// dies with that process and cannot leak into the next test — tests close
/// explicitly at their end instead.
async fn open_petstore_session(client: &Client) -> String {
    let url = petstore_spec_url().await;
    open_session(client, json!({ "spec_url": url })).await
}

/// The python conftest's `openapi_\d+` `re.search` on the session id. The
/// ids are guest-generated (`format!("openapi_{id}")`, src/lib.rs) and hurl's
/// `matches` is an unanchored search; a prefix plus all-digits tail is what
/// that pattern accepts for any id this guest can mint, without pulling a
/// regex crate into a harness that needs no other one.
fn assert_openapi_session_id(session: &str) {
    let rest = session
        .strip_prefix("openapi_")
        .unwrap_or_else(|| panic!("session id {session:?} does not match openapi_\\d+"));
    assert!(
        !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        "session id {session:?} does not match openapi_\\d+"
    );
}

fn tool_named<'a>(tools: &'a [rmcp::model::Tool], name: &str) -> &'a rmcp::model::Tool {
    tools
        .iter()
        .find(|t| t.name.as_ref() == name)
        .unwrap_or_else(|| {
            panic!(
                "no `{name}` tool in {:?}",
                tools.iter().map(|t| t.name.to_string()).collect::<Vec<_>>()
            )
        })
}

/// The advertised tool names, sorted — the python tests compared `{...}`
/// sets, and a sorted vec is the same assertion with a deterministic
/// diagnostic.
fn tool_names(tools: &[rmcp::model::Tool]) -> Vec<String> {
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    names
}

// --- conftest.py: petstore_spec_url -----------------------------------------

/// The upstream OpenAPI spec URL, confirmed reachable before any test opens
/// a session against it — the python conftest's `petstore_spec_url` fixture.
///
/// Starting a call against a sidecar that hasn't finished booting and hoping
/// cost a component a red CI run; this polls 60 × 1s the way that fixture
/// (and the CI job's old separate curl-wait step) did. The CI sidecar is
/// `http://`, so the full GET-and-read-status probe below runs there; for an
/// `https://` URL the harness has no TLS stack, so the probe degrades to a
/// TCP connect — weaker (it cannot see a 500-ing origin) but it still
/// catches the failure mode the fixture exists for, a dark sidecar.
async fn petstore_spec_url() -> String {
    let url = std::env::var("PETSTORE_SPEC")
        .unwrap_or_else(|_| "https://petstore3.swagger.io/api/v3/openapi.json".into());
    let mut last_err = String::from("never probed");
    for _ in 0..60 {
        match probe_spec_reachable(&url).await {
            Ok(()) => return url,
            Err(e) => last_err = e,
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("petstore spec at {url} never became reachable: {last_err}");
}

async fn probe_spec_reachable(url: &str) -> Result<(), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "spec URL has no scheme".to_string())?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        other => return Err(format!("unsupported spec scheme {other:?}")),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    let (host, port) = match authority.rsplit_once(':') {
        // A bracketed IPv6 literal is out of scope for a probe of URLs this
        // suite actually drives (petstore3.swagger.io, localhost:8080).
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => {
            (h, p.parse::<u16>().expect("digits parse"))
        }
        _ => (authority, default_port),
    };

    let connect = async {
        tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect((host, port)))
            .await
            .map_err(|_| "connect timed out".to_string())?
            .map_err(|e| format!("connect failed: {e}"))
    };

    if scheme == "https" {
        connect.await.map(|_| ())
    } else {
        let mut sock = connect.await?;
        let request = format!(
            "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        sock.write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        let mut buf = [0u8; 128];
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .map_err(|_| "status read timed out".to_string())?
            .map_err(|e| format!("read failed: {e}"))?;
        let status_line = String::from_utf8_lossy(&buf[..n]);
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("no status line in {status_line:?}"))?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("spec probe got HTTP {status}"))
        }
    }
}

// --- test_credential_presentation.py: the local echo API --------------------

const TOKEN: &str = "sentinel-token-value";
const USER: &str = "sentinel-user";
const PASSWORD: &str = "sentinel-password";

/// One document per scheme, keyed by the path it is served from. `none`
/// declares no scheme at all: the documented fallback is `Authorization:
/// Bearer`.
fn scheme_definition(name: &str) -> Option<Option<Value>> {
    match name {
        "bearer" => Some(Some(json!({"type": "http", "scheme": "bearer"}))),
        "basic" => Some(Some(json!({"type": "http", "scheme": "basic"}))),
        "apikey-header" => Some(Some(json!({
            "type": "apiKey", "name": "X-Custom-Key", "in": "header"
        }))),
        "apikey-query" => Some(Some(json!({
            "type": "apiKey", "name": "access_key", "in": "query"
        }))),
        "none" => Some(None),
        _ => None,
    }
}

/// The OpenAPI document the python `Api` handler served for `name`, with the
/// `servers` URL filled in by the caller once the server has a port.
fn echo_document(base_url: &str, name: &str) -> Value {
    let mut document = json!({
        "openapi": "3.0.3",
        "info": {"title": "Echo", "version": "1.0"},
        "servers": [{"url": base_url}],
        "paths": {
            "/echo": {"get": {"operationId": "echo", "summary": "Echo"}}
        }
    });
    if let Some(Some(def)) = scheme_definition(name) {
        document["components"] = json!({"securitySchemes": {name: def}});
        document["security"] = json!([{name: []}]);
    }
    document
}

/// A local HTTP server for the credential-presentation tests: an OpenAPI
/// document per scheme, plus one operation that echoes the request back —
/// the rust analogue of the python module's `ThreadingHTTPServer`. Each test
/// spawns its own on an ephemeral port (the python one was module-scoped;
/// per-test keeps the accept loop inside that test's own tokio runtime and
/// costs nothing measurable), served from a detached task — no live or
/// public endpoint, nothing to go dark in CI.
///
/// Every request this server sees is a GET, so end-of-headers is
/// end-of-request; the de-chunking the e2e-harness notes warn about applies
/// to request *bodies*, and the echo operation takes none.
async fn spawn_echo_api() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo API");
    let addr: SocketAddr = listener.local_addr().expect("echo API addr");
    let base_url = format!("http://{addr}");
    let base_url_for_stub = base_url.clone();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let base_url = base_url_for_stub.clone();
            tokio::spawn(async move {
                let raw = match tokio::time::timeout(
                    Duration::from_secs(10),
                    read_head(&mut sock),
                )
                .await
                {
                    Ok(Ok(raw)) => raw,
                    _ => return,
                };
                let text = String::from_utf8_lossy(&raw);
                let mut lines = text.split("\r\n");
                let request_line = lines.next().unwrap_or("");
                let target = request_line.split_whitespace().nth(1).unwrap_or("/");
                let (path, query) = match target.split_once('?') {
                    Some((p, q)) => (p.to_string(), q.to_string()),
                    None => (target.to_string(), String::new()),
                };
                let mut headers = serde_json::Map::new();
                for line in lines.by_ref() {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        headers.insert(
                            k.trim().to_ascii_lowercase(),
                            Value::String(v.trim().to_string()),
                        );
                    }
                }

                // python: name = parsed.path.removeprefix("/").removesuffix(".json")
                let name = path
                    .strip_prefix('/')
                    .unwrap_or(&path)
                    .strip_suffix(".json")
                    .unwrap_or(path.strip_prefix('/').unwrap_or(&path));

                let (status, body) = if path.ends_with(".json") {
                    match scheme_definition(name) {
                        Some(_) => (200, echo_document(&base_url, name)),
                        None => (404, json!({})),
                    }
                } else if path == "/echo" {
                    (200, json!({"headers": headers, "query": query}))
                } else {
                    (404, json!({}))
                };

                let body = serde_json::to_vec(&body).expect("echo response serializes");
                let response = format!(
                    "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    base_url
}

/// Read to the end of the request head (`\r\n\r\n`). A GET has no body, so
/// that is the whole request.
async fn read_head(sock: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(buf)
}

// --- conftest.py: credential_store (test_credential_presentation.py) --------

/// A `--credentials-backend` argument naming a store holding one credential
/// under the key openapi-bridge looks for by default — the python module's
/// module-scoped `credential_store` fixture, created once per process.
///
/// All four field names are written into the one credential on purpose: which
/// of them is read is decided by the *scheme*, and a store holding them all
/// is what makes that visible — the token cases must not start sending
/// Basic, and the Basic case must not start sending the token.
///
/// The only early-out: this CLI has no credential store, so the feature
/// under test does not exist here — every presentation test prints that and
/// returns (the python fixture's `pytest.skip`, in cargo's vocabulary, the
/// same one search-yandex's live tests use). A failed `act secret set` after
/// a passing probe is NOT that: the store broke rather than is absent, and
/// skipping would turn every test below green while proving nothing — that
/// is a panic.
fn credential_store() -> Option<&'static PathBuf> {
    static STORE: OnceLock<Option<PathBuf>> = OnceLock::new();
    STORE
        .get_or_init(|| {
            let probe = new_std_command()
                .args(["secret", "--help"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("probe act secret --help");
            if probe.status.success() {
                Some(provision_credential_store())
            } else {
                None
            }
        })
        .as_ref()
}

fn provision_credential_store() -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("openapi-bridge-e2e-creds-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create credential store root");
    let backend = format!("file:{}", root.display());
    let payload = json!({
        "openapi:token": TOKEN,
        "openapi:username": USER,
        "openapi:password": PASSWORD,
    })
    .to_string();

    let argv = act_argv();
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.args(["secret", "set"]).arg(wasm_path());
    cmd.args([
        "--key",
        "default",
        "--field",
        "openapi:token",
        "--field",
        "openapi:username",
        "--field",
        "openapi:password",
        "--fields-stdin",
        "--credentials-backend",
        &backend,
    ]);
    apply_store_env_std(&mut cmd, store_root());
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // `act secret set` reads the field values from stdin, so the values
    // never appear in a command line, in the child's environment, or in this
    // test's output.
    let mut child = cmd.spawn().expect("spawn act secret set");
    // ChildStdin is a std::io::Write, not tokio's — scoped import so the
    // stub's tokio write_all sites above stay unambiguous.
    use std::io::Write as _;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(payload.as_bytes())
        .expect("write the credential payload");
    let output = child.wait_with_output().expect("act secret set");
    assert!(
        output.status.success(),
        "`act secret set` failed even though `act secret` exists, so the credential \
         store is broken rather than missing:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    root
}

// --- test_info.py -----------------------------------------------------------

#[test]
fn test_manifest_reports_name_and_version() {
    let wasm = wasm_path();
    let mut cmd = new_std_command();
    cmd.args(["inspect", "component-manifest"]).arg(&wasm);
    let output = cmd.output().expect("run act inspect component-manifest");
    assert!(
        output.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value =
        serde_json::from_slice(&output.stdout).expect("manifest is JSON");
    assert_eq!(
        manifest["std"]["name"], "openapi-bridge",
        "packed manifest must carry the component name"
    );
    assert!(
        manifest["std"]["version"].is_string(),
        "packed manifest must carry a version, got: {}",
        manifest["std"]["version"]
    );
}

// --- test_no_session.py -----------------------------------------------------
//
// Without std:session-id, list-tools returns an empty list from the guest's
// own perspective, and call-tool errors with std:invalid-args — the original
// hurl file's contract, exercised over ACT-HTTP then over MCP.

#[tokio::test]
async fn test_no_session_list_tools_shows_only_virtual_tools() {
    let (client, _stderr) = connect().await;
    // The original hurl asserted `$.tools count == 0` over ACT-HTTP, which
    // has no synthesised session tools. Measured (not assumed) over MCP: the
    // guest's own `list-tools` still returns nothing (src/lib.rs,
    // `extract_session_id` -> None -> `tools: []`), but the adapter
    // additionally synthesises `open_session`/`close_session` for any
    // session-provider component (ACT-MCP §4.1) independent of session state
    // — so the true count here is 2, not 0.
    let tools = client.list_all_tools().await.expect("list_all_tools");
    assert_eq!(
        tool_names(&tools),
        ["close_session", "open_session"],
        "without a session only the virtual session tools are advertised"
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_no_session_call_is_invalid_args() {
    let (client, _stderr) = connect().await;
    let result = call_tool(&client, "anything", json!({})).await;
    assert_eq!(result.is_error, Some(true), "expected a refusal: {result:?}");
    let kind = result
        .meta
        .as_ref()
        .and_then(|m| m.0.get("dev.actcore/error-kind"))
        .and_then(Value::as_str);
    assert_eq!(kind, Some("std:invalid-args"), "got {result:?}");
    assert!(
        first_text_block(&result).text.contains("std:session-id"),
        "the refusal must name the missing key, got: {:?}",
        first_text_block(&result).text
    );
    client.cancel().await.ok();
}

// --- test_open_session_args_schema.py ---------------------------------------
//
// The open-session args schema is driven by `BridgeConfig` (schemars). Over
// MCP there is no dedicated `/sessions/open-args-schema` endpoint; the same
// schema is what the adapter publishes as the virtual `open_session` tool's
// `inputSchema` (ACT-MCP §4.1, `get-open-session-args-schema`).

#[tokio::test]
async fn test_open_session_args_schema() {
    let (client, _stderr) = connect().await;
    let tools = client.list_all_tools().await.expect("list_all_tools");
    let schema = &tool_named(&tools, "open_session").input_schema;
    assert_eq!(
        schema.get("type").and_then(Value::as_str),
        Some("object"),
        "open_session inputSchema must be an object, got: {schema:?}"
    );
    assert!(
        schema
            .get("properties")
            .and_then(|p| p.get("spec_url"))
            .is_some(),
        "open_session inputSchema must name spec_url, got: {schema:?}"
    );
    client.cancel().await.ok();
}

// --- test_credentials.py ----------------------------------------------------
//
// The credential is not a session argument, and `headers` cannot become one.
//
// Everything here is observed through the same MCP surface an agent sees. No
// real API key is used anywhere: the assertions are about the published
// open-args schema and about the guest's own refusal paths, all of which
// answer before any authenticated request is made.

/// The text of an `open_session` that must fail. Session-lifecycle failures
/// surface on the JSON-RPC error path rather than as a tool result with
/// `isError` — measured, and documented in the python conftest's
/// `expect_error`. Both are handled so the assertions below read as
/// assertions rather than as transport handling.
async fn refusal_text(client: &Client, arguments: Value) -> String {
    match client
        .call_tool(
            CallToolRequestParams::new("open_session")
                .with_arguments(arguments.as_object().cloned().unwrap_or_default()),
        )
        .await
    {
        Err(rmcp::ServiceError::McpError(e)) => e.message.to_string(),
        Ok(result) => {
            assert_eq!(result.is_error, Some(true), "expected a refusal, got {result:?}");
            text_blocks(&result).join("")
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    }
}

#[tokio::test]
async fn test_open_session_schema_offers_nowhere_to_put_a_credential() {
    let (client, _stderr) = connect().await;
    // `open_session`'s inputSchema is what an agent reads before deciding
    // what to hand over. It must name a credential and carry none.
    let tools = client.list_all_tools().await.expect("list_all_tools");
    let schema = &tool_named(&tools, "open_session").input_schema;
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("open_session inputSchema carries properties");
    let mut names: Vec<&str> = props.keys().map(String::as_str).collect();
    names.sort();
    assert_eq!(
        names,
        ["credential_key", "headers", "security_scheme", "spec_url"],
        "open_session's published properties are exactly the four, got: {names:?}"
    );
    for forbidden in ["password", "passwd", "pwd", "secret", "token", "auth", "api_key"] {
        assert!(
            !names.iter().any(|name| name.to_lowercase().contains(forbidden)),
            "a place to put a {forbidden}: {names:?}"
        );
    }
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_an_auth_shaped_header_is_refused_at_open() {
    // needs: petstore — the URL the refusal names is the suite's petstore
    // spec; the header guard itself fires before any fetch, so an unreachable
    // petstore does not change what this test observes.
    let url = petstore_spec_url().await;
    let (client, _stderr) = connect().await;
    // `headers` survives for non-secret defaults only. A credential smuggled
    // through it would bypass the credential store entirely, so the refusal
    // happens where the caller supplied it.
    for header in ["Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "api-key"] {
        let text = refusal_text(
            &client,
            json!({"spec_url": url, "headers": {header: "sentinel-value"}}),
        )
        .await;
        assert!(
            !text.contains("sentinel-value"),
            "the refusal echoed the value ({header}): {text}"
        );
        assert!(text.contains("credential_key"), "({header}): {text}");
    }
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_a_non_secret_header_is_still_accepted() {
    let url = petstore_spec_url().await;
    let (client, _stderr) = connect().await;
    // The guard is a denylist of credential-bearing names, not a ban on
    // headers: an `Accept` or a tenant id is exactly what `headers` is for.
    let sid = open_session(
        &client,
        json!({
            "spec_url": url,
            "headers": {"Accept": "application/json", "X-Tenant": "acme"},
        }),
    )
    .await;
    assert_openapi_session_id(&sid);
    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_userinfo_in_the_spec_url_is_refused() {
    let (client, _stderr) = connect().await;
    // A URL's spelling of a credential. It also travels: `spec_url` becomes
    // `secret-request.resource`, which leaves the component for the host.
    // The guard fires before any fetch, so nothing outside the machine is
    // contacted for this test.
    let text = refusal_text(
        &client,
        json!({
            "spec_url":
                "https://svc:sentinel-value@petstore3.swagger.io/api/v3/openapi.json"
        }),
    )
    .await;
    assert!(!text.contains("sentinel-value"), "userinfo echoed: {text}");
    assert!(text.contains("userinfo"), "{text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_pinning_an_undeclared_security_scheme_fails_at_open() {
    // needs: petstore — the refusal is raised after the spec is fetched and
    // parsed, and lists what the document actually declares.
    let url = petstore_spec_url().await;
    let (client, _stderr) = connect().await;
    // The pin names a key of `components.securitySchemes`. Naming one the
    // document does not declare is a mistake in these args, so it is refused
    // here rather than on the first tool call — and the refusal lists what
    // the document does declare.
    let text = refusal_text(
        &client,
        json!({"spec_url": url, "security_scheme": "nope"}),
    )
    .await;
    assert!(text.contains("nope") && text.contains("api_key"), "{text}");
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_pinning_a_declared_scheme_opens() {
    // needs: petstore
    let url = petstore_spec_url().await;
    let (client, _stderr) = connect().await;
    // The petstore declares `api_key` (apiKey in header) and `petstore_auth`
    // (oauth2). Both are presentable, so either may be pinned.
    for scheme in ["api_key", "petstore_auth"] {
        let sid = open_session(
            &client,
            json!({"spec_url": url, "security_scheme": scheme}),
        )
        .await;
        close_session(&client, &sid).await;
    }
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_calls_still_work_with_no_credential_stored() {
    // needs: petstore
    let (client, _stderr) = connect().await;
    let sid = open_petstore_session(&client).await;
    // A document declaring a security scheme does not mean every operation
    // enforces it. With nothing in the store, the bridge calls the API
    // unauthenticated rather than refusing on the document's behalf — and
    // the API's own 401/403, not the empty store, is what would fail the
    // call.
    let result = call_tool(
        &client,
        "find_pets_by_status",
        session_args(json!({"status": "sold"}), &sid),
    )
    .await;
    assert_ne!(
        result.is_error,
        Some(true),
        "unauthenticated call failed: {:?}",
        result.content
    );
    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// --- test_list_tools_not_session_scoped.py ----------------------------------
//
// Documents a measured MCP-transport limitation, not a ported assertion.
//
// The original petstore.hurl, after opening a session, asserted
// `$.tools count >= 10` plus 7 `contains` checks (find_pets_by_status,
// get_inventory, add_pet, get_pet_by_id, login_user, place_order,
// delete_order) against `POST /tools {"metadata": {"std:session-id": sid}}` —
// ACT-HTTP lets a caller pass per-request metadata straight into `list-tools`.
//
// MCP's `tools/list` has no equivalent channel: unlike `tools/call`, there is
// no `arguments` object to inject a `_meta` property into (ACT-MCP §3.2 is
// explicitly a `tools/call`-only mechanism), and the transport `_meta` field
// (§3.1) is read for `call_tool` but explicitly discarded for `list_tools`
// (act-cli/src/rmcp_bridge.rs, `list_tools`: `let _ = context;`). So there is
// no way, over MCP, for a client of any library to make `list-tools` reflect
// a particular session's resolved operations — confirmed by reading the
// adapter, not inferred from a client-side symptom.
//
// This is a `tools/list`-specific gap, not a functional one: every
// petstore-derived tool the CRUD tests drive works correctly despite never
// appearing in `list_tools()`, because `call_tool` never consults the
// advertised list — it resolves the operation directly from the session's
// cached spec. The 8 hurl assertions above are therefore not portable and are
// not ported; this test instead pins down the actual observed behavior, so a
// future host change that starts honouring per-request metadata for
// `list-tools` doesn't leave this file's reasoning stale.

#[tokio::test]
async fn test_list_tools_ignores_open_session() {
    // needs: petstore — a live session is the premise.
    let (client, _stderr) = connect().await;
    let sid = open_petstore_session(&client).await;
    let tools = client.list_all_tools().await.expect("list_all_tools");
    assert_eq!(
        tool_names(&tools),
        ["close_session", "open_session"],
        "a live session must not change what tools/list advertises"
    );
    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// --- test_petstore_pet_crud.py ----------------------------------------------
//
// Swagger Petstore 3.0 — public OpenAPI spec, exercised over the
// session-based bridge. Pet resource lifecycle: find, login, add, update,
// get-by-id, delete. One session backs the whole flow, matching the original
// hurl file's single `session_id` reused across every request.

#[tokio::test]
async fn test_pet_crud_and_login() {
    // needs: petstore (PETSTORE_SPEC, default https://petstore3.swagger.io)
    let (client, _stderr) = connect().await;
    let sid = open_petstore_session(&client).await;

    // Session ids are guest-generated (`alloc_session_id`, src/lib.rs):
    // `format!("openapi_{id}")`.
    assert_openapi_session_id(&sid);

    // --- GET with query parameter ---
    let found = call_tool(
        &client,
        "find_pets_by_status",
        session_args(json!({"status": "sold"}), &sid),
    )
    .await;
    assert_ne!(found.is_error, Some(true), "find failed: {found:?}");
    assert!(found.content.len() >= 1, "expected content, got: {found:?}");
    let block = first_text_block(&found);
    let meta = block
        .meta
        .as_ref()
        .expect("first text block must carry _meta");
    assert_eq!(
        meta.0.get("dev.actcore/mime-type").and_then(Value::as_str),
        Some("application/json"),
        "the petstore's JSON answer must surface as the block mime-type"
    );

    let login = call_tool(
        &client,
        "login_user",
        session_args(json!({"username": "test", "password": "test"}), &sid),
    )
    .await;
    assert!(
        first_text_block(&login).text.contains("Logged in"),
        "login reply: {:?}",
        first_text_block(&login).text
    );

    // --- POST with request body ---
    let added = call_tool(
        &client,
        "add_pet",
        session_args(
            json!({
                "id": 99887,
                "name": "TestDog",
                "status": "available",
                "photoUrls": ["http://example.com/dog.jpg"],
            }),
            &sid,
        ),
    )
    .await;
    assert_ne!(added.is_error, Some(true), "add_pet failed: {added:?}");
    let text = &first_text_block(&added).text;
    assert!(text.contains("TestDog") && text.contains("99887"), "{text}");

    // --- PUT with request body ---
    let updated = call_tool(
        &client,
        "update_pet",
        session_args(
            json!({
                "id": 99887,
                "name": "TestDogUpdated",
                "status": "sold",
                "photoUrls": ["http://example.com/dog2.jpg"],
            }),
            &sid,
        ),
    )
    .await;
    assert_ne!(updated.is_error, Some(true), "update_pet failed: {updated:?}");
    let text = &first_text_block(&updated).text;
    assert!(
        text.contains("TestDogUpdated") && text.contains("sold"),
        "{text}"
    );

    // --- GET with path parameter ---
    let got = call_tool(
        &client,
        "get_pet_by_id",
        session_args(json!({"petId": 99887}), &sid),
    )
    .await;
    assert_ne!(got.is_error, Some(true), "get_pet_by_id failed: {got:?}");
    assert!(
        first_text_block(&got).text.contains("TestDogUpdated"),
        "{}",
        first_text_block(&got).text
    );

    // --- DELETE with path parameter ---
    let deleted = call_tool(
        &client,
        "delete_pet",
        session_args(json!({"petId": 99887}), &sid),
    )
    .await;
    assert_ne!(deleted.is_error, Some(true), "delete_pet failed: {deleted:?}");

    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// --- test_petstore_order_crud.py --------------------------------------------
//
// Store: POST + GET + DELETE order cycle, same session-based bridge as
// test_pet_crud_and_login. Orders are an independent resource from pets, so
// this gets its own session rather than sharing that test's.

#[tokio::test]
async fn test_order_crud() {
    // needs: petstore (PETSTORE_SPEC, default https://petstore3.swagger.io)
    let (client, _stderr) = connect().await;
    let sid = open_petstore_session(&client).await;

    let placed = call_tool(
        &client,
        "place_order",
        session_args(
            json!({
                "id": 77788,
                "petId": 1,
                "quantity": 1,
                "status": "placed",
                "complete": true,
            }),
            &sid,
        ),
    )
    .await;
    assert_ne!(placed.is_error, Some(true), "place_order failed: {placed:?}");
    let text = &first_text_block(&placed).text;
    assert!(text.contains("77788") && text.contains("placed"), "{text}");

    let got = call_tool(
        &client,
        "get_order_by_id",
        session_args(json!({"orderId": 77788}), &sid),
    )
    .await;
    assert_ne!(got.is_error, Some(true), "get_order_by_id failed: {got:?}");
    assert!(
        first_text_block(&got).text.contains("77788"),
        "{}",
        first_text_block(&got).text
    );

    let deleted = call_tool(
        &client,
        "delete_order",
        session_args(json!({"orderId": 77788}), &sid),
    )
    .await;
    assert_ne!(deleted.is_error, Some(true), "delete_order failed: {deleted:?}");

    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

// --- test_petstore_errors.py ------------------------------------------------

#[tokio::test]
async fn test_unknown_operation_is_not_found() {
    // needs: petstore — the session pins the petstore spec.
    let (client, _stderr) = connect().await;
    let sid = open_petstore_session(&client).await;
    // A tool name with no matching operation in the spec is a not-found
    // caller error, not an internal one.
    expect_error(
        &client,
        "doesNotExist",
        session_args(json!({}), &sid),
        "std:not-found",
    )
    .await;
    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_call_after_close_is_session_not_found() {
    // needs: petstore
    let url = petstore_spec_url().await;
    let (client, _stderr) = connect().await;
    // After close, calls referencing the id surface std:session-not-found.
    // Opens and closes its own session directly (not the per-test fixture
    // helper, which the other tests close at their end) so the close happens
    // on the test's own schedule, before the assertion it's testing for.
    let sid = open_session(&client, json!({"spec_url": url})).await;

    close_session(&client, &sid).await;

    expect_error(
        &client,
        "find_pets_by_status",
        session_args(json!({"status": "sold"}), &sid),
        "std:session-not-found",
    )
    .await;
    client.cancel().await.ok();
}

// --- test_credential_presentation.py ----------------------------------------
//
// The credential reaches the wire the way the OpenAPI document says it
// should. The unit tests pin the two halves separately — which scheme a
// document selects (src/security.rs) and what header or query parameter a
// credential becomes (src/creds.rs). Neither can drive `get-secret`, which is
// a host import with no host behind it on the test target. This module
// supplies the missing middle: a real `act` process with a real credential
// store, a local API whose document declares one scheme, and an operation
// that echoes back exactly what arrived.
//
// Each case serves a *different* document from the same server shape, so the
// only thing that varies between them is the security scheme — and the header
// the request carries changes with it, which is the property the whole
// feature exists to provide.

/// Open a session against the document for `scheme`, call `echo`, and return
/// what the API received — the python `echo` helper.
async fn echo(client: &Client, api: &str, scheme: &str, open_extra: Value) -> Value {
    let mut open_args = json!({ "spec_url": format!("{api}/{scheme}.json") });
    if let (Some(target), Some(extra)) = (open_args.as_object_mut(), open_extra.as_object()) {
        for (k, v) in extra {
            target.insert(k.clone(), v.clone());
        }
    }
    let sid = open_session(client, open_args).await;
    let result = call_tool(&client, "echo", session_args(json!({}), &sid)).await;
    assert_ne!(result.is_error, Some(true), "echo failed: {result:?}");
    let seen: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("echo reply is JSON");
    close_session(client, &sid).await;
    seen
}

fn present_credentials_or_skip() -> &'static PathBuf {
    match credential_store() {
        Some(root) => root,
        None => {
            eprintln!(
                "skipping credential-presentation tests: this `act` has no credential \
                 store (`act secret`); nothing to drive"
            );
            // A static the tests can borrow for the process lifetime; the
            // path is never dereferenced on this branch.
            static NONE: OnceLock<PathBuf> = OnceLock::new();
            NONE.get_or_init(|| PathBuf::from("/dev/null"))
        }
    }
}

#[tokio::test]
async fn test_bearer_scheme_sends_an_authorization_bearer_header() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    let seen = echo(&client, &api, "bearer", json!({})).await;
    assert_eq!(
        seen["headers"]["authorization"],
        format!("Bearer {TOKEN}"),
        "got: {seen}"
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_a_document_with_no_scheme_falls_back_to_bearer() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    let seen = echo(&client, &api, "none", json!({})).await;
    assert_eq!(
        seen["headers"]["authorization"],
        format!("Bearer {TOKEN}"),
        "got: {seen}"
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_basic_scheme_sends_the_username_and_password_pair() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    let seen = echo(&client, &api, "basic", json!({})).await;
    // base64 of "sentinel-user:sentinel-password", spelled out so the
    // expected wire value is visible in the assertion rather than computed
    // behind a base64 dependency the harness otherwise has no use for.
    let expected = base64_user_password(USER, PASSWORD);
    assert_eq!(
        seen["headers"]["authorization"],
        format!("Basic {expected}"),
        "got: {seen}"
    );
    assert!(
        !serde_json::to_string(&seen).expect("seen serializes").contains(TOKEN),
        "the string token must not be sent as Basic: {seen}"
    );
    client.cancel().await.ok();
}

/// `base64.b64encode(f"{user}:{password}".encode()).decode()` for the one
/// input this suite feeds it. RFC 4648 with padding, three-byte groups —
/// implemented inline so the harness stays dependency-light.
fn base64_user_password(user: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{password}").into_bytes();
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[tokio::test]
async fn test_an_api_key_scheme_uses_the_header_the_document_names() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    let seen = echo(&client, &api, "apikey-header", json!({})).await;
    assert_eq!(
        seen["headers"]["x-custom-key"], TOKEN,
        "the apiKey must ride the header the document names: {seen}"
    );
    assert!(
        seen["headers"].get("authorization").is_none(),
        "no Authorization beside an apiKey header: {:?}",
        seen["headers"]
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_an_api_key_in_query_becomes_a_query_parameter() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    let seen = echo(&client, &api, "apikey-query", json!({})).await;
    let query = seen["query"].as_str().unwrap_or_default();
    assert!(
        query.contains(&format!("access_key={TOKEN}")),
        "the apiKey must ride the query parameter the document names, got: {query:?}"
    );
    assert!(
        seen["headers"].get("authorization").is_none(),
        "no Authorization beside an apiKey query parameter: {:?}",
        seen["headers"]
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_a_per_call_header_override_cannot_displace_the_credential() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    // The guard that would otherwise be decorative. `open-session` refuses
    // `Authorization` in session args; if a per-call `http:header:` override
    // could still displace the credential, a caller would simply set it
    // there instead.
    let sid = open_session(&client, json!({"spec_url": format!("{api}/bearer.json")})).await;
    let result = call_tool(
        &client,
        "echo",
        args_with_meta(
            json!({}),
            json!({
                "std:session-id": sid,
                "http:header:authorization": "Bearer forged",
            }),
        ),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "echo failed: {result:?}");
    let seen: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("echo reply is JSON");
    assert_eq!(
        seen["headers"]["authorization"],
        format!("Bearer {TOKEN}"),
        "the per-call override must not displace the credential: {:?}",
        seen["headers"]
    );
    close_session(&client, &sid).await;
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_the_session_headers_survive_beside_the_credential() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    // The credential merges with `headers` rather than replacing it: the
    // non-secret defaults `headers` was kept for are still sent.
    let seen = echo(
        &client,
        &api,
        "bearer",
        json!({"headers": {"X-Tenant": "acme", "Accept": "application/json"}}),
    )
    .await;
    assert_eq!(seen["headers"]["x-tenant"], "acme", "got: {seen}");
    assert_eq!(
        seen["headers"]["accept"],
        "application/json",
        "got: {seen}"
    );
    assert_eq!(
        seen["headers"]["authorization"],
        format!("Bearer {TOKEN}"),
        "got: {seen}"
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn test_pinning_a_scheme_changes_how_the_credential_is_presented() {
    let backend = present_credentials_or_skip();
    let (client, _stderr) = connect_with_backend(&format!("file:{}", backend.display())).await;
    let api = spawn_echo_api().await;
    // A document declaring several schemes needs a deterministic choice and a
    // way to override it. Here the pin is what makes the presentation differ,
    // with everything else held constant.
    let seen = echo(
        &client,
        &api,
        "apikey-header",
        json!({"security_scheme": "apikey-header"}),
    )
    .await;
    assert_eq!(
        seen["headers"]["x-custom-key"], TOKEN,
        "the pin must decide the presentation: {:?}",
        seen["headers"]
    );
    client.cancel().await.ok();
}

/// Silence the unused-import lint for the map type the header collection
/// reads through on doc-only days; kept next to the helper it documents.
#[allow(dead_code)]
fn unused_headers_map() -> BTreeMap<String, String> {
    BTreeMap::new()
}
