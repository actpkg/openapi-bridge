mod cache;
mod request;
mod spec;
mod tools;

use act_types::cbor;
use spec::BridgeConfig;

wit_bindgen::generate!({
    path: "wit",
    world: "component-world",
    generate_all,
});

// WASM custom sections for component metadata.
// SAFETY: link_section places data in named WASM custom sections; no executable code.
#[unsafe(link_section = "act:component")]
#[used]
static _ACT_COMPONENT: [u8; include_bytes!(concat!(env!("OUT_DIR"), "/act_component.cbor")).len()] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/act_component.cbor"));

#[unsafe(link_section = "version")]
#[used]
static _VERSION: [u8; 5] = *b"0.1.0";

#[unsafe(link_section = "description")]
#[used]
static _DESCRIPTION: [u8; 50] = *b"Dynamically exposes OpenAPI endpoints as ACT tools";

struct OpenApiBridge;

export!(OpenApiBridge);

fn make_error(kind: &str, msg: String) -> act::core::types::ToolError {
    act::core::types::ToolError {
        kind: kind.to_string(),
        message: act::core::types::LocalizedString::Plain(msg),
        metadata: vec![],
    }
}

fn parse_config_from_metadata(
    metadata: &[(String, Vec<u8>)],
) -> Result<BridgeConfig, act::core::types::ToolError> {
    let spec_url = metadata
        .iter()
        .find(|(k, _)| k == "spec_url")
        .map(|(_, v)| cbor::from_cbor::<String>(v))
        .transpose()
        .map_err(|e| {
            make_error(
                act_types::constants::ERR_INVALID_ARGS,
                format!("Invalid spec_url: {e}"),
            )
        })?
        .ok_or_else(|| {
            make_error(
                act_types::constants::ERR_INVALID_ARGS,
                "Missing 'spec_url' in metadata".to_string(),
            )
        })?;

    let headers: std::collections::BTreeMap<String, String> = metadata
        .iter()
        .find(|(k, _)| k == "headers")
        .map(|(_, v)| cbor::from_cbor(v))
        .transpose()
        .map_err(|e| {
            make_error(
                act_types::constants::ERR_INVALID_ARGS,
                format!("Invalid headers: {e}"),
            )
        })?
        .unwrap_or_default();

    Ok(BridgeConfig { spec_url, headers })
}

/// Extract the origin (scheme + authority) from a URL.
/// e.g. "https://example.com/path" -> "https://example.com"
fn url_origin(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        format!("{scheme}://{authority}")
    } else {
        String::new()
    }
}

/// Resolve a server base URL against the spec URL.
/// If the server URL is relative (starts with /), prepend the spec URL's origin.
fn resolve_base_url(spec_url: &str, server_url: &str) -> String {
    if server_url.contains("://") {
        // Absolute URL
        server_url.to_string()
    } else {
        // Relative URL — resolve against spec origin
        format!("{}{}", url_origin(spec_url), server_url)
    }
}

/// Parse a URL into (scheme, authority, path_and_query).
fn parse_url(url: &str) -> Result<(&str, &str, &str), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("Invalid URL (no scheme): {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    Ok((scheme, authority, path))
}

/// Fetch the OpenAPI spec from a URL using wasip3 HTTP client.
async fn fetch_spec(url: &str) -> Result<String, String> {
    use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response, Scheme};

    let (scheme_str, authority, path) = parse_url(url)?;
    let scheme = match scheme_str {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        _ => return Err(format!("Unsupported scheme: {scheme_str}")),
    };

    let headers = Fields::from_list(&[(
        "accept".to_string(),
        b"application/json, application/yaml, text/yaml, */*".to_vec(),
    )])
    .unwrap();

    let (_, trailers_reader) =
        wasip3::wit_future::new::<Result<Option<Fields>, ErrorCode>>(|| Ok(None));

    let (request, _) = Request::new(headers, None, trailers_reader, None);
    let _ = request.set_method(&Method::Get);
    let _ = request.set_scheme(Some(&scheme));
    let _ = request.set_authority(Some(authority));
    let _ = request.set_path_with_query(Some(path));

    let response = wasip3::http::client::send(request)
        .await
        .map_err(|e| format!("Failed to fetch spec: {e:?}"))?;

    let status = response.get_status_code();
    if !(200..300).contains(&status) {
        return Err(format!("Spec fetch returned HTTP {status}"));
    }

    let (_, result_reader) = wasip3::wit_future::new::<Result<(), ErrorCode>>(|| Ok(()));
    let (mut body_stream, _trailers) = Response::consume_body(response, result_reader);

    let mut all_bytes = Vec::new();
    loop {
        let (result, chunk) = body_stream.read(Vec::with_capacity(16384)).await;
        match result {
            wasip3::wit_bindgen::StreamResult::Complete(_) => {
                all_bytes.extend_from_slice(&chunk);
            }
            wasip3::wit_bindgen::StreamResult::Dropped
            | wasip3::wit_bindgen::StreamResult::Cancelled => break,
        }
    }

    String::from_utf8(all_bytes).map_err(|e| format!("Spec response is not valid UTF-8: {e}"))
}

/// Fetch spec (or use cache), parse, and return tools.
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
fn to_wit_tool(tool: &tools::ResolvedTool) -> act::core::types::ToolDefinition {
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

    act::core::types::ToolDefinition {
        name: tool.name.clone(),
        description: act::core::types::LocalizedString::Plain(tool.description.clone()),
        parameters_schema: schema_str,
        metadata,
    }
}

/// Send an HTTP request via wasip3 and stream the response back.
async fn send_api_request(
    prepared: request::PreparedRequest,
    writer: &mut wit_bindgen::StreamWriter<act::core::types::StreamEvent>,
) {
    use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response, Scheme};

    let (scheme_str, authority, path) = match parse_url(&prepared.url) {
        Ok(v) => v,
        Err(e) => {
            let _ = writer
                .write_all(vec![act::core::types::StreamEvent::Error(make_error(
                    act_types::constants::ERR_INTERNAL,
                    format!("Invalid URL: {e}"),
                ))])
                .await;
            return;
        }
    };

    let scheme = match scheme_str {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        _ => {
            let _ = writer
                .write_all(vec![act::core::types::StreamEvent::Error(make_error(
                    act_types::constants::ERR_INTERNAL,
                    format!("Unsupported scheme: {scheme_str}"),
                ))])
                .await;
            return;
        }
    };

    let method = match prepared.method {
        http::Method::GET => Method::Get,
        http::Method::POST => Method::Post,
        http::Method::PUT => Method::Put,
        http::Method::DELETE => Method::Delete,
        http::Method::PATCH => Method::Patch,
        http::Method::HEAD => Method::Head,
        http::Method::OPTIONS => Method::Options,
        ref other => Method::Other(other.to_string()),
    };

    let header_list: Vec<(String, Vec<u8>)> = prepared
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
        .collect();
    let fields = Fields::from_list(&header_list).unwrap();

    let body_stream = prepared.body.map(|body_bytes| {
        let (mut body_writer, body_reader) = wasip3::wit_stream::new::<u8>();
        wit_bindgen::spawn(async move {
            body_writer.write_all(body_bytes).await;
        });
        body_reader
    });

    let (_, trailers_reader) =
        wasip3::wit_future::new::<Result<Option<Fields>, ErrorCode>>(|| Ok(None));

    let (request, _) = Request::new(fields, body_stream, trailers_reader, None);
    let _ = request.set_method(&method);
    let _ = request.set_scheme(Some(&scheme));
    let _ = request.set_authority(Some(authority));
    let _ = request.set_path_with_query(Some(path));

    let response = match wasip3::http::client::send(request).await {
        Ok(r) => r,
        Err(e) => {
            let _ = writer
                .write_all(vec![act::core::types::StreamEvent::Error(make_error(
                    act_types::constants::ERR_INTERNAL,
                    format!("HTTP error: {e:?}"),
                ))])
                .await;
            return;
        }
    };

    let status = response.get_status_code();
    let resp_headers = response.get_headers();
    let content_type = resp_headers
        .get("content-type")
        .first()
        .map(|v| String::from_utf8_lossy(v).to_string());

    let (_, result_reader) = wasip3::wit_future::new::<Result<(), ErrorCode>>(|| Ok(()));
    let (mut body_stream, _trailers) = Response::consume_body(response, result_reader);

    if status >= 400 {
        let mut error_bytes = Vec::new();
        loop {
            let (result, chunk) = body_stream.read(Vec::with_capacity(4096)).await;
            match result {
                wasip3::wit_bindgen::StreamResult::Complete(_) => {
                    error_bytes.extend_from_slice(&chunk);
                }
                _ => break,
            }
        }
        let error_body = String::from_utf8_lossy(&error_bytes);
        let _ = writer
            .write_all(vec![act::core::types::StreamEvent::Error(make_error(
                act_types::constants::ERR_INTERNAL,
                format!("HTTP {status}: {error_body}"),
            ))])
            .await;
        return;
    }

    let mut buf = Vec::with_capacity(16384);
    loop {
        let (result, chunk) = body_stream.read(buf).await;
        match result {
            wasip3::wit_bindgen::StreamResult::Complete(_) => {
                let _ = writer
                    .write_all(vec![act::core::types::StreamEvent::Content(
                        act::core::types::ContentPart {
                            data: chunk,
                            mime_type: content_type.clone(),
                            metadata: vec![],
                        },
                    )])
                    .await;
                buf = Vec::with_capacity(16384);
            }
            wasip3::wit_bindgen::StreamResult::Dropped
            | wasip3::wit_bindgen::StreamResult::Cancelled => break,
        }
    }
}

impl exports::act::core::tool_provider::Guest for OpenApiBridge {
    async fn get_metadata_schema(_metadata: Vec<(String, Vec<u8>)>) -> Option<String> {
        let schema = schemars::schema_for!(BridgeConfig);
        Some(serde_json::to_string(&schema).unwrap_or_else(|_| r#"{"type":"object"}"#.to_string()))
    }

    async fn list_tools(
        metadata: Vec<(String, Vec<u8>)>,
    ) -> Result<act::core::types::ListToolsResponse, act::core::types::ToolError> {
        let config = parse_config_from_metadata(&metadata)?;
        let resolved = get_or_fetch_tools(&config)
            .await
            .map_err(|e| make_error(act_types::constants::ERR_INTERNAL, e))?;

        let tool_defs: Vec<act::core::types::ToolDefinition> =
            resolved.iter().map(to_wit_tool).collect();

        Ok(act::core::types::ListToolsResponse {
            metadata: vec![],
            tools: tool_defs,
        })
    }

    async fn call_tool(
        call: act::core::types::ToolCall,
    ) -> wit_bindgen::rt::async_support::StreamReader<act::core::types::StreamEvent> {
        let (mut writer, reader) = wit_stream::new::<act::core::types::StreamEvent>();

        wit_bindgen::spawn(async move {
            let config = match parse_config_from_metadata(&call.metadata) {
                Ok(c) => c,
                Err(e) => {
                    let _ = writer
                        .write_all(vec![act::core::types::StreamEvent::Error(e)])
                        .await;
                    return;
                }
            };

            // Get the tool from cache (list-tools should have been called first)
            let tool = match cache::get_cached_tool(&config.spec_url, &call.name) {
                Some(t) => t,
                None => {
                    // Try fetching spec if not cached
                    match get_or_fetch_tools(&config).await {
                        Ok(_) => match cache::get_cached_tool(&config.spec_url, &call.name) {
                            Some(t) => t,
                            None => {
                                let _ = writer
                                    .write_all(vec![act::core::types::StreamEvent::Error(
                                        make_error(
                                            act_types::constants::ERR_NOT_FOUND,
                                            format!("Tool '{}' not found in spec", call.name),
                                        ),
                                    )])
                                    .await;
                                return;
                            }
                        },
                        Err(e) => {
                            let _ = writer
                                .write_all(vec![act::core::types::StreamEvent::Error(make_error(
                                    act_types::constants::ERR_INTERNAL,
                                    e,
                                ))])
                                .await;
                            return;
                        }
                    }
                }
            };

            // Deserialize arguments from CBOR
            let args: serde_json::Value = match cbor::from_cbor(&call.arguments) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writer
                        .write_all(vec![act::core::types::StreamEvent::Error(make_error(
                            act_types::constants::ERR_INVALID_ARGS,
                            format!("Invalid arguments: {e}"),
                        ))])
                        .await;
                    return;
                }
            };

            // Extract per-call headers from metadata
            let call_headers = request::extract_call_headers(&call.metadata);

            // Get base URL from cached spec, resolved against spec URL origin
            let raw_base = cache::get_base_url(&config.spec_url).unwrap_or_default();
            let base_url = resolve_base_url(&config.spec_url, &raw_base);

            // Build the HTTP request
            let prepared = match request::build_request(
                &tool,
                &args,
                &base_url,
                &config.headers,
                &call_headers,
            ) {
                Ok(r) => r,
                Err(e) => {
                    let _ = writer
                        .write_all(vec![act::core::types::StreamEvent::Error(make_error(
                            act_types::constants::ERR_INVALID_ARGS,
                            e,
                        ))])
                        .await;
                    return;
                }
            };

            // Send the request and stream response
            send_api_request(prepared, &mut writer).await;
        });

        reader
    }
}
