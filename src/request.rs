use crate::security::Presentation;
use crate::tools::{ParamLocation, ResolvedTool};
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use std::collections::BTreeMap;

/// A prepared HTTP request ready to be sent via wasip3.
#[derive(Debug)]
pub struct PreparedRequest {
    pub method: Method,
    pub url: String,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
}

/// Build an HTTP request from a resolved tool and the call arguments.
///
/// **Precedence, lowest to highest** — the whole point of writing it down is
/// that the last layer is the one that cannot be displaced:
///
/// 1. `config_headers` — the session's non-secret defaults (`Accept`, a tenant
///    id, an API-version pin). `open-session` has already refused the header
///    names that carry a credential.
/// 2. The operation's own `in: header` parameters, supplied as tool arguments.
/// 3. `call_headers` — per-call `http:header:*` metadata overrides.
/// 4. **`credential`** — the header (or query parameter) derived from the
///    credential store, applied last and unconditionally.
///
/// Layer 4 sits on top of layer 3 deliberately. A per-call metadata override
/// that could overwrite the credential-derived header would make the whole
/// session-args guard decorative: a caller refused `Authorization` at
/// `open-session` would simply set it per call instead. The same holds for an
/// `apiKey` in `query`, which is why the credential's query parameter replaces
/// any same-named pair the arguments produced rather than appending beside it.
pub fn build_request(
    tool: &ResolvedTool,
    args: &serde_json::Value,
    base_url: &str,
    config_headers: &BTreeMap<String, String>,
    call_headers: &[(String, String)],
    credential: Option<&Presentation>,
) -> Result<PreparedRequest, String> {
    let args_obj = args.as_object().ok_or("Arguments must be a JSON object")?;

    // 1. Substitute path parameters
    let mut path = tool.path_template.clone();
    let mut body_args = args_obj.clone();

    for param in &tool.parameters {
        match param.location {
            ParamLocation::Path => {
                if let Some(val) = args_obj.get(&param.name) {
                    let val_str = json_value_to_string(val);
                    path = path.replace(&format!("{{{}}}", param.name), &val_str);
                    body_args.remove(&param.name);
                } else {
                    return Err(format!("Missing required path parameter: {}", param.name));
                }
            }
            ParamLocation::Query | ParamLocation::Header => {
                body_args.remove(&param.name);
            }
        }
    }

    // 2. Build URL with query parameters
    let raw_url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let mut url =
        url::Url::parse(&raw_url).map_err(|e| format!("Invalid URL '{}': {}", raw_url, e))?;

    {
        let mut query_pairs = url.query_pairs_mut();
        for param in &tool.parameters {
            if param.location == ParamLocation::Query
                && let Some(val) = args_obj.get(&param.name)
            {
                query_pairs.append_pair(&param.name, &json_value_to_string(val));
            }
        }
        query_pairs.finish();
    }
    if url.query() == Some("") {
        url.set_query(None);
    }

    // 2b. An `apiKey` in `query` is not a header at all. It replaces any
    // same-named pair the arguments produced — an operation that declares the
    // key as an ordinary query parameter must not be able to supply it.
    if let Some(Presentation::Query { name, value }) = credential {
        let kept: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(k, _)| k != name)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.set_query(None);
        {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in &kept {
                pairs.append_pair(k, v);
            }
            pairs.append_pair(name, value);
            pairs.finish();
        }
    }

    // 3. Merge headers: config defaults + param headers + call overrides
    let mut headers = HeaderMap::new();

    for (k, v) in config_headers {
        if let (Ok(name), Ok(value)) = (k.parse::<HeaderName>(), v.parse::<HeaderValue>()) {
            headers.insert(name, value);
        }
    }

    for param in &tool.parameters {
        if param.location == ParamLocation::Header
            && let Some(val) = args_obj.get(&param.name)
        {
            let val_str = json_value_to_string(val);
            if let (Ok(name), Ok(value)) = (
                param.name.parse::<HeaderName>(),
                val_str.parse::<HeaderValue>(),
            ) {
                headers.insert(name, value);
            }
        }
    }

    // Call headers override
    for (k, v) in call_headers {
        if let (Ok(name), Ok(value)) = (k.parse::<HeaderName>(), v.parse::<HeaderValue>()) {
            headers.insert(name, value);
        }
    }

    // 3b. The credential, last of all — see the precedence note above. A
    // failure to parse it is an error rather than a dropped header: sending
    // the request unauthenticated after the component decided to authenticate
    // it produces a bare 401 that points nowhere.
    if let Some(Presentation::Header { name, value }) = credential {
        let (Ok(name), Ok(mut header_value)) =
            (name.parse::<HeaderName>(), value.parse::<HeaderValue>())
        else {
            return Err(format!(
                "the credential cannot be sent as a '{name}' header: the API's security \
                 scheme names a header this HTTP implementation will not carry. The \
                 credential itself is not repeated here."
            ));
        };
        // `http` marks a value sensitive so that it is not echoed by
        // middleware or a `Debug` of the map. Nothing downstream prints these
        // today; this is the cheap half of not finding out later.
        header_value.set_sensitive(true);
        headers.insert(name, header_value);
    }

    // 4. Build body from remaining args (if operation has a request body)
    let body = if tool.body_schema.is_some() && !body_args.is_empty() {
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        Some(serde_json::to_vec(&body_args).unwrap())
    } else {
        None
    };

    // 5. Parse method
    let method = tool
        .method
        .to_uppercase()
        .parse::<Method>()
        .map_err(|e| format!("Invalid HTTP method '{}': {}", tool.method, e))?;

    Ok(PreparedRequest {
        method,
        url: url.to_string(),
        headers,
        body,
    })
}

fn json_value_to_string(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Extract per-call headers from tool-call metadata.
/// Keys prefixed with "http:header:" are forwarded with the prefix stripped.
pub fn extract_call_headers(metadata: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
    const PREFIX: &str = "http:header:";
    metadata
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix(PREFIX).map(|header_name| {
                let val = String::from_utf8_lossy(value).to_string();
                (header_name.to_string(), val)
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{ResolvedParam, ResolvedTool, ToolFlags};
    use serde_json::json;

    fn make_tool() -> ResolvedTool {
        ResolvedTool {
            name: "getUser".to_string(),
            description: "Get a user".to_string(),
            method: "get".to_string(),
            path_template: "/users/{id}".to_string(),
            parameters: vec![
                ResolvedParam {
                    name: "id".to_string(),
                    location: ParamLocation::Path,
                    required: true,
                    description: None,
                    schema: json!({"type": "string"}),
                },
                ResolvedParam {
                    name: "fields".to_string(),
                    location: ParamLocation::Query,
                    required: false,
                    description: None,
                    schema: json!({"type": "string"}),
                },
            ],
            body_schema: None,
            body_required: false,
            metadata_flags: ToolFlags {
                read_only: true,
                ..Default::default()
            },
        }
    }

    #[test]
    fn builds_get_request_with_path_and_query() {
        let tool = make_tool();
        let args = json!({"id": "123", "fields": "name,email"});
        let req = build_request(
            &tool,
            &args,
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            None,
        )
        .unwrap();

        assert_eq!(req.method, Method::GET);
        assert_eq!(
            req.url,
            "https://api.example.com/users/123?fields=name%2Cemail"
        );
        assert!(req.body.is_none());
    }

    #[test]
    fn builds_post_with_body() {
        let tool = ResolvedTool {
            name: "createUser".to_string(),
            description: "".to_string(),
            method: "post".to_string(),
            path_template: "/users".to_string(),
            parameters: vec![],
            body_schema: Some(
                json!({"type": "object", "properties": {"name": {"type": "string"}}}),
            ),
            body_required: true,
            metadata_flags: ToolFlags::default(),
        };
        let args = json!({"name": "Alice"});
        let req = build_request(
            &tool,
            &args,
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            None,
        )
        .unwrap();

        assert_eq!(req.method, Method::POST);
        assert_eq!(req.url, "https://api.example.com/users");
        assert!(req.body.is_some());
        let body: serde_json::Value = serde_json::from_slice(&req.body.unwrap()).unwrap();
        assert_eq!(body["name"], "Alice");
    }

    #[test]
    fn config_headers_and_call_overrides() {
        let tool = make_tool();
        let args = json!({"id": "1"});
        let mut config_headers = BTreeMap::new();
        config_headers.insert("accept".to_string(), "application/json".to_string());
        config_headers.insert("x-tenant".to_string(), "acme".to_string());

        let call_headers = vec![("accept".to_string(), "application/xml".to_string())];

        let req = build_request(
            &tool,
            &args,
            "https://api.example.com",
            &config_headers,
            &call_headers,
            None,
        )
        .unwrap();

        assert_eq!(req.headers.get("accept").unwrap(), "application/xml");
        assert_eq!(req.headers.get("x-tenant").unwrap(), "acme");
    }

    /// The credential merges *with* the session's headers rather than
    /// replacing them: `headers` still carries the non-secret defaults it was
    /// kept for.
    #[test]
    fn the_credential_merges_with_the_session_headers() {
        let tool = make_tool();
        let mut config_headers = BTreeMap::new();
        config_headers.insert("accept".to_string(), "application/json".to_string());
        config_headers.insert("x-tenant".to_string(), "acme".to_string());

        let credential = Presentation::Header {
            name: "authorization".into(),
            value: "Bearer real".into(),
        };
        let req = build_request(
            &tool,
            &json!({"id": "1"}),
            "https://api.example.com",
            &config_headers,
            &[],
            Some(&credential),
        )
        .unwrap();

        assert_eq!(req.headers.get("accept").unwrap(), "application/json");
        assert_eq!(req.headers.get("x-tenant").unwrap(), "acme");
        assert_eq!(req.headers.get("authorization").unwrap(), "Bearer real");
    }

    /// The guard that would otherwise be decorative. `open-session` refuses
    /// `Authorization` in session args; if a per-call metadata override could
    /// still displace the credential, the caller would simply set it there.
    #[test]
    fn a_per_call_header_override_cannot_displace_the_credential() {
        let tool = make_tool();
        let credential = Presentation::Header {
            name: "authorization".into(),
            value: "Bearer real".into(),
        };
        let call_headers = vec![("authorization".to_string(), "Bearer forged".to_string())];

        let req = build_request(
            &tool,
            &json!({"id": "1"}),
            "https://api.example.com",
            &BTreeMap::new(),
            &call_headers,
            Some(&credential),
        )
        .unwrap();

        assert_eq!(req.headers.get("authorization").unwrap(), "Bearer real");
    }

    /// The same rule for an API-key header, whose name comes from the document
    /// rather than from a fixed list.
    #[test]
    fn an_api_key_header_also_wins_over_a_per_call_override() {
        let tool = make_tool();
        let credential = Presentation::Header {
            name: "X-Api-Key".into(),
            value: "real".into(),
        };
        let call_headers = vec![("x-api-key".to_string(), "forged".to_string())];

        let req = build_request(
            &tool,
            &json!({"id": "1"}),
            "https://api.example.com",
            &BTreeMap::new(),
            &call_headers,
            Some(&credential),
        )
        .unwrap();

        assert_eq!(req.headers.get("x-api-key").unwrap(), "real");
    }

    /// The credential header is marked sensitive so a `Debug` of the map or a
    /// logging middleware does not print it.
    #[test]
    fn the_credential_header_is_marked_sensitive() {
        let tool = make_tool();
        let credential = Presentation::Header {
            name: "authorization".into(),
            value: "Bearer sentinel-value".into(),
        };
        let req = build_request(
            &tool,
            &json!({"id": "1"}),
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            Some(&credential),
        )
        .unwrap();
        assert!(req.headers.get("authorization").unwrap().is_sensitive());
        assert!(
            !format!("{:?}", req.headers).contains("sentinel-value"),
            "Debug leaked the credential: {:?}",
            req.headers
        );
    }

    #[test]
    fn an_api_key_in_query_is_appended_to_the_url() {
        let tool = make_tool();
        let credential = Presentation::Query {
            name: "api_key".into(),
            value: "k3y".into(),
        };
        let req = build_request(
            &tool,
            &json!({"id": "1", "fields": "name"}),
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            Some(&credential),
        )
        .unwrap();
        assert_eq!(
            req.url,
            "https://api.example.com/users/1?fields=name&api_key=k3y"
        );
        assert!(req.headers.is_empty(), "a query key is not a header");
    }

    /// An operation that declares the API key as an ordinary query parameter
    /// must not let a tool argument supply it.
    #[test]
    fn a_tool_argument_cannot_supply_the_query_api_key() {
        let mut tool = make_tool();
        tool.parameters.push(ResolvedParam {
            name: "api_key".to_string(),
            location: ParamLocation::Query,
            required: false,
            description: None,
            schema: json!({"type": "string"}),
        });
        let credential = Presentation::Query {
            name: "api_key".into(),
            value: "real".into(),
        };
        let req = build_request(
            &tool,
            &json!({"id": "1", "api_key": "forged"}),
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            Some(&credential),
        )
        .unwrap();
        assert_eq!(req.url, "https://api.example.com/users/1?api_key=real");
    }

    #[test]
    fn a_query_api_key_is_percent_encoded() {
        let tool = make_tool();
        let credential = Presentation::Query {
            name: "api key".into(),
            value: "a b&c=d".into(),
        };
        let req = build_request(
            &tool,
            &json!({"id": "1"}),
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            Some(&credential),
        )
        .unwrap();
        assert_eq!(
            req.url,
            "https://api.example.com/users/1?api+key=a+b%26c%3Dd"
        );
    }

    /// A header name the HTTP layer will not carry is an error, not a silently
    /// dropped credential: an unauthenticated request produces a bare 401 that
    /// points nowhere.
    #[test]
    fn an_unusable_credential_header_name_is_refused_rather_than_dropped() {
        let tool = make_tool();
        let credential = Presentation::Header {
            name: "not a header name".into(),
            value: "sentinel-value".into(),
        };
        let e = build_request(
            &tool,
            &json!({"id": "1"}),
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            Some(&credential),
        )
        .expect_err("refused");
        assert!(!e.contains("sentinel-value"), "credential echoed: {e}");
    }

    #[test]
    fn missing_path_param_returns_error() {
        let tool = make_tool();
        let args = json!({"fields": "name"});
        let result = build_request(
            &tool,
            &args,
            "https://api.example.com",
            &BTreeMap::new(),
            &[],
            None,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Missing required path parameter: id")
        );
    }

    #[test]
    fn extract_call_headers_from_metadata() {
        let metadata = vec![
            (
                "http:header:authorization".to_string(),
                b"Bearer tok".to_vec(),
            ),
            ("http:header:x-custom".to_string(), b"val".to_vec()),
            ("other:key".to_string(), b"ignored".to_vec()),
        ];
        let headers = extract_call_headers(&metadata);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0],
            ("authorization".to_string(), "Bearer tok".to_string())
        );
        assert_eq!(headers[1], ("x-custom".to_string(), "val".to_string()));
    }
}
