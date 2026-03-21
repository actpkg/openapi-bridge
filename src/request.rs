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
pub fn build_request(
    tool: &ResolvedTool,
    args: &serde_json::Value,
    base_url: &str,
    config_headers: &BTreeMap<String, String>,
    call_headers: &[(String, String)],
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
        config_headers.insert("authorization".to_string(), "Bearer old".to_string());
        config_headers.insert("x-api-key".to_string(), "key123".to_string());

        let call_headers = vec![("authorization".to_string(), "Bearer new".to_string())];

        let req = build_request(
            &tool,
            &args,
            "https://api.example.com",
            &config_headers,
            &call_headers,
        )
        .unwrap();

        assert_eq!(req.headers.get("authorization").unwrap(), "Bearer new");
        assert_eq!(req.headers.get("x-api-key").unwrap(), "key123");
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
