use crate::tools::{ParamLocation, ResolvedTool};
use std::collections::BTreeMap;

/// A prepared HTTP request ready to be sent via wasip3.
#[derive(Debug)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
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
                    let val_str = match val {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
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

    // 2. Build query string
    let query_params: Vec<String> = tool
        .parameters
        .iter()
        .filter(|p| p.location == ParamLocation::Query)
        .filter_map(|p| {
            args_obj.get(&p.name).map(|v| {
                let val_str = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                format!("{}={}", percent_encode(&p.name), percent_encode(&val_str))
            })
        })
        .collect();

    let url = if query_params.is_empty() {
        format!("{}{}", base_url.trim_end_matches('/'), path)
    } else {
        format!(
            "{}{}?{}",
            base_url.trim_end_matches('/'),
            path,
            query_params.join("&")
        )
    };

    // 3. Merge headers: config defaults + param headers + call overrides
    let mut headers: Vec<(String, String)> = config_headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for param in &tool.parameters {
        if param.location == ParamLocation::Header
            && let Some(val) = args_obj.get(&param.name)
        {
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            headers.push((param.name.clone(), val_str));
        }
    }

    // Call headers override (by name, case-insensitive)
    for (k, v) in call_headers {
        headers.retain(|(existing_k, _)| !existing_k.eq_ignore_ascii_case(k));
        headers.push((k.clone(), v.clone()));
    }

    // 4. Build body from remaining args (if operation has a request body)
    let body = if tool.body_schema.is_some() && !body_args.is_empty() {
        headers.push(("content-type".to_string(), "application/json".to_string()));
        Some(serde_json::to_vec(&body_args).unwrap())
    } else {
        None
    };

    Ok(PreparedRequest {
        method: tool.method.to_uppercase(),
        url,
        headers,
        body,
    })
}

/// Minimal percent-encoding for query parameters.
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
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

        assert_eq!(req.method, "GET");
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

        assert_eq!(req.method, "POST");
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

        let auth_headers: Vec<_> = req
            .headers
            .iter()
            .filter(|(k, _)| k == "authorization")
            .collect();
        assert_eq!(auth_headers.len(), 1);
        assert_eq!(auth_headers[0].1, "Bearer new");
        assert!(
            req.headers
                .iter()
                .any(|(k, v)| k == "x-api-key" && v == "key123")
        );
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
