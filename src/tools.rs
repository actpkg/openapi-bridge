use crate::spec::OpenApiSpec;
use serde_json::json;

/// A resolved operation ready to become an ACT tool.
#[derive(Debug, Clone)]
pub struct ResolvedTool {
    pub name: String,
    pub description: String,
    pub method: String,
    pub path_template: String,
    pub parameters: Vec<ResolvedParam>,
    pub body_schema: Option<serde_json::Value>,
    pub body_required: bool,
    pub metadata_flags: ToolFlags,
}

#[derive(Debug, Clone)]
pub struct ResolvedParam {
    pub name: String,
    pub location: ParamLocation,
    pub required: bool,
    pub description: Option<String>,
    pub schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParamLocation {
    Path,
    Query,
    Header,
}

#[derive(Debug, Clone, Default)]
pub struct ToolFlags {
    pub read_only: bool,
    pub idempotent: bool,
    pub destructive: bool,
}

/// Generate a tool name from HTTP method and path when operationId is absent.
/// e.g. GET /users/{id}/posts -> get_users_by_id_posts
pub fn generate_tool_name(method: &str, path: &str) -> String {
    let segments: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with('}') {
                format!("by_{}", &seg[1..seg.len() - 1])
            } else {
                seg.replace('-', "_")
            }
        })
        .collect();

    if segments.is_empty() {
        method.to_lowercase()
    } else {
        format!("{}_{}", method.to_lowercase(), segments.join("_"))
    }
}

fn flags_for_method(method: &str) -> ToolFlags {
    match method {
        "get" | "head" | "options" => ToolFlags {
            read_only: true,
            ..Default::default()
        },
        "put" => ToolFlags {
            idempotent: true,
            ..Default::default()
        },
        "delete" => ToolFlags {
            destructive: true,
            ..Default::default()
        },
        _ => ToolFlags::default(),
    }
}

fn parse_location(s: &str) -> Option<ParamLocation> {
    match s {
        "path" => Some(ParamLocation::Path),
        "query" => Some(ParamLocation::Query),
        "header" => Some(ParamLocation::Header),
        _ => None, // skip cookie params etc.
    }
}

/// Build the combined JSON Schema for a tool's parameters.
pub fn build_parameters_schema(tool: &ResolvedTool) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for param in &tool.parameters {
        let mut schema = param.schema.clone();
        if let Some(desc) = &param.description
            && let serde_json::Value::Object(ref mut map) = schema
        {
            map.insert("description".to_string(), json!(desc));
        }
        properties.insert(param.name.clone(), schema);
        if param.required {
            required.push(json!(param.name));
        }
    }

    // Add request body properties
    if let Some(body_schema) = &tool.body_schema {
        if let Some(serde_json::Value::Object(bp)) = body_schema.get("properties") {
            for (k, v) in bp {
                properties.insert(k.clone(), v.clone());
            }
        }
        // Merge body required fields
        if let Some(serde_json::Value::Array(br)) = body_schema.get("required")
            && tool.body_required
        {
            required.extend(br.iter().cloned());
        }
    }

    let mut schema = json!({
        "type": "object",
        "properties": properties,
    });
    if !required.is_empty() {
        schema["required"] = json!(required);
    }
    schema
}

/// Extract all tools from a parsed OpenAPI spec.
pub fn extract_tools(spec: &OpenApiSpec) -> Vec<ResolvedTool> {
    let mut tools = Vec::new();

    for (path, path_item) in &spec.paths {
        for (method, operation) in path_item.operations() {
            let name = operation
                .operation_id
                .clone()
                .unwrap_or_else(|| generate_tool_name(method, path));

            let description = operation
                .summary
                .clone()
                .or_else(|| operation.description.clone())
                .unwrap_or_default();

            // Merge path-level and operation-level parameters
            let mut params = Vec::new();
            let mut seen_names = std::collections::HashSet::new();

            // Operation params override path-level params
            for p in &operation.parameters {
                if let Some(loc) = parse_location(&p.location) {
                    seen_names.insert(p.name.clone());
                    params.push(ResolvedParam {
                        name: p.name.clone(),
                        location: loc,
                        required: if p.location == "path" {
                            true
                        } else {
                            p.required
                        },
                        description: p.description.clone(),
                        schema: p.schema.clone().unwrap_or(json!({"type": "string"})),
                    });
                }
            }
            for p in &path_item.parameters {
                if seen_names.contains(&p.name) {
                    continue;
                }
                if let Some(loc) = parse_location(&p.location) {
                    params.push(ResolvedParam {
                        name: p.name.clone(),
                        location: loc,
                        required: if p.location == "path" {
                            true
                        } else {
                            p.required
                        },
                        description: p.description.clone(),
                        schema: p.schema.clone().unwrap_or(json!({"type": "string"})),
                    });
                }
            }

            // Request body
            let (body_schema, body_required) = operation
                .request_body
                .as_ref()
                .and_then(|rb| {
                    let schema = rb
                        .content
                        .get("application/json")
                        .and_then(|mt| mt.schema.clone());
                    schema.map(|s| (s, rb.required))
                })
                .map(|(s, r)| (Some(s), r))
                .unwrap_or((None, false));

            tools.push(ResolvedTool {
                name,
                description,
                method: method.to_string(),
                path_template: path.clone(),
                parameters: params,
                body_schema,
                body_required,
                metadata_flags: flags_for_method(method),
            });
        }
    }

    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::OpenApiSpec;

    #[test]
    fn generate_name_simple() {
        assert_eq!(generate_tool_name("get", "/users"), "get_users");
        assert_eq!(generate_tool_name("post", "/orders"), "post_orders");
    }

    #[test]
    fn generate_name_with_path_param() {
        assert_eq!(
            generate_tool_name("get", "/users/{id}/posts"),
            "get_users_by_id_posts"
        );
    }

    #[test]
    fn generate_name_with_hyphens() {
        assert_eq!(
            generate_tool_name("get", "/user-groups/{groupId}"),
            "get_user_groups_by_groupId"
        );
    }

    #[test]
    fn generate_name_root_path() {
        assert_eq!(generate_tool_name("get", "/"), "get");
    }

    #[test]
    fn flags_for_methods() {
        assert!(flags_for_method("get").read_only);
        assert!(flags_for_method("head").read_only);
        assert!(flags_for_method("options").read_only);
        assert!(flags_for_method("put").idempotent);
        assert!(flags_for_method("delete").destructive);
        let post_flags = flags_for_method("post");
        assert!(!post_flags.read_only && !post_flags.idempotent && !post_flags.destructive);
    }

    #[test]
    fn extract_tools_uses_operation_id() {
        let spec = OpenApiSpec::parse(
            r#"{
            "openapi": "3.0.3",
            "info": {"title":"T","version":"1"},
            "paths": {
                "/users": {
                    "get": {"operationId": "listUsers", "summary": "List users"}
                }
            }
        }"#,
        )
        .unwrap();
        let tools = extract_tools(&spec);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "listUsers");
        assert_eq!(tools[0].description, "List users");
        assert!(tools[0].metadata_flags.read_only);
    }

    #[test]
    fn extract_tools_generates_name_when_no_operation_id() {
        let spec = OpenApiSpec::parse(
            r#"{
            "openapi": "3.0.3",
            "info": {"title":"T","version":"1"},
            "paths": {
                "/pets/{petId}": {
                    "delete": {"summary": "Delete a pet"}
                }
            }
        }"#,
        )
        .unwrap();
        let tools = extract_tools(&spec);
        assert_eq!(tools[0].name, "delete_pets_by_petId");
        assert!(tools[0].metadata_flags.destructive);
    }

    #[test]
    fn extract_tools_merges_path_and_op_params() {
        let spec = OpenApiSpec::parse(
            r#"{
            "openapi": "3.0.3",
            "info": {"title":"T","version":"1"},
            "paths": {
                "/items/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": true, "schema": {"type":"string"}}
                    ],
                    "get": {
                        "operationId": "getItem",
                        "parameters": [
                            {"name": "fields", "in": "query", "schema": {"type":"string"}}
                        ]
                    }
                }
            }
        }"#,
        )
        .unwrap();
        let tools = extract_tools(&spec);
        assert_eq!(tools[0].parameters.len(), 2);
        assert_eq!(tools[0].parameters[1].name, "id"); // from path-level
        assert!(tools[0].parameters[1].required); // path params always required
    }

    #[test]
    fn build_schema_combines_params_and_body() {
        let tool = ResolvedTool {
            name: "createUser".to_string(),
            description: "Create a user".to_string(),
            method: "post".to_string(),
            path_template: "/users".to_string(),
            parameters: vec![ResolvedParam {
                name: "x_request_id".to_string(),
                location: ParamLocation::Header,
                required: false,
                description: Some("Request ID".to_string()),
                schema: json!({"type": "string"}),
            }],
            body_schema: Some(json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string"}
                },
                "required": ["name"]
            })),
            body_required: true,
            metadata_flags: ToolFlags::default(),
        };
        let schema = build_parameters_schema(&tool);
        let props = schema["properties"].as_object().unwrap();
        assert!(props.contains_key("x_request_id"));
        assert!(props.contains_key("name"));
        assert!(props.contains_key("email"));
        let req = schema["required"].as_array().unwrap();
        assert!(req.contains(&json!("name")));
    }
}
