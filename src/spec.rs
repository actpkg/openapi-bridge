use serde::Deserialize;
use std::collections::BTreeMap;

/// Bridge config passed via ACT config.
#[derive(Deserialize, schemars::JsonSchema)]
pub struct BridgeConfig {
    /// URL to the OpenAPI spec (JSON or YAML)
    pub spec_url: String,
    /// Default headers to send with every API request
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// Minimal OpenAPI 3.x document model.
#[derive(Debug, Deserialize)]
pub struct OpenApiSpec {
    #[expect(dead_code)]
    pub openapi: String,
    #[serde(default)]
    #[expect(dead_code)]
    pub info: SpecInfo,
    #[serde(default)]
    pub servers: Vec<Server>,
    #[serde(default)]
    pub paths: BTreeMap<String, PathItem>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SpecInfo {
    #[serde(default)]
    #[expect(dead_code)]
    pub title: String,
    #[serde(default)]
    #[expect(dead_code)]
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub url: String,
}

/// A path item containing operations keyed by HTTP method.
#[derive(Debug, Default, Deserialize)]
pub struct PathItem {
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    pub get: Option<Operation>,
    pub post: Option<Operation>,
    pub put: Option<Operation>,
    pub patch: Option<Operation>,
    pub delete: Option<Operation>,
    pub head: Option<Operation>,
    pub options: Option<Operation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Operation {
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<RequestBody>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String,
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    pub schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestBody {
    #[expect(dead_code)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub content: BTreeMap<String, MediaType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MediaType {
    pub schema: Option<serde_json::Value>,
}

impl OpenApiSpec {
    /// Parse an OpenAPI spec from YAML (which is a superset of JSON).
    pub fn parse(input: &str) -> Result<Self, String> {
        serde_yml::from_str(input).map_err(|e| format!("Failed to parse OpenAPI spec: {e}"))
    }

    /// Get the base URL from servers, or default to "".
    pub fn base_url(&self) -> &str {
        self.servers.first().map(|s| s.url.as_str()).unwrap_or("")
    }
}

impl PathItem {
    /// Iterate over (method_str, operation) pairs.
    pub fn operations(&self) -> Vec<(&str, &Operation)> {
        let mut ops = Vec::new();
        if let Some(op) = &self.get {
            ops.push(("get", op));
        }
        if let Some(op) = &self.post {
            ops.push(("post", op));
        }
        if let Some(op) = &self.put {
            ops.push(("put", op));
        }
        if let Some(op) = &self.patch {
            ops.push(("patch", op));
        }
        if let Some(op) = &self.delete {
            ops.push(("delete", op));
        }
        if let Some(op) = &self.head {
            ops.push(("head", op));
        }
        if let Some(op) = &self.options {
            ops.push(("options", op));
        }
        ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_json_spec() {
        let spec_json = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Test API", "version": "1.0.0" },
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "summary": "List all users"
                    }
                }
            }
        }"#;
        let spec = OpenApiSpec::parse(spec_json).unwrap();
        assert_eq!(spec.openapi, "3.0.3");
        assert_eq!(spec.info.title, "Test API");
        let path = &spec.paths["/users"];
        let get = path.get.as_ref().unwrap();
        assert_eq!(get.operation_id.as_deref(), Some("listUsers"));
        assert_eq!(get.summary.as_deref(), Some("List all users"));
    }

    #[test]
    fn parse_yaml_spec() {
        let spec_yaml = r#"
openapi: "3.1.0"
info:
  title: Pet Store
  version: "1.0"
servers:
  - url: https://api.petstore.com/v1
paths:
  /pets/{petId}:
    parameters:
      - name: petId
        in: path
        required: true
        schema:
          type: string
    get:
      operationId: getPet
      summary: Get a pet by ID
    delete:
      summary: Delete a pet
"#;
        let spec = OpenApiSpec::parse(spec_yaml).unwrap();
        assert_eq!(spec.openapi, "3.1.0");
        assert_eq!(spec.base_url(), "https://api.petstore.com/v1");
        let path = &spec.paths["/pets/{petId}"];
        assert_eq!(path.parameters.len(), 1);
        assert_eq!(path.parameters[0].name, "petId");
        assert_eq!(path.parameters[0].location, "path");
        assert!(path.get.is_some());
        assert!(path.delete.is_some());
        assert_eq!(path.delete.as_ref().unwrap().operation_id, None);
    }

    #[test]
    fn parse_spec_with_request_body() {
        let spec_json = r#"{
            "openapi": "3.0.3",
            "info": { "title": "Test", "version": "1.0" },
            "paths": {
                "/users": {
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" },
                                            "email": { "type": "string" }
                                        },
                                        "required": ["name", "email"]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let spec = OpenApiSpec::parse(spec_json).unwrap();
        let post = spec.paths["/users"].post.as_ref().unwrap();
        let body = post.request_body.as_ref().unwrap();
        assert!(body.required);
        assert!(body.content.contains_key("application/json"));
        let schema = body.content["application/json"].schema.as_ref().unwrap();
        assert_eq!(schema["type"], "object");
    }

    #[test]
    fn path_item_operations_iterator() {
        let spec_json = r#"{
            "openapi": "3.0.3",
            "info": { "title": "T", "version": "1" },
            "paths": {
                "/items": {
                    "get": { "operationId": "list" },
                    "post": { "operationId": "create" },
                    "delete": { "operationId": "deleteAll" }
                }
            }
        }"#;
        let spec = OpenApiSpec::parse(spec_json).unwrap();
        let ops = spec.paths["/items"].operations();
        let methods: Vec<&str> = ops.iter().map(|(m, _)| *m).collect();
        assert_eq!(methods, vec!["get", "post", "delete"]);
    }

    #[test]
    fn config_deserialization() {
        let json = r#"{"spec_url": "https://example.com/api.json", "headers": {"authorization": "Bearer tok"}}"#;
        let config: BridgeConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.spec_url, "https://example.com/api.json");
        assert_eq!(config.headers["authorization"], "Bearer tok");
    }

    #[test]
    fn config_without_headers() {
        let json = r#"{"spec_url": "https://example.com/api.json"}"#;
        let config: BridgeConfig = serde_json::from_str(json).unwrap();
        assert!(config.headers.is_empty());
    }
}
