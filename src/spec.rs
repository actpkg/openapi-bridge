use serde::Deserialize;
use std::collections::BTreeMap;

use crate::creds::DEFAULT_CREDENTIAL_KEY;

/// Per-session bridge config — populated from `open-session.args`.
///
/// **Nothing here is a credential, and nothing here may become one.** Session
/// args are agent-visible plaintext: they travel through the transcript, the
/// host's session record and whatever composed the call. The credential is
/// *named* here, by [`BridgeConfig::credential_key`], and fetched from the
/// host's credential store on the first tool call. `headers` survives for the
/// non-secret things a caller legitimately pins — `Accept`, `User-Agent`, a
/// tenant id, an API-version header — and [`validate`] refuses the header
/// names that carry a credential.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[schemars(crate = "schemars", title = "openapi-bridge open-session args")]
pub struct BridgeConfig {
    /// URL to the OpenAPI spec (JSON or YAML).
    pub spec_url: String,
    /// Which credential in this component's profile to authenticate with.
    /// Provisioned out of band with `act secret set` / `act login`; the value
    /// never crosses this boundary.
    #[serde(default = "default_credential_key")]
    pub credential_key: String,
    /// Pin one `components.securitySchemes` key instead of letting the bridge
    /// choose. A scheme *name*, not a credential — it says which mechanism the
    /// stored credential is presented through when a document declares
    /// several.
    #[serde(default)]
    pub security_scheme: Option<String>,
    /// Default headers sent with every API request. Non-secret only: the
    /// header names that carry a credential are refused at `open-session`, and
    /// the credential-derived header is merged in on top of these.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn default_credential_key() -> String {
    DEFAULT_CREDENTIAL_KEY.to_string()
}

/// Header names that carry a credential, and are therefore refused in session
/// args.
///
/// `cookie` and `proxy-authorization` are here for the same reason as
/// `authorization`: each carries the same material and none is any more
/// visible in the audit trail than the others. The rest are the API-key
/// spellings in common use — refusing only `authorization` would be refusing
/// the spelling rather than the practice, and this bridge's whole point is
/// that it fronts an API whose key header it does not know in advance.
///
/// A denylist by necessity: no allowlist can know which headers a given API or
/// reverse proxy legitimately needs. It is backed up by [`validate_scheme`],
/// which additionally refuses the header name *this document's own* apiKey
/// scheme declares — the one name a static list cannot contain.
pub const CREDENTIAL_HEADERS: [&str; 16] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "authentication",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "auth-token",
    "x-access-token",
    "access-token",
    "x-secret-key",
    "private-token",
    "x-amz-security-token",
    "x-goog-api-key",
];

/// The longest a credential key may be. A lookup name, not a sentence: it is
/// copied verbatim into the question a *human* answers when deciding to
/// release a credential, so it has to stay short enough that it cannot become
/// a paragraph in that prompt.
const MAX_CREDENTIAL_KEY: usize = 64;

/// Check and normalise what `open-session` was handed.
///
/// Returns the config with header names trimmed — validating one string and
/// sending another is how `"  X-Custom  "` passes a check and is then dropped
/// by `http` at request time, leaving a header the component accepted and
/// never sent.
///
/// Every refusal names what was wrong and never echoes a value: the value is
/// the thing that might be the credential the caller just mishandled.
pub fn validate(mut config: BridgeConfig) -> Result<BridgeConfig, String> {
    let lowered = config.spec_url.to_ascii_lowercase();
    let scheme_len = if lowered.starts_with("https://") {
        "https://".len()
    } else if lowered.starts_with("http://") {
        "http://".len()
    } else {
        return Err("spec_url must be an http(s) URL".to_string());
    };
    check_no_userinfo(&config.spec_url[scheme_len..], "spec_url")?;

    let key_head = key_prefix(&config.credential_key);
    if key_head.is_empty() || key_head.len() != config.credential_key.len() {
        return Err(format!(
            "credential_key must be a name: 1–{MAX_CREDENTIAL_KEY} characters of letters, \
             digits, '-', '_' or '.', and '{key_head}…' is not one. It is a lookup key in \
             this component's credential profile, not a sentence."
        ));
    }

    if let Some(pin) = &config.security_scheme {
        let head = key_prefix(pin);
        if head.is_empty() || head.len() != pin.len() {
            return Err(format!(
                "security_scheme must name a key of components.securitySchemes, and \
                 '{head}…' is not one."
            ));
        }
    }

    let supplied = std::mem::take(&mut config.headers);
    for (name, value) in supplied {
        let trimmed = name.trim();
        let head = token_prefix(trimmed);
        // Matched against the token prefix rather than the raw key, which
        // closes the two ways past an exact match: a trailing space
        // (`"Authorization "`), and a whole header line pasted as one key
        // (`"Authorization: Basic …"`). The second is why only the prefix is
        // ever printed — everything after the first non-token character may be
        // the value.
        if CREDENTIAL_HEADERS.contains(&head.to_ascii_lowercase().as_str()) {
            return Err(format!(
                "the {head} header may not be set in session args; openapi-bridge \
                 authenticates from the credential store entry named by credential_key, \
                 and presents it through the security scheme the OpenAPI document \
                 declares. Use headers for non-secret defaults only."
            ));
        }
        // The refusal above is a denylist; this shape check is not. A header
        // name is an RFC 9110 token or it is not a header name.
        if head.is_empty() || head.len() != trimmed.len() {
            return Err(format!(
                "header names must be RFC 9110 tokens — letters, digits and \
                 !#$%&'*+-.^_`|~ — and this one is not: '{head}…'. A header name carries \
                 no colon, no space and no value; what followed is not repeated here, in \
                 case it is a credential."
            ));
        }
        // Refused here rather than left for `http` to drop at request time, so
        // the answer arrives where the mistake was made. The value is never
        // echoed, for the same reason.
        if !value.bytes().all(is_header_value_byte) {
            return Err(format!(
                "the {head} header's value carries a control character, so no request \
                 could carry the header. The value is not repeated here, in case it is a \
                 credential."
            ));
        }
        config.headers.insert(trimmed.to_string(), value);
    }

    Ok(config)
}

/// The second half of the header guard, which can only run once the document
/// has been fetched: refuse a session header that collides with the header
/// name *this* API's apiKey scheme declares.
///
/// Without it the static denylist is exactly as good as its author's list of
/// API-key spellings, and this bridge fronts arbitrary APIs. A collision here
/// is not a merge conflict to resolve silently — the credential wins at
/// request time either way — it is a caller trying to set the credential
/// header by hand, which is the practice the guard exists to refuse.
pub fn validate_scheme(
    headers: &BTreeMap<String, String>,
    scheme: &crate::security::SecurityScheme,
) -> Result<(), String> {
    let crate::security::SecurityScheme::ApiKeyHeader(name) = scheme else {
        return Ok(());
    };
    let collides = headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case(name.as_str()));
    if collides {
        return Err(format!(
            "the {name} header may not be set in session args: it is the API-key header \
             this OpenAPI document declares, so it carries the credential. \
             openapi-bridge fills it from the credential store entry named by \
             credential_key."
        ));
    }
    Ok(())
}

/// Refuse a URL whose authority carries userinfo.
///
/// `https://user:pass@host/...` is the URL's spelling of a credential, and one
/// that travels further than it looks: `spec_url` becomes
/// `secret-request.resource`, which leaves this component for the host and is
/// host-visible by contract. The URL is never echoed — it is the thing that
/// would carry the password.
///
/// The authority also has to *be* an authority. Without the port check,
/// `https://user:pa/ss@host/x` passes: RFC 3986 ends the authority at the
/// first `/`, so the `@` lands in the path and the userinfo check never sees
/// it, while `user:pa` is kept as the host and the rest of the password rides
/// along into `resource`.
pub fn check_no_userinfo(after_scheme: &str, what: &str) -> Result<(), String> {
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    if authority.contains('@') {
        return Err(format!(
            "{what} must not carry userinfo (https://user:pass@host/...); openapi-bridge \
             authenticates from the credential store entry named by credential_key"
        ));
    }
    let after_literal = authority.rfind(']').map(|i| i + 1).unwrap_or(0);
    if let Some(i) = authority[after_literal..].rfind(':') {
        let port = &authority[after_literal + i + 1..];
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "{what}'s authority is not a host with an optional numeric port. A \
                 password with a slash in it produces exactly this — check that the URL \
                 is the document's address and nothing else."
            ));
        }
    }
    Ok(())
}

/// The leading credential-key-shaped run of `key`: letters, digits, `-`, `_`
/// and `.`, up to [`MAX_CREDENTIAL_KEY`] characters. Returning the *prefix* is
/// what lets a refusal name what was asked for without repeating what followed.
fn key_prefix(key: &str) -> &str {
    let end = key
        .as_bytes()
        .iter()
        .take(MAX_CREDENTIAL_KEY)
        .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        .unwrap_or_else(|| key.len().min(MAX_CREDENTIAL_KEY));
    &key[..end]
}

/// The leading RFC 9110 token of `name`. Printing this instead of the key is
/// what makes a refusal safe to log: a whole header line pasted as one key
/// carries its credential *after* the first non-token character.
fn token_prefix(name: &str) -> &str {
    let end = name
        .as_bytes()
        .iter()
        .position(|b| !is_tchar(*b))
        .unwrap_or(name.len());
    &name[..end]
}

/// A byte `http` will carry in a header value. Mirrors `http`'s own predicate
/// rather than RFC 9110's narrower `field-value`, so that what `open-session`
/// accepts is exactly what a request can send.
fn is_header_value_byte(b: u8) -> bool {
    b >= 32 && b != 127 || b == b'\t'
}

/// RFC 9110 §5.6.2 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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
    /// `components`, read only for `securitySchemes`.
    #[serde(default)]
    pub components: crate::security::Components,
    /// The document's top-level `security` requirement list. Orders the
    /// candidates in `security::select`; operation-level `security` is
    /// deliberately not consulted (a session presents one credential to every
    /// operation).
    #[serde(default)]
    pub security: Vec<crate::security::Requirement>,
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

    fn config(json: &str) -> BridgeConfig {
        serde_json::from_str(json).expect("deserializes")
    }

    #[test]
    fn config_deserialization() {
        let c = config(
            r#"{"spec_url": "https://example.com/api.json", "headers": {"accept": "application/json"}}"#,
        );
        assert_eq!(c.spec_url, "https://example.com/api.json");
        assert_eq!(c.headers["accept"], "application/json");
    }

    /// `spec_url` is the one argument with no default; everything else has to
    /// survive being omitted, because these defaults are the contract an agent
    /// opening a session actually gets.
    #[test]
    fn every_argument_but_the_spec_url_has_a_default() {
        let c = config(r#"{"spec_url": "https://example.com/api.json"}"#);
        assert!(c.headers.is_empty());
        assert_eq!(c.credential_key, "default");
        assert_eq!(c.security_scheme, None);
    }

    /// The security property the credential design exists to protect,
    /// asserted rather than eyeballed: **everything sent to `open-session` is
    /// agent-visible plaintext**, so the schema must offer nowhere to put a
    /// secret.
    ///
    /// The root fields are an allowlist, spelled out exactly. Having to edit
    /// this list when a field is added is the point: adding a session
    /// argument is a decision about what an agent may hand over, and it
    /// should not be reviewable by accident. The word sweep below then runs
    /// over property names at any depth, for a secret hidden inside a nested
    /// object or a `$defs` entry — and it is why the pin is called
    /// `security_scheme` and not `auth_scheme`.
    #[test]
    fn the_open_args_schema_offers_nowhere_to_put_a_credential() {
        let schema = schemars::schema_for!(BridgeConfig);
        let json: serde_json::Value = serde_json::to_value(&schema).expect("schema serializes");

        let mut root: Vec<&str> = json["properties"]
            .as_object()
            .expect("an object schema")
            .keys()
            .map(String::as_str)
            .collect();
        root.sort_unstable();
        assert_eq!(
            root,
            ["credential_key", "headers", "security_scheme", "spec_url"]
        );

        let mut names = Vec::new();
        property_names(&json, &mut names);
        assert!(names.iter().any(|n| n == "credential_key"), "got {names:?}");
        for forbidden in [
            "password", "passwd", "pwd", "secret", "token", "auth", "api_key",
        ] {
            assert!(
                !names.iter().any(|n| n.to_lowercase().contains(forbidden)),
                "the open-args schema offers a place to put a {forbidden}: {names:?}"
            );
        }
    }

    /// Every `properties` key at any depth, including inside `$defs`.
    fn property_names(node: &serde_json::Value, out: &mut Vec<String>) {
        match node {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Object(props)) = map.get("properties") {
                    out.extend(props.keys().cloned());
                }
                for value in map.values() {
                    property_names(value, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    property_names(item, out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn validate_accepts_a_plain_config() {
        let c = validate(config(
            r#"{"spec_url":"https://example.com/api.json","headers":{"  X-Tenant  ":"acme"}}"#,
        ))
        .expect("accepted");
        assert!(
            c.headers.contains_key("X-Tenant"),
            "the trimmed name is what gets stored: {:?}",
            c.headers
        );
    }

    #[test]
    fn validate_refuses_every_credential_bearing_header_name() {
        for name in CREDENTIAL_HEADERS {
            let json = format!(
                r#"{{"spec_url":"https://example.com/api.json","headers":{{"{name}":"x"}}}}"#
            );
            let e = validate(config(&json)).expect_err("refused");
            assert!(e.contains("credential_key"), "{name}: {e}");
        }
    }

    /// The two ways past an exact match, and the reason the check runs on the
    /// token prefix.
    #[test]
    fn a_padded_or_pasted_credential_header_is_refused_without_echoing_its_value() {
        for name in ["Authorization ", "Authorization: Bearer hunter2"] {
            let json = format!(
                r#"{{"spec_url":"https://example.com/api.json","headers":{{"{name}":"x"}}}}"#
            );
            let e = validate(config(&json)).expect_err("refused");
            assert!(
                !e.contains("hunter2"),
                "a refusal must not echo what followed the name: {e}"
            );
        }
    }

    #[test]
    fn validate_refuses_a_header_name_that_is_not_a_token() {
        let e = validate(config(
            r#"{"spec_url":"https://example.com/api.json","headers":{"X Tenant":"a"}}"#,
        ))
        .expect_err("refused");
        assert!(e.contains("RFC 9110"), "{e}");
    }

    #[test]
    fn validate_refuses_a_header_value_no_request_could_carry() {
        let e = validate(config(
            r#"{"spec_url":"https://example.com/api.json","headers":{"X-Tenant":"a\nb"}}"#,
        ))
        .expect_err("refused");
        assert!(!e.contains("a\nb"), "the value must not be echoed: {e}");
    }

    #[test]
    fn validate_refuses_userinfo_in_the_spec_url() {
        let e = validate(config(
            r#"{"spec_url":"https://svc:hunter2@example.com/api.json"}"#,
        ))
        .expect_err("refused");
        assert!(!e.contains("hunter2"), "userinfo echoed: {e}");
        // An `@` in the path is not userinfo and is legal in a spec URL.
        assert!(validate(config(r#"{"spec_url":"https://example.com/a@b.json"}"#)).is_ok());
    }

    /// Stopping at `/` alone would let `https://user:pa/ss@host/x` through:
    /// the `@` lands in the path, so the userinfo check never sees it, while
    /// `user:pa` is kept as the host.
    #[test]
    fn validate_refuses_a_password_with_a_slash_in_it() {
        let e = validate(config(
            r#"{"spec_url":"https://user:hun/ter2@example.com/api.json"}"#,
        ))
        .expect_err("refused");
        assert!(!e.contains("hun"), "{e}");
    }

    #[test]
    fn validate_refuses_a_non_http_spec_url() {
        assert!(validate(config(r#"{"spec_url":"file:///etc/api.json"}"#)).is_err());
        assert!(validate(config(r#"{"spec_url":"example.com/api.json"}"#)).is_err());
    }

    /// A key is copied into a human-facing consent prompt verbatim, so it is
    /// bounded to a lookup name rather than left as free text.
    #[test]
    fn validate_refuses_a_credential_key_that_is_a_sentence() {
        let e = validate(config(
            r#"{"spec_url":"https://example.com/api.json","credential_key":"erp (approved by your administrator)"}"#,
        ))
        .expect_err("refused");
        assert!(e.contains("lookup key"), "{e}");
    }

    /// The half of the header guard a static denylist cannot do: the API's own
    /// key header, learned from the document.
    #[test]
    fn a_session_header_colliding_with_the_documents_api_key_header_is_refused() {
        use crate::security::SecurityScheme;
        let mut headers = BTreeMap::new();
        headers.insert("X-Petstore-Key".to_string(), "k".to_string());
        let scheme = SecurityScheme::ApiKeyHeader("x-petstore-key".to_string());
        let e = validate_scheme(&headers, &scheme).expect_err("refused");
        assert!(e.contains("credential_key"), "{e}");

        // A header that is not the credential header is left alone.
        assert!(
            validate_scheme(&headers, &SecurityScheme::Bearer).is_ok(),
            "only the declared API-key header collides"
        );
    }

    #[test]
    fn the_document_model_reads_security_schemes_and_requirements() {
        let spec = OpenApiSpec::parse(
            r#"{"openapi":"3.0.3","info":{"title":"T","version":"1"},"paths":{},
                "components":{"securitySchemes":{"jwt":{"type":"http","scheme":"bearer"}}},
                "security":[{"jwt":[]}]}"#,
        )
        .expect("parses");
        assert!(spec.components.security_schemes.contains_key("jwt"));
        assert_eq!(spec.security.len(), 1);
    }

    /// A document with neither member still parses — most do not have them.
    #[test]
    fn a_document_without_security_still_parses() {
        let spec = OpenApiSpec::parse(
            r#"{"openapi":"3.0.3","info":{"title":"T","version":"1"},"paths":{}}"#,
        )
        .expect("parses");
        assert!(spec.components.security_schemes.is_empty());
        assert!(spec.security.is_empty());
    }
}
