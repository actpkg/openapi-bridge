//! OpenAPI security schemes, and the one this bridge presents a credential
//! through.
//!
//! An OpenAPI document already says how the API wants to be authenticated:
//! `components.securitySchemes` names the mechanisms and the top-level
//! `security` list says which of them apply. Reading that is what removes the
//! operator's need to know whether *this* API spells its key
//! `Authorization: Bearer`, `X-API-Key`, or `?api_key=`. The credential itself
//! never appears here — this module decides the **shape** of the presentation
//! and `creds.rs` fills in the value.
//!
//! Pure by design: no network, no bindings, no `get-secret`. Every rule below
//! is driven from a real OpenAPI fragment in the tests at the bottom.

use serde::Deserialize;
use std::collections::BTreeMap;

/// `components`, reduced to the one member this bridge reads.
#[derive(Debug, Default, Deserialize)]
pub struct Components {
    #[serde(rename = "securitySchemes", default)]
    pub security_schemes: BTreeMap<String, RawSecurityScheme>,
}

/// One `components.securitySchemes` entry, before it is judged supported.
///
/// Kept as the document wrote it so an *unsupported* scheme can still be named
/// in a refusal — an operator who pinned `openIdConnect` needs to be told that
/// the scheme exists and this bridge cannot present it, not that it is missing.
#[derive(Debug, Clone, Deserialize)]
pub struct RawSecurityScheme {
    #[serde(rename = "type", default)]
    pub kind: String,
    /// `http` schemes: `bearer`, `basic`, `digest`, …
    #[serde(default)]
    pub scheme: Option<String>,
    /// `apiKey` schemes: the parameter name.
    #[serde(default)]
    pub name: Option<String>,
    /// `apiKey` schemes: `header`, `query` or `cookie`.
    #[serde(rename = "in", default)]
    pub location: Option<String>,
    /// `oauth2` schemes, keyed by flow name.
    #[serde(default)]
    pub flows: BTreeMap<String, OAuthFlow>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OAuthFlow {
    /// Scope name to description. Only the names are used.
    #[serde(default)]
    pub scopes: BTreeMap<String, String>,
}

/// A `security` requirement entry: scheme name to the scopes it needs.
///
/// A `BTreeMap` rather than an order-preserving map on purpose. Within one
/// requirement object the schemes are an AND and the document's ordering is
/// not meaningful, while this bridge presents exactly one credential — so it
/// has to choose, and alphabetical is a choice that does not change when the
/// document is reserialised.
pub type Requirement = BTreeMap<String, Vec<String>>;

/// A scheme this bridge knows how to present a credential through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityScheme {
    /// `http` + `bearer`, and the presentation `oauth2` also uses.
    Bearer,
    /// `http` + `basic`.
    Basic,
    /// `apiKey` in `header`, carrying the header name.
    ApiKeyHeader(String),
    /// `apiKey` in `query`, carrying the query-parameter name. Not a header
    /// at all, which is why [`Presentation`] has two variants.
    ApiKeyQuery(String),
    /// `oauth2`. Presented as `Authorization: Bearer`, but kept distinct
    /// because it is the only scheme that carries scopes to ask the store for.
    OAuth2,
}

/// The scheme selection, with everything the caller needs downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The `securitySchemes` key, or [`NO_DECLARED_SCHEME`].
    pub name: String,
    pub scheme: SecurityScheme,
    /// Scopes to put in `secret-request.scopes`. Empty for everything but
    /// `oauth2`.
    pub scopes: Vec<String>,
}

/// The name reported when the document declares nothing this bridge can use
/// and the `Authorization: Bearer` fallback applies. Parenthesised so it
/// cannot collide with a real `securitySchemes` key, which is a JSON object
/// key an OpenAPI document would not spell this way.
pub const NO_DECLARED_SCHEME: &str = "(none declared)";

/// How a credential is attached to one outgoing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presentation {
    Header { name: String, value: String },
    Query { name: String, value: String },
}

impl RawSecurityScheme {
    /// The supported scheme this entry describes, or `None`.
    ///
    /// `None` covers `openIdConnect`, `mutualTLS`, `http` with a scheme other
    /// than bearer/basic (digest, negotiate), an `apiKey` in `cookie`, and any
    /// entry missing the member its type requires. Each of those is a real
    /// mechanism this bridge cannot present, and treating it as unsupported —
    /// rather than guessing a header — is the difference between an
    /// explainable refusal and a request that silently authenticates as
    /// nobody.
    pub fn supported(&self) -> Option<SecurityScheme> {
        match self.kind.as_str() {
            "http" => match self
                .scheme
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("bearer") => Some(SecurityScheme::Bearer),
                Some("basic") => Some(SecurityScheme::Basic),
                _ => None,
            },
            "apiKey" => {
                let name = self.name.as_deref().filter(|n| !n.is_empty())?;
                match self.location.as_deref() {
                    Some("header") => Some(SecurityScheme::ApiKeyHeader(name.to_string())),
                    Some("query") => Some(SecurityScheme::ApiKeyQuery(name.to_string())),
                    _ => None,
                }
            }
            "oauth2" => Some(SecurityScheme::OAuth2),
            _ => None,
        }
    }

    /// Every scope name the entry's flows declare, deduplicated and sorted.
    pub fn declared_scopes(&self) -> Vec<String> {
        let mut scopes: Vec<String> = self
            .flows
            .values()
            .flat_map(|f| f.scopes.keys().cloned())
            .collect();
        scopes.sort_unstable();
        scopes.dedup();
        scopes
    }
}

/// Choose the scheme this session presents its credential through.
///
/// The order is fixed and documented, because a bridge that picked
/// differently between two runs of the same spec would authenticate
/// differently between them:
///
/// 1. **`security_scheme`, when the session pinned one.** It must name an
///    entry in `components.securitySchemes` and that entry must be supported;
///    both failures are refused by name rather than silently falling through,
///    since an operator who named a scheme wants that scheme.
/// 2. **The document's top-level `security` list**, in document order; within
///    one requirement object, the alphabetically first supported scheme.
/// 3. **`components.securitySchemes`** alphabetically, when `security` is
///    absent, empty, or names nothing supported.
/// 4. **`Authorization: Bearer`**, when the document declares nothing usable.
///
/// Operation-level `security` is deliberately not consulted: a session holds
/// one credential and presents it to every operation, so a per-operation
/// override would make the presentation depend on which tool was called.
///
/// The returned `scopes` are the requirement's own scopes when step 2 chose an
/// `oauth2` scheme and listed any — those are the scopes the API actually
/// asks for — and the union of the scheme's declared flow scopes otherwise.
pub fn select(
    schemes: &BTreeMap<String, RawSecurityScheme>,
    requirements: &[Requirement],
    pin: Option<&str>,
) -> Result<Selection, String> {
    if let Some(pin) = pin {
        let Some(raw) = schemes.get(pin) else {
            return Err(format!(
                "security_scheme '{pin}' is not declared by this OpenAPI document. \
                 It names a key of components.securitySchemes, and this document \
                 declares: {}.",
                names_or_none(schemes)
            ));
        };
        let Some(scheme) = raw.supported() else {
            return Err(format!(
                "security_scheme '{pin}' is declared as type '{}', which this bridge \
                 cannot present. It presents http+bearer, http+basic, apiKey in header \
                 or query, and oauth2. Supported schemes in this document: {}.",
                raw.kind,
                supported_names_or_none(schemes)
            ));
        };
        return Ok(Selection {
            scopes: oauth_scopes(&scheme, raw, None),
            name: pin.to_string(),
            scheme,
        });
    }

    for requirement in requirements {
        for (name, requested) in requirement {
            let Some(raw) = schemes.get(name) else {
                continue;
            };
            let Some(scheme) = raw.supported() else {
                continue;
            };
            return Ok(Selection {
                scopes: oauth_scopes(&scheme, raw, Some(requested)),
                name: name.clone(),
                scheme,
            });
        }
    }

    for (name, raw) in schemes {
        if let Some(scheme) = raw.supported() {
            return Ok(Selection {
                scopes: oauth_scopes(&scheme, raw, None),
                name: name.clone(),
                scheme,
            });
        }
    }

    Ok(Selection {
        name: NO_DECLARED_SCHEME.to_string(),
        scheme: SecurityScheme::Bearer,
        scopes: Vec::new(),
    })
}

/// Scopes worth asking the credential store for. Only `oauth2` carries any:
/// a bearer token or an API key has no scope vocabulary, and inventing one
/// would put words in the issuer's mouth.
fn oauth_scopes(
    scheme: &SecurityScheme,
    raw: &RawSecurityScheme,
    requested: Option<&Vec<String>>,
) -> Vec<String> {
    if *scheme != SecurityScheme::OAuth2 {
        return Vec::new();
    }
    match requested {
        Some(r) if !r.is_empty() => {
            let mut scopes = r.clone();
            scopes.sort_unstable();
            scopes.dedup();
            scopes
        }
        _ => raw.declared_scopes(),
    }
}

fn names_or_none(schemes: &BTreeMap<String, RawSecurityScheme>) -> String {
    if schemes.is_empty() {
        "none".to_string()
    } else {
        schemes.keys().cloned().collect::<Vec<_>>().join(", ")
    }
}

fn supported_names_or_none(schemes: &BTreeMap<String, RawSecurityScheme>) -> String {
    let names: Vec<String> = schemes
        .iter()
        .filter(|(_, raw)| raw.supported().is_some())
        .map(|(name, _)| name.clone())
        .collect();
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::OpenApiSpec;

    /// Build a spec around whatever `components`/`security` fragment is under
    /// test, so every case below runs through the real document parser rather
    /// than a hand-built map.
    fn spec(fragment: &str) -> OpenApiSpec {
        let doc = format!(
            r#"{{"openapi":"3.0.3","info":{{"title":"T","version":"1"}},"paths":{{}},{fragment}}}"#
        );
        OpenApiSpec::parse(&doc).expect("fragment parses")
    }

    fn choose(fragment: &str, pin: Option<&str>) -> Result<Selection, String> {
        let s = spec(fragment);
        select(&s.components.security_schemes, &s.security, pin)
    }

    #[test]
    fn bearer_is_read_from_an_http_scheme() {
        let sel = choose(
            r#""components":{"securitySchemes":{"jwt":{"type":"http","scheme":"bearer","bearerFormat":"JWT"}}}"#,
            None,
        )
        .expect("selects");
        assert_eq!(sel.scheme, SecurityScheme::Bearer);
        assert_eq!(sel.name, "jwt");
    }

    #[test]
    fn basic_is_read_from_an_http_scheme() {
        let sel = choose(
            r#""components":{"securitySchemes":{"pw":{"type":"http","scheme":"Basic"}}}"#,
            None,
        )
        .expect("selects");
        // The scheme token is case-insensitive per RFC 9110 §11.1, and a
        // document that capitalises it is not declaring something else.
        assert_eq!(sel.scheme, SecurityScheme::Basic);
    }

    #[test]
    fn an_api_key_carries_the_header_name_the_api_wants() {
        let sel = choose(
            r#""components":{"securitySchemes":{"k":{"type":"apiKey","name":"X-Api-Key","in":"header"}}}"#,
            None,
        )
        .expect("selects");
        assert_eq!(
            sel.scheme,
            SecurityScheme::ApiKeyHeader("X-Api-Key".to_string())
        );
    }

    /// The case that is not a header at all, and the reason the presentation
    /// type has two variants.
    #[test]
    fn an_api_key_in_query_is_a_query_parameter() {
        let sel = choose(
            r#""components":{"securitySchemes":{"k":{"type":"apiKey","name":"api_key","in":"query"}}}"#,
            None,
        )
        .expect("selects");
        assert_eq!(
            sel.scheme,
            SecurityScheme::ApiKeyQuery("api_key".to_string())
        );
    }

    #[test]
    fn an_api_key_in_a_cookie_is_not_supported() {
        // A cookie is a credential header this bridge refuses in session args;
        // presenting one here would reintroduce it through the back door.
        let sel = choose(
            r#""components":{"securitySchemes":{"k":{"type":"apiKey","name":"sid","in":"cookie"}}}"#,
            None,
        )
        .expect("falls back");
        assert_eq!(sel.name, NO_DECLARED_SCHEME);
        assert_eq!(sel.scheme, SecurityScheme::Bearer);
    }

    #[test]
    fn a_document_declaring_nothing_falls_back_to_bearer() {
        let sel = choose(r#""x-unused":true"#, None).expect("falls back");
        assert_eq!(sel.name, NO_DECLARED_SCHEME);
        assert_eq!(sel.scheme, SecurityScheme::Bearer);
        assert!(sel.scopes.is_empty());
    }

    #[test]
    fn an_unpresentable_scheme_falls_back_rather_than_guessing() {
        let sel = choose(
            r#""components":{"securitySchemes":{"oidc":{"type":"openIdConnect","openIdConnectUrl":"https://x/.well-known/openid-configuration"},"d":{"type":"http","scheme":"digest"}}}"#,
            None,
        )
        .expect("falls back");
        assert_eq!(sel.name, NO_DECLARED_SCHEME);
    }

    /// The whole point of reading `security`: the document says which of the
    /// declared schemes actually applies, and it is not the alphabetically
    /// first one here.
    #[test]
    fn the_security_list_outranks_alphabetical_order() {
        let sel = choose(
            r#""components":{"securitySchemes":{
                 "aaa_key":{"type":"apiKey","name":"X-Key","in":"header"},
                 "zzz_bearer":{"type":"http","scheme":"bearer"}}},
               "security":[{"zzz_bearer":[]}]"#,
            None,
        )
        .expect("selects");
        assert_eq!(sel.name, "zzz_bearer");
    }

    #[test]
    fn without_a_security_list_the_choice_is_alphabetical_and_stable() {
        let fragment = r#""components":{"securitySchemes":{
             "zzz_bearer":{"type":"http","scheme":"bearer"},
             "aaa_key":{"type":"apiKey","name":"X-Key","in":"header"}}}"#;
        let first = choose(fragment, None).expect("selects");
        let again = choose(fragment, None).expect("selects");
        assert_eq!(first.name, "aaa_key");
        assert_eq!(first, again, "selection must not vary between runs");
    }

    #[test]
    fn a_security_entry_naming_an_unsupported_scheme_is_skipped() {
        let sel = choose(
            r#""components":{"securitySchemes":{
                 "oidc":{"type":"openIdConnect","openIdConnectUrl":"https://x/c"},
                 "key":{"type":"apiKey","name":"X-Key","in":"header"}}},
               "security":[{"oidc":[]},{"key":[]}]"#,
            None,
        )
        .expect("selects");
        assert_eq!(sel.name, "key");
    }

    #[test]
    fn a_pin_overrides_everything_the_document_prefers() {
        let sel = choose(
            r#""components":{"securitySchemes":{
                 "key":{"type":"apiKey","name":"X-Key","in":"header"},
                 "jwt":{"type":"http","scheme":"bearer"}}},
               "security":[{"key":[]}]"#,
            Some("jwt"),
        )
        .expect("selects");
        assert_eq!(sel.name, "jwt");
        assert_eq!(sel.scheme, SecurityScheme::Bearer);
    }

    #[test]
    fn a_pin_that_names_nothing_is_refused_with_the_available_names() {
        let err = choose(
            r#""components":{"securitySchemes":{"key":{"type":"apiKey","name":"X-Key","in":"header"}}}"#,
            Some("jwt"),
        )
        .expect_err("refused");
        assert!(err.contains("jwt"), "{err}");
        assert!(
            err.contains("key"),
            "the refusal must list what exists: {err}"
        );
    }

    #[test]
    fn a_pin_naming_an_unpresentable_scheme_says_so_rather_than_falling_back() {
        let err = choose(
            r#""components":{"securitySchemes":{
                 "oidc":{"type":"openIdConnect","openIdConnectUrl":"https://x/c"},
                 "key":{"type":"apiKey","name":"X-Key","in":"header"}}}"#,
            Some("oidc"),
        )
        .expect_err("refused");
        assert!(err.contains("openIdConnect"), "{err}");
        assert!(
            err.contains("key"),
            "the refusal must name a scheme that would work: {err}"
        );
    }

    #[test]
    fn oauth_scopes_come_from_the_requirement_when_it_lists_any() {
        let sel = choose(
            r#""components":{"securitySchemes":{"oauth":{"type":"oauth2","flows":{
                 "authorizationCode":{"authorizationUrl":"https://x/a","tokenUrl":"https://x/t",
                   "scopes":{"read:pets":"r","write:pets":"w","admin":"a"}}}}}},
               "security":[{"oauth":["write:pets","read:pets"]}]"#,
            None,
        )
        .expect("selects");
        assert_eq!(sel.scheme, SecurityScheme::OAuth2);
        assert_eq!(
            sel.scopes,
            vec!["read:pets".to_string(), "write:pets".to_string()],
            "the requirement's scopes, sorted — not the scheme's whole catalogue"
        );
    }

    #[test]
    fn oauth_scopes_fall_back_to_every_scope_the_flows_declare() {
        let sel = choose(
            r#""components":{"securitySchemes":{"oauth":{"type":"oauth2","flows":{
                 "implicit":{"authorizationUrl":"https://x/a","scopes":{"read:pets":"r"}},
                 "authorizationCode":{"authorizationUrl":"https://x/a","tokenUrl":"https://x/t",
                   "scopes":{"write:pets":"w","read:pets":"r"}}}}}}"#,
            None,
        )
        .expect("selects");
        assert_eq!(
            sel.scopes,
            vec!["read:pets".to_string(), "write:pets".to_string()],
            "deduplicated across flows"
        );
    }

    #[test]
    fn a_non_oauth_scheme_asks_for_no_scopes() {
        let sel = choose(
            r#""components":{"securitySchemes":{"key":{"type":"apiKey","name":"X-Key","in":"header"}}},
               "security":[{"key":["nonsense"]}]"#,
            None,
        )
        .expect("selects");
        assert!(
            sel.scopes.is_empty(),
            "an API key has no scope vocabulary: {:?}",
            sel.scopes
        );
    }

    /// The Swagger Petstore, which is what the e2e suite drives: two schemes,
    /// no top-level `security`. The documented rule has to produce a stable
    /// answer for it, and this is that answer.
    #[test]
    fn the_petstore_shape_selects_its_api_key() {
        let sel = choose(
            r#""components":{"securitySchemes":{
                 "petstore_auth":{"type":"oauth2","flows":{"implicit":{
                   "authorizationUrl":"https://petstore3.swagger.io/oauth/authorize",
                   "scopes":{"write:pets":"w","read:pets":"r"}}}},
                 "api_key":{"type":"apiKey","name":"api_key","in":"header"}}}"#,
            None,
        )
        .expect("selects");
        assert_eq!(sel.name, "api_key");
        assert_eq!(
            sel.scheme,
            SecurityScheme::ApiKeyHeader("api_key".to_string())
        );
    }
}
