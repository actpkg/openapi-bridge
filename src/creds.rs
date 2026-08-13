//! The credential this bridge fetches, and how it turns into one header or
//! one query parameter.
//!
//! Four field names, all in this component's own namespace. `ACT-CONSTANTS.md`
//! §8.2 registers field *types*, not field *names*, and a `std:`-prefixed name
//! is refused at pack time — so the component that reads a field is the party
//! that asked for it, and every error below prints the exact `act secret set`
//! command that provisions the names it just looked for.
//!
//! **Dispatch is on the field name, never on the shape** (§8.1–8.2). A
//! `std:oauth2` value is a CBOR map and a `std:string` value is CBOR text, but
//! the reader does not go looking for whichever one it finds: it reads
//! [`FIELD_OAUTH`] as an OAuth field because that is the name reserved for one,
//! and [`FIELD_TOKEN`] as a string because that is the name reserved for that.
//! Guessing from shape is how a two-member map that happens to look like a
//! token gets authenticated with.
//!
//! Pure by design: `get-secret` lives in `lib.rs`, where the generated
//! bindings are, so everything here runs on the host target under test.

use act_sdk::credentials::Secret;

use crate::security::{Presentation, SecurityScheme};

/// The credential key used when a session names none. A lookup name in this
/// component's own profile (`ACT-AUTH.md` §1.1.3), not a shared identifier.
pub const DEFAULT_CREDENTIAL_KEY: &str = "default";

/// A `std:oauth2` field — a CBOR map whose `std:access-token` member is the
/// token (`ACT-CONSTANTS.md` §8.3). Provisioned by `act login`, which runs the
/// flow; `act secret set --field openapi:oauth=std:oauth2 --fields-stdin`
/// stores one obtained by hand.
pub const FIELD_OAUTH: &str = "openapi:oauth";

/// A `std:string` field holding a bearer token or an API key verbatim —
/// whatever the selected scheme wants to carry.
pub const FIELD_TOKEN: &str = "openapi:token";

/// A `std:string` field: the user half of an HTTP Basic credential.
pub const FIELD_USERNAME: &str = "openapi:username";

/// A `std:string` field: the password half of an HTTP Basic credential.
pub const FIELD_PASSWORD: &str = "openapi:password";

/// How long before a stated expiry a token is treated as already expired.
///
/// A token that expires in the next few seconds will very likely have expired
/// by the time the upstream validates it, and the failure it produces then is
/// a bare 401 with no explanation. Refusing early buys the actionable message
/// below instead. Thirty seconds is generous for one request and short enough
/// that it never discards a token with real life left in it.
const EXPIRY_SKEW_SECS: u64 = 30;

/// Build the presentation for `scheme` from `secret`.
///
/// `now` is Unix seconds, passed in rather than read here so the expiry rule
/// is drivable under test. Every error is `std:credential-required` at the
/// call site: nothing about the *call* was wrong, and the fix is a
/// provisioning command (`ACT-CONSTANTS.md` §9).
pub fn present(
    secret: &Secret,
    scheme: &SecurityScheme,
    key: &str,
    now: u64,
) -> Result<Presentation, String> {
    match scheme {
        SecurityScheme::Basic => {
            let (Some(user), Some(password)) = (
                secret.field_str(FIELD_USERNAME).filter(|s| !s.is_empty()),
                secret.field_str(FIELD_PASSWORD),
            ) else {
                return Err(missing_basic(key));
            };
            Ok(Presentation::Header {
                name: "authorization".to_string(),
                value: format!("Basic {}", base64_standard(user, password)),
            })
        }
        SecurityScheme::Bearer | SecurityScheme::OAuth2 => Ok(Presentation::Header {
            name: "authorization".to_string(),
            value: format!("Bearer {}", token(secret, key, now)?),
        }),
        SecurityScheme::ApiKeyHeader(name) => Ok(Presentation::Header {
            name: name.clone(),
            value: token(secret, key, now)?,
        }),
        SecurityScheme::ApiKeyQuery(name) => Ok(Presentation::Query {
            name: name.clone(),
            value: token(secret, key, now)?,
        }),
    }
}

/// The single token value, read by name.
///
/// [`FIELD_OAUTH`] outranks [`FIELD_TOKEN`] when a credential carries both.
/// The precedence is fixed rather than "whichever is present" so that storing
/// a second field can never quietly change which one authenticates: the OAuth
/// field is the one with an expiry and a scope list, so it is the one whose
/// failures can be explained, and a stale hand-set `openapi:token` left behind
/// beside a freshly acquired OAuth field is the likelier of the two mistakes.
fn token(secret: &Secret, key: &str, now: u64) -> Result<String, String> {
    if secret.field(FIELD_OAUTH).is_some() {
        let Some(oauth) = secret.as_oauth2(FIELD_OAUTH) else {
            return Err(format!(
                "The credential under key '{key}' has a {FIELD_OAUTH} field that is not a \
                 std:oauth2 value. That field must be a map with a std:access-token member \
                 (ACT-CONSTANTS.md §8.3); a plain string belongs under {FIELD_TOKEN}. \
                 Re-provision it with `act login <component-ref> --key {key} --force`, or \
                 store the string under the right name:\n  \
                 act secret set <component-ref> --key {key} --field {FIELD_TOKEN} --fields-stdin"
            ));
        };
        // The host does not refresh (ACT-AUTH.md §1.1, scope note): an expired
        // token is re-acquired, not renewed, so the message says so instead of
        // implying a retry would help.
        if let Some(expires_at) = oauth.expires_at
            && expires_at <= now.saturating_add(EXPIRY_SKEW_SECS)
        {
            return Err(format!(
                "The OAuth access token under key '{key}' expired at {expires_at} (Unix \
                 seconds). ACT does not refresh tokens silently — re-acquire it with:\n  \
                 act login <component-ref> --key {key} --force"
            ));
        }
        if oauth.access_token.is_empty() {
            return Err(missing_token(key));
        }
        return Ok(oauth.access_token);
    }

    match secret.field_str(FIELD_TOKEN).filter(|s| !s.is_empty()) {
        Some(t) => Ok(t.to_string()),
        None => Err(missing_token(key)),
    }
}

fn missing_token(key: &str) -> String {
    format!(
        "The credential under key '{key}' carries no usable {FIELD_TOKEN} or {FIELD_OAUTH} \
         field. Store one of them:\n  \
         act secret set <component-ref> --key {key} --field {FIELD_TOKEN} --fields-stdin\n  \
         {{\"{FIELD_TOKEN}\": \"...\"}}\n\
         For an OAuth API, declare the field's type instead and run the flow:\n  \
         act secret set <component-ref> --key {key} --field {FIELD_OAUTH}=std:oauth2 --fields-stdin"
    )
}

fn missing_basic(key: &str) -> String {
    format!(
        "This API declares HTTP Basic authentication, and the credential under key '{key}' \
         carries no {FIELD_USERNAME} / {FIELD_PASSWORD} pair. Store one with:\n  \
         act secret set <component-ref> --key {key} \
         --field {FIELD_USERNAME} --field {FIELD_PASSWORD} --fields-stdin\n  \
         {{\"{FIELD_USERNAME}\": \"...\", \"{FIELD_PASSWORD}\": \"...\"}}"
    )
}

/// RFC 4648 §4 base64 of `user:password`, which is what RFC 7617 puts after
/// `Basic `.
///
/// Hand-rolled rather than pulled in as a dependency: it is one table and one
/// loop, it is the only encoding this component needs, and a credential is not
/// something to hand to a crate for the sake of six lines.
fn base64_standard(user: &str, password: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{password}");
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    const NOW: u64 = 1_760_000_000;

    /// A token value distinctive enough that "is it echoed?" is a real
    /// question. A short one like `at` appears inside ordinary English words
    /// and inside the timestamps these messages print, so it answers yes by
    /// accident.
    const SENTINEL: &str = "sentinel-access-token";

    fn secret(pairs: Vec<(&str, Value)>) -> Secret {
        Secret::from_wit(
            "std:fields".into(),
            pairs
                .into_iter()
                .map(|(k, v)| {
                    let mut buf = Vec::new();
                    ciborium::into_writer(&v, &mut buf).expect("encode");
                    (k.to_string(), buf)
                })
                .collect(),
        )
        .expect("fields decode")
    }

    fn oauth_field(members: Vec<(&str, Value)>) -> Value {
        Value::Map(
            members
                .into_iter()
                .map(|(k, v)| (Value::Text(k.into()), v))
                .collect(),
        )
    }

    fn header(p: &Presentation) -> (&str, &str) {
        match p {
            Presentation::Header { name, value } => (name.as_str(), value.as_str()),
            other => panic!("expected a header, got {other:?}"),
        }
    }

    #[test]
    fn a_bearer_scheme_builds_an_authorization_header() {
        let s = secret(vec![(FIELD_TOKEN, Value::Text("tok".into()))]);
        let p = present(&s, &SecurityScheme::Bearer, "default", NOW).expect("presents");
        assert_eq!(header(&p), ("authorization", "Bearer tok"));
    }

    /// The scheme decides the header, which is the point of reading the
    /// document: the same stored token becomes a different request.
    #[test]
    fn an_api_key_scheme_uses_the_header_name_the_document_named() {
        let s = secret(vec![(FIELD_TOKEN, Value::Text("tok".into()))]);
        let p = present(
            &s,
            &SecurityScheme::ApiKeyHeader("X-Api-Key".into()),
            "default",
            NOW,
        )
        .expect("presents");
        assert_eq!(header(&p), ("X-Api-Key", "tok"));
    }

    #[test]
    fn an_api_key_in_query_is_not_a_header_at_all() {
        let s = secret(vec![(FIELD_TOKEN, Value::Text("tok".into()))]);
        let p = present(
            &s,
            &SecurityScheme::ApiKeyQuery("api_key".into()),
            "default",
            NOW,
        )
        .expect("presents");
        assert_eq!(
            p,
            Presentation::Query {
                name: "api_key".into(),
                value: "tok".into()
            }
        );
    }

    #[test]
    fn basic_encodes_the_pair_the_way_rfc_7617_does() {
        let s = secret(vec![
            (FIELD_USERNAME, Value::Text("Aladdin".into())),
            (FIELD_PASSWORD, Value::Text("open sesame".into())),
        ]);
        let p = present(&s, &SecurityScheme::Basic, "default", NOW).expect("presents");
        // The example from RFC 7617 §2 itself, so the encoder is pinned
        // against the specification rather than against its own output.
        assert_eq!(
            header(&p),
            ("authorization", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
        );
    }

    #[test]
    fn base64_pads_every_input_length() {
        assert_eq!(base64_standard("a", ""), "YTo=");
        assert_eq!(base64_standard("ab", ""), "YWI6");
        assert_eq!(base64_standard("abc", ""), "YWJjOg==");
        assert_eq!(base64_standard("", ""), "Og==");
    }

    #[test]
    fn basic_without_both_fields_names_the_command_that_fixes_it() {
        let s = secret(vec![(FIELD_USERNAME, Value::Text("u".into()))]);
        let e = present(&s, &SecurityScheme::Basic, "prod", NOW).expect_err("refused");
        assert!(e.contains("act secret set"), "{e}");
        assert!(e.contains(FIELD_PASSWORD), "{e}");
        assert!(e.contains("--key prod"), "{e}");
    }

    /// An empty password is legal in RFC 7617 and an empty *username* is not
    /// a credential — the two are not symmetric and must not be treated so.
    #[test]
    fn basic_accepts_an_empty_password_but_not_an_empty_username() {
        let ok = secret(vec![
            (FIELD_USERNAME, Value::Text("u".into())),
            (FIELD_PASSWORD, Value::Text("".into())),
        ]);
        assert!(present(&ok, &SecurityScheme::Basic, "k", NOW).is_ok());

        let blank = secret(vec![
            (FIELD_USERNAME, Value::Text("".into())),
            (FIELD_PASSWORD, Value::Text("p".into())),
        ]);
        assert!(present(&blank, &SecurityScheme::Basic, "k", NOW).is_err());
    }

    #[test]
    fn an_oauth_field_supplies_the_access_token() {
        let s = secret(vec![(
            FIELD_OAUTH,
            oauth_field(vec![("std:access-token", Value::Text("at".into()))]),
        )]);
        let p = present(&s, &SecurityScheme::OAuth2, "default", NOW).expect("presents");
        assert_eq!(header(&p), ("authorization", "Bearer at"));
    }

    /// Dispatch is by name: the OAuth field is read as OAuth because of what
    /// it is called, and it outranks a string field stored beside it.
    #[test]
    fn the_oauth_field_outranks_a_token_stored_beside_it() {
        let s = secret(vec![
            (FIELD_TOKEN, Value::Text("stale".into())),
            (
                FIELD_OAUTH,
                oauth_field(vec![("std:access-token", Value::Text("fresh".into()))]),
            ),
        ]);
        let p = present(&s, &SecurityScheme::Bearer, "default", NOW).expect("presents");
        assert_eq!(header(&p), ("authorization", "Bearer fresh"));
    }

    /// A map under the *string* field's name is not an OAuth credential: no
    /// accessor here goes looking for a shape it was not pointed at.
    #[test]
    fn an_oauth_shaped_map_under_the_string_name_is_not_read_as_oauth() {
        let s = secret(vec![(
            FIELD_TOKEN,
            oauth_field(vec![("std:access-token", Value::Text(SENTINEL.into()))]),
        )]);
        let e = present(&s, &SecurityScheme::Bearer, "default", NOW).expect_err("refused");
        assert!(e.contains(FIELD_TOKEN), "{e}");
        assert!(
            !e.contains(SENTINEL),
            "a refusal must not echo credential material: {e}"
        );
    }

    #[test]
    fn an_expired_token_says_it_is_re_acquired_not_refreshed() {
        let s = secret(vec![(
            FIELD_OAUTH,
            oauth_field(vec![
                ("std:access-token", Value::Text(SENTINEL.into())),
                ("std:expires-at", Value::Integer((NOW - 1).into())),
            ]),
        )]);
        let e = present(&s, &SecurityScheme::Bearer, "prod", NOW).expect_err("refused");
        assert!(e.contains("act login"), "the fix must be named: {e}");
        assert!(e.contains("--force"), "{e}");
        assert!(e.contains("--key prod"), "{e}");
        // The host does not refresh (ACT-AUTH.md §1.1, scope note), so the
        // message must not suggest waiting or retrying would help.
        assert!(
            e.contains("does not refresh"),
            "the message must say re-acquire, not refresh: {e}"
        );
        assert!(!e.contains(SENTINEL), "the token must not be echoed: {e}");
    }

    /// The skew, driven at the boundary rather than described in a comment.
    #[test]
    fn a_token_expiring_within_the_skew_is_already_expired() {
        let about_to = secret(vec![(
            FIELD_OAUTH,
            oauth_field(vec![
                ("std:access-token", Value::Text("at".into())),
                (
                    "std:expires-at",
                    Value::Integer((NOW + EXPIRY_SKEW_SECS - 1).into()),
                ),
            ]),
        )]);
        assert!(present(&about_to, &SecurityScheme::Bearer, "k", NOW).is_err());

        let alive = secret(vec![(
            FIELD_OAUTH,
            oauth_field(vec![
                ("std:access-token", Value::Text("at".into())),
                (
                    "std:expires-at",
                    Value::Integer((NOW + EXPIRY_SKEW_SECS + 1).into()),
                ),
            ]),
        )]);
        assert!(present(&alive, &SecurityScheme::Bearer, "k", NOW).is_ok());
    }

    /// `ACT-CONSTANTS.md` §8.3: a missing `std:expires-at` reads as "no known
    /// expiry", not as "expired now".
    #[test]
    fn a_token_without_an_expiry_is_not_treated_as_expired() {
        let s = secret(vec![(
            FIELD_OAUTH,
            oauth_field(vec![("std:access-token", Value::Text("at".into()))]),
        )]);
        assert!(present(&s, &SecurityScheme::Bearer, "k", u64::MAX).is_ok());
    }

    #[test]
    fn an_empty_credential_names_both_provisioning_commands() {
        let s = secret(vec![("openapi:tenant", Value::Text("t-42".into()))]);
        let e = present(&s, &SecurityScheme::Bearer, "default", NOW).expect_err("refused");
        assert!(e.contains("act secret set"), "{e}");
        assert!(e.contains(FIELD_TOKEN) && e.contains(FIELD_OAUTH), "{e}");
    }

    /// Every message an operator can reach has to name the command that ends
    /// the problem — a refusal that only states the problem sends them to the
    /// source.
    #[test]
    fn every_refusal_is_actionable() {
        let cases = [
            missing_token("k"),
            missing_basic("k"),
            present(
                &secret(vec![(FIELD_TOKEN, Value::Text("".into()))]),
                &SecurityScheme::Bearer,
                "k",
                NOW,
            )
            .expect_err("blank token is not a credential"),
            present(
                &secret(vec![(
                    FIELD_OAUTH,
                    oauth_field(vec![
                        ("std:access-token", Value::Text("at".into())),
                        ("std:expires-at", Value::Integer(1.into())),
                    ]),
                )]),
                &SecurityScheme::Bearer,
                "k",
                NOW,
            )
            .expect_err("expired"),
            present(
                &secret(vec![(FIELD_TOKEN, Value::Integer(7.into()))]),
                &SecurityScheme::Bearer,
                "k",
                NOW,
            )
            .expect_err("an integer field is not a token"),
        ];
        for message in cases {
            assert!(
                message.contains("act secret set") || message.contains("act login"),
                "not actionable: {message}"
            );
        }
    }
}
