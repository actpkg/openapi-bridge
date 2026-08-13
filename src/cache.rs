use std::collections::HashMap;
use std::sync::Mutex;

use crate::spec::OpenApiSpec;
use crate::tools::ResolvedTool;

/// Cached parsed spec and its resolved tools.
pub struct CachedSpec {
    pub spec: OpenApiSpec,
    pub tools: Vec<ResolvedTool>,
}

static CACHE: std::sync::OnceLock<Mutex<HashMap<String, CachedSpec>>> = std::sync::OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, CachedSpec>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get cached tools for a URL, or return None if not cached.
pub fn get_cached(url: &str) -> Option<Vec<ResolvedTool>> {
    let lock = cache().lock().unwrap();
    lock.get(url).map(|c| c.tools.clone())
}

/// Get a cached tool by URL and tool name.
pub fn get_cached_tool(url: &str, tool_name: &str) -> Option<ResolvedTool> {
    let lock = cache().lock().unwrap();
    lock.get(url)
        .and_then(|c| c.tools.iter().find(|t| t.name == tool_name).cloned())
}

/// Choose the security scheme for a cached document.
///
/// `None` when the document is not cached at all; `Some(Err(_))` when it is
/// cached and the caller's `pin` names nothing it can present. Run against the
/// cache rather than against a spec the caller holds, so that one parse serves
/// every session opened against the same `spec_url`.
pub fn select_scheme(
    url: &str,
    pin: Option<&str>,
) -> Option<Result<crate::security::Selection, String>> {
    let lock = cache().lock().unwrap();
    lock.get(url).map(|c| {
        crate::security::select(&c.spec.components.security_schemes, &c.spec.security, pin)
    })
}

/// Get the base URL from a cached spec.
pub fn get_base_url(url: &str) -> Option<String> {
    let lock = cache().lock().unwrap();
    lock.get(url).map(|c| c.spec.base_url().to_string())
}

/// Cache a parsed spec and its resolved tools.
pub fn put_cached(url: String, spec: OpenApiSpec, tools: Vec<ResolvedTool>) {
    let mut lock = cache().lock().unwrap();
    lock.insert(url, CachedSpec { spec, tools });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_miss_returns_none() {
        assert!(get_cached("https://nonexistent.example.com/spec.json").is_none());
    }
}
