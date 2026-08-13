wasm := "target/wasm32-wasip2/release/openapi_bridge.wasm"

act := env("ACT", "npx @actcore/act")
actbuild := env("ACT_BUILD", "npx @actcore/act-build")
registry := env("OCI_REGISTRY", "actpkg.dev/library")

# Fetch WIT deps from the registry (ghcr.io/actcore) into wit/deps/.
# wkg-registry.toml maps the act namespace -> actcore.dev (well-known -> ghcr.io/actcore).
init:
    WKG_CONFIG_FILE=wkg-registry.toml wkg wit fetch --type wit

setup: init
    prek install

build:
    cargo build --release
    {{actbuild}} pack {{wasm}}

# Re-embed act:component metadata and act:skill without rebuilding. `pack` is
# idempotent, so running it after `build` is harmless.
pack:
    {{actbuild}} pack {{wasm}}

# Host-target unit tests. The crate is a cdylib for wasm32-wasip2, so the
# target has to be named: the pure logic (security-scheme selection, credential
# presentation, the open-args guard) is what these drive, and none of it can
# run under `cargo test` on the default wasm target.
test-unit:
    cargo test --target x86_64-unknown-linux-gnu

test: build
    ACT="{{act}}" uv run --project e2e pytest e2e/ -v

publish:
    #!/usr/bin/env bash
    set -euo pipefail
    INFO=$({{act}} inspect component-manifest {{wasm}})
    NAME=$(echo "$INFO" | jq -r .std.name)
    VERSION=$(echo "$INFO" | jq -r .std.version)
    OUTPUT=$({{actbuild}} push {{wasm}} "{{registry}}/$NAME:$VERSION" \
      --skip-if-exists \
      --also-tag latest 2>&1) || { echo "$OUTPUT" >&2; exit 1; }
    echo "$OUTPUT"
    DIGEST=$(echo "$OUTPUT" | grep "^Digest:" | awk '{print $2}' || true)
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "image={{registry}}/$NAME" >> "$GITHUB_OUTPUT"
      echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
    fi
