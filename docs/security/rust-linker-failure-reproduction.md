# Rust Linker Failure Reproduction

**Commit where failure occurred:** `1c808006d489cfbe5d69e30a314df651295adf08`
**Fix commit:** `40eb61840b761eb61c2d412e2265382e50eae36c`

---

## Environment

| Field | Value |
|---|---|
| rustc version | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| cargo version | `cargo 1.96.0 (30a34c682 2026-05-25)` |
| Affected OS | Ubuntu 22.04 (GitHub Actions `ubuntu-latest` runner) |
| Safe OS | Windows 10 (MINGW64 / link.exe — does not use GNU-ld version-script) |
| wit-bindgen | `0.24` |

---

## Reproduction Steps (Linux only)

```bash
git checkout 1c808006d489cfbe5d69e30a314df651295adf08
cd contract
cargo test --locked -- --nocapture
```

> **Note:** This failure is platform-specific to Linux/Ubuntu with `rust-lld`.
> On Windows, `link.exe` is used and the version-script constraint does not apply.
> The failure was observed in GitHub Actions CI (`ubuntu-latest`) and is reproducible
> on any Ubuntu 22+ host with the standard Rust toolchain.

---

## Failing Behaviour

`cargo test --locked` exits with a **linker error** — no test output is produced
because the build step fails before any test binary is emitted.

### Error Output (ubuntu-latest / rust-lld)

```
error: linking with `cc` failed: exit status: 1
  |
  = note: /usr/bin/ld: version script assignment of `cabi_post_z:adn-processor/contracts@0.1.0#audit-decisions' failed: symbol not found
  = note: /usr/bin/ld: version script assignment of `cabi_post_z:adn-processor/contracts@0.1.0#process-data' failed: symbol not found
  = note: collect2: error: ld returned 1 exit status

error: could not compile `adn-processor` (lib test) due to 1 previous error
```

*(Exact wording varies slightly by linker version; the key marker is
`version script` + a symbol name containing `:`.)*

---

## Root Cause

### 1. Dual `crate-type`

`contract/Cargo.toml` declares:

```toml
[lib]
crate-type = ["cdylib", "lib"]
```

`cdylib` produces the WASM component artifact.
`lib` keeps native linkage so that `cargo test` can compile and run unit tests.

### 2. Unconditional `export!(Component)`

At commit `1c808006`, `contract/src/lib.rs` contained:

```rust
wit_bindgen::generate!({ world: "adn-processor", path: "wit" });

struct Component;
export!(Component);    // ← no cfg gate
```

`export!(Component)` is a WIT-bindgen 0.24 macro that emits the full
component-model ABI: `cabi_post_*`, `cabi_realloc`, and related symbols.

### 3. Colon in version-script symbol names

WIT interface names follow the form `namespace:package/interface@version#method`,
e.g.:

```
cabi_post_z:adn-processor/contracts@0.1.0#audit-decisions
```

The colon (`:`) in this symbol name is **not valid** in GNU-ld version-script
node names. When `cargo test` compiles for a native Linux target using `crate-type = ["cdylib", "lib"]`,
`rust-lld` generates a version script and the colon causes the link step to abort.

### 4. Why WASM builds are not affected

When targeting `wasm32-wasip2`, the WASM linker (`wasm-ld`) processes a binary
format — it does not use GNU-ld version scripts. The `cabi_post_*` symbols are
valid WASM export names. So `cargo build --target wasm32-wasip2 --release`
succeeds on all platforms.

---

## Fix

Gate `export!(Component)` behind `#[cfg(target_arch = "wasm32")]` in
`contract/src/lib.rs`:

```rust
// Only emit the Wasm component-model ABI trampolines when targeting wasm32.
// On native (cargo test), the cabi_post_* symbol names contain `:` which is
// invalid in GNU-ld version-script syntax and causes rust-lld to fail.
#[cfg(target_arch = "wasm32")]
export!(Component);
```

This prevents WIT ABI trampolines from being compiled into the native test
binary. The WASM build is entirely unaffected.

**Changed file:** `contract/src/lib.rs` (+4 lines)

---

## Verification

After the fix (at commit `40eb618` and all subsequent commits):

| Test mode | Command | Result |
|---|---|---|
| Plain | `cargo test --locked -- --nocapture` | 25 passed, 0 failed |
| Pinned-issuer | `ADN_TRUSTED_ISSUER=58da990a8f4a3a6ca7cb6315d68a140105917352 ADN_TENANT_DID=did:t3n:fixture cargo test --locked -- --nocapture` | 25 passed, 0 failed |
| WASM release | `cargo build --locked --target wasm32-wasip2 --release` | Finished (exit 0) |
| WASM SHA256 | — | `9c6cc9383a0cb3cb0641209f0e9fc8745af69f4d41c3bc7defff0dc7fc4dd665` |

---

## Regression Test

**File:** `contract/src/lib.rs` — `mod regression_tests`
**Test name:** `regression_tests::native_build_does_not_emit_wit_abi_trampolines`

```bash
cargo test --locked native_build -- --nocapture
# running 1 test
# test regression_tests::native_build_does_not_emit_wit_abi_trampolines ... ok
```

This test passes if and only if the native build linked successfully.
If `export!(Component)` is ever un-gated, the test binary will fail to link
on Linux before this test can run.

---

## Timeline

| Commit | Event |
|---|---|
| `1c808006` | Failure introduced: `export!(Component)` unconditional |
| `40eb618` | Fix: `#[cfg(target_arch = "wasm32")]` gate added (Phase 0) |
| `4cf55f9` | Phase 0 freeze: all claims verified |
| Phase 1 | This document and regression test added |
