# Notice of modifications

This is a fork of [greetd](https://git.sr.ht/~kennylevinsen/greetd) by
Kenny Levinsen, licensed GPL-3.0-only. Per GPL-3.0 §5(a), this file
records that the source has been modified from upstream.

Maintained by [Zainium Dynamics](https://zainiumdynamics.tech) for
Zainium OS.

## Changes from upstream

- **Zainium path fixes**: `pam_service_exists()`, the default
  `config.toml` search path, `os-release`/`issue` reads, and the
  fallback shell path all hardcoded real FHS paths (`/etc/...`,
  `/bin/sh`) that don't exist on Zainium (no real `/etc`, `/usr`, or
  `/bin` at the root — everything lives under `/overlayer/syshub`).
  Each now tries the real Zainium path first, falling back to the
  plain FHS path for portability on a real FHS host.
- **`pam-sys` removed**: replaced with a direct dependency on
  [`elevate-pam`](https://github.com/Zainium-Dynamics/elevate-privilege)'s
  own native Rust API (`PamBuilder`/`PamHandle`) instead of the C-ABI
  `pam-sys` crate, which dlopened/linked against whatever
  `libpam.so.0` happened to be on the runtime linker path.
  `pam/ffi.rs` and `pam/env.rs` are gone; `session/conv.rs`'s
  `SessionConv` now owns a duplicated socket fd instead of borrowing
  one, since elevate-pam's conversation API requires a `'static`
  converser.
- **`fakegreet` removed**: unused on Zainium.

All modified files retain their original GPL-3.0-only license.
