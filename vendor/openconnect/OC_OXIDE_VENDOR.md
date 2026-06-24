# OpenConnect Vendor Metadata

This directory contains a vendored copy of upstream OpenConnect source code.

## Upstream

- Project: OpenConnect VPN client
- Repository: `https://gitlab.com/openconnect/openconnect.git`
- Branch: `master`
- Commit: `237fc974b8ba6ac5dafd66d39f2fb1a9d021e483`
- Fetched: `2026-06-18`

## License

OpenConnect's public header and bundled license identify the library under the
GNU Lesser General Public License version 2.1. Keep upstream license files with
the vendored source.

## Local Policy

- Do not make oc-oxide-specific edits directly inside vendored upstream files.
- Put build integration, Rust bindings, and callback shims under
  `crates/oc-oxide-openconnect-sys`.
- If an upstream source patch becomes necessary, document it here and keep it as
  a small reviewable patch.
- When staging a full vendor update, use `git add -f vendor/openconnect` because
  upstream's own `.gitignore` ignores a few source-tree files.
- Do not store VPN credentials, OTP seeds, session cookies, private keys, or
  router credentials in this directory.
