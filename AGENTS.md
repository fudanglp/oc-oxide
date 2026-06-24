# oc-oxide Codex Notes

This repo is for a Rust/Tauri OpenConnect helper.

## Hard Direction

- Use `libopenconnect` directly through Rust FFI from the first implementation.
- Do not implement an intermediate wrapper around the external `openconnect` CLI.
- Do not reimplement AnyConnect/CSTP/DTLS in Rust.
- Do not store passwords, OTP values, cookies, private keys, or router credentials in repo files.

## Reference Material

Use repository references before searching elsewhere:

- `vendor/openconnect`: vendored upstream OpenConnect source used for oc-oxide builds and distribution.
- `vendor/openconnect/openconnect.h`: public `libopenconnect` API.
- `vendor/openconnect/main.c`: OpenConnect CLI flow reference for FFI ordering.
- `vendor/openconnect/auth.c`: auth form handling reference.
- `vendor/openconnect/script.c`: server-pushed config to environment mapping.

## Project Docs

Read these first:

- `docs/README.md`
- `docs/ONBOARDING.md`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY_MODEL.md`
- `docs/DEVELOPMENT.md`
- `docs/DISTRIBUTION.md`

Use these for historical design context when relevant:

- `docs/archive/IMPLEMENTATION_PLAN.md`
- `docs/archive/GITHUB_SYNC.md`
- `docs/archive/ANYCONNECT_AUTH_AND_FAKE_IP_NOTES.md`

## Implementation Bias

- Treat `vendor/openconnect` as upstream-owned source. Do not make oc-oxide-specific edits there unless a patch is explicitly documented.
- Keep `libopenconnect` calls on one tunnel thread unless proven safe otherwise.
- Use typed Rust events for progress/auth/status.
- Keep privileged route/DNS work in a daemon/helper, not in the Tauri UI process.
- Make route/DNS changes reversible and testable.
- Treat OpenClash fake-ip routing as a first-class policy, not a one-off shell hack.

## Commit Messages

- Write commit messages with a clear subject and a useful body.
- Do not use a subject-only commit unless the change is truly mechanical and obvious.
- The body should explain what changed, why it changed, and how it was verified.
- Mention notable constraints or exclusions, such as avoiding secrets, avoiding the external `openconnect` CLI wrapper, or limiting a commit to one milestone.
