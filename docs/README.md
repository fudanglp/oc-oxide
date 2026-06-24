# Documentation Index

Use this page as the map for current project documentation. Files in the root
of `docs/` describe the current codebase and operating model. Files under
`docs/archive/` are historical design records and implementation notes.

## Current Docs

- [ONBOARDING.md](ONBOARDING.md): contributor orientation, core direction,
  contribution boundaries, and tunnel-path references.
- [ARCHITECTURE.md](ARCHITECTURE.md): crate responsibilities, daemon/client
  split, runtime model, IPC shape, and recovery overview.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): privilege boundaries, polkit,
  keyring usage, non-secret profile rules, sync boundaries, and redaction
  requirements.
- [DEVELOPMENT.md](DEVELOPMENT.md): local build/test commands, development
  runtime options, real-VPN manual E2E checklist, and troubleshooting.
- [DISTRIBUTION.md](DISTRIBUTION.md): local distribution layout, tarball and
  Debian packaging, systemd install behavior, signing, apt repository metadata,
  updater metadata, and artifact verification.

## Archived Design Records

Archive files are useful when you need the rationale behind current behavior,
but they are not active implementation plans:

- [archive/IMPLEMENTATION_PLAN.md](archive/IMPLEMENTATION_PLAN.md)
- [archive/GITHUB_SYNC.md](archive/GITHUB_SYNC.md)
- [archive/ANYCONNECT_AUTH_AND_FAKE_IP_NOTES.md](archive/ANYCONNECT_AUTH_AND_FAKE_IP_NOTES.md)
- [archive/POLICY_MODE_DESIGN.md](archive/POLICY_MODE_DESIGN.md)
- [archive/TOML_PROFILE_AND_VAULT_PLAN.md](archive/TOML_PROFILE_AND_VAULT_PLAN.md)
