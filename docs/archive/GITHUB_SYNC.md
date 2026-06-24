# GitHub Profile Sync

This document records the public GitHub App configuration and the implementation
constraints for GitHub private repo profile synchronization.

The sync boundary is intentionally narrow: GitHub stores non-secret profile
configuration in a selected private repository. It is not a password manager and
must not receive VPN auth material.

## GitHub App

Public identifiers:

```toml
[github_app]
owner = "fudanglp"
app_id = 4125299
client_id = "Iv23lioGMVnzQNiz9AE5"
homepage = "https://oc-oxide.glp.ai"
privacy = "https://oc-oxide.glp.ai/privacy.html"
```

The App is owned by `@fudanglp`.

The desktop client should authenticate with GitHub App device flow using the
Client ID. Do not put a GitHub App private key in oc-oxide desktop binaries. Do
not require a client secret for the device-flow path.

Secrets that must not be committed or logged:

- GitHub client secret
- GitHub App private key
- webhook secret
- GitHub access token
- GitHub refresh token
- installation access token

## Permissions

The GitHub App should remain scoped to the selected sync repository.

Repository permissions:

```text
Contents: Read and write
Metadata: Read-only, if GitHub grants it implicitly
```

Everything else should stay at `No access` unless a later design document
justifies the additional permission.

Webhooks are not needed for the initial sync design and should stay disabled.

## Sync Repository

Current private sync repository:

```toml
[sync_repository]
owner = "fudanglp"
name = "oc-oxide-sync"
default_branch = "master"
visibility = "private"
url = "https://github.com/fudanglp/oc-oxide-sync"
```

The GitHub App installation should use `Only select repositories` and select
only `fudanglp/oc-oxide-sync`, not all repositories.

## Repository Layout

Target layout:

```text
README.md
manifest.json
profiles/
  <profile-id>.json
deleted/
  <profile-id>.json
```

`README.md` is a human warning file. Current application state belongs in the
JSON files. Older `.enc` files are ignored by the private-repo sync codec.

## Data Rules

Allowed in GitHub:

- non-secret profile configuration
- manifest data
- normal GitHub repository metadata such as commits, timestamps, and file names

Not allowed in GitHub sync:

- VPN passwords
- OTP values
- session cookies
- private keys
- client certificate passphrases
- router credentials
- daemon tokens
- temporary OpenConnect auth-form answers
- full local VPN profile files if they contain secret fields

Profile export must happen through the stable sync schema before upload. That
schema rejects passwords, OTP values, cookies, private keys, and unknown fields
that could carry secret material. The selected private GitHub repository is the
storage trust boundary.

## Token Storage

Store GitHub refresh tokens in the OS keyring only. The current keyring service
is `oc-oxide.github`, and the default account is `fudanglp:oc-oxide-sync`.
Access tokens can be kept in memory and refreshed as needed.

Do not store GitHub tokens in TOML profile files, repository files, logs, daemon
journals, diagnostics, screenshots, or test fixtures.

## Implementation Notes

The normal desktop flow should be:

```text
desktop app starts GitHub App device flow with Client ID
user approves in browser
desktop app stores refresh token in OS keyring
desktop app reads/writes sync objects in the selected private repo
local profile delete can explicitly upload a remote tombstone
same-name restore conflicts are imported as local copies instead of overwriting local profiles
```

Installation-token flows are intentionally excluded from the desktop client
because they require a GitHub App private key. If installation tokens are ever
needed, they must be brokered by a server-side component, not by the desktop
binary.

## Implementation Slices

### Slice 1: Sync Model

Status: complete.

Tasks:

- Add `oc-oxide-sync` to the workspace.
- Record public GitHub App constants and the selected private sync repository.
- Model application object paths only:

```text
manifest.json
profiles/<profile-id>.json
deleted/<profile-id>.json
```

- Define the decoded manifest model and private-repo storage mode.
- Add an injectable sync backend trait and a no-network in-memory backend for
  tests.
- Model GitHub Contents API optimistic concurrency through object SHA conflicts.

Tests:

- Public App and repository constants match the registered GitHub App.
- Sync paths reject non-JSON files and path traversal.
- Manifest entries point to profile JSON paths.
- Blob debug output redacts object bytes.
- The in-memory backend detects create/update/delete SHA conflicts without
  touching GitHub.

### Slice 2: Profile Codec

Status: complete.

Tasks:

- Define the codec boundary that turns a validated non-secret profile snapshot
  into repository JSON bytes.
- Use the private-repo JSON codec for all production sync paths.
- Reject secret-bearing profile snapshots before encoding.
- Keep profile secret-field rejection in `oc-oxide-config`.
- Keep fake/legacy encrypted codecs out of production sync paths. Production
  sync writes private-repo JSON through the stable non-secret schema.

Tests:

- Codec output is non-empty and never logged by debug output.
- Invalid or secret-bearing profile snapshots are rejected before encoding.
- Decoding rejects unknown plaintext fields such as passwords through the stable
  sync profile schema.
- Profile blob paths must match the decoded profile id.

### Slice 3: GitHub Device Flow

Status: complete.

Tasks:

- Add a developer CLI smoke command for GitHub App device flow:
  `ocx github-device-login [--no-store]`.
- Store refresh tokens in the OS keyring only. The smoke command stores the
  refresh token by default and uses `--no-store` only for throwaway testing.
- Keep access tokens in memory and never print them.
- Reuse the keyring-backed refresh token for sync commands, and only fall back
  to Device Flow when no refresh token exists or refresh fails.
- Store the rotated refresh token after each successful refresh response.
- Redact every token-like value from debug output and errors.
- Model Device Flow start, pending, slow-down, terminal, and token-success
  outcomes without requiring network access.
- Add redacted access/refresh token wrappers and an injectable refresh-token
  vault boundary.
- Add an injectable Device Flow HTTP boundary and a scripted no-network backend
  before introducing a real GitHub HTTP client.
- Add a real GitHub HTTP backend only in the developer CLI, leaving the sync
  crate transport-trait-based.

Tests:

- Device-flow state transitions are testable with injected HTTP responses.
- Scripted no-network HTTP tests cover pending, slow-down, authorized, invalid
  poll inputs, and exhausted scripts.
- GitHub JSON response parsing is covered with no-network fixtures.
- CLI argument parsing covers default keyring storage, `--no-store`, and
  unknown options.
- Token responses redact access and refresh token values.
- Expired access token refresh uses the keyring-backed refresh token without
  writing token material to profile files.
- Sync smoke/init commands prefer refresh-token auth when keyring storage is
  enabled, keeping access tokens in memory only.
- The no-network token vault can store, read, overwrite, and delete refresh
  tokens without leaking token values through debug output.

### Slice 4: GitHub Contents Backend

Status: complete.

Tasks:

- Implement a GitHub Contents API backend behind the sync backend trait.
- Read and write sync objects in `fudanglp/oc-oxide-sync`.
- Preserve SHA-based optimistic concurrency.
- Leave conflict resolution to higher-level profile sync orchestration.
- Keep the sync crate transport-trait-based; real HTTP clients can implement
  the `GithubContentsHttp` boundary without moving token handling into tests.
- Add a developer smoke command, `ocx github-sync-smoke [--no-store]`, that
  authenticates with Device Flow and reads `manifest.json` through the real
  GitHub API without writing repository content.
- Add `ocx github-sync-init [--no-store]` to create the initial empty
  `manifest.json`. It skips initialization if the manifest already exists.
- Add `ocx github-sync-reset [--no-store]` as a developer
  recovery command that overwrites the remote manifest with a new empty
  manifest.

Tests:

- HTTP tests cover read, create, update, delete, 404, 409, and authorization
  failures with no real GitHub token.
- Error types do not include token values or raw profile contents.
- Request debug output redacts JSON bodies so sync object bytes are not
  sprayed through diagnostics.
- Private repo codec tests round-trip manifest and profile payloads as JSON,
  while debug output redacts object bytes.
- CLI argument tests cover the read-only sync smoke command without touching
  GitHub.

### Slice 5: Profile Restore

Status: complete.

Tasks:

- Add a shared `download_profile_documents` core helper that reads the remote
  manifest and all referenced profile JSON objects.
- Add a desktop restore command that writes downloaded profiles into the local
  profile directory.
- Keep restore conservative: never overwrite same-name local profiles. Import
  same-name remote profiles as local copies with a `-remote` suffix.
- Render restored profiles through the same TOML writer used by local profile
  creation so restored files keep the same non-secret profile boundary.
- Add a Cloud Sync restore dialog next to upload.

Tests:

- No-network sync tests cover manifest/profile download and missing referenced
  profile objects.
- Desktop tests cover restoring a sync profile document back to local TOML
  without adding VPN passwords or other auth material.
- Frontend build verifies the restore dialog and operation state wiring.

## Current Sync State

The basic private-repo sync flow is implemented: sign in, refresh token from
keyring, initialize manifest, upload local non-secret profiles, and restore
remote profiles that do not already exist locally. Explicit delete/tombstone
behavior is also implemented: when a user opts into Cloud Sync tombstone upload
while deleting a local profile, the remote profile is removed from
`manifest.json`, a non-secret `deleted/<profile-id>.json` tombstone is written
or updated, and the old `profiles/<profile-id>.json` object is deleted when it
exists. Re-uploading a profile with the same id clears the matching tombstone.
The desktop also keeps a local non-secret `sync-history.json` under the
oc-oxide user config directory with recent operation summaries, manifest SHA,
manifest byte count, repository name, and timestamp.

No storage-foundation sync work is currently open in this document. Future
multi-device merge UX can still be improved if users need richer side-by-side
profile diffing beyond the current restore-as-copy behavior and actionable
upload conflict guidance.
