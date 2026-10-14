# Distribution

oc-oxide currently has Linux distribution helpers for local testing and early
release artifacts. These scripts package the Tauri desktop binary, the
privileged daemon, the `ocx` developer client, and the vendored
`libopenconnect` built from `vendor/openconnect`.

The package helpers do not store credentials, VPN cookies, GitHub tokens,
profile secrets, or router credentials. User profiles remain outside the
repository, under the normal user config directory by default.

## Ubuntu Compatibility

Build separately on Ubuntu 24.04 and 26.04. The bundled `libopenconnect`
links against the build system's libxml2 ABI: `libxml2.so.2` on 24.04 and
`libxml2.so.16` on 26.04. A 24.04 binary must not be assumed to work after
upgrading the operating system to 26.04.

| Build OS | Debian artifact | Tarball artifact |
| --- | --- | --- |
| Ubuntu 24.04 | `oc-oxide_<version>_<arch>.deb` | `oc-oxide-<version>-linux-<arch>.tar.gz` |
| Ubuntu 26.04 | `oc-oxide_<version>+ubuntu26.04_<arch>.deb` | `oc-oxide-<version>-linux-<arch>-ubuntu26.04.tar.gz` |

24.04 retains the legacy asset names for existing clients. The release
installer, desktop updater, and privileged update helper select artifacts
using the running system's `/etc/os-release`, including after an OS upgrade.
Older installed clients do not know these names; use the updated release
installer to migrate them to the 26.04 build. There is no fallback to the
24.04 artifact when the 26.04 artifact is missing.

The Debian package version on 26.04 includes `+ubuntu26.04`, allowing apt to
replace the 24.04 build at the same application version. Dependencies are
generated with `dpkg-shlibdeps` from the desktop, daemon, CLI, and bundled
library, including the correct libxml2 package and minimum library versions.
Builds require `dpkg-dev`, `python3`, and the native development dependencies
listed in `.github/workflows/release.yml`. Other Linux distributions still
require native builds and are outside this Ubuntu compatibility matrix.

Run `make package-deb` on the target Ubuntu release. The scripts detect the
host release; do not rename an artifact to claim compatibility with another
release. Cargo rebuilds the vendored C library when `/etc/os-release` changes,
and packaging selects the library from that Cargo invocation's metadata.
`SKIP_BUILD=1` requires a previous successful `make dist-local` (or packaging
build) on the same OS.

## Release Installer

The public one-line installer is published through GitHub Pages:

```sh
curl -LsSf https://oc-oxide.glp.ai/install.sh | sh
```

Install a specific release:

```sh
curl -LsSf https://oc-oxide.glp.ai/install.sh | sh -s -- --version v0.1.1
```

The script lives in `packaging/linux/install-release.sh`. The Pages workflow
publishes it as `site/install.sh`, and the release workflow uploads the same
script as a GitHub Release asset named `install.sh`.

The release installer:

- supports Linux `x86_64` and `aarch64`/`arm64`
- resolves the latest GitHub Release unless `--version` or
  `OC_OXIDE_VERSION` is set
- downloads the release artifact and its `.sha256` file
- verifies the checksum before installing
- prefers the Debian package on systems with `apt` and `dpkg`
- falls back to the tarball installer on other supported Linux systems
- supports `--method auto|deb|tarball` and `--dry-run`

It does not build from source, create profiles, or store secrets.

## Local Dist Layout

Build a local installable tree:

```sh
make dist-local
```

This produces:

```text
dist/oc-oxide-<version>-linux-<arch>/
```

The layout includes:

- `bin/` wrapper scripts for `oc-oxide`, `oc-oxide-daemon`, and `ocx`
- `libexec/oc-oxide/` release binaries
- `lib/libopenconnect.so*` from the vendored OpenConnect build
- `share/applications/com.github.fudanglp.oc-oxide.desktop`
- `share/icons/hicolor/<size>x<size>/apps/com.github.fudanglp.oc-oxide.png`
- `systemd/oc-oxide-daemon.service`
- `install.sh`
- `uninstall.sh`
- `SHA256SUMS`

The wrappers set `LD_LIBRARY_PATH` relative to the installed layout so the
bundled `libopenconnect` is used without requiring a system OpenConnect
installation.

## Tarball

Build a compressed archive:

```sh
make dist-tarball
```

This creates:

```text
dist/oc-oxide-<version>-linux-<arch>.tar.gz
dist/oc-oxide-<version>-linux-<arch>.tar.gz.sha256
```

To install from an extracted tarball:

```sh
sudo ./install.sh
```

The installer reloads systemd, enables the idle daemon service, and restarts it
when systemd is available.

To uninstall a tarball install:

```sh
sudo /usr/local/libexec/oc-oxide/uninstall.sh
```

You can also run `sudo ./uninstall.sh` from the extracted archive. The
uninstaller stops and disables the daemon, removes installed program files,
reloads systemd, and leaves user profiles, keyring entries, and system profiles
under `/etc/oc-oxide` in place.

For non-root smoke testing, install into a temporary prefix and skip systemd:

```sh
PREFIX=/tmp/oc-oxide-install-test SKIP_SYSTEMD=1 ./install.sh
/tmp/oc-oxide-install-test/bin/ocx help
```

## Debian Package

Build a Debian package:

```sh
make package-deb
```

This creates:

```text
dist/oc-oxide_<version>_<deb-arch>.deb
dist/oc-oxide_<version>_<deb-arch>.deb.sha256
```

The Debian package installs to system paths:

- `/etc/oc-oxide/profiles`
- `/usr/bin`
- `/usr/libexec/oc-oxide`
- `/usr/lib`
- `/usr/share/applications`
- `/usr/share/icons/hicolor/*/apps`
- `/usr/share/polkit-1/actions`
- `/usr/lib/systemd/system`

The package currently targets Linux desktop systems with GTK/WebKitGTK and
systemd.

Installing or upgrading the Debian package reloads systemd, enables the idle
`oc-oxide-daemon.service`, and restarts it so the running daemon matches the
installed binary. Starting or restarting the service does not connect a VPN
profile.

The packaged daemon can read VPN profile TOML files from
`/etc/oc-oxide/profiles` for CLI/system-profile workflows. The desktop app
sends the selected user's non-secret profile TOML over IPC when connecting, so
users do not need to copy desktop-managed profiles into `/etc`. Desktop and CLI
clients do not need Unix group membership; the daemon authorizes socket clients
through polkit action `com.github.fudanglp.oc-oxide.control`. The default
policy allows the active local desktop session without an extra password prompt,
while inactive or non-local sessions still require admin authorization.

On `apt remove oc-oxide` or `dpkg -r oc-oxide`, the Debian `prerm` script stops
and disables `oc-oxide-daemon.service`. The `postrm` script reloads systemd,
resets failed service state, and refreshes the desktop database when available.
Package-owned files are removed by dpkg.

On `apt purge oc-oxide`, `postrm purge` also removes `/etc/oc-oxide/profiles`
and `/etc/oc-oxide` only if those directories are empty. User-created system
profiles are intentionally preserved. User config profiles and OS keyring
entries are outside the Debian package and are not removed.

## Release Version

`version.yml` is the single human-edited release version source. Before
building or tagging a release, update `version.yml` and run:

```sh
make sync-version
```

The sync target propagates the version to Cargo, npm, and Tauri manifests. It
lets Cargo and npm update their own lockfiles, so release bumps should not
manually edit `Cargo.lock` or `apps/desktop/package-lock.json`.

## GitHub Release Workflow

.github/workflows/release.yml builds in separate `ubuntu:24.04` and
`ubuntu:26.04` containers on an `ubuntu-24.04` runner. Cargo caches are isolated
by Ubuntu release. Each job runs Rust and installer-selection tests, builds
the package, installs it, checks runtime libraries, and starts an idle daemon
to verify socket creation. A separate publish job waits for both builds.

The workflow runs for pushes and pull requests to `master`, or manually with
`workflow_dispatch`. These runs build and verify artifacts, then upload them
as workflow artifacts without creating a release.

Pushing a tag matching `v*` runs the same build and verification steps, then
creates a GitHub Release for that tag with:

- `install.sh`
- `install.sh.sha256`
- `oc-oxide-<version>-linux-<arch>.tar.gz`
- `oc-oxide-<version>-linux-<arch>.tar.gz.sha256`
- `oc-oxide_<version>_<deb-arch>.deb`
- `oc-oxide_<version>_<deb-arch>.deb.sha256`
- the corresponding `+ubuntu26.04` Debian and `-ubuntu26.04` tarball artifacts

The workflow generates an apt archive for each Ubuntu release. Signing and
optional updater metadata require the corresponding signing/update secrets.
It does not publish an apt server.

## Signing

Detached ASCII signatures can be generated for release artifacts:

```sh
make sign-artifacts
```

This runs `packaging/linux/sign-artifacts.sh`, which signs tarballs, Debian
packages, checksum files, `latest.json`, and the apt repository tarball when
they exist. Set `SIGNING_KEY=<gpg-key-id>` to select a specific local GPG key.

In GitHub Actions, add these secrets to enable signing:

- `RELEASE_GPG_PRIVATE_KEY`: ASCII-armored private key imported only during the
  release job
- `RELEASE_GPG_KEY_ID`: optional key id passed to `gpg --local-user`

The repository does not store private signing keys.

## Apt Repository

Build flat apt repository metadata from the generated Debian package:

```sh
make apt-repo
```

This creates:

```text
dist/apt/
  dists/stable/Release
  dists/stable/InRelease            # when SIGNING_KEY is set
  dists/stable/Release.gpg          # when SIGNING_KEY is set
  dists/stable/main/binary-<arch>/Packages
  dists/stable/main/binary-<arch>/Packages.gz
  pool/main/o/oc-oxide/*.deb
```

The release workflow also archives this tree as
`dist/oc-oxide-apt-repo-ubuntu<release>.tar.gz` with a `.sha256` file so it can be attached to a
GitHub Release or published to static hosting. Keep the two Ubuntu repository
archives at separate URLs; their packages target different system ABIs.

## Updater Metadata

Generate a Tauri updater `latest.json` feed:

```sh
TAURI_UPDATE_URL=https://example.invalid/oc-oxide.tar.gz \
TAURI_UPDATE_SIGNATURE=<tauri-signature> \
make updater-json
```

The script writes `dist/latest.json`. It requires a real Tauri updater
signature through `TAURI_UPDATE_SIGNATURE` or `TAURI_UPDATE_SIGNATURE_FILE`; it
does not invent a signature. In GitHub Actions, set `TAURI_UPDATE_SIGNATURE` for the 24.04 tarball and
`TAURI_UPDATE_SIGNATURE_UBUNTU26` for the distinct 26.04 tarball to emit
`latest.json` and `latest-ubuntu26.04.json`, respectively, for tag builds. The latter uses the target `linux-<arch>-ubuntu26.04`. The file is included in workflow artifacts
and GitHub Release assets when generated.

The desktop app also has a system-package update path for Linux installs. It
checks the GitHub Releases `latest` redirect in the background after startup,
avoiding the GitHub REST API rate limit. The Settings view can explicitly
check, download, verify, and install a release artifact. The desktop process
downloads the matching `.deb` or tarball into the user's XDG cache directory
and verifies the release `.sha256` before requesting elevated installation.

The elevated installer is intentionally small:

```text
/usr/libexec/oc-oxide/oc-oxide-update
/usr/local/libexec/oc-oxide/oc-oxide-update
```

It accepts only an app-generated install manifest, performs final root-side
validation of the version, architecture, artifact name, and sha256 digest, then
installs the package. It does not download files or relaunch the desktop UI.
After a successful install, the desktop app requests its own relaunch.

The packaged polkit file includes a dedicated update action:

```text
com.github.fudanglp.oc-oxide.update
com.github.fudanglp.oc-oxide.update-local
```

These actions are separate from daemon connection control and require admin
authorization.

## Verification

Installer/update platform-selection tests (no installation or network access):

```sh
python3 packaging/linux/test_release_platform.py
```

In a disposable Ubuntu environment, run the install/socket smoke test as root:

```sh
./packaging/linux/smoke-test.sh /path/to/oc-oxide_<version>_<arch>.deb
```

The artifact examples below use 24.04 names; append the 26.04 suffixes from
the compatibility table when testing a 26.04 build.

Useful local checks:

```sh
make dist-local
dist/oc-oxide-<version>-linux-<arch>/bin/ocx help
cd dist/oc-oxide-<version>-linux-<arch> && sha256sum -c SHA256SUMS
```

For tarballs:

```sh
sha256sum -c dist/oc-oxide-<version>-linux-<arch>.tar.gz.sha256
tar -tzf dist/oc-oxide-<version>-linux-<arch>.tar.gz
```

For Debian packages:

```sh
sha256sum -c dist/oc-oxide_<version>_<deb-arch>.deb.sha256
dpkg-deb --info dist/oc-oxide_<version>_<deb-arch>.deb
dpkg-deb --contents dist/oc-oxide_<version>_<deb-arch>.deb
```

For signing, apt repository, and updater metadata:

```sh
sh -n packaging/linux/sign-artifacts.sh
sh -n packaging/linux/build-apt-repo.sh
sh -n packaging/linux/generate-updater-json.sh
sh -n packaging/linux/install-release.sh
sh -n packaging/linux/install.sh
sh -n packaging/linux/uninstall.sh
python3 -m json.tool dist/latest.json
```

Generated artifacts in `dist/` and temporary packaging state under
`target/package/` should be cleaned after verification unless they are being
handed off deliberately.
