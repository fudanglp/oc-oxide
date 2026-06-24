SHELL := /bin/sh

CARGO ?= cargo
NPM ?= npm
SUDO ?= sudo

DESKTOP_DIR := apps/desktop
DAEMON_BIN := target/debug/oc-oxide-daemon
OCX_BIN := target/debug/ocx

SOCKET ?= /tmp/oc-oxide-daemon.sock
PROFILE ?= office
PROFILE_DIR ?= $(HOME)/.config/oc-oxide/profiles

.PHONY: help
help:
	@printf '%s\n' 'oc-oxide development targets:'
	@printf '%s\n' ''
	@printf '%s\n' '  make build              Build Rust workspace and desktop frontend'
	@printf '%s\n' '  make build-rust         Build the Rust workspace'
	@printf '%s\n' '  make build-app          Build the desktop frontend'
	@printf '%s\n' '  make package            Build the Tauri desktop package'
	@printf '%s\n' '  make package-no-bundle  Build the Tauri app without OS bundles'
	@printf '%s\n' '  make dist-local         Build a local Linux dist layout'
	@printf '%s\n' '  make dist-tarball       Build a Linux tarball from the local dist layout'
	@printf '%s\n' '  make package-deb        Build a Debian package from the local dist layout'
	@printf '%s\n' '  make sign-artifacts     GPG-sign dist artifacts'
	@printf '%s\n' '  make apt-repo           Build flat apt repository metadata'
	@printf '%s\n' '  make updater-json       Generate Tauri updater latest.json'
	@printf '%s\n' '  make check              Run Rust checks and frontend type/build checks'
	@printf '%s\n' '  make test               Run Rust workspace tests'
	@printf '%s\n' '  make fmt                Format Rust code'
	@printf '%s\n' '  make daemon             Build and start the privileged daemon'
	@printf '%s\n' '  make app                Start the Tauri desktop app'
	@printf '%s\n' '  make app-web            Start the Vite web frontend only'
	@printf '%s\n' '  make status             Query daemon status with ocx'
	@printf '%s\n' '  make diagnostics        Query daemon diagnostics with ocx'
	@printf '%s\n' '  make connect            Connect PROFILE=office through ocx'
	@printf '%s\n' '  make disconnect         Disconnect through ocx'
	@printf '%s\n' ''
	@printf '%s\n' 'Variables: PROFILE=office PROFILE_DIR=$$HOME/.config/oc-oxide/profiles SOCKET=/tmp/oc-oxide-daemon.sock SUDO=sudo'

.PHONY: build
build: build-rust build-app

.PHONY: build-rust
build-rust:
	$(CARGO) build --workspace

.PHONY: build-app
build-app:
	cd $(DESKTOP_DIR) && $(NPM) run build

.PHONY: package
package:
	cd $(DESKTOP_DIR) && $(NPM) run tauri -- build

.PHONY: package-no-bundle
package-no-bundle:
	cd $(DESKTOP_DIR) && $(NPM) run tauri -- build --no-bundle

.PHONY: dist-local
dist-local:
	./packaging/dist-local.sh

.PHONY: dist-tarball
dist-tarball:
	./packaging/linux/build-tarball.sh

.PHONY: package-deb
package-deb:
	./packaging/linux/build-deb.sh

.PHONY: sign-artifacts
sign-artifacts:
	./packaging/linux/sign-artifacts.sh

.PHONY: apt-repo
apt-repo:
	./packaging/linux/build-apt-repo.sh

.PHONY: updater-json
updater-json:
	./packaging/linux/generate-updater-json.sh

.PHONY: check
check:
	$(CARGO) check --workspace
	cd $(DESKTOP_DIR) && $(NPM) run build

.PHONY: test
test:
	$(CARGO) test --workspace

.PHONY: fmt
fmt:
	$(CARGO) fmt --all

.PHONY: daemon
daemon: build-rust
	$(SUDO) env OC_OXIDE_DAEMON_SOCKET="$(SOCKET)" OC_OXIDE_PROFILE_DIR="$(PROFILE_DIR)" $(DAEMON_BIN) serve

.PHONY: app
app:
	cd $(DESKTOP_DIR) && OC_OXIDE_DAEMON_SOCKET="$(SOCKET)" OC_OXIDE_PROFILE_DIR="$(PROFILE_DIR)" $(NPM) run tauri -- dev

.PHONY: app-web
app-web:
	cd $(DESKTOP_DIR) && OC_OXIDE_DAEMON_SOCKET="$(SOCKET)" OC_OXIDE_PROFILE_DIR="$(PROFILE_DIR)" $(NPM) run dev

.PHONY: status
status: build-rust
	OC_OXIDE_DAEMON_SOCKET="$(SOCKET)" $(OCX_BIN) status

.PHONY: diagnostics
diagnostics: build-rust
	OC_OXIDE_DAEMON_SOCKET="$(SOCKET)" $(OCX_BIN) diagnostics

.PHONY: connect
connect: build-rust
	OC_OXIDE_DAEMON_SOCKET="$(SOCKET)" OC_OXIDE_PROFILE_DIR="$(PROFILE_DIR)" $(OCX_BIN) connect "$(PROFILE)"

.PHONY: disconnect
disconnect: build-rust
	OC_OXIDE_DAEMON_SOCKET="$(SOCKET)" $(OCX_BIN) disconnect

.PHONY: clean
clean:
	$(CARGO) clean
	cd $(DESKTOP_DIR) && rm -rf dist
