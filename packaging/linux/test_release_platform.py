"""Exercise installer selection and root helper validation without installing."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PACKAGING = Path(__file__).resolve().parent


class ReleasePlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.os_release = self.root / "os-release"
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        self.command("id", "#!/bin/sh\necho 0\n")
        self.command("apt", f"#!/bin/sh\nprintf '%s\\n' \"$*\" > '{self.root}/apt-called'\n")
        self.command("curl", r"""#!/usr/bin/env python3
import hashlib
from pathlib import Path
import sys
args = sys.argv[1:]
name = args[-1].rsplit('/', 1)[-1]
payload = b'fixture package'
if name.endswith('.sha256'):
    payload = (hashlib.sha256(payload).hexdigest() + '  ' + name[:-7] + '\n').encode()
Path(args[args.index('-o') + 1]).write_bytes(payload)
""")

    def command(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def platform(self, release, arch="x86_64"):
        self.os_release.write_text(f'ID=ubuntu\nVERSION_ID="{release}"\nVERSION="test"\n')
        self.command("uname", f'#!/bin/sh\ncase "$1" in -s) echo Linux;; *) echo {arch};; esac\n')

    def run_script(self, name, *args):
        # Substitute only in this disposable test copy, never add a root-side
        # environment override for the host OS in the production helper.
        script = self.root / name
        script.write_text((PACKAGING / name).read_text().replace(
            "/etc/os-release", str(self.os_release)))
        return subprocess.run(["sh", str(script), *args], env=self.env,
                              capture_output=True, text=True)

    def test_installer_selects_native_artifacts(self):
        for release, suffix, deb_suffix in [("24.04", "", ""),
                ("26.04", "-ubuntu26.04", "+ubuntu26.04")]:
            for arch, deb_arch in [("x86_64", "amd64"), ("aarch64", "arm64")]:
                self.platform(release, arch)
                for method, name in [
                    ("deb", f"oc-oxide_0.1.3{deb_suffix}_{deb_arch}.deb"),
                    ("tarball", f"oc-oxide-0.1.3-linux-{arch}{suffix}.tar.gz")]:
                    with self.subTest(release=release, arch=arch, method=method):
                        result = self.run_script("install-release.sh", "--version", "v0.1.3",
                                                 "--method", method, "--dry-run")
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn(name, result.stdout)
                        self.assertFalse((self.root / "apt-called").exists())

    def test_unknown_ubuntu_is_rejected(self):
        self.platform("28.04")
        result = self.run_script("install-release.sh", "--version", "v0.1.3", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported Ubuntu", result.stderr)

    def test_update_helper_rejects_wrong_abi_after_os_upgrade(self):
        for release, suffix in [("24.04", ""), ("26.04", "+ubuntu26.04")]:
            self.platform(release)
            for artifact_suffix in ["", "+ubuntu26.04"]:
                with self.subTest(release=release, artifact_suffix=artifact_suffix):
                    called = self.root / "apt-called"
                    called.unlink(missing_ok=True)
                    artifact = self.root / f"oc-oxide_0.1.3{artifact_suffix}_amd64.deb"
                    artifact.write_bytes(b"fixture package")
                    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                    sha = artifact.with_name(artifact.name + ".sha256")
                    sha.write_text(f"{digest}  {artifact.name}\n")
                    manifest = self.root / "manifest.json"
                    manifest.write_text(json.dumps(dict(version="v0.1.3", method="deb",
                        artifact=str(artifact), sha256=str(sha), expectedSha256=digest), indent=2))
                    result = self.run_script("oc-oxide-update.sh", "install", "--manifest", str(manifest))
                    if artifact_suffix == suffix:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertTrue(called.exists())
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("unexpected artifact name", result.stderr)
                        self.assertFalse(called.exists())

    def test_build_detection_preserves_requested_version(self):
        self.platform("26.04")
        script = (PACKAGING / "platform.sh").read_text().replace("/etc/os-release", str(self.os_release))
        result = subprocess.run(["sh", "-c", 'VERSION=0.1.3\n' + script +
            '\nprintf "%s %s %s" "$VERSION" "$PLATFORM_SUFFIX" "$DEB_VERSION_SUFFIX"'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "0.1.3 -ubuntu26.04 +ubuntu26.04")


if __name__ == "__main__":
    unittest.main()
