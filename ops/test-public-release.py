"""Offline public-release tests. Filesystem transactions use root-owned temp fixtures."""
import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT/'yurich-panel.sh').read_text(encoding='utf-8')
NAMES = ('admin-bot-health.py', 'admin-bot-menu.py', 'admin-incidents.py', 'admin-monitor.py')
MANIFEST = dict((name, digest) for digest, name in re.findall(
    r'^([a-f0-9]{64})  (admin-[a-z-]+\.py)$', SOURCE, re.M))
ROOT_LINUX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0
spec = importlib.util.spec_from_file_location('public_monitor', ROOT/'ops/admin-monitor.py')
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class PackageTests(unittest.TestCase):
    def test_alias_version_and_sidecars(self):
        source = (ROOT/'yurich-panel.sh').read_bytes()
        self.assertEqual(source, (ROOT/'naiveproxy.sh').read_bytes())
        self.assertIn('VERSION="5.8.12"', SOURCE)
        self.assertNotIn(b'\r', source)
        for name in ('yurich-panel.sh', 'naiveproxy.sh'):
            self.assertEqual((ROOT/(name+'.sha256')).read_text().strip(),
                             hashlib.sha256(source).hexdigest()+'  '+name)

    def test_four_modules_are_complete_valid_and_hash_pinned(self):
        self.assertEqual(set(MANIFEST), set(NAMES))
        for name in NAMES:
            data = (ROOT/'ops'/name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), MANIFEST[name])
            ast.parse(data, filename=name)
        self.assertIn('naiveproxy/v${VERSION}/ops', SOURCE)
        body = SOURCE[SOURCE.index('install_bot_service()'):]
        self.assertIn('install_admin_bot_modules ||', body)
        self.assertIn('install_admin_bot_modules || return 1', SOURCE)

    def test_no_personal_infrastructure_in_runtime(self):
        for path in (ROOT/'yurich-panel.sh', *(ROOT/'ops'/name for name in NAMES)):
            text = path.read_text(encoding='utf-8')
            self.assertNotRegex(text, r'(?i)(go-it\.tech|dns-ai\.online|yurichconnect\.ru|dzen\.ru/|YC_connect_bot)')
            self.assertNotRegex(text, r'[A-Z]:[/\\](?:Users|Projects)[/\\]')
        self.assertIn('PROJECT_DONATION_URL="${YURICH_DONATION_URL:-}"', SOURCE)
        self.assertIn('${donation_button_html}', SOURCE)


class RegistryTests(unittest.TestCase):
    def registry(self, text):
        with patch.object(monitor, 'process', return_value=text):
            return monitor.registry()

    def test_local_domain_and_identity_come_from_config(self):
        rows = self.registry('primary\tmain.example.com\n')
        self.assertEqual(rows, [{'name': 'primary', 'local': True, 'domain': 'main.example.com'}])
        rows = self.registry('poland\tpoland.example.com\n')
        self.assertEqual(rows[0]['name'], 'poland')

    def test_all_enabled_countries_supported_and_disabled_skipped(self):
        rows = self.registry('primary\tmain.example.com\ngermany|203.0.113.8|22|proxyadmin|de.example.com|edge|1|1\n'
                             'disabled|203.0.113.9|22|proxyadmin|off.example.com|edge|1|0\n')
        self.assertEqual([row['name'] for row in rows], ['primary', 'germany'])

    def test_invalid_local_domain_and_duplicate_names_rejected(self):
        for text in ('', 'primary\t\n', 'bad/name\tmain.example.com\n',
                     'primary\tmain.example.com\nprimary|203.0.113.8|22|proxyadmin|node.example.com|edge|1|1\n'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                self.registry(text)


@unittest.skipUnless(ROOT_LINUX, 'Root Linux filesystem fixtures required')
class ModuleInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='yurich-public-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'ops'
        self.source.mkdir(mode=0o700)
        self.target = self.root/'runtime'
        self.target.mkdir(mode=0o700)
        for name in NAMES:
            shutil.copyfile(ROOT/'ops'/name, self.source/name)
        start = SOURCE.index('admin_modules_manifest()')
        end = SOURCE.index('\ninstall_bot_service()', start)
        self.launcher = self.root/'install.sh'
        self.launcher.write_text('set -euo pipefail\nVERSION=5.8.12\nADMIN_MODULES_DIR='+str(self.target)+'\n'
            +SOURCE[start:end]+'\ncurl() { return 99; }\ninstall_admin_bot_modules\n')

    def run_install(self):
        return subprocess.run(['bash', '--noprofile', '--norc', str(self.launcher)],
                              capture_output=True, timeout=20)

    def old_modules(self):
        for name in NAMES:
            (self.target/name).write_text('# previous release\n')
            (self.target/name).chmod(0o700)

    def assert_old(self):
        for name in NAMES:
            self.assertEqual((self.target/name).read_text(), '# previous release\n')

    def test_install_from_full_copy_without_network(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        for name in NAMES:
            self.assertEqual((self.target/name).read_bytes(), (self.source/name).read_bytes())
            self.assertEqual((self.target/name).stat().st_mode & 0o777, 0o700)

    def test_bad_hash_or_unavailable_download_preserves_all_old_modules(self):
        self.old_modules()
        (self.source/NAMES[-1]).write_text('# tampered\n')
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assert_old()

    def test_target_symlink_rejected_without_touching_other_file(self):
        outside = self.root/'unrelated'
        outside.write_text('keep')
        (self.target/NAMES[0]).symlink_to(outside)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(outside.read_text(), 'keep')

    def test_writable_destination_rejected(self):
        self.old_modules()
        self.target.chmod(0o777)
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assert_old()
        self.target.chmod(0o700)

    def test_lock_contention_preserves_old_modules(self):
        import fcntl
        self.old_modules()
        lock = self.target/'.module-install.lock'
        with lock.open('w') as stream:
            lock.chmod(0o600)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertNotEqual(self.run_install().returncode, 0)
        self.assert_old()

    def test_mid_transaction_failure_restores_all_previous_modules(self):
        self.old_modules()
        stage = self.root/'stage'
        stage.mkdir(mode=0o700)
        for name in NAMES:
            shutil.copyfile(self.source/name, stage/name)
        (stage/'manifest').write_text(''.join(MANIFEST[name]+'  '+name+'\n' for name in NAMES))
        start = SOURCE.index('import ast, fcntl, hashlib, os, shutil, stat, sys\n')
        program = SOURCE[start:SOURCE.index('\nPY\n', start)]
        original = os.replace
        def replace(source, destination):
            if Path(source) == stage/NAMES[2]:
                raise OSError('synthetic replace failure')
            return original(source, destination)
        with patch('sys.argv', ['fixture', str(stage), str(self.target)]), patch('os.replace', side_effect=replace):
            with self.assertRaises(OSError):
                exec(compile(program, '<module-transaction-fixture>', 'exec'), {})
        self.assert_old()


if __name__ == '__main__':
    unittest.main(verbosity=2)
