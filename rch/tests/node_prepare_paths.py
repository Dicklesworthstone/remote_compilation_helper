#!/usr/bin/env python3
"""Run the production preparation wrapper with real executable search paths.

Only rch-wkr and the compiler executables are fixtures. The shell, directory
changes, PATH resolution, stdin, argument passing and exit status are real.
No package-manager install, remote worker or Rust compilation is simulated as
passed. Test-owned files are retained. Cargo may provide the compiled script.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src/transfer/node_prepare.sh"
SHELL = os.environ.get("RCH_TEST_SHELL", "/bin/sh")


class PreparedTools(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-prepared-tools-")).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        self.tools = self.root / "worker-tools"
        self.tools.mkdir()
        self.env = dict(os.environ, PATH=str(self.tools) + ":/usr/bin:/bin",
                        RCH_TEST_PREPARE_LOG=str(self.root / "preparation.json"),
                        RCH_TEST_EXECUTED=str(self.root / "executed"),
                        RCH_TEST_PREPARE_EXIT="0")
        self.script = Path(os.environ.get("RCH_NODE_PREPARE_SCRIPT", SOURCE)).read_text()
        self.executable(self.tools / "rch-wkr", """
import json, os, sys
from pathlib import Path
Path(os.environ['RCH_TEST_PREPARE_LOG']).write_text(json.dumps({
    'args': sys.argv[1:], 'cwd': os.getcwd(), 'stdin': sys.stdin.buffer.read().hex()}))
print('fixture preparation diagnostic', flush=True)
sys.exit(int(os.environ['RCH_TEST_PREPARE_EXIT']))
""")
        self.compiler(self.tools, "global")

    @staticmethod
    def executable(path, body):
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o700)

    def compiler(self, directory, origin):
        directory.mkdir(parents=True, exist_ok=True)
        self.executable(directory / "tsc", """
import json, os, sys
from pathlib import Path
with Path(os.environ['RCH_TEST_EXECUTED']).open('a') as log:
    log.write(%r + '\\n')
print(json.dumps({'origin': %r, 'cwd': os.getcwd(), 'args': sys.argv[1:],
                  'stdin': sys.stdin.buffer.read().hex()}), flush=True)
sys.exit(7)
""" % (origin, origin))

    def package(self):
        (self.project / "package.json").write_text('{"name":"fixture","version":"1.0.0"}\n')

    def invoke(self, *, destination=None, arguments=(), data=b"", runtime="node", prefix=""):
        if destination is None:
            command = ["tsc", *arguments]
        else:
            command = [SHELL, "-c", 'cd "$1" || exit 93; shift; exec tsc "$@"',
                       "workload", str(destination), *arguments]
        return subprocess.run([SHELL, "-c", prefix + self.script, "rch-prepare", runtime, *command],
                              cwd=self.project, env=self.env, input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)

    def assert_tool(self, result, origin, *, args=(), data=b"", cwd=None):
        self.assertEqual(result.returncode, 7, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, {'origin': origin, 'cwd': str(cwd or self.project),
                                  'args': list(args), 'stdin': data.hex()})
        return report

    def test_changed_cwd_keeps_the_prepared_compiler_for_node_and_bun(self):
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        nested = self.project / "packages/app"
        self.compiler(nested / "node_modules/.bin", "different-package")
        for runtime in ("node", "bun"):
            with self.subTest(runtime=runtime):
                result = self.invoke(destination=nested, runtime=runtime)
                self.assert_tool(result, "prepared", cwd=nested)
                prepared = json.loads((self.root / "preparation.json").read_text())
                self.assertEqual(prepared, {'args': ['prepare', '--project', '.', '--runtime', runtime],
                                           'cwd': str(self.project), 'stdin': ''})
                self.assertIn(b"fixture preparation diagnostic", result.stderr)

    def test_directory_change_cannot_fall_back_to_global_compiler(self):
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        nested = self.project / "src"
        nested.mkdir()
        self.assert_tool(self.invoke(destination=nested), "prepared", cwd=nested)

    def test_special_path_bytes_and_literal_workload_arguments_survive(self):
        moved = self.root / "project with 'quotes' $literal\n\n"
        self.project.rename(moved)
        self.project = moved
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        nested = self.project / "nested"
        nested.mkdir()
        arguments = ("", "--project", "space 'quotes' $() ;", "line\nargument", "café")
        data = bytes(range(256)) * 64 + b"tail\x00\xff"
        result = self.invoke(destination=nested, arguments=arguments, data=data)
        self.assert_tool(result, "prepared", args=arguments, data=data, cwd=nested)

    def test_bin_directory_alias_uses_its_prepared_physical_directory(self):
        self.package()
        actual = self.root / "package-manager-store" / "bin\n\n"
        self.compiler(actual, "prepared-store")
        (self.project / "node_modules").mkdir()
        (self.project / "node_modules/.bin").symlink_to(actual, target_is_directory=True)
        nested = self.project / "nested"
        nested.mkdir()
        self.assert_tool(self.invoke(destination=nested), "prepared-store", cwd=nested)

    def test_ambient_pwd_and_cdpath_do_not_choose_tool_directory(self):
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        wrong = self.root / "ambient"
        self.compiler(wrong / "node_modules/.bin", "ambient")
        self.env.update(PWD=str(wrong), CDPATH=str(wrong))
        nested = self.project / "nested"
        nested.mkdir()
        self.assert_tool(self.invoke(destination=nested), "prepared", cwd=nested)

    def test_colon_path_refuses_instead_of_splitting_executable_search_roots(self):
        moved = self.root / "project:other"
        self.project.rename(moved)
        self.project = moved
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        result = self.invoke()
        self.assertEqual(result.returncode, 121, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"PATH separator", result.stderr)
        self.assertFalse((self.root / "executed").exists())

    def test_resolution_failure_starts_no_workload(self):
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        result = self.invoke(prefix="pwd() { return 19; }\n")
        self.assertEqual(result.returncode, 121, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"tool directory is unavailable", result.stderr)
        self.assertFalse((self.root / "executed").exists())

    def test_failed_preparation_does_not_run_any_compiler(self):
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        self.env['RCH_TEST_PREPARE_EXIT'] = '31'
        result = self.invoke()
        self.assertEqual(result.returncode, 121, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"preparation failed (exit 31)", result.stderr)
        self.assertFalse((self.root / "executed").exists())

    def test_without_package_manifest_original_path_is_preserved(self):
        self.compiler(self.project / "node_modules/.bin", "unprepared")
        self.assert_tool(self.invoke(), "global")
        self.assertFalse((self.root / "preparation.json").exists())

    def test_without_project_tools_existing_global_tool_still_works(self):
        self.package()
        data = b"unconsumed workload stdin"
        self.assert_tool(self.invoke(arguments=("--version",), data=data), "global",
                         args=("--version",), data=data)


if __name__ == '__main__':
    unittest.main(verbosity=2)
