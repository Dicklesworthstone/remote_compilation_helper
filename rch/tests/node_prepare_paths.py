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
print('fixture preparation diagnostic', file=sys.stderr, flush=True)
if 'RCH_TEST_PREPARE_RESPONSE_HEX' in os.environ:
    sys.stdout.buffer.write(bytes.fromhex(os.environ['RCH_TEST_PREPARE_RESPONSE_HEX']))
elif sys.argv[1] == 'prepare-proof':
    print('RCH_PREPARED_DEPENDENCIES_VERIFIED', flush=True)
else:
    marker = 'RCH_PREPARED_NODE_MODULES'
    if '--workspace-root' in sys.argv:
        marker += ':' + os.environ.get('RCH_TEST_PREPARE_ROOT_PARENTS', '0')
    print(marker, flush=True)
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

    def invoke(self, *, destination=None, arguments=(), data=b"", runtime="node", prefix="",
               proof_root=None, boundary=None):
        if destination is None:
            command = ["tsc", *arguments]
        else:
            command = [SHELL, "-c", 'cd "$1" || exit 93; shift; exec tsc "$@"',
                       "workload", str(destination), *arguments]
        proof = ([] if proof_root is None else
                 ["--source-proof", "a" * 64, "b" * 64, "--preparation-root", str(proof_root)])
        scope = [] if boundary is None else ["--preparation-boundary", str(boundary)]
        return subprocess.run([SHELL, "-c", prefix + self.script, "rch-prepare", runtime, *scope, *proof, *command],
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
                self.assertEqual(prepared, {'args': ['prepare', '--project', '.', '--runtime', runtime,
                                                    '--execution-layout', '--workspace-root'],
                                           'cwd': str(self.project), 'stdin': ''})
                self.assertIn(b"fixture preparation diagnostic", result.stderr)

    def test_directory_change_cannot_fall_back_to_global_compiler(self):
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        nested = self.project / "src"
        nested.mkdir()
        self.assert_tool(self.invoke(destination=nested), "prepared", cwd=nested)

    def workspace_member(self):
        workspace = self.root / "workspace with 'quotes' $literal"
        self.project.rename(workspace)
        (workspace / "package.json").write_text('{"workspaces":["packages/*"]}\n')
        self.project = workspace / "packages/app"
        self.project.mkdir(parents=True)
        self.package()
        return workspace

    def test_workspace_hoisted_tools_keep_member_cwd_arguments_and_binary_stdin(self):
        workspace = self.workspace_member()
        self.compiler(workspace / "node_modules/.bin", "workspace")
        nested = self.project / "src"
        nested.mkdir()
        arguments = ("", "--project", "space 'quotes' $() ;", "café")
        data = bytes(range(256)) * 64 + b"tail\x00\xff"
        for runtime in ("node", "bun"):
            with self.subTest(runtime=runtime):
                result = self.invoke(destination=nested, arguments=arguments, data=data,
                                     runtime=runtime, proof_root=workspace)
                self.assert_tool(result, "workspace", args=arguments, data=data, cwd=nested)
                prepared = json.loads((self.root / "preparation.json").read_text())
                self.assertEqual(prepared, {
                    'args': ['prepare-proof', '--mode', 'verify', '--project', str(workspace),
                             '--runtime', runtime, '--expected-request-digest', 'a' * 64,
                             '--expected-attestation-digest', 'b' * 64,
                             '--invocation-project', '.'],
                    'cwd': str(self.project), 'stdin': '',
                })

    def test_workspace_member_tools_precede_hoisted_and_global_tools(self):
        workspace = self.workspace_member()
        self.compiler(workspace / "node_modules/.bin", "workspace")
        self.compiler(self.project / "node_modules/.bin", "member")
        self.assert_tool(self.invoke(proof_root=workspace), "member")
        # Absolute entries continue selecting the same prepared member tools.
        self.assert_tool(self.invoke(destination=workspace, proof_root=workspace),
                         "member", cwd=workspace)

    def test_normal_workspace_preparation_serves_hoisted_tools_without_changing_cwd(self):
        workspace = self.workspace_member()
        self.env['RCH_TEST_PREPARE_ROOT_PARENTS'] = '2'
        self.compiler(workspace / "node_modules/.bin", "workspace")
        data = bytes(range(256)) + b"tail\x00\xff"
        arguments = ("--project", "member config 'literal' $.json")
        self.assert_tool(self.invoke(arguments=arguments, data=data), "workspace",
                         args=arguments, data=data)
        prepared = json.loads((self.root / "preparation.json").read_text())
        self.assertEqual(prepared['cwd'], str(self.project))
        self.assertEqual(prepared['stdin'], '')
        self.assertEqual(prepared['args'], ['prepare', '--project', '.', '--runtime', 'node',
                                           '--execution-layout', '--workspace-root'])
        self.compiler(self.project / "node_modules/.bin", "member")
        self.assert_tool(self.invoke(destination=workspace), "member", cwd=workspace)

    def test_malformed_workspace_selectors_never_authorize_execution(self):
        self.package()
        self.compiler(self.project / "node_modules/.bin", "prepared")
        for response in [b'RCH_PREPARED_NODE_MODULES:65\n', b'RCH_PREPARED_NODE_MODULES:-1\n',
                         b'RCH_PREPARED_NODE_MODULES:00\n', b'RCH_PREPARED_NODE_MODULES:0\n\n',
                         b'RCH_PREPARED_NODE_MODULES:0\x00\n',
                         b'RCH_PREPARED_NODE_MODULES:0\nRCH_PREPARE_STATUS:0',
                         b'RCH_PREPARED_NODE_MODULES:0\n' + b'x' * 300]:
            with self.subTest(response=response):
                self.env['RCH_TEST_PREPARE_RESPONSE_HEX'] = response.hex()
                result = self.invoke()
                self.assertEqual(result.returncode, 121, result.stderr)
                self.assertEqual(result.stdout, b'')
                self.assertFalse((self.root / 'executed').exists())

    def test_bounded_normal_subdirectory_uses_intermediate_member_tools(self):
        workspace = self.workspace_member()
        self.compiler(workspace / "node_modules/.bin", "workspace")
        self.compiler(self.project / "node_modules/.bin", "member")
        self.project = self.project / "src"
        self.project.mkdir()
        self.env['RCH_TEST_PREPARE_ROOT_PARENTS'] = '3'
        data = b'member cwd input\x00\xff'
        self.assert_tool(self.invoke(boundary=workspace, data=data), "member", data=data)
        prepared = json.loads((self.root / "preparation.json").read_text())
        self.assertEqual(prepared['cwd'], str(self.project))
        self.assertEqual(prepared['args'][-2:], ['--preparation-boundary', str(workspace)])

    def test_failed_workspace_proof_never_runs_a_hoisted_tool(self):
        workspace = self.workspace_member()
        self.compiler(workspace / "node_modules/.bin", "workspace")
        self.env["RCH_TEST_PREPARE_EXIT"] = "73"
        result = self.invoke(proof_root=workspace)
        self.assertEqual(result.returncode, 121, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse((self.root / "executed").exists())
        prepared = json.loads((self.root / "preparation.json").read_text())
        self.assertEqual(prepared["args"][0], "prepare-proof")
        self.assertEqual(prepared["args"][4], str(workspace))
        self.assertIn(b"the command was not run", result.stderr)

    def test_relative_workspace_root_is_refused_before_verification(self):
        self.workspace_member()
        result = self.invoke(proof_root="../..")
        self.assertEqual(result.returncode, 121, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse((self.root / "preparation.json").exists())
        self.assertFalse((self.root / "executed").exists())

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
        self.assertIn(b"preparation failed or returned an unknown layout", result.stderr)
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
