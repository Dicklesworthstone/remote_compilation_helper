#!/usr/bin/env python3
"""Real Yarn Berry PnP preparation, ownership and compiler execution.

Run with the compiled worker as the first argument. This suite never downloads
packages: provide RCH_TEST_YARN_JS (the official @yarnpkg/cli-dist 4.18.1
bin/yarn.js), RCH_TEST_TYPESCRIPT_ARCHIVE (the official typescript 5.9.3 tgz),
and optionally RCH_TEST_NODE. Both package artifacts are checked against their
published-download hashes used to qualify this fixture. All installs run with
YARN_ENABLE_NETWORK=0 and a private home; no machine package manager is changed.

The actual worker supervises Yarn, publishes and verifies output ownership, and
the shipped shell wrapper invokes the actual TypeScript binary. This is local
Linux qualification, not an SSH/fleet or arbitrary Yarn-plugin qualification.
Fixtures and command logs are retained. BLAKE3 uses prepare_outputs.py's real
compiled helper; RCH_TEST_BLAKE3 can name an existing stdin-to-hex executable.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "rch_prepared_outputs", Path(__file__).with_name("prepare_outputs.py")
)
prepared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepared)
WORKER = prepared.fixture.WORKER
REPOSITORY = Path(__file__).resolve().parents[2]
WRAPPER = REPOSITORY / "rch/src/transfer/node_prepare.sh"
YARN_SHA256 = "a28ad591febb769f939c11f82f89bacad0b0fac0c884d3b78fa2aaaee970907e"
TYPESCRIPT_SHA256 = "10e108c9cf7d5f2879053dff18515fb405abf2ccef63eaaf017d9c571687a1d3"


class RealYarnPnp(unittest.TestCase):
    # Reuse the protocol fixture's request construction, not a substitute
    # transaction, source barrier, output scanner or proof implementation.
    request = prepared.PreparedOutputs.request

    @classmethod
    def setUpClass(cls):
        cls.node = Path(os.environ.get("RCH_TEST_NODE") or shutil.which("node") or "")
        cls.yarn = Path(os.environ.get("RCH_TEST_YARN_JS", ""))
        cls.typescript = Path(os.environ.get("RCH_TEST_TYPESCRIPT_ARCHIVE", ""))
        for path, digest, label in (
            (cls.yarn, YARN_SHA256, "RCH_TEST_YARN_JS"),
            (cls.typescript, TYPESCRIPT_SHA256, "RCH_TEST_TYPESCRIPT_ARCHIVE"),
        ):
            if not path.is_file():
                raise RuntimeError(f"{label} must name the pinned authentic package artifact")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError(f"{label} does not match the qualified artifact SHA-256")
        if not cls.node.is_file():
            raise RuntimeError("RCH_TEST_NODE or PATH must provide Node")
        cls.node = cls.node.resolve()
        cls.yarn = cls.yarn.resolve()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="rch-real-yarn-pnp-"))
        self.home = self.root / "home"
        self.bin = self.root / "bin"
        self.home.mkdir()
        self.bin.mkdir()
        (self.bin / "yarn").write_text(
            "#!/bin/sh\nexec " + shlex.quote(str(self.node)) + " "
            + shlex.quote(str(self.yarn)) + ' "$@"\n'
        )
        (self.bin / "yarn").chmod(0o755)
        (self.bin / "rch-wkr").symlink_to(WORKER)
        self.global_tsc = self.root / "global-tsc-ran"
        self.script_tsc = self.root / "script-tsc-ran"
        (self.bin / "tsc").write_text(
            "#!/bin/sh\nprintf global > " + shlex.quote(str(self.global_tsc)) + "\nexit 94\n"
        )
        (self.bin / "tsc").chmod(0o755)
        self.env = {
            "PATH": os.pathsep.join((str(self.bin), str(self.node.parent), "/usr/bin", "/bin")),
            "HOME": str(self.home), "LANG": "C.UTF-8", "CI": "1",
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_DATA_HOME": str(self.home / ".local/share"),
            "XDG_STATE_HOME": str(self.home / ".local/state"),
            "YARN_GLOBAL_FOLDER": str(self.root / "yarn-global"),
            "YARN_ENABLE_NETWORK": "0", "YARN_ENABLE_TELEMETRY": "0",
            "YARN_ENABLE_IMMUTABLE_INSTALLS": "0", "TOKIO_WORKER_THREADS": "2",
            "RCH_PREPARE_INSTALL_TIMEOUT_SECS": "60",
        }
        self.command_number = 0
        version = self.invoke(["yarn", "--version"], self.root)
        self.assertEqual(version.stdout, b"4.18.1\n")
        print(f"\nretained real-Yarn fixture: {self.root}", flush=True)

    def invoke(self, argv, cwd, *, data=None, expected=0, env=None):
        self.command_number += 1
        result = subprocess.run(
            list(map(str, argv)), cwd=cwd, env=self.env if env is None else env,
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90,
        )
        prefix = self.root / f"command-{self.command_number:03}"
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        prefix.with_suffix(".json").write_text(json.dumps({
            "argv": list(map(str, argv)), "cwd": str(cwd), "status": result.returncode,
        }, indent=2))
        if expected is not None:
            self.assertEqual(result.returncode, expected,
                             (argv, result.stdout[-6000:], result.stderr[-6000:]))
        return result

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")

    def project(self, name, *, typescript=False, auto_esm=False, keep_generated=False,
                external_protocol=None):
        project = self.root / name
        project.mkdir()
        vendor = project / "vendor/local"
        vendor.mkdir(parents=True)
        self.write_json(vendor / "package.json", {
            "name": "@rch/local", "version": "1.0.0", "main": "index.js",
            "types": "index.d.ts",
        })
        (vendor / "index.js").write_text('exports.label = "offline-local";\n')
        (vendor / "index.d.ts").write_text("export declare const label: string;\n")
        lib = project / "packages/lib"
        lib.mkdir(parents=True)
        self.write_json(lib / "package.json", {
            "name": "@rch/lib", "version": "1.0.0", "main": "index.js",
            "types": "index.d.ts",
        })
        (lib / "index.js").write_text("exports.answer = 37;\n")
        (lib / "index.d.ts").write_text("export declare const answer: number;\n")
        source = project / "packages/app/src"
        source.mkdir(parents=True)
        dependencies = {"@rch/lib": "workspace:*", "@rch/local": "file:" + str(vendor)}
        if external_protocol is not None:
            external = self.root / (name + "-external")
            external.mkdir()
            self.write_json(external / "package.json", {
                "name": "@rch/external", "version": "1.0.0", "main": "index.js",
            })
            (external / "index.js").write_text("exports.answer = 99;\n")
            dependencies["@rch/external"] = external_protocol + ":" + str(external)
        root_manifest = {
            "name": "rch-yarn-root", "private": True, "packageManager": "yarn@4.18.1",
            "workspaces": ["packages/*"], "dependencies": dependencies,
            "dependenciesMeta": {"@rch/local": {"unplugged": True}},
        }
        app_manifest = {"name": "@rch/app", "version": "1.0.0", "dependencies": dependencies}
        # A global executable and a same-named package script must not shadow
        # the package binary selected by Yarn's --binaries-only execution.
        scripts = {"tsc": "printf script > " + shlex.quote(str(self.script_tsc))}
        root_manifest["scripts"] = scripts
        app_manifest["scripts"] = scripts
        if auto_esm:
            root_manifest["type"] = "module"
        if typescript:
            archive = project / "vendor/typescript-5.9.3.tgz"
            shutil.copyfile(self.typescript, archive)
            tools = {"typescript": "file:" + str(archive)}
            root_manifest["devDependencies"] = tools
            app_manifest["devDependencies"] = tools
        self.write_json(project / "package.json", root_manifest)
        self.write_json(source.parent / "package.json", app_manifest)
        (source / "index.ts").write_text(
            'import { answer } from "@rch/lib";\n'
            'import { label } from "@rch/local";\n'
            "const checked: number = answer;\nconsole.log(checked, label);\n"
        )
        self.write_json(source / "tsconfig with spaces.json", {
            "compilerOptions": {"strict": True, "noEmit": True, "skipLibCheck": True,
                                "target": "es2020", "module": "commonjs",
                                "composite": True, "incremental": True, "outDir": "dist"},
            "files": ["index.ts"],
        })
        config = ("nodeLinker: pnp\nenableGlobalCache: false\nenableScripts: false\n"
                  "pnpEnableInlining: false\n")
        if not auto_esm:
            config += "pnpEnableEsmLoader: true\n"
        (project / ".yarnrc.yml").write_text(config)
        self.invoke(["yarn", "install"], project)
        self.assertTrue((project / ".pnp.loader.mjs").is_file())
        self.assertTrue((project / ".yarn/unplugged").is_dir())
        self.assertFalse((project / ".yarn/__virtual__").exists())
        generated = (".pnp.cjs", ".pnp.data.json", ".pnp.loader.mjs", ".yarn")
        if not keep_generated:
            seed = self.root / (name + "-seed-outputs")
            seed.mkdir()
            for item in generated:
                (project / item).rename(seed / item)
        paths = sorted(path.relative_to(project).as_posix() for path in project.rglob("*")
                       if path.is_file() and not any(
                           path.relative_to(project).as_posix() == item
                           or path.relative_to(project).as_posix().startswith(item + "/")
                           for item in generated))
        return project, paths

    def proof(self, project, request, *, mode="install", runtime="node", expected=0):
        result = self.invoke(
            [WORKER, "prepare-proof", "--mode", mode, "--project", project,
             "--runtime", runtime], project, data=json.dumps(request).encode(), expected=expected,
        )
        if result.returncode:
            self.assertEqual(result.stdout, b"")
            return result
        value = json.loads(result.stdout)
        self.assertEqual(result.stdout, json.dumps(
            value, ensure_ascii=False, separators=(",", ":")
        ).encode() + b"\n")
        return value

    @staticmethod
    def attestation_digest(attestation):
        return prepared.blake3_digest(json.dumps(
            attestation, ensure_ascii=False, separators=(",", ":")
        ).encode())

    def verify(self, project, attestation, *, invocation=None, expected=0):
        argv = [WORKER, "prepare-proof", "--mode", "verify", "--project", project,
                "--runtime", "node", "--expected-request-digest", attestation["request_digest"],
                "--expected-attestation-digest", self.attestation_digest(attestation)]
        if invocation is not None:
            argv.extend(["--invocation-project", invocation])
        result = self.invoke(argv, project, expected=expected)
        if result.returncode == 0:
            self.assertEqual(result.stdout, b"RCH_PREPARED_DEPENDENCIES_VERIFIED_YARN_PNP\n")
        else:
            self.assertEqual(result.stdout, b"")
        return result

    def ordinary(self, project, *, expected=0, selector=False, runtime="node"):
        argv = [WORKER, "prepare", "--project", project, "--runtime", runtime]
        if selector:
            argv.append("--execution-layout")
        result = self.invoke(argv, project, expected=expected)
        if result.returncode or selector:
            return result
        return json.loads(result.stdout)

    def assert_no_installed_node_modules(self, project):
        # An unplugged archive intentionally has its own package layout under
        # .yarn/unplugged/.../node_modules. No workspace uses node_modules.
        for path in (project, project / "packages/app", project / "packages/lib"):
            self.assertFalse((path / "node_modules").exists(), path)
        self.assertFalse((project / ".yarn/__virtual__").exists())

    @staticmethod
    def namespace(project):
        entries = {}
        for path in project.rglob("*"):
            relative = path.relative_to(project).as_posix()
            metadata = path.lstat()
            if path.is_symlink():
                entries[relative] = ("symlink", os.readlink(path), metadata.st_mode)
            elif path.is_file():
                entries[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest(), metadata.st_mode)
            else:
                entries[relative] = ("directory", metadata.st_mode)
        return entries

    def test_fresh_and_retained_workspace_pnp_runs_real_typescript(self):
        project, paths = self.project("typescript", typescript=True)
        source_bytes = {path: ((project / path).read_bytes(), (project / path).stat().st_mode)
                        for path in paths}
        for number, invocation in enumerate((project, project / "packages/app",
                                             project / "packages/app/src")):
            request = self.request(invocation, paths, source=project,
                                   preparation=project if invocation != project else None,
                                   attempt=f"pnp-{number}")
            attestation = self.proof(project, request)
            self.assertEqual(attestation["disposition"], "fresh" if number == 0 else "retained")
            self.verify(project, attestation, invocation=invocation)
            inventory = {entry["path"] for entry in attestation["state"]["inventory"]["files"]}
            self.assertTrue({".pnp.cjs", ".pnp.data.json", ".pnp.loader.mjs",
                             ".yarn/install-state.gz"}.issubset(inventory))
            self.assertGreaterEqual(sum(path.endswith(".zip") for path in inventory), 3)
            self.assertTrue(any(path.startswith(".yarn/unplugged/") and path.endswith("index.js")
                                for path in inventory))
            self.assert_no_installed_node_modules(project)
            config = os.path.relpath(project / "packages/app/src/tsconfig with spaces.json", invocation)
            args = ["--noEmit", "--incremental", "false", "--composite", "false", "--project", config]
            proof = ["--source-proof", attestation["request_digest"],
                     self.attestation_digest(attestation), "--preparation-root", str(project)]
            # These literal arguments are the wrapper's dedicated PnP tsc
            # frame; the client planner is tested independently in Rust.
            argv = ["/bin/sh", WRAPPER, "node", *proof, "--pnp-tsc", str(len(args)),
                    *args, "sh", "-c", shlex.join(["tsc", *args])]
            before_compiler = self.namespace(project)
            result = self.invoke(argv, invocation, data=b"unused compiler stdin\n")
            self.assertEqual(result.stdout, b"")
            self.assertEqual(self.namespace(project), before_compiler,
                             "type checking must not write composite build info or other outputs")
            self.assertFalse(self.global_tsc.exists())
            self.assertFalse(self.script_tsc.exists())
            self.assertEqual({path: ((project / path).read_bytes(), (project / path).stat().st_mode)
                              for path in paths}, source_bytes)
        bad_args = ["--noEmit", "--incremental", "false", "--composite", "false",
                    "--project", "missing config.json"]
        oracle = self.invoke(["yarn", "run", "--binaries-only", "tsc", *bad_args],
                             invocation, expected=None)
        self.assertNotEqual(oracle.returncode, 0)
        rejected = self.invoke(
            ["/bin/sh", WRAPPER, "node", *proof, "--pnp-tsc", str(len(bad_args)),
             *bad_args, "sh", "-c", shlex.join(["tsc", *bad_args])],
            invocation, expected=oracle.returncode,
        )
        self.assertEqual(rejected.stdout, oracle.stdout)
        self.assertFalse(self.global_tsc.exists())
        self.assertFalse(self.script_tsc.exists())
        # The qualified subdirectory run above preserves the same cwd and
        # relative config behavior as Yarn's ordinary direct execution.
        nested = project / "packages/app/src"
        nested_result = self.invoke(
            ["yarn", "run", "--binaries-only", "tsc", "--noEmit", "--incremental", "false",
             "--composite", "false",
             "--project", "tsconfig with spaces.json"], nested,
        )
        self.assertEqual(nested_result.stdout, b"")

    def test_direct_guarded_worker_executes_only_the_prepared_typescript_binary(self):
        project, paths = self.project("direct-worker", typescript=True)
        original = {path: (project / path).read_bytes() for path in paths}
        args = ["--noEmit", "--incremental", "false", "--composite", "false", "--project",
                "packages/app/src/tsconfig with spaces.json"]

        def execute(root, arguments, expected=0):
            return self.invoke(
                [WORKER, "execute", "--workdir", root, "--command",
                 shlex.join(["tsc", *arguments]), "--disk-budget-bytes", str(256 << 20),
                 "--disk-min-free-bytes", str(1 << 20)], root, expected=expected,
            )

        execute(project, args)
        self.assertFalse(self.global_tsc.exists())
        self.assertFalse(self.script_tsc.exists())
        self.assert_no_installed_node_modules(project)
        self.assertEqual({path: (project / path).read_bytes() for path in paths}, original)
        # Direct execute legitimately creates its monitor/cache metadata and
        # prepared dependency outputs. Authored sources and TypeScript output
        # locations must still remain unchanged.
        self.assertFalse((project / "packages/app/src/dist").exists())
        self.assertEqual(list(project.rglob("*.tsbuildinfo")), [])
        bad_args = ["--noEmit", "--incremental", "false", "--composite", "false", "--project",
                    "missing config.json"]
        oracle = self.invoke(["yarn", "run", "--binaries-only", "tsc", *bad_args],
                             project, expected=None)
        self.assertNotEqual(oracle.returncode, 0)
        execute(project, bad_args, expected=oracle.returncode)
        unsupported = execute(project, ["--noEmit", "--incremental", "false"], expected=None)
        self.assertNotEqual(unsupported.returncode, 0)
        self.assertFalse(self.global_tsc.exists())
        self.assertFalse(self.script_tsc.exists())
        self.assertEqual(list(project.rglob("*.tsbuildinfo")), [])
        missing, _ = self.project("direct-worker-missing-compiler")
        rejected = execute(missing, ["--noEmit", "--incremental", "false", "--composite", "false"],
                           expected=None)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(self.global_tsc.exists())
        self.assertFalse(self.script_tsc.exists())
        unguarded_marker = self.root / "unsupported-composed-command-ran"
        node_command = shlex.join([
            "node", "-e", 'require("fs").writeFileSync('
            + json.dumps(str(unguarded_marker)) + ', "ran")',
        ])
        # Semicolon composition has no inferred compilation disk budget, but
        # the leading tsc still requests Node preparation. This reaches the
        # plain executor's PnP planner instead of unrelated generic execution.
        composed_command = (
            "tsc --noEmit --incremental false --composite false; " + node_command
        )
        unguarded = self.invoke(
            [WORKER, "execute", "--workdir", missing, "--command", composed_command],
            missing, expected=121,
        )
        self.assertIn(b"Yarn PnP requires literal tsc", unguarded.stderr)
        self.assertFalse(unguarded_marker.exists())
        self.assertFalse(self.global_tsc.exists())
        self.assertFalse(self.script_tsc.exists())

    def test_qualified_pnp_rejects_changed_missing_and_unregistered_outputs(self):
        project, paths = self.project("ownership")
        request = self.request(project, paths)
        attestation = self.proof(project, request)
        no_binary = self.invoke(
            ["/bin/sh", WRAPPER, "node", "--source-proof", attestation["request_digest"],
             self.attestation_digest(attestation), "--pnp-tsc", "5", "--noEmit",
             "--incremental", "false", "--composite", "false", "sh", "-c",
             "tsc --noEmit --incremental false --composite false"],
            project, expected=None,
        )
        self.assertNotEqual(no_binary.returncode, 0)
        self.assertFalse(self.global_tsc.exists())
        self.assertFalse(self.script_tsc.exists())
        inventory = attestation["state"]["inventory"]["files"]
        targets = [".pnp.cjs", ".pnp.data.json", ".pnp.loader.mjs",
                   next(entry["path"] for entry in inventory if entry["path"].endswith(".zip")),
                   next(entry["path"] for entry in inventory
                        if entry["path"].startswith(".yarn/unplugged/")
                        and entry["path"].endswith("index.js"))]
        for name in targets:
            with self.subTest(changed=name):
                path = project / name
                original = path.read_bytes()
                path.write_bytes(original + b"\nchanged after acceptance\n")
                self.assertNotEqual(self.verify(project, attestation, expected=None).returncode, 0)
                path.write_bytes(original)
        self.verify(project, attestation)
        loader = project / ".pnp.loader.mjs"
        retained = self.root / "missing-loader"
        loader.rename(retained)
        self.assertNotEqual(self.verify(project, attestation, expected=None).returncode, 0)
        retained.rename(loader)
        addition = project / ".yarn/cache/unregistered.zip"
        addition.write_text("unregistered dependency output\n")
        self.assertNotEqual(self.verify(project, attestation, expected=None).returncode, 0)
        addition.rename(self.root / "unregistered-cache-output")
        self.verify(project, attestation)
        refusal = self.proof(project, request, runtime="bun", expected=None)
        self.assertNotEqual(refusal.returncode, 0)
        self.assertIn(b"Yarn PnP preparation requires the Node runtime", refusal.stderr)

    def test_ordinary_pnp_repairs_missing_auto_loader_and_cache(self):
        project, _ = self.project("ordinary-auto-esm", auto_esm=True)
        self.assertNotIn("pnpEnableEsmLoader", (project / ".yarnrc.yml").read_text())
        unsupported = self.ordinary(project, runtime="bun", expected=None, selector=True)
        self.assertNotEqual(unsupported.returncode, 0)
        self.assertEqual(unsupported.stdout, b"")
        self.assertIn(b"Yarn PnP preparation requires the Node runtime", unsupported.stderr)
        self.assertFalse((project / ".pnp.cjs").exists())
        # A deterministic pre-install refusal must not leave an interrupted
        # transaction fence that prevents the supported Node request.
        first = self.ordinary(project)
        self.assertEqual(first["action"], "Installed")
        self.assert_no_installed_node_modules(project)
        (project / ".pnp.loader.mjs").rename(self.root / "ordinary-loader-before-repair")
        repaired = self.ordinary(project)
        self.assertEqual(repaired["action"], "Installed")
        self.assertTrue((project / ".pnp.loader.mjs").is_file())
        archive = next((project / ".yarn/cache").glob("*.zip"))
        archive.rename(self.root / "ordinary-cache-before-repair.zip")
        selected = self.ordinary(project, selector=True)
        self.assertEqual(selected.stdout, b"RCH_PREPARED_YARN_PNP\n")
        self.assertTrue(archive.is_file())
        self.assertIn(b'"action":"Installed"', selected.stderr)
        config = project / ".yarnrc.yml"
        original = config.read_text()
        config.write_text(original.replace("enableGlobalCache: false", "enableGlobalCache: true"))
        refusal = self.ordinary(project, expected=None, selector=True)
        self.assertNotEqual(refusal.returncode, 0)
        self.assertEqual(refusal.stdout, b"")
        self.assertIn(b"enableGlobalCache", refusal.stderr)
        config.write_text(original + "cacheFolder: .yarn/custom-cache\n")
        refusal = self.ordinary(project, expected=None, selector=True)
        self.assertNotEqual(refusal.returncode, 0)
        self.assertEqual(refusal.stdout, b"")
        self.assertFalse((project / ".yarn/custom-cache").exists())
        config.write_text(original + "pnpIgnorePatterns:\n  - '**'\n")
        refusal = self.ordinary(project, expected=None, selector=True)
        self.assertNotEqual(refusal.returncode, 0)
        self.assertEqual(refusal.stdout, b"")
        self.assertIn(b"ignore patterns require an ambient resolution contract", refusal.stderr)

    def test_zero_install_selected_loaders_and_archives_remain_source(self):
        project, paths = self.project("zero-install", keep_generated=True)
        # Selected zero-install loader/cache files are source. Machine state
        # and unplugged files are regenerated, then owned as installer output.
        state = self.root / "zero-install-seed-state"
        state.mkdir()
        (project / ".yarn/install-state.gz").rename(state / "install-state.gz")
        (project / ".yarn/unplugged").rename(state / "unplugged")
        selected_outputs = [".pnp.cjs", ".pnp.data.json", ".pnp.loader.mjs"]
        selected_outputs.extend(path.relative_to(project).as_posix()
                                for path in (project / ".yarn/cache").rglob("*") if path.is_file())
        paths = sorted(paths + selected_outputs)
        original = {path: ((project / path).read_bytes(), (project / path).stat().st_mode)
                    for path in selected_outputs}
        request = self.request(project, paths)
        attestation = self.proof(project, request)
        self.assertEqual(attestation["disposition"], "fresh")
        owned = {entry["path"] for entry in attestation["state"]["inventory"]["files"]}
        self.assertTrue(owned.isdisjoint(selected_outputs))
        self.assertIn(".yarn/install-state.gz", owned)
        self.assertEqual({path: ((project / path).read_bytes(), (project / path).stat().st_mode)
                          for path in selected_outputs}, original)
        self.verify(project, attestation)
        again = copy.deepcopy(request)
        again["attempt_id"] = "zero-install-retained"
        self.assertEqual(self.proof(project, again)["disposition"], "retained")
        self.assert_no_installed_node_modules(project)

    def test_real_portal_and_link_dependencies_refuse_unowned_runtime_locations(self):
        for protocol in ("portal", "link"):
            with self.subTest(protocol=protocol):
                # The authentic seed install succeeds, proving this is a real
                # Yarn descriptor. Its runtime directory is outside selection.
                project, paths = self.project(protocol, external_protocol=protocol)
                external = self.root / (protocol + "-external")
                original = {path.name: path.read_bytes() for path in external.iterdir()}
                request = self.request(project, paths)
                refusal = self.proof(project, request, expected=None)
                self.assertNotEqual(refusal.returncode, 0)
                self.assertIn(b"portal/link dependencies require a separate runtime ownership contract",
                              refusal.stderr)
                self.assertFalse((project / ".pnp.cjs").exists())
                self.assertFalse((project / ".yarn").exists())
                self.assertEqual({path.name: path.read_bytes() for path in external.iterdir()}, original)
        # Berry's summary hides the contents of MAP settings. This extension
        # was not present when the real seed lock was generated, so neither a
        # manifest-only nor lock-only check can establish this refusal.
        project, paths = self.project("extension-runtime-location")
        external = self.root / "extension-external"
        external.mkdir()
        self.write_json(external / "package.json", {
            "name": "@rch/extension-external", "version": "1.0.0",
        })
        rc = project / ".yarnrc.yml"
        rc.write_text(rc.read_text() + "packageExtensions:\n  '@rch/local@*':\n"
                      "    dependencies:\n      '@rch/extension-external': 'portal:"
                      + str(external) + "'\n")
        self.assertNotIn("portal:", (project / "yarn.lock").read_text())
        refusal = self.proof(project, self.request(project, paths), expected=None)
        self.assertNotEqual(refusal.returncode, 0)
        self.assertIn(b"portal/link dependencies require a separate runtime ownership contract",
                      refusal.stderr)
        self.assertFalse((project / ".pnp.cjs").exists())
        self.assertFalse((project / ".yarn").exists())

    def test_member_overrides_and_generated_parent_alias_refuse_before_install(self):
        for filename, contents, diagnostic in (
            (".yarnrc.yml", "nodeLinker: node-modules\n", b"member Yarn configuration"),
            (".env.yarn", "RCH_MEMBER_ONLY=value\n", b"member Yarn environment files"),
        ):
            with self.subTest(member_input=filename):
                project, paths = self.project("member-" + filename.replace(".", ""))
                member = project / "packages/app"
                (member / filename).write_text(contents)
                paths.append("packages/app/" + filename)
                request = self.request(member, paths, source=project, preparation=project)
                refusal = self.proof(project, request, expected=None)
                self.assertNotEqual(refusal.returncode, 0)
                self.assertIn(diagnostic, refusal.stderr)
                self.assertFalse((project / ".pnp.cjs").exists())
        project, _ = self.project("generated-parent-alias")
        outside = self.root / "outside-yarn-outputs"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"outside unchanged\n")
        (project / ".yarn").symlink_to(outside, target_is_directory=True)
        refusal = self.ordinary(project, expected=None, selector=True)
        self.assertNotEqual(refusal.returncode, 0)
        self.assertEqual(refusal.stdout, b"")
        self.assertIn(b"Yarn generated output path", refusal.stderr)
        self.assertEqual([path.name for path in outside.iterdir()], ["sentinel"])
        self.assertEqual((outside / "sentinel").read_bytes(), b"outside unchanged\n")
        self.assertFalse((project / ".pnp.cjs").exists())


if __name__ == "__main__":
    if WORKER is None or not Path(WORKER).is_file():
        raise SystemExit("usage: prepare_yarn_pnp.py /absolute/path/to/rch-wkr [test_name ...]")
    names = sys.argv[1:] or sorted(name for name in RealYarnPnp.__dict__ if name.startswith("test_"))
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestSuite(RealYarnPnp(name) for name in names)
    )
    raise SystemExit(not result.wasSuccessful())
