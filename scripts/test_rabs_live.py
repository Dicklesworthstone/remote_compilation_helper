#!/usr/bin/env python3
"""Build matching binaries, then run a real Cargo RABS acceptance suite.

The default daemon-release profile exercises the shipping throughput profile,
not an inner unoptimized daemon. --profile dev selects the debug path explicitly.
Cargo's own JSON artifact records select executables; no sibling/PATH guess,
preseeded cache, warmup build, retry, or altered serving budget is used. The
worktrees Rust helper verifies both binary hashes before starting the daemon. Compiler
diagnostics and test output retain their original streams.

Usage: python3 scripts/test_rabs_live.py [--suite worktrees|canonical]
       [--profile PROFILE] [--target-dir DIR]
       [--output-dir NEW_DIR] [--cargo CARGO] [-- LIBTEST_ARGS...]

The default worktrees suite verifies live dependency serving. The canonical
suite builds the worker and Cargo supervisor too, and explicitly includes the
ignored production namespace/Cargo/TLS tests, serially unless a thread count
is supplied. Host support and every original acceptance assertion remain
mandatory. Neither suite is a performance qualification.

Requires Linux, Python 3.9+, and the repository's Rust toolchain. Build and test
failures propagate. Preparation records remain in the output directory; this
program neither cleans target trees nor edits Cargo configuration. It records
Cargo exit statuses, not a claim of cache hits or benchmark improvement.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

SCHEMA = "rabs.test-binaries"
MANIFEST_ENV = "RABS_TEST_BINARIES"
MAX_FRAME = 4 * 1024 * 1024
MAX_LOG = 64 * 1024 * 1024
NAMES = ("rabs-wrap", "rabsd")
CANONICAL_NAMES = NAMES + ("rabs-wkr", "rabs-cargo-root")
BINARY_SOURCES = {name: Path(name) / "src/main.rs" for name in NAMES + ("rabs-wkr",)}
BINARY_SOURCES["rabs-cargo-root"] = Path("rabs-wkr/src/bin/rabs-cargo-root.rs")
BINARY_SOURCES["canonical_check_local"] = Path("rabsd/tests/canonical_check_local.rs")


class PreparationError(Exception):
    pass


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise PreparationError("duplicate Cargo JSON field: " + key)
        value[key] = item
    return value


def decode_frame(data):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as error:
        raise PreparationError("invalid Cargo JSON output") from error
    if not isinstance(value, dict):
        raise PreparationError("Cargo JSON frame is not an object")
    return value


def signature(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mode,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def fingerprint(path):
    """Read one exact regular executable through a stable descriptor."""
    path = Path(path)
    if not path.is_absolute():
        raise PreparationError("Cargo artifact path is not absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            raise PreparationError("Cargo artifact is not a regular executable: " + str(path))
        if signature(os.lstat(path)) != signature(before):
            raise PreparationError("Cargo artifact changed while opening")
        remaining = before.st_size
        digest = hashlib.sha256()
        while remaining:
            data = os.read(descriptor, min(65536, remaining))
            if not data:
                raise PreparationError("Cargo artifact was truncated while hashing")
            digest.update(data)
            remaining -= len(data)
        if (os.read(descriptor, 1)
                or signature(os.fstat(descriptor)) != signature(before)
                or signature(os.lstat(path)) != signature(before)):
            raise PreparationError("Cargo artifact changed while hashing")
    finally:
        os.close(descriptor)
    return {"path": str(path), "sha256": digest.hexdigest(), "size": before.st_size}


class CargoArtifacts:
    """Accept only the requested workspace binaries and one successful finish."""
    def __init__(self, workspace, names=NAMES):
        self.workspace = workspace
        self.names = names
        self.executables = {}
        self.finished = None

    def accept(self, value):
        reason = value.get("reason")
        if reason == "build-finished":
            if self.finished is not None or type(value.get("success")) is not bool:
                raise PreparationError("ambiguous Cargo build-finished record")
            self.finished = value["success"]
            return
        if reason != "compiler-artifact":
            return
        target = value.get("target")
        if not isinstance(target, dict) or target.get("name") not in self.names:
            return
        profile = value.get("profile")
        harness = target["name"] == "canonical_check_local"
        if (target.get("kind") != (["test"] if harness else ["bin"])
                or not isinstance(profile, dict) or profile.get("test") is not harness):
            return
        name = target["name"]
        source = target.get("src_path")
        expected = self.workspace / BINARY_SOURCES[name]
        if not isinstance(source, str) or Path(source) != expected:
            raise PreparationError(f"Cargo reported {name} from another source tree")
        executable = value.get("executable")
        if not isinstance(executable, str) or not os.path.isabs(executable):
            raise PreparationError(f"Cargo did not name an absolute {name} executable")
        old = self.executables.get(name)
        if old is not None and old != executable:
            raise PreparationError(f"Cargo reported multiple {name} executables")
        self.executables[name] = executable

    def finish(self):
        if self.finished is not True:
            raise PreparationError("Cargo did not confirm a successful build")
        if set(self.executables) != set(self.names):
            missing = sorted(set(self.names) - set(self.executables))
            raise PreparationError("Cargo did not report required binary artifacts: " + ", ".join(missing))
        return {name: fingerprint(self.executables[name]) for name in self.names}


def write_new_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def collect_build(command, workspace, env, log, names=NAMES):
    """Bound each JSON allocation; drain rejected output before reaping Cargo."""
    collector = CargoArtifacts(workspace, names)
    # Preserve the caller's explicitly inheritable descriptors, as Cargo's
    # normal exec path does. Keeping CARGO_MAKEFLAGS while closing its pipe
    # descriptors breaks the jobserver; guessing/recreating tokens would invent
    # capacity. Python-created log/pipe descriptors remain close-on-exec.
    process = subprocess.Popen(command, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, close_fds=False)
    failure = None
    total = 0
    try:
        with process.stdout:
            while True:
                frame = process.stdout.readline(MAX_FRAME + 1)
                if not frame:
                    break
                total += len(frame)
                if len(frame) > MAX_FRAME or total > MAX_LOG:
                    failure = "Cargo output exceeded the preparation log/frame bound"
                if failure is None:
                    log.write(frame)
                    try:
                        collector.accept(decode_frame(frame))
                    except PreparationError as error:
                        failure = str(error)
                if failure is not None:
                    # Do not leave a full stdout pipe blocking the child after
                    # a rejected frame. Nothing else is parsed or retained.
                    while process.stdout.read(65536):
                        pass
                    break
        status = process.wait()
    except BaseException:
        # Only our Cargo child, never a shared daemon or other build. Cargo's
        # normal cancellation/supervision handles its own compiler descendants.
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        raise
    if status != 0:
        return status, None
    if failure is not None:
        raise PreparationError(failure)
    return status, collector.finish()


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", default="daemon-release")
    parser.add_argument("--suite", choices=("worktrees", "canonical"), default="worktrees")
    parser.add_argument("--target-dir")
    parser.add_argument("--output-dir", help="new directory for artifact records and Cargo build log")
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    parser.add_argument("test_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.test_args[:1] == ["--"]:
        args.test_args.pop(0)
    if (not args.profile or not all(c.isascii() and (c.isalnum() or c in "-_")
                                    for c in args.profile)):
        parser.error("profile must be a Cargo profile name")
    return args


def run(args, workspace):
    if sys.platform != "linux":
        raise PreparationError("the live Cargo acceptance suite requires Linux")
    workspace = workspace.resolve(strict=True)
    cargo = shutil.which(args.cargo)
    if cargo is None:
        raise PreparationError("Cargo executable was not found: " + args.cargo)
    # Keep the final symlink spelling: rustup dispatches on the invoked basename.
    cargo = os.path.abspath(cargo)
    target = Path(args.target_dir or os.environ.get("CARGO_TARGET_DIR") or workspace / "target").resolve()
    output = (Path(args.output_dir).resolve() if args.output_dir else
              target / "rabs-live-validation" / (str(os.getpid()) + "-" + str(time.time_ns())))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    common = ["--locked", "--manifest-path", str(workspace / "Cargo.toml"),
              "--target-dir", str(target), "--profile", args.profile]
    canonical = args.suite == "canonical"
    names = CANONICAL_NAMES if canonical else NAMES
    packages = ["-p", "rabs-wrap", "-p", "rabs-wkr" if canonical else "rabsd"]
    build = [cargo, "build"] + common + packages + ["--bins", "--message-format=json-render-diagnostics"]
    test_target = (["-p", "rabsd", "--test", "canonical_check_local"] if canonical else
                   ["-p", "rabs-wrap", "--test", "live_cargo_worktrees"])
    test_options = ["--nocapture"]
    if canonical:
        test_options += ["--include-ignored"]
        if not any(value == "--test-threads" or value.startswith("--test-threads=")
                   for value in args.test_args):
            test_options += ["--test-threads=1"]
    test = [cargo, "test"] + common + test_target + ["--"] + test_options + args.test_args
    test_preparation = ([cargo, "test"] + common + test_target +
                        ["--no-run", "--message-format=json-render-diagnostics"] if canonical else None)
    env = dict(os.environ)
    # An old manifest from a calling test session is not this build's output.
    for key in (MANIFEST_ENV, "RABS_CANONICAL_TEST_WRAPPER", "RABS_TEST_WORKER_BIN"):
        env.pop(key, None)
    report = {"schema": "rabs.live-test-run", "version": 1,
              "workspace_root": str(workspace), "profile": args.profile, "suite": args.suite,
              "build_source": env.get("RCH_BUILD_SOURCE"),
              "build_command": build, "test_command": test,
              "test_preparation_command": test_preparation, "test_preparation_exit": None,
              "build_exit": None, "test_exit": None}
    start = time.monotonic()
    try:
        print(f"RABS binary preparation ({args.profile}) -> {output}", file=sys.stderr, flush=True)
        descriptor = os.open(output / "cargo-build.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as log:
            build_names = tuple(name for name in names if not canonical or name != "rabsd")
            status, binaries = collect_build(build, workspace, env, log, build_names)
        report["build_exit"] = status
        report["preparation_seconds"] = time.monotonic() - start
        if status != 0:
            return status
        if canonical and (Path(binaries["rabs-wkr"]["path"]).parent !=
                          Path(binaries["rabs-cargo-root"]["path"]).parent):
            raise PreparationError("worker and Cargo supervisor artifacts are not siblings")
        if canonical:
            # Cargo's dev dependencies can rebuild the daemon with a different
            # feature graph. Prepare the SAME integration target before binding
            # its executable, rather than guessing that the normal build is it.
            descriptor = os.open(output / "cargo-test-build.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as log:
                status, test_binaries = collect_build(test_preparation, workspace, env, log,
                                                     ("rabsd", "canonical_check_local"))
            report["test_preparation_exit"] = status
            if status != 0:
                return status
            for name, artifact in binaries.items():
                if fingerprint(artifact["path"]) != artifact:
                    raise PreparationError("test preparation changed the prepared " + name)
            binaries.update(test_binaries)
        report["preparation_seconds"] = time.monotonic() - start
        manifest = output / "binaries.json"
        record = {"schema": "rabs.canonical-test-binaries" if canonical else SCHEMA,
                  "version": 1, "workspace_root": str(workspace),
                  "profile": args.profile, **binaries}
        write_new_json(manifest, record)
        if canonical:
            env["RABS_CANONICAL_TEST_WRAPPER"] = binaries["rabs-wrap"]["path"]
            env["RABS_TEST_WORKER_BIN"] = binaries["rabs-wkr"]["path"]
        else:
            env[MANIFEST_ENV] = str(manifest)
        print(f"RABS live Cargo tests ({args.suite}) -> prepared binaries",
              file=sys.stderr, flush=True)
        started_test = time.monotonic()
        # The test Cargo needs the SAME inherited jobserver, not just its env.
        status = subprocess.call(test, cwd=workspace, env=env, close_fds=False)
        report["test_seconds"] = time.monotonic() - started_test
        report["test_exit"] = status
        if canonical:
            for name, artifact in binaries.items():
                if fingerprint(artifact["path"]) != artifact:
                    raise PreparationError("test execution changed the prepared " + name)
        return status
    except (OSError, PreparationError) as error:
        report["preparation_error"] = str(error)
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - start
        write_new_json(output / "run.json", report)


def main(argv=None):
    args = arguments(sys.argv[1:] if argv is None else argv)
    try:
        status = run(args, Path(__file__).resolve().parents[1])
    except (OSError, PreparationError) as error:
        print("RABS preparation failed: " + str(error), file=sys.stderr)
        return 2
    if status < 0:
        signal.signal(-status, signal.SIG_DFL)
        os.kill(os.getpid(), -status)
    return status


if __name__ == "__main__":
    sys.exit(main())
