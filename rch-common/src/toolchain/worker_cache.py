"""Worker-side environment preparation for RCH's opt-in local RABS profile.

Embedded by the existing Rust remote-command builder, after env controls.
Import the installed cargo-rabs preparation API without invoking its CLI or a
second Cargo. Neither this adapter nor readiness grants compiler-skip authority.
"""

import ast
import os
import shutil
import signal
import stat
import sys


ACTIVE = "RCH_RABS_WORKER_ACTIVE"
MAX_LAUNCHER_BYTES = 128 * 1024


def load_prepare(launcher):
    # Inspect the version contract WITHOUT executing an older launcher's CLI.
    # Use the same captured source for inspection and execution; do not reopen
    # a path that an installation upgrade may have replaced in between.
    launcher = os.path.realpath(launcher)
    descriptor = os.open(launcher, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise RuntimeError("cargo-rabs is not a regular script")
        content = source.read(MAX_LAUNCHER_BYTES + 1)
    if len(content) > MAX_LAUNCHER_BYTES:
        raise RuntimeError("cargo-rabs exceeds the preparation source bound")
    tree = ast.parse(content, filename=launcher)
    versions = [node.value.value for node in tree.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "RCH_WORKER_PREPARATION_API"
                and isinstance(node.value, ast.Constant)]
    if len(versions) != 1 or type(versions[0]) is not int or versions[0] != 1:
        raise RuntimeError("installed cargo-rabs lacks preparation API version 1")
    namespace = {"__name__": "rch_rabs_worker_launcher", "__file__": launcher}
    exec(compile(tree, launcher, "exec"), namespace)
    prepare = namespace.get("prepare")
    if not callable(prepare):
        raise RuntimeError("installed cargo-rabs lacks the preparation API")
    return prepare


def prepared_environment(original):
    if sys.platform != "linux" or sys.version_info < (3, 9) or original.get(ACTIVE) == "1":
        return original
    launcher = shutil.which("cargo-rabs", path=original.get("PATH"))
    if launcher is None:
        print("rch: worker-local RABS unavailable: cargo-rabs is not installed; using stock Cargo",
              file=sys.stderr)
        return original
    try:
        # Installed scripts are worker-selected executable code, not uploaded
        # source or data. Incompatible installations refuse BEFORE execution.
        prepare = load_prepare(launcher)
        candidate = dict(original)
        candidate[ACTIVE] = "1"
        prepared = prepare(candidate, no_start=False)
        if not isinstance(prepared, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in prepared.items()):
            raise RuntimeError("installed cargo-rabs returned an invalid environment")
        return prepared
    except Exception as error:
        # Preparation only: no Cargo/rustc or output writer has started. Keep
        # the original environment, including explicit custom wrappers. Never
        # repeat a Cargo command after it has executed or exposed any output.
        print("rch: worker-local RABS setup unavailable: {}; using stock Cargo".format(error),
              file=sys.stderr)
        return original


def main():
    argv = sys.argv[1:]
    if not argv:
        print("rch: worker-local RABS runner requires an executable", file=sys.stderr)
        return 127
    # Retain the complete original argv, including `rustup run TC cargo`.
    # `rustup run TC python ...` followed by a PATH lookup for Cargo is NOT
    # equivalent: it may select a different Cargo shim or lose custom-toolchain
    # fallback. Setup changes only the wrapper environment, never that choice.
    original = dict(os.environ)
    try:
        environment = prepared_environment(original)
    except KeyboardInterrupt:
        return 130
    # Python ignores these signals for its own I/O. Restore the ordinary shell
    # defaults at the exec boundary rather than leaking Python's dispositions.
    for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
        number = getattr(signal, name, None)
        if number is not None:
            signal.signal(number, signal.SIG_DFL)
    try:
        os.execvpe(argv[0], argv, environment)
    except OSError as error:
        print("rch: could not execute {}: {}".format(argv[0], error), file=sys.stderr)
        return 127 if isinstance(error, FileNotFoundError) else 126


if __name__ == "__main__":
    sys.exit(main())
