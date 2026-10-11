#!/usr/bin/env python3
"""Qualify opt-in Cargo stdout through the installed shim and real workers.

Run only inside an externally admitted DSR/native lane, after disk and RCH
retain-all admission. Requires a real Snowflake source/build identity, the
canonical PATH Cargo shim, a qualified RCH binary, a real b3sum, and an admitted
RCH_TARGET_BASE. Builds are serial, request one normal worker slot, and retain
every target tree and output. No direct SSH, local compiler, cleanup or mock.
Also requires a real multi-repository closure source/package for the explicit
source-content receipt case; a single-root input fails that gate.
This checks that isolated mode's actual build/receipt and verbose routing,
the named-output route and completed same-id stdout recovery;
full installer, wrapper-loss/pending recovery, Windows and
same-invocation live-incumbent/A/A performance acceptance remain separate.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "closure-source", "evidence-root", "rch", "b3sum"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("worker", "version", "git-sha", "source-digest", "target", "closure-package"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(os.name != "nt", "This acceptance route requires a native POSIX caller")
    require(args.evidence_root.is_absolute() and args.evidence_root.is_dir(),
            "An existing, admitted absolute evidence root is required")
    require(all(path.is_absolute() and path.is_file() and os.access(path, os.X_OK)
                for path in (args.rch, args.b3sum)), "Actual admitted RCH and b3sum are required")
    target_base_setting = os.environ.get("RCH_TARGET_BASE")
    require(target_base_setting is not None, "An admitted RCH_TARGET_BASE is required for target isolation")
    target_base = Path(target_base_setting).resolve(strict=True)
    require(Path(target_base_setting).is_absolute() and target_base.is_dir(), "RCH_TARGET_BASE must be an existing absolute directory")
    if sys.platform == "darwin":
        require(str(target_base).startswith("/Volumes/USB_NVME/"), "Mac target isolation must use the external NVMe")
    source = args.source.resolve(strict=True)
    closure_source = args.closure_source.resolve(strict=True)
    require(closure_source.is_dir() and (closure_source / "Cargo.toml").is_file()
            and (closure_source / "Cargo.lock").is_file(),
            "A real locked multi-repository closure project is required")
    require(args.closure_package and all(c.isascii() and (c.isalnum() or c in "-_")
                                        for c in args.closure_package),
            "The real closure package must be a literal Cargo package name")
    manifest = source / "crates/franken-snowflake-cli/Cargo.toml"
    require(manifest.is_file() and (source / "Cargo.lock").is_file(), "The real locked CLI source is required")
    require(len(args.source_digest) == 64 and all(c in "0123456789abcdef" for c in args.source_digest)
            and args.git_sha not in ("", "unknown") and args.target not in ("", "unknown"),
            "Independent admitted source, commit and native target bindings are required")
    cargo = shutil.which("cargo")
    shim = Path.home() / ".rch/shims/cargo"
    require(cargo is not None and Path(cargo).resolve(strict=True) == shim.resolve(strict=True),
            "PATH cargo must be the installed canonical shim")
    rch_on_path = shutil.which("rch")
    require(rch_on_path is not None and Path(rch_on_path).resolve(strict=True) == args.rch.resolve(strict=True),
            "The canonical shim must select the exact admitted RCH binary through PATH")
    require(os.environ.get("RCH_CARGO_WRAPPER_BYPASS") != "1"
            and os.environ.get("RCH_SHIM_LOCAL_IDE") != "1"
            and not os.environ.get("RUSTC_WORKSPACE_WRAPPER"),
            "Installed shim local bypass settings are incompatible with worker acceptance")
    shim_hash = sha256(shim)
    rch_hash = sha256(args.rch)
    b3sum_hash = sha256(args.b3sum)
    source_hashes = {str(path): sha256(path) for path in
                     (manifest, source / "Cargo.toml", source / "Cargo.lock", source / "install.sh")}
    token = uuid.uuid4().hex
    evidence = args.evidence_root / ("cargo-json-stdout-" + token)
    evidence.mkdir()
    physical_target = target_base / ("cargo-json α " + token)
    physical_target.mkdir()
    target_alias = target_base / ("cargo-json alias " + token)
    target_alias.symlink_to(physical_target, target_is_directory=True)
    env = os.environ.copy()
    env.update({"RCH_CARGO_JSON_STDOUT": "1", "RCH_REQUIRE_REMOTE": "1",
                "RCH_QUEUE_WHEN_BUSY": "1", "RCH_WORKER": args.worker,
                "CARGO_BUILD_JOBS": "1",
                "CARGO_TARGET_DIR": str(target_alias), "CARGO_BUILD_TARGET": args.target})
    names = ("franken-snowflake", "fsnow")
    command = ["cargo", "build", "-j1", "--locked", "--release", "-p", "franken-snowflake-cli",
               "--bin", names[0], "--bin", names[1], "--message-format=json,json-render-diagnostics"]
    outcomes = []

    def run(name, argv, environment, timeout_seconds=1800, working_directory=None):
        case = evidence / name
        case.mkdir()
        (case / "argv.json").write_text(json.dumps(argv) + "\n")
        case_cwd = source if working_directory is None else working_directory
        (case / "cwd.txt").write_text(str(case_cwd) + "\n")
        stdout_path = case / "stdout.bin"
        stderr_path = case / "stderr.bin"
        # subprocess.run kills its child on timeout. An observation deadline
        # must not kill an RCH wrapper or close its output pipes while remote
        # ownership may still be active. Child-owned regular-file descriptors
        # continue retaining output if the harness exits at its original cap.
        with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
            child = subprocess.Popen(argv, cwd=case_cwd, env=environment,
                                     stdout=stdout_file, stderr=stderr_file)
            try:
                code = child.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                (case / "termination.json").write_text(json.dumps({
                    "state": "timeout", "timeout_seconds": timeout_seconds,
                    "child_pid": child.pid, "child_stopped": False,
                    "output_complete": False}) + "\n")
                sys.stderr.buffer.write(stderr_path.read_bytes())
                sys.stderr.buffer.flush()
                raise
        result = subprocess.CompletedProcess(argv, code, stdout_path.read_bytes(), stderr_path.read_bytes())
        (case / "returncode.txt").write_text(str(result.returncode) + "\n")
        # Diagnostics are retained in full, including successful builds.
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
        outcomes.append({"case": name, "returncode": result.returncode})
        return result, case

    def admitted_journal(payload, case, expected_build=None):
        # Read the real producer's stored journal. This is identity/recovery
        # linkage only, not a composite source/toolchain/SDK/slot attestation.
        reference = payload.get("admission")
        require(isinstance(reference, dict), "Machine compiler output lacks its admission reference")
        wrapper = reference.get("local_wrapper_id", "")
        build = reference.get("remote_build_id", "")
        require(isinstance(wrapper, str) and wrapper.startswith("rchw-")
                and isinstance(build, str) and build.isascii() and build.isdecimal() and int(build) > 0
                and reference.get("worker_id") == args.worker
                and reference.get("terminal_acknowledged") is True
                and reference.get("strict_remote") is True,
                "Machine compiler identity is missing, unconfirmed or bound to a different worker")
        require(str(uuid.UUID(wrapper[5:])) == wrapper[5:], "Machine wrapper identity is not canonical")
        if expected_build is not None:
            require(build == expected_build, "Machine admission and real source receipt name different builds")
        selected = reference.get("journal_path")
        require(isinstance(selected, str), "Machine admission lacks its actual journal path")
        journal_path = Path(selected)
        require(journal_path.is_absolute() and not journal_path.is_symlink() and journal_path.is_file(),
                "Machine admission journal is missing, a symlink or relative")
        original = journal_path.read_bytes()
        journal = json.loads(original)
        require(journal.get("schema_version") == 1
                and journal.get("identity", {}).get("local_wrapper_id") == wrapper
                and journal.get("identity", {}).get("remote_build_id") == int(build)
                and journal.get("worker_id") == args.worker
                and journal.get("terminal_acknowledged") is True
                and journal.get("strict_remote") is True
                and journal.get("command_fingerprint") == reference.get("caller_command_fingerprint"),
                "Machine admission disagrees with its real durable ownership record")
        observed_exit = payload.get("remote_exit_code")
        if observed_exit is not None:
            require(type(observed_exit) is int and type(journal.get("exit_code")) is int
                    and journal["exit_code"] == observed_exit,
                    "Machine command status differs from its actual retained exit observation")
        with (case / "admission-journal.bin").open("xb") as retained:
            retained.write(original)
        require(journal_path.read_bytes() == original, "Journal changed while checking terminal identity")
        return reference

    def spawn_with_closed_stdout(argv, environment, diagnostics, working_directory=None):
        # Close the read endpoint before spawning: closing child.stdout after
        # spawn races a child that writes before the parent closes it.
        reader, writer = os.pipe()
        os.close(reader)
        try:
            return subprocess.Popen(argv, cwd=source if working_directory is None else working_directory, env=environment,
                                    stdout=writer,
                                    stderr=writer if diagnostics is None else diagnostics)
        finally:
            os.close(writer)

    # Exercise the explicit isolated-source mode through the actual CLI/worker.
    # It has its own machine envelope, so the Cargo-stdout opt-in stays absent.
    # This is not the ordinary closure route, a Windows positive, or proof that
    # every canonical checkout byte/metadata stayed unchanged; those need their
    # original independent before/after and runtime qualification.
    # Explicit-worker policy is checked using real private configuration, with
    # no compiler/service substitute. The deliberately absent bin cannot be a
    # positive build; these cases qualify only refusal before local execution.
    for policy, settings, reason in [
        ("force-local", b"[general]\nenabled = true\nforce_local = true\nforce_remote = false\n", "force_local"),
        ("disabled", b"[general]\nenabled = false\n", "rch disabled (general.enabled=false)"),
    ]:
        policy_root = evidence / ("exact-worker-policy-" + policy)
        policy_root.mkdir()
        policy_config = policy_root / "config.toml"
        with policy_config.open("xb") as config_file:
            config_file.write(settings)
        policy_env = {key: value for key, value in env.items() if not key.startswith("GIT_")}
        for name in ("RCH_CARGO_JSON_STDOUT", "RCH_JSON", "RCH_OUTPUT_FORMAT", "RCH_DAEMON_SOCKET",
                     "RCH_ENABLED", "RCH_FORCE_REMOTE"):
            policy_env.pop(name, None)
        policy_env.update({"RCH_CONFIG_DIR": str(policy_root), "RCH_REQUIRE_REMOTE": "0",
                           "RCH_DISABLE_CONFIG_CACHE": "1", "RCH_NO_UPDATE_CHECK": "1",
                           "XDG_STATE_HOME": str(policy_root / "state"),
                           "RCH_LOG_FILE": str(policy_root / "policy.log")})
        git_env = {key: value for key, value in policy_env.items() if not key.startswith("GIT_")}
        boundary, _ = run("exact-worker-policy-root-" + policy,
                          ["git", "init", "--quiet", "--initial-branch=main", "--template=", str(policy_root)],
                          git_env, timeout_seconds=30, working_directory=policy_root)
        require(boundary.returncode == 0, "Could not bound actual private policy discovery")
        refused, _ = run("exact-worker-refuses-" + policy,
                         [str(args.rch), "--json", "exec", "--worker", args.worker, "--",
                          "cargo", "build", "--bin", "absent-policy-target-" + token],
                         policy_env, timeout_seconds=30, working_directory=policy_root)
        result = json.loads(refused.stdout)
        require(refused.returncode != 0 and result.get("outcome") == "refused"
                and result.get("fallback_reason") == reason and result.get("worker_id") is None
                and result.get("remote_exit_code") is None and result.get("admission") is None
                and b"[RCH] local" not in refused.stderr,
                "Explicit native worker permitted configured local execution or lost the refusal")
        require(policy_config.read_bytes() == settings and not (policy_root / "target").exists()
                and not any(physical_target.iterdir()),
                "Policy refusal changed private input or produced local Cargo output")
        tool_refusal, _ = run("compiler-tool-refuses-" + policy,
            [str(args.rch), "--json", "exec", "--require-tool", "cargo-xwin", "--",
             "cargo", "build", "--bin", "absent-policy-target-" + token],
            policy_env, timeout_seconds=30, working_directory=policy_root)
        tool_result = json.loads(tool_refusal.stdout)
        require(tool_refusal.returncode != 0 and tool_result.get("outcome") == "refused"
                and tool_result.get("fallback_reason") == reason
                and tool_result.get("worker_id") is None and tool_result.get("admission") is None
                and tool_result.get("remote_exit_code") is None
                and b"[RCH] local" not in tool_refusal.stderr
                and policy_config.read_bytes() == settings and not (policy_root / "target").exists()
                and not any(physical_target.iterdir()),
                "Verified compiler tool requirement permitted explicit configured local execution")
        if policy == "force-local":
            for closed_stderr in (False, True):
                name = "admission-refusal-closed-" + ("both-streams" if closed_stderr else "stdout")
                case = evidence / name
                case.mkdir()
                argv = [str(args.rch), "--json", "exec", "--worker", args.worker, "--",
                        "cargo", "build", "--bin", "absent-policy-target-" + token]
                (case / "argv.json").write_text(json.dumps(argv) + "\n")
                with (case / "stderr.bin").open("xb") as diagnostics:
                    child = spawn_with_closed_stdout(argv, policy_env,
                        None if closed_stderr else diagnostics, working_directory=policy_root)
                    try:
                        code = child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        (case / "termination.json").write_text(json.dumps({
                            "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
                            "child_stopped": False, "output_complete": False}) + "\n")
                        raise
                (case / "returncode.txt").write_text(str(code) + "\n")
                outcomes.append({"case": name, "returncode": code})
                require(code == 1, "Lost compiler-refusal output was swallowed or panicked")
                if not closed_stderr:
                    transcript = (case / "stderr.bin").read_bytes()
                    sys.stderr.buffer.write(transcript)
                    sys.stderr.buffer.flush()
                    require(b"execution result output failed" in transcript
                            and b"broken pipe" in transcript.lower() and b"panicked" not in transcript,
                            "Compiler-refusal delivery lost the actual output error")
                # Both closed streams expose status only, not diagnostics.
                require(policy_config.read_bytes() == settings and not any(physical_target.iterdir()),
                        "Lost refusal output changed private policy or generated compiler artifacts")

    closure_target = target_base / ("source-content closure " + token)
    closure_target.mkdir()
    closure_env = dict(env)
    closure_env.pop("RCH_CARGO_JSON_STDOUT", None)
    closure_env.pop("RCH_JSON", None)
    closure_env.pop("RCH_OUTPUT_FORMAT", None)
    closure_env.pop("RCH_QUIET", None)
    closure_env["RCH_VISIBILITY"] = "verbose"
    closure_env["RCH_VERBOSE"] = "1"
    closure_env["RCH_DISABLE_CONFIG_CACHE"] = "1"
    closure_env["RCH_NO_UPDATE_CHECK"] = "1"
    closure_env["RCH_LOG_FILE"] = str(evidence / "source-content-closure.log")
    closure_env["CARGO_TARGET_DIR"] = str(closure_target)
    closure_command = ["cargo", "check", "--locked", "-j1", "-p", args.closure_package]
    closure_manifests = {str(path): sha256(path) for path in
                         (closure_source / "Cargo.toml", closure_source / "Cargo.lock")}
    isolated, isolated_case = run("source-content-isolated-closure",
                      [str(args.rch), "--json", "--format", "json", "exec",
                       "--worker", args.worker, "--source-content-receipt", "--"] + closure_command,
                      closure_env, working_directory=closure_source)
    envelope = json.loads(isolated.stdout)
    require(isolated.returncode == 0 and envelope.get("api_version") == "1.0"
            and envelope.get("command") == " ".join(closure_command)
            and envelope.get("outcome") == "completed" and envelope.get("location") == "remote"
            and envelope.get("worker_id") == args.worker and envelope.get("remote_exit_code") == 0
            and envelope.get("error_code") is None,
            "The actual isolated closure did not finish on its admitted worker")
    receipt_prefix = b"[RCH] source content receipt: "
    receipts = [json.loads(line[len(receipt_prefix):]) for line in isolated.stderr.splitlines()
                if line.startswith(receipt_prefix)]
    require(len(receipts) == 1, "The actual isolated closure must emit exactly one source receipt")
    receipt = receipts[0]
    roots = receipt.get("roots", [])
    build_id = receipt.get("build_id", "")
    require(receipt.get("schema") == "rch.source_content_receipt.v1"
            and receipt.get("worker_id") == args.worker and isinstance(build_id, str)
            and build_id.isascii() and build_id.isdecimal() and int(build_id) > 0
            and receipt.get("command_sha256") == hashlib.sha256(" ".join(closure_command).encode()).hexdigest()
            and receipt.get("command_exit_code") == 0
            and receipt.get("root_count") == len(roots) and len(roots) >= 2
            and sum(root.get("is_primary") is True for root in roots) == 1,
            "The actual source receipt lost worker/command/closure identity")
    admitted_journal(envelope, isolated_case, expected_build=build_id)
    primary_root = next(root for root in roots if root.get("is_primary") is True)
    primary_manifests = [file for file in primary_root.get("files", [])
                         if file.get("path") == "Cargo.toml"]
    require(Path(primary_root.get("local_root", "")).resolve(strict=True) == closure_source
            and len(primary_manifests) == 1
            and primary_manifests[0].get("sha256") == closure_manifests[str(closure_source / "Cargo.toml")],
            "The actual source receipt was not bound to the selected caller manifest")
    require(all(root.get("schema") == "rch.source_content_root.v1"
                and any(part.startswith("source-content-" + build_id + "-")
                        for part in Path(root.get("remote_root", "")).parts)
                and root.get("filter_policy", {}).get("checksum_transfer") is True
                and root.get("file_count") == len(root.get("files", []))
                and root.get("file_count", 0) > 0 for root in roots),
            "The actual closure did not bind every selected root to isolated checked sources")
    staging_bases = set()
    for root in roots:
        remote = PurePosixPath(root["remote_root"])
        require(remote.is_absolute(), "The isolated source receipt must name absolute worker roots")
        container = next(index for index, part in enumerate(remote.parts)
                         if part.startswith("source-content-" + build_id + "-"))
        staging_bases.add(str(PurePosixPath(*remote.parts[:container])))
    require(len(staging_bases) == 1, "The isolated closure must use one admitted staging topology")
    staging_base = next(iter(staging_bases))
    topology_line = ("[RCH] topology preflight ok on " + args.worker + " ("
                     + staging_base + " -> " + staging_base + " enforced)").encode()
    require(isolated.stderr.splitlines().count(topology_line) == 1,
            "The actual isolated build did not preflight its receipt-bound staging topology")
    root_fields = ["schema", "ordinal", "project_id", "local_root", "remote_root", "root_hash",
                   "is_primary", "mode", "filter_policy", "file_count", "byte_count", "files"]
    for root in roots:
        preimage = {key: root[key] for key in root_fields}
        encoded = json.dumps(preimage, ensure_ascii=False, separators=(",", ":")).encode()
        require(root.get("content_root") == hashlib.sha256(encoded).hexdigest(),
                "The actual isolated source manifest lost its content-root binding")
    receipt_fields = ["schema", "worker_id", "build_id", "command_sha256", "command_exit_code",
                      "root_count", "roots"]
    preimage = {key: receipt[key] for key in receipt_fields}
    encoded = json.dumps(preimage, ensure_ascii=False, separators=(",", ":")).encode()
    require(receipt.get("receipt_root") == hashlib.sha256(encoded).hexdigest(),
            "The actual isolated source receipt lost its root-set binding")
    require(b"[RCH] canonical checkout convergence skipped for isolated source" in isolated.stderr
            and b"[RCH] repo_updater" not in isolated.stderr
            and b"[RCH] local" not in isolated.stderr,
            "The explicit isolated build entered canonical convergence or local fallback")
    require(all(sha256(Path(path)) == digest for path, digest in closure_manifests.items()),
            "The explicit isolated build changed its retained caller manifests")

    # Exercise general structured output with private user configuration and an
    # explicit socket setting; normal project/system layers may still be read.
    # Background update warming is outside these cases; its existing opt-out
    # prevents an unrelated network/cache side effect, not a release qualification.
    config_state = evidence / "config-output-state"
    config_state.mkdir()
    config_runtime = evidence / "configuration runtime's α \"quoted\""
    config_runtime.mkdir()
    config_path = config_state / "config.toml"
    config_bytes = b"[general]\nenabled = true\n"
    with config_path.open("xb") as config_file:
        config_file.write(config_bytes)
    config_socket = str(config_state / "unused.sock")
    config_env = dict(env)
    config_env.update({"RCH_CONFIG_DIR": str(config_state),
                       "RCH_SOCKET_PATH": config_socket,
                       "XDG_RUNTIME_DIR": str(config_runtime),
                       "RCH_DISABLE_CONFIG_CACHE": "1",
                       "RCH_NO_UPDATE_CHECK": "1",
                       "RCH_LOG_FILE": str(evidence / "config-output.log")})
    config_env.pop("RCH_DAEMON_SOCKET", None)
    config_env.pop("RCH_JSON", None)
    config_env.pop("RCH_OUTPUT_FORMAT", None)
    for action, arguments in [
        ("get", ["config", "get", "general.socket_path"]),
        ("show", ["config", "show"]),
        ("export", ["config", "export", "--format", "json"]),
    ]:
        argv = [str(args.rch), "--json", "--format", "json"] + arguments
        positive, _ = run("config-output-" + action, argv, config_env, timeout_seconds=30)
        document = json.loads(positive.stdout)
        require(positive.returncode == 0 and document.get("success") is True
                and document.get("command") == "config " + action
                and document.get("api_version") == "1.0" and document.get("error") is None,
                "Actual configuration CLI did not deliver its exact successful envelope")
        if action == "get":
            require(document.get("data") == {"key": "general.socket_path", "value": config_socket},
                    "Configuration get was not bound to the isolated socket setting")
        else:
            require(document.get("data", {}).get("general", {}).get("socket_path") == config_socket,
                    "Configuration output did not preserve the isolated socket setting")
        for collect_stderr in (True, False):
            name = "config-closed-output-" + action + ("" if collect_stderr else "-both")
            case = evidence / name
            case.mkdir()
            (case / "argv.json").write_text(json.dumps(argv) + "\n")
            if collect_stderr:
                with (case / "stderr.bin").open("xb") as diagnostics:
                    child = spawn_with_closed_stdout(argv, config_env, diagnostics)
            else:
                child = spawn_with_closed_stdout(argv, config_env, None)
            try:
                code = child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                (case / "termination.json").write_text(json.dumps({
                    "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
                    "child_stopped": False}) + "\n")
                raise
            (case / "returncode.txt").write_text(str(code) + "\n")
            outcomes.append({"case": name, "returncode": code})
            require(code == 1, "Configuration CLI swallowed a failed structured delivery")
            if collect_stderr:
                diagnostics = (case / "stderr.bin").read_bytes()
                sys.stderr.buffer.write(diagnostics)
                sys.stderr.buffer.flush()
                require(b"structured output could not be delivered" in diagnostics
                        and b"broken pipe" in diagnostics.lower() and b"panicked" not in diagnostics,
                        "Configuration output failure lost its cause or panicked")
            # With both streams closed, only the exit status is observable.
            require(config_path.read_bytes() == config_bytes
                    and list(config_state.iterdir()) == [config_path],
                    "Read-only configuration output changed its private input namespace")

    # Initialization writes only inside each retained private user config root.
    # Repeat it to prove that existing files are reported and never replaced.
    for mode, flags in [("simple", []), ("wizard-defaults", ["--wizard", "--non-interactive"])]:
        init_state = evidence / ("config-init-state-" + mode)
        init_state.mkdir()
        init_env = dict(config_env)
        init_env["RCH_CONFIG_DIR"] = str(init_state)
        init_env["RCH_SOCKET_PATH"] = str(init_state / "unused.sock")
        # A real nested Git root bounds project-config discovery even when the
        # admitted evidence directory is inside another checkout. Disable
        # template copying and inherited Git path redirects for this fixture.
        git_env = {key: value for key, value in init_env.items() if not key.startswith("GIT_")}
        git, _ = run("config-init-" + mode + "-private-git-root",
                     ["git", "init", "--quiet", "--initial-branch=main", "--template=", str(init_state)],
                     git_env, timeout_seconds=30, working_directory=init_state)
        require(git.returncode == 0 and (init_state / ".git").is_dir(),
                "The real private configuration discovery boundary could not be established")
        argv = [str(args.rch), "--json", "--format", "json", "config", "init"] + flags
        files = [init_state / "config.toml", init_state / "workers.toml"]
        namespace = files + [init_state / ".git"]
        expected_paths = [str(path) for path in files]
        persisted_env = dict(init_env)
        persisted_env.pop("RCH_SOCKET_PATH", None)
        persisted_env.pop("RCH_DAEMON_SOCKET", None)
        getter = [str(args.rch), "--json", "--format", "json", "config", "get", "general.socket_path"]
        expected_socket_data = {"key": "general.socket_path", "value": str(config_runtime / "rch.sock")}
        # The empty user root binds the real caller default. Use a private cwd
        # so project config cannot mask the setting persisted by initialization.
        default, _ = run("config-init-" + mode + "-caller-default", getter, persisted_env,
                         timeout_seconds=30, working_directory=init_state)
        default_document = json.loads(default.stdout)
        require(default.returncode == 0 and default_document.get("success") is True
                and default_document.get("api_version") == "1.0"
                and default_document.get("command") == "config get"
                and default_document.get("error") is None
                and default_document.get("data") == expected_socket_data,
                "Actual caller default did not honor the retained private runtime directory")
        initial_bytes = None
        for existing in (False, True):
            result, _ = run("config-init-" + mode + ("-existing" if existing else "-fresh"),
                            argv, init_env, timeout_seconds=30)
            document = json.loads(result.stdout)
            require(result.returncode == 0 and document.get("success") is True
                    and document.get("command") == "config init"
                    and document.get("data") == {
                        "created": [] if existing else expected_paths,
                        "already_existed": expected_paths if existing else []},
                    "Actual initialization did not distinguish created and retained files")
            actual_bytes = [path.read_bytes() for path in files]
            require(all(actual_bytes) and sorted(init_state.iterdir()) == sorted(namespace),
                    "Initialization changed its retained configuration/Git namespace")
            if existing:
                require(actual_bytes == initial_bytes, "Repeated initialization replaced existing bytes")
            else:
                initial_bytes = actual_bytes
            persisted, _ = run("config-init-" + mode + ("-existing-socket" if existing else "-fresh-socket"),
                               getter, persisted_env, timeout_seconds=30, working_directory=init_state)
            persisted_document = json.loads(persisted.stdout)
            require(persisted.returncode == 0 and persisted_document.get("success") is True
                    and persisted_document.get("api_version") == "1.0"
                    and persisted_document.get("command") == "config get"
                    and persisted_document.get("error") is None
                    and persisted_document.get("data") == expected_socket_data,
                    "Generated configuration changed the caller's shared socket default")
            require([path.read_bytes() for path in files] == initial_bytes
                    and sorted(init_state.iterdir()) == sorted(namespace),
                    "Reading persisted defaults changed the retained configuration namespace")
        case = evidence / ("config-init-" + mode + "-closed-stdout")
        case.mkdir()
        (case / "argv.json").write_text(json.dumps(argv) + "\n")
        with (case / "stderr.bin").open("xb") as diagnostics:
            child = spawn_with_closed_stdout(argv, init_env, diagnostics)
        try:
            code = child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            (case / "termination.json").write_text(json.dumps({
                "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
                "child_stopped": False}) + "\n")
            raise
        (case / "returncode.txt").write_text(str(code) + "\n")
        diagnostics = (case / "stderr.bin").read_bytes()
        sys.stderr.buffer.write(diagnostics)
        sys.stderr.buffer.flush()
        outcomes.append({"case": case.name, "returncode": code})
        require(code == 1 and b"structured output could not be delivered" in diagnostics
                and b"broken pipe" in diagnostics.lower() and b"panicked" not in diagnostics,
                "Initialization swallowed its acknowledgement failure or panicked")
        require([path.read_bytes() for path in files] == initial_bytes
                and sorted(init_state.iterdir()) == sorted(namespace),
                "Failed initialization acknowledgement changed retained inputs")

    # Admission and URL reporting never contact the daemon/dashboard or launch
    # a browser. Check resolves its private, absent socket and reports
    # not_ready; no fake daemon is substituted. None of these cases compiles.
    # Output delivery failures must reach the same typed exit path as config.
    dashboard_url = "https://dashboard.example.invalid/fleet/"
    for action, arguments, expected_code in [
        ("admit", ["admit", "--", "cargo", "build", "--release"], 0),
        ("web", ["web", "--url", dashboard_url, "--no-open"], 0),
        ("check", ["check"], 2),
    ]:
        require(not Path(config_socket).exists(),
                "The private output-case daemon socket must remain absent")
        argv = [str(args.rch), "--json", "--format", "json"] + arguments
        positive, _ = run("read-only-output-" + action, argv, config_env, timeout_seconds=30)
        document = json.loads(positive.stdout)
        require(positive.returncode == expected_code and document.get("api_version") == "1.0"
                and document.get("command") == action and document.get("success") is True
                and document.get("error") is None,
                "Read-only CLI did not deliver exactly one report with its original exit status")
        data = document.get("data", {})
        if action == "admit":
            require(data.get("command") == "cargo build --release"
                    and data.get("is_compilation") is True
                    and data.get("family") == "cargo_build"
                    and data.get("base_recommendation") == "offload"
                    and data.get("proof_policy") is True
                    and data.get("required", {}).get("needs_cargo") is True,
                    "Actual admission reporter lost its classification or strict policy")
        elif action == "web":
            require(data == {"url": dashboard_url,
                             "agent_endpoint": "https://dashboard.example.invalid/fleet/api/fleet?view=help",
                             "opened": False},
                    "Actual no-open dashboard reporter lost its URL or browser state")
        else:
            # This verifies delivery of an actual unavailable-daemon report,
            # not healthy-daemon/worker readiness or successful compilation.
            require(data.get("status") == "not_ready" and data.get("exit_code") == 2
                    and data.get("daemon") == {"running": False, "pid": None, "uptime_secs": None}
                    and data.get("workers") == {"total": 0, "healthy": 0, "unhealthy": []}
                    and data.get("issues") == ["Daemon not running"],
                    "Readiness check lost its real unavailable-daemon state")
        require(config_path.read_bytes() == config_bytes
                and list(config_state.iterdir()) == [config_path]
                and not Path(config_socket).exists(),
                "Delivered read-only reporting changed its private input namespace")
        for collect_stderr in (True, False):
            name = "read-only-closed-output-" + action + ("" if collect_stderr else "-both")
            case = evidence / name
            case.mkdir()
            (case / "argv.json").write_text(json.dumps(argv) + "\n")
            (case / "cwd.txt").write_text(str(source) + "\n")
            if collect_stderr:
                with (case / "stderr.bin").open("xb") as diagnostics:
                    child = spawn_with_closed_stdout(argv, config_env, diagnostics)
            else:
                child = spawn_with_closed_stdout(argv, config_env, None)
            try:
                code = child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                (case / "termination.json").write_text(json.dumps({
                    "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
                    "child_stopped": False}) + "\n")
                raise
            (case / "returncode.txt").write_text(str(code) + "\n")
            outcomes.append({"case": name, "returncode": code})
            require(code == 1, "Read-only CLI swallowed a failed structured delivery")
            if collect_stderr:
                diagnostics = (case / "stderr.bin").read_bytes()
                sys.stderr.buffer.write(diagnostics)
                sys.stderr.buffer.flush()
                require(b"structured output could not be delivered" in diagnostics
                        and b"broken pipe" in diagnostics.lower() and b"panicked" not in diagnostics,
                        "Read-only output failure lost its cause or panicked")
            # Both closed streams expose only the process status.
            require(config_path.read_bytes() == config_bytes
                    and list(config_state.iterdir()) == [config_path]
                    and not Path(config_socket).exists(),
                    "Read-only reporting changed the private configuration input namespace")

    # These actual dry-run self-tests only report plans against the same absent
    # private daemon socket. They do not qualify canaries, scheduler admission,
    # remote identities or live storm invariants. Smoke may retain a planned
    # JSONL trace in the platform cache; it must never report executed events.
    self_test_env = dict(config_env)
    self_test_env.update({"RCH_LOAD_WAVES": "1", "RCH_LOAD_CONCURRENCY": "1"})
    for mode, flags in [("smoke", []), ("load", ["--load"])]:
        require(not Path(config_socket).exists(),
                "The private self-test daemon socket must remain absent")
        argv = [str(args.rch), "--json", "--format", "json", "self-test",
                "--smoke", "--dry-run"] + flags
        positive, _ = run("self-test-output-" + mode, argv, self_test_env, timeout_seconds=30)
        document = json.loads(positive.stdout)
        require(positive.returncode == 0 and document.get("mode") == mode
                and document.get("dry_run") is True
                and document.get("daemon_reachable") is False
                and isinstance(document.get("run_id"), str) and document["run_id"]
                and "passed" not in document,
                "Dry-run self-test did not deliver one honest plan document")
        if mode == "load":
            require(document.get("executed") is False
                    and document.get("schedulable_workers") == 0
                    and document.get("planned_jobs") == 0
                    and document.get("waves") == 1 and document.get("concurrency") == 1
                    and document.get("reason") == "dry-run: planned the load swarm but executed nothing"
                    and "events" not in document and "invariants" not in document,
                    "Unavailable-daemon load planning manufactured execution or qualification")
        else:
            events = document.get("events", [])
            plan = document.get("plan", {})
            require(document.get("remote_execution_available") is False
                    and document.get("overall_skipped") is True
                    and plan.get("mode") == "smoke" and plan.get("overall_skipped") is True
                    and events and len(events) == len(plan.get("scenarios", []))
                    and all(event.get("event") == "planned"
                            and event.get("run_id") == document["run_id"]
                            and event.get("duration_ms") == 0
                            and "remote_job_id" not in event
                            and "artifact_summary" not in event for event in events),
                    "Dry-run smoke planning manufactured executed or returned-artifact outcomes")
        for collect_stderr in (True, False):
            name = "self-test-closed-output-" + mode + ("" if collect_stderr else "-both")
            case = evidence / name
            case.mkdir()
            (case / "argv.json").write_text(json.dumps(argv) + "\n")
            (case / "cwd.txt").write_text(str(source) + "\n")
            if collect_stderr:
                with (case / "stderr.bin").open("xb") as diagnostics:
                    child = spawn_with_closed_stdout(argv, self_test_env, diagnostics)
            else:
                child = spawn_with_closed_stdout(argv, self_test_env, None)
            try:
                code = child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                (case / "termination.json").write_text(json.dumps({
                    "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
                    "child_stopped": False}) + "\n")
                raise
            (case / "returncode.txt").write_text(str(code) + "\n")
            outcomes.append({"case": name, "returncode": code})
            require(code == 1, "Self-test swallowed a failed structured delivery")
            if collect_stderr:
                diagnostics = (case / "stderr.bin").read_bytes()
                sys.stderr.buffer.write(diagnostics)
                sys.stderr.buffer.flush()
                require(b"structured output could not be delivered" in diagnostics
                        and b"broken pipe" in diagnostics.lower() and b"panicked" not in diagnostics,
                        "Self-test output failure lost its cause or panicked")
            require(config_path.read_bytes() == config_bytes
                    and list(config_state.iterdir()) == [config_path]
                    and not Path(config_socket).exists(),
                    "Dry-run self-test output changed its private configuration/socket namespace")

    # Real OS launch refusal: no fake browser, daemon or replacement executable.
    # A missing launcher must produce one error document, never an earlier
    # success followed by a second document. This is not a browser-open positive.
    browser_path = evidence / "empty-browser-launcher-path"
    browser_path.mkdir()
    browser_env = dict(config_env)
    browser_env["PATH"] = str(browser_path)
    browser_failure, _ = run("web-missing-browser-launcher",
                             [str(args.rch), "--json", "--format", "json", "web", "--url", dashboard_url],
                             browser_env, timeout_seconds=30)
    failure_document = json.loads(browser_failure.stdout)
    failure_error = failure_document.get("error") or {}
    require(browser_failure.returncode == 1
            and failure_document.get("api_version") == "1.0"
            and failure_document.get("command") == "rch"
            and failure_document.get("success") is False
            and failure_document.get("data") is None
            and failure_error.get("code") == "RCH-E504"
            and failure_error.get("message") == "Unexpected internal state"
            and b"panicked" not in browser_failure.stderr,
            "Missing real browser launchers did not produce one failed web envelope")
    failure_details = failure_error.get("details", "")
    if sys.platform in ("darwin", "linux"):
        require("no such file" in failure_details.lower(),
                "Missing native launcher error lost its real OS cause")
    else:
        require(failure_details == "Opening the dashboard browser is unsupported on this platform",
                "Unsupported POSIX browser launch did not preserve its explicit refusal")
    require(list(browser_path.iterdir()) == [] and config_path.read_bytes() == config_bytes
            and list(config_state.iterdir()) == [config_path],
            "Browser launch refusal changed the retained inputs or empty launcher namespace")

    # Dashboard UI query/fragment fields must never absorb the API path. These
    # are actual no-open CLI cases, without a dashboard request or browser.
    for index, (url, endpoint) in enumerate([
        ("https://dashboard.example.invalid/fleet/?tab=workers#selection",
         "https://dashboard.example.invalid/fleet/api/fleet?view=help"),
        ("https://dashboard.example.invalid/?tab=workers#selection",
         "https://dashboard.example.invalid/api/fleet?view=help"),
        ("https://dashboard.example.invalid/team%20α/?view=old#selection",
         "https://dashboard.example.invalid/team%20%CE%B1/api/fleet?view=help"),
        ("http://[::1]:8080/fleet?tab=workers#selection",
         "http://[::1]:8080/fleet/api/fleet?view=help"),
    ]):
        actual, _ = run("web-structured-endpoint-" + str(index),
                        [str(args.rch), "--json", "--format", "json", "web", "--url", url, "--no-open"],
                        config_env, timeout_seconds=30)
        document = json.loads(actual.stdout)
        require(actual.returncode == 0 and document.get("api_version") == "1.0"
                and document.get("command") == "web" and document.get("success") is True
                and document.get("error") is None
                and document.get("data") == {"url": url, "agent_endpoint": endpoint, "opened": False},
                "Actual dashboard endpoint lost path identity or mixed UI query/fragment fields")
        require(config_path.read_bytes() == config_bytes and list(config_state.iterdir()) == [config_path],
                "Dashboard endpoint reporting changed its retained configuration inputs")
    for index, url in enumerate(["https://", "https://dashboard.example.invalid:99999"]):
        # Empty PATH distinguishes the required URL cause from a launcher
        # error; this fixture does not instrument or prove zero launch attempts.
        actual, _ = run("web-malformed-http-url-" + str(index),
                        [str(args.rch), "--json", "--format", "json", "web", "--url", url],
                        browser_env, timeout_seconds=30)
        document = json.loads(actual.stdout)
        failure = document.get("error") or {}
        require(actual.returncode == 1 and document.get("api_version") == "1.0"
                and document.get("command") == "rch" and document.get("success") is False
                and document.get("data") is None
                and failure.get("code") == "RCH-E504"
                and failure.get("message") == "Unexpected internal state"
                and failure.get("details") == "Dashboard URL " + json.dumps(url) + " is not an http(s) URL"
                and b"panicked" not in actual.stderr,
                "Malformed HTTP URL did not preserve the exact validation refusal")
        require(list(browser_path.iterdir()) == [] and config_path.read_bytes() == config_bytes
                and list(config_state.iterdir()) == [config_path],
                "Malformed dashboard URL refusal changed retained inputs")

    # Exercise actual CLI delivery and exit routing in an isolated, initially
    # absent journal namespace. These are not real-worker ownership positives;
    # the real build/failure/recovery cases below retain that responsibility.
    jobs_env = dict(env)
    jobs_state = evidence / "jobs-output-state"
    jobs_env["RCH_STATE_HOME"] = str(jobs_state)
    jobs_env.pop("RCH_JSON", None)
    jobs_env.pop("RCH_OUTPUT_FORMAT", None)
    for mode, flags in [("json", ["--json", "--format", "json"]),
                        ("plain", ["--color", "never"])]:
        argv = [str(args.rch)] + flags + ["jobs"]
        positive, _ = run("jobs-empty-output-" + mode, argv, jobs_env, timeout_seconds=30)
        require(positive.returncode == 0 and json.loads(positive.stdout) ==
                {"jobs": [], "complete": True, "journal_errors": []},
                "Actual job listing did not deliver one complete empty document")

    for mode, flags in [("json", ["--json", "--format", "json"]),
                        ("toon", ["--json", "--format", "toon"]),
                        ("plain", ["--color", "never"])]:
        name = "jobs-closed-stdout-" + mode
        case = evidence / name
        case.mkdir()
        argv = [str(args.rch)] + flags + ["jobs"]
        (case / "argv.json").write_text(json.dumps(argv) + "\n")
        with (case / "stderr.bin").open("xb") as diagnostics:
            child = spawn_with_closed_stdout(argv, jobs_env, diagnostics)
            try:
                code = child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                (case / "termination.json").write_text(json.dumps({
                    "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
                    "child_stopped": False}) + "\n")
                raise
        (case / "returncode.txt").write_text(str(code) + "\n")
        diagnostics = (case / "stderr.bin").read_bytes()
        sys.stderr.buffer.write(diagnostics)
        sys.stderr.buffer.flush()
        outcomes.append({"case": name, "returncode": code})
        require(code == 1 and b"job output could not be delivered" in diagnostics
                and b"broken pipe" in diagnostics.lower() and b"panicked" not in diagnostics,
                "Actual jobs CLI hid output failure or panicked instead of returning exit 1")
    # With both output streams closed, diagnostics cannot be collected. Keep
    # that limitation explicit and require the actual exit path to remain 1.
    name = "jobs-closed-stdout-and-stderr"
    case = evidence / name
    case.mkdir()
    argv = [str(args.rch), "--json", "--format", "json", "jobs"]
    (case / "argv.json").write_text(json.dumps(argv) + "\n")
    child = spawn_with_closed_stdout(argv, jobs_env, None)
    try:
        code = child.wait(timeout=30)
    except subprocess.TimeoutExpired:
        (case / "termination.json").write_text(json.dumps({
            "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
            "child_stopped": False}) + "\n")
        raise
    (case / "returncode.txt").write_text(str(code) + "\n")
    outcomes.append({"case": name, "returncode": code})
    require(code == 1, "Closing stderr as well as stdout changed the actual jobs failure exit")
    require(not (jobs_state / "job-leases").exists(),
            "Read-only job output cases created an initially absent journal directory")

    # A delivered partial listing is still useful when its diagnostic stream
    # breaks. Exercise that actual CLI branch with stdout retained, then prove
    # the corrupt source journal was not rewritten or removed.
    journal_directory = jobs_state / "job-leases"
    journal_directory.mkdir(parents=True)
    corrupt_journal = journal_directory / "corrupt.json"
    corrupt_bytes = b'{"identity":'
    with corrupt_journal.open("xb") as journal:
        journal.write(corrupt_bytes)

    def check_incomplete_listing(stdout):
        listing = json.loads(stdout)
        require(listing.get("complete") is False and listing.get("jobs") == []
                and len(listing.get("journal_errors", [])) == 1,
                "Actual CLI did not deliver one incomplete document with its corrupt journal")
        error = listing["journal_errors"][0]
        require(error.get("path") == str(corrupt_journal)
                and "EOF" in error.get("error", ""),
                "Actual CLI lost the exact corrupt path or parse diagnostic")

    argv = [str(args.rch), "--json", "--format", "json", "jobs"]
    incomplete, _ = run("jobs-incomplete-output-json", argv, jobs_env, timeout_seconds=30)
    check_incomplete_listing(incomplete.stdout)
    require(incomplete.returncode == 1 and b"job listing is incomplete" in incomplete.stderr
            and b"panicked" not in incomplete.stderr,
            "Actual incomplete listing did not retain its deliberate error status and diagnostic")

    name = "jobs-incomplete-closed-stderr"
    case = evidence / name
    case.mkdir()
    (case / "argv.json").write_text(json.dumps(argv) + "\n")
    reader, writer = os.pipe()
    os.close(reader)
    try:
        with (case / "stdout.bin").open("xb") as output:
            child = subprocess.Popen(argv, cwd=source, env=jobs_env,
                                     stdout=output, stderr=writer)
    finally:
        os.close(writer)
    try:
        code = child.wait(timeout=30)
    except subprocess.TimeoutExpired:
        (case / "termination.json").write_text(json.dumps({
            "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
            "child_stopped": False}) + "\n")
        raise
    (case / "returncode.txt").write_text(str(code) + "\n")
    outcomes.append({"case": name, "returncode": code})
    check_incomplete_listing((case / "stdout.bin").read_bytes())
    require(code == 1, "Closed stderr panicked or changed the delivered incomplete listing exit")
    require(corrupt_journal.read_bytes() == corrupt_bytes
            and list(journal_directory.iterdir()) == [corrupt_journal],
            "Incomplete listing changed its retained source journal namespace")

    def blake3(path, case):
        result = subprocess.run([str(args.b3sum), "--no-names", str(path)],
                                capture_output=True, timeout=120)
        key = hashlib.sha256(str(path).encode()).hexdigest() + "-" + uuid.uuid4().hex
        (case / (key + "-b3sum.stdout")).write_bytes(result.stdout)
        (case / (key + "-b3sum.stderr")).write_bytes(result.stderr)
        (case / (key + "-b3sum.returncode")).write_text(str(result.returncode) + "\n")
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
        require(result.returncode == 0, "The real independent BLAKE3 reader failed")
        value = result.stdout.decode().strip()
        require(len(value) == 64 and all(c in "0123456789abcdef" for c in value), "BLAKE3 output is malformed")
        return value

    def check_success(result, case, cached):
        require(result.returncode == 0, "The actual Cargo build or artifact delivery failed")
        rows = [json.loads(line) for line in result.stdout.decode().splitlines()]
        finished = [row for row in rows if row.get("reason") == "build-finished"]
        require(len(finished) == 1 and finished[0].get("success") is True,
                "Actual stdout needs exactly one successful Cargo terminal record")
        selected = {}
        for row in rows:
            if row.get("reason") != "compiler-artifact" or row.get("target", {}).get("name") not in names:
                continue
            if row.get("target", {}).get("kind") != ["bin"] or Path(row["manifest_path"]).resolve() != manifest.resolve():
                continue
            name = row["target"]["name"]
            require(name not in selected, "Actual stdout has ambiguous selected binaries")
            path = Path(row["executable"])
            require(path.is_absolute() and path.is_file() and not path.is_symlink()
                    and path.is_relative_to(physical_target), "Selected executable is not in the actual delivered target tree")
            require(str(path) in row["filenames"], "Selected executable is not an emitted filename")
            binding = row["rch"]
            require(Path(binding["receipt"]["published_output_root"]).resolve() == physical_target,
                    "Caller Cargo target policy differs from the independently bound physical target")
            require(path.is_relative_to(Path(binding["receipt"]["caller_output_root"])),
                    "Advertised executable is not in this invocation's retained delivery copy")
            receipt = Path(binding["receipt"]["path"])
            require(receipt.is_absolute() and receipt.is_file() and not receipt.is_symlink(), "Exact producer receipt is not retained")
            require(blake3(receipt, case) == binding["receipt"]["blake3"], "Producer receipt bytes differ from the binding")
            diagnostic = binding["receipt"]["stderr"]
            diagnostic_path = Path(diagnostic["path"])
            require(diagnostic_path.is_absolute() and diagnostic_path.is_file()
                    and not diagnostic_path.is_symlink()
                    and diagnostic_path.stat().st_size == diagnostic["bytes"]
                    and diagnostic["exit_code"] == 0,
                    "Complete stderr is not retained for the original successful invocation")
            require(blake3(diagnostic_path, case) == diagnostic["blake3"],
                    "Actual retained diagnostic bytes differ from their receipt binding")
            require(blake3(path, case) == binding["executable_blake3"], "Actual executable differs from its publication fingerprint")
            producer_rows = []
            for line in receipt.read_text().splitlines():
                try:
                    producer_rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            require(binding["worker_record"] in producer_rows, "Mapped record is not in the exact real producer receipt")
            require(binding["worker_record"]["target"]["name"] == name
                    and binding["receipt"]["build_id"] > 0
                    and binding["receipt"]["wrapper_id"], "Selected producer identity is incomplete")
            if cached:
                require(row.get("fresh") is True, "Repeat delivery did not exercise an actual cached Cargo output")
            caps, _ = run(name + ("-cached" if cached else "-native"),
                          [str(path), "capabilities", "--json", "--with-exe-hash"], env)
            require(caps.returncode == 0, "Actual native capabilities failed")
            data = json.loads(caps.stdout)
            build = data["data"]["build"]
            require(data.get("ok") is True and data.get("command_id") == "capabilities"
                    and data["data"]["version"] == args.version and build["version"] == args.version
                    and build["git_sha"] == args.git_sha and build["source_digest"] == args.source_digest
                    and build["target"] == args.target and build["profile"] == "release"
                    and build["exe_sha256"] == sha256(path), "Actual executable differs from the independent admitted native build identity")
            selected[name] = path
        require(set(selected) == set(names) and selected[names[0]] != selected[names[1]], "Both actual CLI binaries must be delivered distinctly")
        return selected

    first, first_case = run("fresh-build", command, env)
    paths = check_success(first, first_case, False)
    first_hashes = {name: sha256(path) for name, path in paths.items()}
    first_bindings = [row["rch"]["receipt"] for row in
                      (json.loads(line) for line in first.stdout.decode().splitlines())
                      if row.get("reason") == "compiler-artifact" and "rch" in row]
    require(first_bindings and len({item["wrapper_id"] for item in first_bindings}) == 1,
            "Actual first delivery does not bind one original wrapper")
    wrapper_id = first_bindings[0]["wrapper_id"]
    first_diagnostic = first_bindings[0]["stderr"]
    require(all(item["stderr"] == first_diagnostic for item in first_bindings),
            "Selected records disagree on their original complete stderr receipt")
    diagnostic_path = Path(first_diagnostic["path"])
    diagnostic_bytes = diagnostic_path.read_bytes()
    diagnostic_sha = sha256(diagnostic_path)
    recovery_command = [str(args.rch), "jobs", "recover", wrapper_id, "--cargo-json"]
    recovered, _ = run("completed-cargo-json-recovery", recovery_command, env)
    require(recovered.returncode == 0 and recovered.stdout == first.stdout
            and recovered.stderr == diagnostic_bytes,
            "Completed same-id recovery changed original caller JSON or complete compiler stderr")
    repeat, repeat_case = run("cached-build", command, env)
    repeated_paths = check_success(repeat, repeat_case, True)
    require(all(paths[name] != repeated_paths[name] and sha256(paths[name]) == first_hashes[name] for name in names),
            "Repeat publication reused or changed an earlier invocation's retained executable")
    recovered_after, _ = run("completed-recovery-after-later-build", recovery_command, env)
    require(recovered_after.returncode == 0 and recovered_after.stdout == first.stdout
            and recovered_after.stderr == diagnostic_bytes
            and sha256(diagnostic_path) == diagnostic_sha
            and all(sha256(paths[name]) == first_hashes[name] for name in names),
            "Recovery selected a later invocation's outputs or changed the retained originals")
    # Close the read end of our own new recovery child's actual stdout pipe.
    # This is a real failed write, not an injected recovery receipt or a signal
    # to a shared wrapper/daemon. A later retry must emit the original bytes.
    broken_case = evidence / "completed-recovery-broken-stdout"
    broken_case.mkdir()
    (broken_case / "argv.json").write_text(json.dumps(recovery_command) + "\n")
    with (broken_case / "stderr.bin").open("xb") as diagnostics:
        child = spawn_with_closed_stdout(recovery_command, env, diagnostics)
        try:
            broken_code = child.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            (broken_case / "termination.json").write_text(json.dumps({
                "state": "timeout", "timeout_seconds": 1800, "child_pid": child.pid,
                "child_stopped": False}) + "\n")
            raise
    (broken_case / "returncode.txt").write_text(str(broken_code) + "\n")
    broken_stderr = (broken_case / "stderr.bin").read_bytes()
    sys.stderr.buffer.write(broken_stderr)
    sys.stderr.buffer.flush()
    outcomes.append({"case": "completed-recovery-broken-stdout", "returncode": broken_code})
    require(broken_code == 1 and b"broken pipe" in broken_stderr.lower()
            and b"job output could not be delivered" in broken_stderr
            and b"panicked" not in broken_stderr
            and broken_stderr.startswith(diagnostic_bytes),
            "Closed recovery stdout did not report delivery failure with exit 1 and original diagnostics")
    retry, _ = run("completed-recovery-after-broken-stdout", recovery_command, env)
    require(retry.returncode == 0 and retry.stdout == first.stdout
            and retry.stderr == diagnostic_bytes and sha256(diagnostic_path) == diagnostic_sha,
            "A failed stdout write consumed or changed the retained same-id delivery")
    conflict_command = [str(args.rch), "--json", "jobs", "recover", wrapper_id, "--cargo-json"]
    conflict, _ = run("recovery-machine-envelope-conflict", conflict_command, env)
    # --json requests the normal API error envelope even when the requested
    # raw Cargo recovery mode conflicts. It must not replay compiler records.
    conflict_payload = json.loads(conflict.stdout)
    conflict_error = conflict_payload.get("error") or {}
    require(conflict.returncode == 1 and conflict_payload.get("api_version") == "1.0"
            and conflict_payload.get("command") == "rch"
            and conflict_payload.get("success") is False
            and conflict_payload.get("data") is None
            and "reason" not in conflict_payload
            and conflict_error.get("code") == "RCH-E504"
            and conflict_error.get("details") == "Cargo JSON recovery conflicts with machine envelopes"
            and b"panicked" not in conflict.stderr,
            "Conflicting recovery modes did not return one exact failed machine envelope")
    require(sha256(diagnostic_path) == diagnostic_sha
            and all(sha256(paths[name]) == first_hashes[name] for name in names),
            "Mode-conflict rejection changed the original retained output bytes")
    # The general machine-error branch must handle output failure as well as
    # the jobs-specific delivery path. Reuse the exact conflict command above;
    # its positive case binds the error to the deliberate mode rejection.
    for collect_stderr in (True, False):
        name = ("recovery-conflict-closed-stdout" if collect_stderr
                else "recovery-conflict-closed-stdout-and-stderr")
        case = evidence / name
        case.mkdir()
        (case / "argv.json").write_text(json.dumps(conflict_command) + "\n")
        if collect_stderr:
            with (case / "stderr.bin").open("xb") as diagnostics:
                child = spawn_with_closed_stdout(conflict_command, env, diagnostics)
        else:
            child = spawn_with_closed_stdout(conflict_command, env, None)
        try:
            code = child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            (case / "termination.json").write_text(json.dumps({
                "state": "timeout", "timeout_seconds": 30, "child_pid": child.pid,
                "child_stopped": False}) + "\n")
            raise
        (case / "returncode.txt").write_text(str(code) + "\n")
        outcomes.append({"case": name, "returncode": code})
        require(code == 1, "Closed output changed the general machine-error exit path")
        if collect_stderr:
            diagnostics = (case / "stderr.bin").read_bytes()
            sys.stderr.buffer.write(diagnostics)
            sys.stderr.buffer.flush()
            require(b"Failed to write JSON error response" in diagnostics
                    and b"broken pipe" in diagnostics.lower() and b"panicked" not in diagnostics,
                    "The general machine-error branch hid a delivery failure or panicked")
        # When both streams are closed, only the actual exit status is observable.
        require(sha256(diagnostic_path) == diagnostic_sha
                and all(sha256(paths[name]) == first_hashes[name] for name in names),
                "Closed machine-error output changed the retained compiler delivery")
    paths = repeated_paths
    # Exercise the actual Bash consumer and all its real-stream negatives.
    consume, _ = run("actual-installer-consumer", [sys.executable,
        str(source / "scripts/e2e/source_artifacts_e2e.py"), "--consumer", "bash",
        "--messages", str(repeat_case / "stdout.bin"), "--source", str(source),
        "--evidence-root", str(evidence), "--canonical", str(paths[names[0]]),
        "--alias", str(paths[names[1]]), "--version", args.version, "--git-sha", args.git_sha,
        "--source-digest", args.source_digest, "--target", args.target], env)
    require(consume.returncode == 0, "The actual installer consumer or its real-artifact negatives failed")
    ordinary_env = env.copy()
    ordinary_env.pop("RCH_CARGO_JSON_STDOUT")
    envelope, envelope_case = run("ordinary-machine-envelope",
                      [str(args.rch), "--json", "exec", "--worker", args.worker, "--"] + command, ordinary_env)
    require(envelope.returncode == 0, "The ordinary machine-envelope build failed")
    payload = json.loads(envelope.stdout)
    require(payload.get("outcome") == "completed" and payload.get("location") == "remote"
            and payload.get("worker_id") == args.worker and payload.get("remote_exit_code") == 0,
            "Machine stdout contains compiler records or lacks its exact-worker remote envelope")
    original_admission = admitted_journal(payload, envelope_case)
    terminal_journal = Path(original_admission["journal_path"])
    before_terminal_readback = terminal_journal.read_bytes()
    terminal_readback, _ = run("ordinary-machine-terminal-recovery-readback",
        [str(args.rch), "--json", "jobs", "recover", original_admission["local_wrapper_id"],
         "--timeout-secs", "30"], ordinary_env, timeout_seconds=30)
    require(terminal_readback.returncode == 0, "Actual same-id terminal recovery readback failed")
    recovered = json.loads(terminal_readback.stdout)
    require(recovered.get("status") == "completed" and recovered.get("exit_code") == 0
            and recovered.get("terminal_acknowledged") is True
            and recovered.get("admission") == original_admission
            and recovered.get("identity", {}).get("local_wrapper_id") == original_admission["local_wrapper_id"]
            and recovered.get("identity", {}).get("remote_build_id") == int(original_admission["remote_build_id"]),
            "Recovery mixed old identity, command exit or terminal fields")
    require(terminal_journal.read_bytes() == before_terminal_readback,
            "Already-completed recovery readback rewrote its retained journal")
    # Same-origin journal/reference custody, not SDK/native/slot qualification
    # or reconstruction of the original ExecResultEnvelope/output bytes.
    before_failure, _ = run("jobs-before-genuine-failure", [str(args.rch), "--json", "jobs"], env)
    require(before_failure.returncode == 0, "Actual pre-failure job observation failed")
    before_listing = json.loads(before_failure.stdout)
    require(before_listing.get("complete") is True and before_listing.get("journal_errors") == [],
            "Pre-failure ownership observation has unreadable journals or lacks a complete listing contract")
    prior_ids = {item["lease"]["identity"]["local_wrapper_id"]
                 for item in before_listing["jobs"]}
    missing = "absent-cargo-json-" + token
    failure, _ = run("genuine-cargo-target-failure", ["cargo", "build", "-j1", "--locked", "--release",
        "-p", "franken-snowflake-cli", "--bin", missing, "--message-format=json,json-render-diagnostics"], env)
    require(failure.returncode == 101 and b"error: no bin target named" in failure.stderr
            and missing.encode() in failure.stderr, "Negative case did not reach the real Cargo target-selection failure")
    require(not any(json.loads(line).get("success") is True for line in failure.stdout.decode().splitlines()
                    if line.startswith('{"reason":"build-finished"')), "Compiler failure advertised Cargo success")
    after_failure, failure_jobs_case = run("jobs-after-genuine-failure",
                                          [str(args.rch), "--json", "jobs"], env)
    require(after_failure.returncode == 0, "Actual post-failure job observation failed")
    after_listing = json.loads(after_failure.stdout)
    require(after_listing.get("complete") is True and after_listing.get("journal_errors") == [],
            "Post-failure ownership observation has unreadable journals or lacks a complete listing contract")
    failures = []
    for item in after_listing["jobs"]:
        lease = item["lease"]
        recipe = lease.get("recovery") or {}
        identity = lease["identity"]
        project_root = recipe.get("project_root")
        if (identity["local_wrapper_id"] in prior_ids or lease.get("worker_id") != args.worker
                or lease.get("exit_code") != 101 or lease.get("terminal_acknowledged") is not True
                or lease.get("strict_remote") is not True or recipe.get("exit_code") != 101
                or recipe.get("returned") != 101 or recipe.get("retired") is not True
                or not isinstance(project_root, str) or not Path(project_root).is_absolute()
                or Path(project_root).resolve() != source):
            continue
        diagnostic = recipe.get("cargo_stderr")
        if not diagnostic:
            continue
        path = Path(diagnostic["path"])
        require(path.is_absolute() and path.is_file() and not path.is_symlink(),
                "Observed failed invocation has no regular retained diagnostic log")
        actual_diagnostic = path.read_bytes()
        if b"error: no bin target named" not in actual_diagnostic or missing.encode() not in actual_diagnostic:
            continue
        require(diagnostic["exit_code"] == 101 and diagnostic["bytes"] == len(actual_diagnostic)
                and blake3(path, failure_jobs_case) == diagnostic["blake3"],
                "Actual failed compiler diagnostics contradict their exact receipt")
        failures.append((identity["local_wrapper_id"], actual_diagnostic))
    require(len(failures) == 1, "The genuine failure did not bind one new same-id retained invocation")
    failed_wrapper, failed_diagnostics = failures[0]
    failed_recovery, _ = run("genuine-failure-complete-output-recovery",
                            [str(args.rch), "jobs", "recover", failed_wrapper, "--cargo-json"], env)
    require(failed_recovery.returncode == 101 and failed_recovery.stdout == failure.stdout
            and failed_recovery.stderr == failed_diagnostics,
            "Same-id recovery changed actual compiler failure status, stdout or complete stderr")
    unsupported, _ = run("unsupported-target-selection", ["cargo", "build", "--bins", "--message-format=json"], env)
    require(unsupported.returncode != 0 and not unsupported.stdout
            and b"requires cargo build with literal --bin targets" in unsupported.stderr,
            "Unsupported selection was silently admitted or failed for a different reason")
    require(sha256(shim) == shim_hash and sha256(args.rch) == rch_hash and sha256(args.b3sum) == b3sum_hash,
            "Installed tool bytes changed during acceptance")
    require(all(sha256(Path(path)) == digest for path, digest in source_hashes.items()),
            "Original source/lock/installer bytes changed during acceptance")
    summary = {"scope": "actual-named-cargo-stdout-shim-worker-delivery",
               "rch_sha256": rch_hash, "shim_sha256": shim_hash, "cases": outcomes,
               "physical_target": str(physical_target), "caller_target_alias": str(target_alias),
               "retained_evidence": str(evidence)}
    (evidence / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Cargo stdout real-worker E2E failed: {error}", file=sys.stderr)
        sys.exit(1)
