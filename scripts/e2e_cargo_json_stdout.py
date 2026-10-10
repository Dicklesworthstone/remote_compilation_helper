#!/usr/bin/env python3
"""Qualify opt-in Cargo stdout through the installed shim and real workers.

Run only inside an externally admitted DSR/native lane, after disk and RCH
retain-all admission. Requires a real Snowflake source/build identity, the
canonical PATH Cargo shim, a qualified RCH binary, a real b3sum, and an admitted
RCH_TARGET_BASE. Builds are serial, request one normal worker slot, and retain
every target tree and output. No direct SSH, local compiler, cleanup or mock.
This checks the named-output route and completed same-id stdout recovery;
full installer, wrapper-loss/pending recovery, Windows and
same-invocation live-incumbent/A/A performance acceptance remain separate.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
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
    for name in ("source", "evidence-root", "rch", "b3sum"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("worker", "version", "git-sha", "source-digest", "target"):
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

    def run(name, argv, environment, timeout_seconds=1800):
        case = evidence / name
        case.mkdir()
        (case / "argv.json").write_text(json.dumps(argv) + "\n")
        try:
            result = subprocess.run(argv, cwd=source, env=environment,
                                    capture_output=True, timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            (case / "stdout.bin").write_bytes(error.stdout or b"")
            (case / "stderr.bin").write_bytes(error.stderr or b"")
            (case / "termination.json").write_text(json.dumps({"state": "timeout", "timeout_seconds": timeout_seconds}) + "\n")
            sys.stderr.buffer.write(error.stderr or b"")
            sys.stderr.buffer.flush()
            raise
        (case / "stdout.bin").write_bytes(result.stdout)
        (case / "stderr.bin").write_bytes(result.stderr)
        (case / "returncode.txt").write_text(str(result.returncode) + "\n")
        # Diagnostics are retained in full, including successful builds.
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
        outcomes.append({"case": name, "returncode": result.returncode})
        return result, case

    def spawn_with_closed_stdout(argv, environment, diagnostics):
        # Close the read endpoint before spawning: closing child.stdout after
        # spawn races a child that writes before the parent closes it.
        reader, writer = os.pipe()
        os.close(reader)
        try:
            return subprocess.Popen(argv, cwd=source, env=environment,
                                    stdout=writer,
                                    stderr=writer if diagnostics is None else diagnostics)
        finally:
            os.close(writer)

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
    conflict, _ = run("recovery-machine-envelope-conflict",
                      [str(args.rch), "--json", "jobs", "recover", wrapper_id, "--cargo-json"], env)
    require(conflict.returncode != 0 and not conflict.stdout
            and b"conflicts with machine envelopes" in conflict.stderr,
            "Cargo JSON recovery contaminated a machine envelope or failed for another reason")
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
    envelope, _ = run("ordinary-machine-envelope", [str(args.rch), "--json", "exec", "--"] + command, ordinary_env)
    require(envelope.returncode == 0, "The ordinary machine-envelope build failed")
    payload = json.loads(envelope.stdout)
    require(payload.get("outcome") == "completed" and payload.get("location") == "remote"
            and payload.get("remote_exit_code") == 0, "Machine stdout contains compiler records or lacks its remote envelope")
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
