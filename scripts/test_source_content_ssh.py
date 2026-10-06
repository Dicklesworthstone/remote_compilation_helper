#!/usr/bin/env python3
"""Exercise the exact Rust receipt policy through real OpenSSH and rsync.

Linux regression fixture, not a fleet test. sshd runs in inetd mode for each
ProxyCommand: no listening socket, persistent daemon, or user SSH config edits.
The fixture's ephemeral keys are never used outside these local connections.
Requires rustc, rsync >=3.2.4, ssh, ssh-keygen, sshd and passwordless sudo.
"""

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import subprocess
import tempfile


def run(argv, *, check=True, timeout=30):
    result = subprocess.run(argv, capture_output=True, timeout=timeout)
    if check and result.returncode != 0:
        raise AssertionError(
            f"{shlex.join(map(str, argv))}: exit {result.returncode}\n"
            f"{result.stdout.decode(errors='replace')}\n"
            f"{result.stderr.decode(errors='replace')}"
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    repository = Path(__file__).resolve().parents[1]
    module = repository / "rch/src/transfer/source_content_barrier.rs"
    for tool in ("rustc", "rsync", "ssh", "ssh-keygen", "sudo"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required test tool is missing: {tool}")
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not Path(sshd).is_file():
        raise RuntimeError("required test tool is missing: sshd")
    banner = run(["rsync", "--version"]).stdout.decode()
    version = re.search(r"version (\d+)\.(\d+)\.(\d+)", banner)
    if version is None or tuple(map(int, version.groups())) < (3, 2, 4):
        raise RuntimeError(f"this modern-rsync fixture requires >=3.2.4: {banner}")
    (args.evidence / "versions.txt").write_bytes(
        banner.encode() + run(["rustc", "--version"]).stdout + run(["ssh", "-V"]).stderr
    )
    records = []
    with tempfile.TemporaryDirectory(prefix="rch-receipt-ssh-") as temporary:
        root = Path(temporary)
        # Both the test executable and the transport probe import the exact
        # production policy. There is no Python copy of its acceptance logic.
        driver = root / "probe.rs"
        driver.write_text(
            f"#[path = {json.dumps(str(module))}]\nmod source_content_barrier;\n"
            + r'''
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args[1] == "ssh" {
        println!("{}", source_content_barrier::ssh_command(&args[2]));
    } else {
        use std::os::unix::process::ExitStatusExt;
        let code: i32 = args[2].parse().unwrap();
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: std::fs::read(&args[3]).unwrap(),
            stderr: std::fs::read(&args[4]).unwrap(),
        };
        if let Err(error) = source_content_barrier::verify_output(&output) {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
'''
        )
        probe, tests = root / "probe", root / "policy-tests"
        run(["rustc", "--edition=2024", "-Dwarnings", str(driver), "-o", str(probe)], timeout=120)
        run(["rustc", "--edition=2024", "-Dwarnings", "--test", str(driver), "-o", str(tests)], timeout=120)
        test_output = run([str(tests), "--nocapture"])
        (args.evidence / "policy-tests.log").write_bytes(test_output.stdout + test_output.stderr)
        user = pwd.getpwuid(os.getuid()).pw_name
        for name in ("host", "client", "wrong-host", "wrong-client"):
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)])
        shutil.copyfile(root / "client.pub", root / "authorized_keys")
        server = root / "sshd_config"
        server.write_text(
            f"HostKey {root}/host\nAuthorizedKeysFile {root}/authorized_keys\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "PubkeyAuthentication yes\nUsePAM yes\nStrictModes no\n"
            "PermitRootLogin prohibit-password\nPrintMotd no\nPrintLastLog no\n"
            "LogLevel ERROR\n"
            f"AllowUsers {user}\nPidFile {root}/unused-pid\n"
        )
        # Only the isolated runner's privilege-separation directory is needed;
        # -i never binds a port and exits with its one SSH connection.
        run(["sudo", "-n", "mkdir", "-p", "/run/sshd"])
        run(["sudo", "-n", sshd, "-t", "-f", str(server)])
        config = root / "ssh_config"
        proxy = shlex.join(["sudo", "-n", sshd, "-i", "-e", "-f", str(server)])
        config.write_text(
            f"Host *\n  ProxyCommand {proxy}\n  User {user}\n"
            "  UserKnownHostsFile /dev/null\n  GlobalKnownHostsFile /dev/null\n"
            "  HostKeyAlgorithms ssh-ed25519\n  IdentitiesOnly yes\n"
            "  ControlMaster no\n  LogLevel INFO\n"
        )
        host = "rch-receipt-fixture"

        def transport(*, fixed=True, known_hosts=None, strict="accept-new", key="client"):
            command = shlex.join([
                "ssh", "-i", str(root / key), "-o", f"StrictHostKeyChecking={strict}",
                "-o", "BatchMode=yes", "-F", str(config),
            ])
            if known_hosts is not None:
                command += " " + shlex.join(["-o", f"UserKnownHostsFile={known_hosts}"])
            if fixed:
                command = run([str(probe), "ssh", command]).stdout.decode().rstrip("\n")
            return command

        def barrier(label, source, destination, *, accepted, rsync_path="rsync", **ssh):
            command = [
                "rsync", "-azn", "--checksum", "--itemize-changes", "--out-format=%i\t%n",
                "--no-owner", "--no-group", "--delete", "-e", transport(**ssh),
                "--rsync-path", rsync_path, f"{source}/", f"{host}:{destination}",
            ]
            result = run(command, check=False)
            stdout, stderr = root / "stdout", root / "stderr"
            stdout.write_bytes(result.stdout)
            stderr.write_bytes(result.stderr)
            verdict = run([str(probe), "verify", str(result.returncode), str(stdout), str(stderr)], check=False)
            record = {
                "case": label, "rsync_exit": result.returncode,
                "accepted": verdict.returncode == 0,
                "stdout": result.stdout.decode(errors="replace"),
                "stderr": result.stderr.decode(errors="replace"),
                "reason": verdict.stderr.decode(errors="replace"),
            }
            records.append(record)
            (args.evidence / "transport.json").write_text(json.dumps(records, indent=2) + "\n")
            assert record["accepted"] == accepted, record
            print(f"PASS {label}: rsync={result.returncode}, accepted={record['accepted']}", flush=True)
            return result

        for name in ("plain", "p q", "x:y"):
            source, destination = root / "source" / name, root / "worker" / name
            source.mkdir(parents=True)
            destination.mkdir(parents=True)
            (source / "input.rs").write_bytes(b"same original source\n")
            shutil.copy2(source / "input.rs", destination / "input.rs")
            old = barrier(f"{name}: original notice reproduces refusal", source, destination, accepted=False, fixed=False)
            assert old.returncode == 0 and b"Permanently added" in old.stderr
            for attempt in range(3):
                fixed = barrier(f"{name}: repeated clean barrier {attempt}", source, destination, accepted=True)
                assert fixed.returncode == 0 and fixed.stderr == b""
            stat = (destination / "input.rs").stat()
            (destination / "input.rs").write_bytes(b"DIFF original source\n")
            os.utime(destination / "input.rs", ns=(stat.st_atime_ns, stat.st_mtime_ns))
            assert stat.st_size == (destination / "input.rs").stat().st_size
            delta = barrier(f"{name}: same-size same-mtime corruption", source, destination, accepted=False)
            assert delta.returncode == 0 and b"input.rs" in delta.stdout
            shutil.copy2(source / "input.rs", destination / "input.rs")
            for notice in ("rsync integrity warning", "Warning: Permanently added 'worker' (ED25519) to the list of known hosts."):
                remote = f"printf '%s\\n' {shlex.quote(notice)} >&2; exec rsync"
                warning = barrier(f"{name}: remote stderr is not suppressed: {notice}", source, destination, accepted=False, rsync_path=remote)
                assert warning.returncode == 0 and notice.encode() in warning.stderr
            failed = barrier(f"{name}: remote command failure", source, destination, accepted=False, rsync_path="false")
            assert failed.returncode != 0
            (destination / "extra.rs").write_text("unselected extra source")
            deletion = barrier(f"{name}: remote deletion delta", source, destination, accepted=False)
            assert deletion.returncode == 0 and b"*deleting" in deletion.stdout
        wrong_hosts = root / "wrong_known_hosts"
        wrong_hosts.write_text(f"{host} {(root / 'wrong-host.pub').read_text()}")
        changed = barrier("changed host key is still a fatal visible error", source, destination, accepted=False, known_hosts=wrong_hosts)
        assert changed.returncode != 0 and b"REMOTE HOST IDENTIFICATION HAS CHANGED" in changed.stderr
        unknown = barrier("strict untrusted host still refuses", source, destination, accepted=False, strict="yes")
        assert unknown.returncode != 0 and b"Host key verification failed" in unknown.stderr
        denied = barrier("authentication errors remain visible", source, destination, accepted=False, key="wrong-client")
        assert denied.returncode != 0 and b"Permission denied" in denied.stderr
    print(f"PASS: {len(records)} real SSH/rsync cases; exact Rust policy tests passed", flush=True)


if __name__ == "__main__":
    main()
