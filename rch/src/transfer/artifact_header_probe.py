#!/usr/bin/env python3
"""Read bounded executable-header evidence; never copy or execute artifacts.

This is a candidate worker-side helper for RCH #110, not an installed RCH
entry point. The caller must run it inside the job's existing source-authority
activity lease and supply the exact selected regular-file paths from retrieval
planning. A successful response is evidence, not publication authorization.

The protocol intentionally has no dispatcher-environment or platform override:
recovery must supply the policy captured in its original durable recipe.
"""

import json
import os
import stat
import sys

VERSION = 1
HEADER_BYTES = 64
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_FILES = 16384
MAX_PATH_BYTES = 4096
MAX_DEPTH = 64
MAX_REPLY_BYTES = 8 * 1024 * 1024


class Refused(Exception):
    """The requested evidence cannot be established without guessing."""


def require(condition, detail):
    if not condition:
        raise Refused(detail)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def relative_parts(value):
    require(isinstance(value, str), "artifact path is not a string")
    require(0 < len(value.encode("utf-8")) <= MAX_PATH_BYTES, "invalid artifact path length")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value),
            "control character in artifact path")
    # Reject ambiguous POSIX/Windows spellings rather than opening another path.
    require("\\" not in value and ":" not in value, "ambiguous artifact path")
    parts = value.split("/")
    require(all(part not in ("", ".", "..") for part in parts),
            "artifact path must be a literal relative path")
    require(len(parts) <= MAX_DEPTH, "artifact path exceeds depth limit")
    return parts


def parse_request(raw):
    require(len(raw) <= MAX_REQUEST_BYTES, "request exceeds header-probe limit")
    request = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    require(isinstance(request, dict), "request must be an object")
    require(set(request) == {"version", "nonce", "root", "cargo_target_root", "paths"},
            "unexpected or missing request fields")
    require(type(request["version"]) is int and request["version"] == VERSION,
            "unsupported header-probe version")
    nonce = request["nonce"]
    require(isinstance(nonce, str) and len(nonce) == 32
            and all(char in "0123456789abcdef" for char in nonce), "invalid request nonce")
    for key in ("root", "cargo_target_root"):
        value = request[key]
        if key == "cargo_target_root" and value is None:
            continue
        require(isinstance(value, str) and os.path.isabs(value)
                and len(os.fsencode(value)) <= MAX_PATH_BYTES
                and not any(ord(char) < 32 or ord(char) == 127 for char in value),
                "invalid absolute probe root")
    paths = request["paths"]
    require(isinstance(paths, list) and len(paths) <= MAX_FILES, "too many selected files")
    for path in paths:
        relative_parts(path)
    require(len(set(paths)) == len(paths), "duplicate selected file")
    return request


def generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def same_inode(left, right):
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def open_root(path):
    # /tmp itself can be a symlink on Darwin, and configured target roots can
    # be aliases. Resolve only the explicitly authorized root, never a candidate
    # path. Keep its descriptor and verify that the supplied name still binds it.
    resolved = os.path.realpath(path)
    descriptor = os.open(resolved, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        require(same_inode(os.fstat(descriptor), os.stat(path)), "probe root changed while opening")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_header(root, target, path):
    parts = relative_parts(path)
    opened = [os.dup(root)]
    directory = opened[0]
    chain = []
    file_descriptor = None
    target_alias = target is not None and parts[0] == "target" and len(parts) > 1
    try:
        # The sole permitted in-tree directory alias is the managed Cargo
        # target/ link. Bind it to the caller's separately authorized target
        # descriptor, never to an arbitrary symlink destination. Directories
        # and files below it are still opened with O_NOFOLLOW.
        if target_alias:
            selected = os.stat("target", dir_fd=root, follow_symlinks=True)
            require(same_inode(selected, os.fstat(target)), "target alias has a different owner root")
            directory = os.dup(target)
            opened.append(directory)
            parts = parts[1:]
        for part in parts[:-1]:
            next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                                     | os.O_NOFOLLOW, dir_fd=directory)
            opened.append(next_directory)
            chain.append((directory, part, next_directory))
            directory = next_directory
        file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                                  | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=directory)
        before = os.fstat(file_descriptor)
        require(stat.S_ISREG(before.st_mode), "selected artifact is not a regular file")
        prefix = bytearray()
        wanted = min(HEADER_BYTES, before.st_size)
        while len(prefix) < wanted:
            chunk = os.read(file_descriptor, wanted - len(prefix))
            require(chunk, "selected artifact was truncated while reading its header")
            prefix.extend(chunk)
        after = os.fstat(file_descriptor)
        named = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        require(generation(before) == generation(after) == generation(named),
                "selected artifact changed while reading its header")
        for parent, name, child in reversed(chain):
            require(same_inode(os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(child)),
                    "selected artifact directory changed while reading its header")
        if target_alias:
            require(same_inode(os.stat("target", dir_fd=root), os.fstat(target)),
                    "target alias changed while reading its header")
        return {"path": path, "length": before.st_size, "prefix_hex": prefix.hex()}
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        for descriptor in reversed(opened):
            os.close(descriptor)


def collect(request):
    root = open_root(request["root"])
    target = None
    try:
        if request["cargo_target_root"] is not None:
            target = open_root(request["cargo_target_root"])
        headers = [read_header(root, target, path) for path in request["paths"]]
        require(same_inode(os.fstat(root), os.stat(request["root"])),
                "probe root changed before response")
        if target is not None:
            require(same_inode(os.fstat(target), os.stat(request["cargo_target_root"])),
                    "target root changed before response")
        response = {"version": VERSION, "nonce": request["nonce"],
                    "headers": headers}
        encoded = json.dumps(response, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        require(len(encoded) <= MAX_REPLY_BYTES, "header response exceeds limit")
        return encoded + b"\n"
    finally:
        if target is not None:
            os.close(target)
        os.close(root)


def main():
    try:
        # Detect oversize input without consuming an unbounded SSH stream.
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        request = parse_request(raw)
        response = collect(request)
    except (Refused, OSError, UnicodeError, ValueError, TypeError, AttributeError) as error:
        # No partial success frame; the caller must not fall back to copying.
        sys.stderr.write("RCH_ARTIFACT_HEADER_PROBE_REFUSED: " + str(error) + "\n")
        return 74
    sys.stdout.buffer.write(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
