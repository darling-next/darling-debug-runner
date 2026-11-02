#!/usr/bin/env python3
"""Opt-in Linux integration: python3 tests/exact_capture.py PATH_TO_RUNNER.

Requires a C compiler, Python-enabled GDB, readelf, noninteractive sudo, and
DWDIAG_WORKSPACE pointing to the companion evidence authority.
Exercises real ptrace/core generation and verified stored-payload readers.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import shutil
import time
import uuid

sys.path.insert(0, str(Path(os.environ["DWDIAG_WORKSPACE"]) / "west_commands"))
from evidence_storage import open_payload


FIXTURE = r'''
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int fd = open(argv[1], O_RDONLY);
    struct stat info;
    if (fd < 0 || fstat(fd, &info)) return 2;
    void *image = mmap(NULL, info.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (image == MAP_FAILED || unlink(argv[1])) return 3;
    close(fd);
    size_t bytes = atoi(argv[2]) * 1024UL * 1024UL;
    char *state = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) return 4;
    memset(state, 0x5a, bytes);
    strcpy(state, argv[3]);
    printf("%p\n", state);
    fflush(stdout);
    for (;;) pause();
}
'''


def run_case(runner, root, *, memory_mib, budget_mib):
    prefix = root / "prefix with spaces"
    prefix.mkdir()
    original = b"original mapped object\n" * 4096
    mapped = root / "mapped object"
    mapped.write_bytes(original)
    prefix_fd = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY)
    token = "EXACT_RUNTIME_" + uuid.uuid4().hex
    process = subprocess.Popen(
        [str(root / "mldr"), str(mapped), str(memory_mib), token],
        env={"__mldr_sockpath": f"/proc/{os.getpid()}/fd/{prefix_fd}/.darlingserver.sock"},
        pass_fds=(prefix_fd,), stdout=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    os.close(prefix_fd)
    try:
        assert select.select([process.stdout], [], [], 5)[0], "fixture did not become ready"
        address = process.stdout.readline().strip()
        assert address.startswith("0x"), f"fixture failed: {process.poll()}"
        # The pathname now names a different inode. Capturing it would be a false
        # exact snapshot; the still-mapped deleted object must come from map_files.
        mapped.write_bytes(b"replacement, not the loaded object\n")
        before = time.monotonic()
        result = subprocess.run(
            [str(runner), "capture", "--capture-exact", "--capture-prefix", str(prefix),
             "--name", "prefix-exact", "--bundle-root", str(root / "bundles"),
             "--exact-timeout-seconds", "10", "--exact-max-mib", str(budget_mib),
             "--snapshots", "0"],
            capture_output=True, text=True, timeout=20,
        )
        assert time.monotonic() - before < 15, result.stdout + result.stderr
        bundle = next((root / "bundles").iterdir())
        exact = bundle / "exact"
        manifest = json.loads((exact / "manifest.json").read_text())
        assert manifest["prefix_selection"]["owned_processes"] == 1, manifest
        record, = manifest["processes"]
        assert record["pid"] == process.pid, record
        assert record["ownership"] == "mldr-retained-prefix-fd", record
        assert process.poll() is None, "capture killed the target"
        proc_status = Path(f"/proc/{process.pid}/status").read_text()
        assert "TracerPid:\t0\n" in proc_status, proc_status
        assert "State:\tT" not in proc_status and "State:\tt" not in proc_status, proc_status
        loaded, = [image for image in record["images"] if image["path"] == str(mapped) + " (deleted)"]
        assert loaded["complete"], loaded
        with open_payload(exact / loaded["file"]) as payload:
            archived = payload.read()
        assert archived == original, "captured replacement instead of the mapped inode"
        assert loaded["sha256"] == hashlib.sha256(archived).hexdigest()
        files = [path for path in exact.rglob("*") if path.is_file()]
        assert sum(path.stat().st_size for path in files) <= budget_mib * 1024 * 1024
        assert all(path.stat().st_uid == os.getuid() for path in files), "root-only evidence"
        assert not any(path.name == "environ" for path in files)
        if memory_mib > budget_mib:
            assert not manifest["complete"] and result.returncode != 0, manifest
            assert not record["core"]["complete"], record
        else:
            core = exact / record["core"]["file"]
            with tempfile.NamedTemporaryFile(dir=root, suffix=".core") as decoded:
                with open_payload(core) as payload:
                    shutil.copyfileobj(payload, decoded)
                decoded.flush()
                subprocess.run(["readelf", "-h", decoded.name], check=True, capture_output=True)
                offline = subprocess.run(
                    ["gdb", "-nx", "-nh", "-q", "-batch", "-iex", "set auto-load off",
                     "-c", decoded.name, "-ex", "x/s " + address],
                    capture_output=True, text=True, timeout=10,
                )
                assert token in offline.stdout, offline.stdout + offline.stderr
            with open_payload(exact / "gdb.txt") as payload:
                assert "rax" in payload.read().decode(), "lost register diagnostics"
        print(f"PASS exact-capture memory={memory_mib}MiB budget={budget_mib}MiB "
              f"complete={manifest['complete']} elapsed={time.monotonic() - before:.2f}s")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()


def main():
    runner = Path(sys.argv[1]).resolve(strict=True)
    subprocess.run(["sudo", "-n", "true"], check=True)
    with tempfile.TemporaryDirectory(prefix="exact-capture-contract-") as temporary:
        root = Path(temporary)
        source = root / "fixture.c"
        source.write_text(FIXTURE)
        binary = root / "mldr"
        subprocess.run(["cc", "-g", str(source), "-o", str(binary)], check=True)
        for index, (memory, budget) in enumerate(((1, 32), (48, 16))):
            case = root / str(index)
            case.mkdir()
            (case / "mldr").write_bytes(binary.read_bytes())
            (case / "mldr").chmod(0o755)
            run_case(runner, case, memory_mib=memory, budget_mib=budget)


if __name__ == "__main__":
    main()
