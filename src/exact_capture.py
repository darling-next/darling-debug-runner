"""Embedded GDB worker. Executed only by the runner's explicit exact-capture mode."""
import gdb
import hashlib
import json
import os
import resource
import re
import stat
import struct
import sys
import time


class Limit(Exception):
    pass


uid, gid, maximum, seconds, requested, *targets = open("config.txt").read().split()
uid, gid, maximum, seconds, requested = map(int, (uid, gid, maximum, seconds, requested))
targets = list(map(int, targets))
selected_identity = {}
ownership = {}
os.umask(0o077)
deadline = time.monotonic() + seconds
# Reserve debugger output, status/configuration and a bounded, repeatedly replaced manifest.
used = sum(os.stat(name).st_size for name in os.listdir(".")) + 1024 * 1024 + 65536
reserve = 2 * 1024 * 1024
manifest = {
    "version": 1,
    "complete": False,
    "requested_processes": requested,
    "limits": {"bytes": maximum, "seconds": seconds, "processes": 128},
    "notes": [
        "No environ or cmdline blob is archived. Prefix discovery reads only ownership markers and server argv[1]. Core memory, mapped files and fd paths may contain secrets.",
        "Mapped files are verified against the stopped process's device/inode; core contains mapped memory, including private modifications.",
        "External writers can change files while the target is stopped; detected changes invalidate that file.",
        "Linux ELF cores plus exact mapped images support offline Mach-O address/slide symbolization; this is not a macOS core format.",
    ],
    "processes": [],
}


def flush_output():
    # os._exit is deliberate for ptrace teardown, but must not discard buffered
    # register dumps or diagnostics. Flush incrementally as well as at final exit.
    for stream in (gdb.STDOUT, gdb.STDERR):
        try:
            gdb.flush(stream)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass


def check():
    if time.monotonic() >= deadline:
        raise Limit("total capture deadline reached")


def own(path):
    os.chmod(path, 0o700 if os.path.isdir(path) else 0o600)
    os.chown(path, uid, gid)


def persist():
    data = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode()
    if len(data) > reserve:
        raise Limit("manifest metadata limit reached")
    # In-place writing avoids reserving two complete manifests. The outer status file
    # remains authoritative if the debugger is killed during this write.
    with open("manifest.json", "wb") as output:
        output.write(data)
    own("manifest.json")


def save(path, data):
    global used
    check()
    if used + reserve + len(data) > maximum:
        raise Limit("total storage limit reached")
    with open(path, "xb") as output:
        output.write(data)
    own(path)
    used += len(data)


def read_small(path, limit=1024 * 1024):
    check()
    with open(path, "rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise Limit("metadata limit reached: " + path)
    return data


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def matches(info, major, minor, inode):
    return (stat.S_ISREG(info.st_mode) and os.major(info.st_dev) == major
            and os.minor(info.st_dev) == minor and info.st_ino == inode)


def copy_image(pid, row, destination):
    global used
    address, permissions, offset, device, inode, *pathname = row.split(None, 5)
    major, minor = (int(value, 16) for value in device.split(":"))
    inode = int(inode)
    record = {"range": address, "permissions": permissions, "offset": offset,
              "device": device, "inode": inode, "path": pathname[0] if pathname else None,
              "complete": False}
    if not inode:
        return record
    candidates = [(f"/proc/{pid}/map_files/{address}", "map_files")]
    # Never resolve in the runner's namespace. Never assume a removed/replaced path
    # still names the mapped object: fstat on the opened handle is mandatory.
    if pathname and pathname[0].startswith("/") and not pathname[0].endswith(" (deleted)"):
        path = pathname[0].replace("\\012", "\n")
        candidates.append((f"/proc/{pid}/root" + path, "namespace-root"))
    errors = []
    for path, method in candidates:
        check()
        descriptor = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            before = os.fstat(descriptor)
            if not matches(before, major, minor, inode):
                raise OSError("opened file does not match mapping device/inode or is not regular")
            if used + reserve + before.st_size > maximum:
                raise Limit("mapped file exceeds remaining total storage")
            digest = hashlib.sha256()
            count = 0
            with os.fdopen(descriptor, "rb") as source:
                descriptor = None
                with open(destination, "xb") as output:
                    own(destination)
                    while True:
                        check()
                        data = source.read(min(1024 * 1024, before.st_size - count + 1))
                        if not data:
                            break
                        if count + len(data) > before.st_size:
                            raise OSError("mapped file grew during copy")
                        output.write(data)
                        digest.update(data)
                        count += len(data)
                after = os.fstat(source.fileno())
            if fingerprint(before) != fingerprint(after) or count != before.st_size:
                raise OSError("mapped file changed during copy")
            used += count
            record.update(complete=True, file=destination, source=method, size=count,
                          sha256=digest.hexdigest(), mtime_ns=before.st_mtime_ns,
                          ctime_ns=before.st_ctime_ns)
            return record
        except (OSError, Limit) as error:
            errors.append(method + ": " + str(error))
            if os.path.exists(destination):
                os.unlink(destination)
            if isinstance(error, Limit):
                break
        finally:
            if descriptor is not None:
                os.close(descriptor)
    record["error"] = "; ".join(errors)
    return record


def valid_core(path):
    size = os.stat(path).st_size
    with open(path, "rb") as source:
        header = source.read(64)
        if len(header) != 64 or header[:4] != b"\x7fELF" or header[4] not in (1, 2):
            return False
        endian = "<" if header[5] == 1 else ">"
        if struct.unpack_from(endian + "H", header, 16)[0] != 4:
            return False
        wide = header[4] == 2
        phoff = struct.unpack_from(endian + ("Q" if wide else "I"), header, 32 if wide else 28)[0]
        entsize, count = struct.unpack_from(endian + "HH", header, 54 if wide else 42)
        if not count or count == 65535 or entsize < (56 if wide else 32) or phoff + entsize * count > size:
            return False
        for index in range(count):
            source.seek(phoff + index * entsize)
            entry = source.read(entsize)
            offset = struct.unpack_from(endian + ("Q" if wide else "I"), entry, 8 if wide else 4)[0]
            length = struct.unpack_from(endian + ("Q" if wide else "I"), entry, 32 if wide else 16)[0]
            if offset + length > size:
                return False
    return True


def prefix_markers(pid):
    """Stream procfs; retain only allowlisted ownership values, never an env blob."""
    allowed = {b"DPREFIX", b"DARLING_PREFIX", b"DARLING_ROOTLESS", b"__mldr_sockpath"}
    markers = {}
    key = bytearray()
    value = bytearray()
    reading_value = False
    retain = False
    total = 0
    with open(f"/proc/{pid}/environ", "rb") as source:
        while True:
            check()
            chunk = source.read(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > 1024 * 1024:
                raise OSError("ownership environment exceeds scan limit")
            for byte in chunk:
                if byte == 0:
                    if retain:
                        markers[bytes(key)] = bytes(value)
                    key.clear()
                    value.clear()
                    reading_value = False
                    retain = False
                elif not reading_value:
                    if byte == 61:
                        reading_value = True
                        retain = bytes(key) in allowed
                    elif len(key) < 64:
                        key.append(byte)
                elif retain:
                    if len(value) >= 8192:
                        raise OSError("ownership marker exceeds scan limit")
                    value.append(byte)
    return markers


def prefix_owner(pid, prefix, prefix_identity):
    process = f"/proc/{pid}"
    executable = os.path.basename(os.readlink(process + "/exe").removesuffix(" (deleted)"))
    try:
        markers = prefix_markers(pid)
    except OSError:
        markers = {}

    def same_prefix(path):
        if not path or not os.path.isabs(path):
            return False
        try:
            info = os.stat(path)
            return (info.st_dev, info.st_ino) == prefix_identity
        except OSError:
            return False

    rootless = markers.get(b"DARLING_ROOTLESS") == b"1"
    if executable == "mldr":
        endpoint = markers.get(b"__mldr_sockpath", b"")
        match = re.fullmatch(rb"/proc/[0-9]+/fd/([0-9]+)/\.darlingserver\.sock", endpoint)
        if match and same_prefix(process + "/fd/" + match[1].decode("ascii")):
            return executable, "mldr-retained-prefix-fd"
    if same_prefix(markers.get(b"DPREFIX")):
        return executable, "DPREFIX"
    if rootless and same_prefix(markers.get(b"DARLING_PREFIX")):
        return executable, "rootless-DARLING_PREFIX"
    if executable == "darlingserver":
        # Server prefix is a structured argv element, never a substring of ps output.
        with open(process + "/cmdline", "rb") as source:
            fields = source.read(16384).split(b"\0", 2)
        if len(fields) >= 3 and same_prefix(fields[1]):
            return executable, "darlingserver-prefix-argument"
    if rootless:
        for name in ("cwd", "exe"):
            try:
                path = os.path.realpath(process + "/" + name)
                if os.path.commonpath((path, prefix)) == prefix:
                    return executable, "rootless-prefix-" + name
            except (OSError, ValueError):
                pass
    return None


def select_prefix_targets():
    global targets, requested
    prefix = os.fsdecode(read_small("prefix.bin", 8192))
    info = os.stat(prefix)
    prefix_identity = (info.st_dev, info.st_ino)
    excluded = set()
    ancestor = os.getpid()
    while ancestor > 1 and ancestor not in excluded:
        excluded.add(ancestor)
        try:
            ancestor = int(read_small(f"/proc/{ancestor}/stat").rsplit(b")", 1)[1].split()[1])
        except OSError:
            break
    found = []
    scanned = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            check()
            if not entry.name.isdigit():
                continue
            scanned += 1
            if scanned > 65536:
                raise Limit("prefix process scan limit reached")
            pid = int(entry.name)
            if pid in excluded:
                continue
            try:
                identity = read_small(f"/proc/{pid}/stat").rsplit(b")", 1)[1].split()[19]
                owned = prefix_owner(pid, prefix, prefix_identity)
                if owned:
                    selected_identity[pid] = identity
                    executable, reason = owned
                    ownership[pid] = reason
                    found.append((0 if executable == "mldr" else 1, -int(identity), pid))
            except (OSError, ProcessLookupError):
                continue
    manifest["prefix_selection"] = {"owned_processes": len(found), "scanned_processes": scanned}
    if not found:
        raise RuntimeError("no-owned-target: no process has exact prefix ownership evidence")
    prioritized = [pid for _, _, pid in sorted(found)]
    prioritized.extend(pid for pid in targets if pid not in ownership and pid not in excluded)
    omitted_input = max(0, requested - len(targets))
    requested = len(prioritized) + omitted_input
    targets = prioritized[:128]
    manifest["requested_processes"] = requested
    persist()


def capture(pid):
    global used
    check()
    directory = f"pid-{pid}"
    os.mkdir(directory)
    own(directory)
    record = {"pid": pid, "complete": False, "images": [], "errors": []}
    if pid in ownership:
        record["ownership"] = ownership[pid]
    manifest["processes"].append(record)
    persist()
    attached = False
    try:
        # Pin process identity across attach; PID reuse must not turn into wrong-target success.
        before = read_small(f"/proc/{pid}/stat")
        identity = before.rsplit(b")", 1)[1].split()[19]
        if pid in selected_identity and selected_identity[pid] != identity:
            raise RuntimeError("process identity changed after prefix discovery")
        gdb.execute(f"attach {pid}")
        attached = True
        after = read_small(f"/proc/{pid}/stat")
        if after.rsplit(b")", 1)[1].split()[19] != identity:
            raise RuntimeError("process identity changed during attach")
        save(directory + "/stat", after)
        maps = read_small(f"/proc/{pid}/maps")
        save(directory + "/maps", maps)
        save(directory + "/status", read_small(f"/proc/{pid}/status"))
        save(directory + "/mountinfo", read_small(f"/proc/{pid}/mountinfo"))
        fds = []
        with os.scandir(f"/proc/{pid}/fd") as entries:
            for entry in entries:
                check()
                if len(fds) >= 4096:
                    raise Limit("fd metadata entry limit reached")
                item = {"fd": entry.name}
                try:
                    item["target"] = os.readlink(entry.path)
                    item["info"] = read_small(f"/proc/{pid}/fdinfo/{entry.name}", 16384).decode("utf-8", "replace")
                except OSError as error:
                    item["error"] = str(error)
                    record["errors"].append("fd state unavailable: " + entry.name)
                fds.append(item)
        save(directory + "/fds.json", (json.dumps(fds, ensure_ascii=True) + "\n").encode())
        images = {}
        for row in maps.decode("utf-8", "surrogateescape").splitlines():
            check()
            columns = row.split(None, 5)
            if len(columns) < 5 or columns[4] == "0":
                continue
            key = (columns[3], columns[4])
            if key in images:
                continue
            if len(images) >= 4096:
                raise Limit("mapped image entry limit reached")
            image = copy_image(pid, row, directory + f"/image-{len(images):04d}")
            images[key] = image
            record["images"].append(image)
        # Native unwinding can fail for Mach-O. Raw per-thread registers and the
        # core retain stack/frame pointers without guessing ABI or frame-chain validity.
        gdb.execute("thread apply all info registers")
        flush_output()
        record["core"] = {"file": directory + "/core", "complete": False}
        persist()
        check()
        available = maximum - used - reserve
        if available < 4096:
            raise Limit("no space remaining for core")
        core = directory + "/core"
        save(core, b"")
        old_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        resource.setrlimit(resource.RLIMIT_FSIZE, (min(available, old_limit[0]) if old_limit[0] != resource.RLIM_INFINITY else available, old_limit[1]))
        try:
            gdb.execute("set use-coredump-filter off")
            gdb.execute("set dump-excluded-mappings on")
            output = gdb.execute("generate-core-file " + core, to_string=True)
            gdb.write(output[:65536])
            flush_output()
            warnings = "\n".join(
                line for line in output.splitlines()
                if any(marker in line.lower() for marker in ("warning", "failed", "cannot"))
            )
            record["core"]["diagnostics"] = output[:8192]
            record["core"]["diagnostics_truncated_characters"] = max(0, len(output) - 8192)
            record["core"]["warnings"] = warnings[:8192]
            record["core"]["warnings_truncated_characters"] = max(0, len(warnings) - 8192)
            if "warning" in output.lower() or "failed" in output.lower() or "cannot" in output.lower():
                record["errors"].append("GDB reported core-generation warnings; see core.warnings and gdb.txt")
            if not valid_core(core):
                raise RuntimeError("core is truncated, unsupported or invalid")
            record["core"].update(complete=not record["errors"], size=os.stat(core).st_size)
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, old_limit)
            if os.path.exists(core):
                own(core)
                used += os.stat(core).st_size
        record["complete"] = not record["errors"] and all(image["complete"] for image in record["images"])
    except Exception as error:
        record["errors"].append(str(error))
    finally:
        detach_error = None
        if attached or gdb.selected_inferior().pid:
            try:
                gdb.execute("detach")
            except Exception as error:
                record["complete"] = False
                record["errors"].append("detach failed: " + str(error))
                detach_error = error
        persist()
        if detach_error is not None:
            raise RuntimeError("detach failed; exiting tracer rather than attaching another process")


try:
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set debuginfod enabled off")
    gdb.execute("set auto-solib-add off")
    if os.path.exists("prefix.bin"):
        select_prefix_targets()
    for target in targets:
        capture(target)
    manifest["complete"] = requested == len(targets) and bool(targets) and all(
        process["complete"] for process in manifest["processes"])
    persist()
    if manifest["complete"]:
        save("complete", b"complete\n")
except Exception as error:
    manifest["complete"] = False
    manifest["error"] = str(error)
    try:
        persist()
    except Exception:
        # Keep the prior explicitly incomplete manifest if metadata exhausted.
        pass
finally:
    # A detach error must not allow GDB's normal quit path to kill the target.
    # Exiting the tracer releases ptrace even on timeout/escalation.
    flush_output()
    os._exit(0 if manifest["complete"] else 1)
