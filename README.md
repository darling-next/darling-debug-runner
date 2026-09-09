# darling-debug-runner

Runs commands in an isolated process group and writes reproducible debug
bundles. It can detect stalls from log activity, capture `/proc` state and GDB
backtraces, signal matching processes, and run preparation/capture/cleanup
hooks.

Build:

```sh
cargo build --release
```

Capture a process:

```sh
target/release/darling-debug-runner capture \
  --pattern darlingserver \
  --gdb \
  --gdb-cwd ~/work/darling \
  --gdb-executable ~/work/darling-build/src/external/darlingserver/darlingserver
```

Add `--tree` to capture the matched process and all of its descendants. During
`run` or `darling`, combine `--capture-gdb --capture-tree` to do the same on a
timeout or detected stall. Add `--gdb-namespace` when the target runs in a
nested PID namespace; the runner will also attach GDB using the target's
namespace-local PID.

Run a command with a hard timeout:

```sh
target/release/darling-debug-runner run \
  --name example \
  --timeout-seconds 60 \
  -- sleep 120
```

The `darling` subcommand gently shuts down the selected prefix before running
and optionally installs a freshly built `darlingserver`. On timeout, detected
stall, or cancellation it uses `darling shutdown` instead of signaling the
process group.

Existing stall logs are followed from their current end, so old events do not
affect a new run. Use `--terminate-command` with `run` when the target has its
own safe shutdown mechanism.

The runner reports a command that exits unsuccessfully as `RESULT=failed` and
returns a non-zero status without treating it as a stall.

Use `--forward-output` with `run` or `darling` when an enclosing test runner
needs the command's stdout and stderr, not just bundle/result records. Captured
streams are replayed to their corresponding output streams after execution and
cleanup; this is not live streaming. Command failure still returns non-zero.

SIGINT and SIGTERM request cancellation through the runner's normal cleanup
path and produce `RESULT=cancelled` with a non-zero exit status. Cancellation
wakes the runner even with a long polling interval and skips GDB/capture hooks
so the owner can shut down promptly. A configured `--terminate-command` must
succeed and the managed child must exit before cleanup is reported complete;
failure is reported without falling back to a process-group kill.

For prefix-backed commands, use `darling` or supply the prefix owner's
`--terminate-command` explicitly. The generic `run` fallback cannot infer
dependencies such as guests needing a live RPC server during termination.

## Exact images and cores

Opt in before cleanup or runtime restoration can replace the loaded binaries:

```sh
target/release/darling-debug-runner capture \
  --capture-exact --capture-prefix "$DPREFIX" \
  --exact-timeout-seconds 60 --exact-max-mib 512
```

`run` and `darling` accept the same flags and capture on timeout or detected
stall, before termination. Without a prefix, selection uses the existing
PID/pattern and tree options. Prefix selection also finds detached loaders by
their retained prefix directory fd, even when the guest cleared its environment.
It prioritizes guest loaders and refuses to substitute an unrelated process when
no prefix owner is found. Cancellation does not initiate exact capture.

`exact/manifest.json` indexes per-process maps, fd state, registers in `gdb.txt`,
Linux ELF cores, and `image-NNNN` files. Each image records its mapped
device/inode, source method, size, and SHA-256. Images are opened through
`/proc/PID/map_files`, or the target's namespace root with identity verification;
a replacement pathname is not accepted as the old mapped object.

The defaults are **60 seconds plus a 2-second kill grace** and **512 MiB total**
for the exact archive, shared across at most 128 processes. These limits do not
cover legacy capture hooks, ordinary stdout/stderr, or owner shutdown.
`exact/status.txt` remains authoritative if capture is interrupted.
Standalone incomplete capture returns nonzero; `run` retains the payload's
timeout/stall result. Missing images, storage exhaustion, ptrace denial, and
core-generation warnings are incomplete, not fallback success. Linux can refuse
the `vsyscall` page at `0xffffffffff600000`; its actual warning is retained even
when the resulting core's user stacks and registers are usable.

Exact capture requires noninteractive `sudo`, GNU `timeout`, and Python-enabled
GDB. Core memory, mapped files, fd paths, and command diagnostics **can contain
secrets**. Exact mode does not archive an environment blob and redacts values
in the ordinary `env.txt`; this does not make a core safe to publish.

For offline work, use the archived images, never binaries restored into the
current prefix. The manifest maps original image paths to archive filenames.
Mach-O symbolization requires the captured mappings and Mach-O load commands to
derive the image slide; account for the slice offset of a universal binary.
Feed the archived image and its link-time address to `llvm-symbolizer`.
Disable GDB auto-loading and use an empty sysroot for raw core inspection unless
you have reconstructed a sysroot from the archived images. GDB otherwise may
silently read today's mapped files instead of the captured versions.

Opt-in Linux regression (real ptrace, deleted/replaced mappings, scrubbed
prefix-fd ownership, offline core memory, and storage exhaustion):

```sh
cargo build
python3 -B tests/exact_capture.py target/debug/darling-debug-runner
```
