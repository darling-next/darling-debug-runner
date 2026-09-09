# darling-debug-runner

Runs commands in an isolated process group and writes reproducible debug
bundles. It can enforce a hard deadline or an explicitly configured
log-pattern inactivity policy, capture `/proc` state and GDB backtraces, signal
matching processes, and run preparation/capture/cleanup hooks. A `stalled`
result records that policy firing; log silence alone does not prove a hang.

## Darling workspace workflow

For the four supported development scenarios, use the manifest's managed
entrypoint.
From the sibling `darling-workspace` directory, configure a context once:

```sh
mise run dw dev context homebrew --prefix /absolute/path/to/new-prefix
mise run dw dev run homebrew-prepare
mise run dw dev run homebrew-preflight
mise run dw dev run exact-capture
mise run dw dev run homebrew-source
```

A new prefix must be absent or empty. The default runtime is
`homebrew-lz4-source`; the runner is incrementally built in release mode unless
an explicit `--executor` is selected, and archives default to the workspace
parent's `darling-debug` directory. `--dry-run` prints the underlying command
without build, boot, prefix or job creation. `--detach` starts without an
observer; use the printed `mise run dw dev follow JOB` / `mise run dw dev cancel JOB`
commands to reconnect or request owner cleanup.

Runner stdout/stderr and Homebrew log directories register automatically with
the job. Follow streams them and reports phase, paths and last-write age without
classifying quiet periods as hangs. The manifest's `mise run dw ...` and
`mise run west ...` proxy tasks select the pinned environment and forward
arguments unchanged. From the workspace root use
`mise -C darling-workspace run dw ...` or `run west ...`.
Execute advanced prefix-backed tests with
`scripts/west-job.sh start --state-dir DIR -- mise run west test ...`,
then attach `scripts/west-job.sh follow --state-dir DIR`.
Never overwrite/delete a live prefix's binaries: use the owning West shutdown
and deployment transaction, preserving failure evidence.

Each scenario has independent acceptance criteria. Validate SDK identity against
authoritative package metadata and retain provenance evidence. Do not invent
version metadata or disable SDK compatibility checks. Record results and
blockers in Beads and diagnostic archives. See the manifest's
`docs/test-infra.md` for prerequisite, provenance and acceptance contracts.

## Low-level runner interfaces

The standalone capture/run examples below describe supported advanced APIs;
they do not replace West's prefix lifecycle ownership. Build manually only
when using those interfaces outside the managed dev workflow:

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
The optional inactivity policy requires `--stall-log`, `--stall-pattern` and
`--stall-seconds`; `--stall-after-output` can defer arming until a payload
marker. It measures time without a matching event, not general log growth.
Keep that configured result distinct from a diagnosed deadlock.


The runner reports a command that exits unsuccessfully as `RESULT=failed` and
returns a non-zero status without treating it as a stall.

Use `--forward-output` with `run` or `darling` when an enclosing test runner
needs the command's stdout and stderr, not just bundle/result records. Captured
streams are replayed to their corresponding output streams after execution and
cleanup; this is not live streaming. Command failure returns non-zero.

`BUNDLE=...` is published and flushed when the bundle is created, before the
target starts; `RESULT=...` is the completion record. Under `west-job`,
the runner atomically registers its stdout/stderr files in the job state so
the attached observer can stream them without guessing timestamped paths.
Registration does not change process ownership or cancellation behavior.

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
`exact/status.txt` is authoritative if capture is interrupted.
Standalone incomplete capture returns nonzero; `run` retains the payload's
timeout/stall result. Missing images, storage exhaustion, ptrace denial, and
core-generation warnings are incomplete, not fallback success. Linux can refuse
the `vsyscall` page at `0xffffffffff600000`; its actual warning is retained even
when the resulting core's user stacks and registers are usable.

The workspace's `mise run dw dev run exact-capture` is a guest diagnostic with an
intentional payload timeout. Its diagnostic PASS requires the readiness marker,
an identity-hashed guest Mach-O image and structurally complete ELF core for
the same process, registers and successful prefix cleanup. That oracle can pass
while the archive reports `exact_complete=false` for an unreadable
vsyscall mapping. It neither changes standalone incomplete-capture status nor
makes a normal timed-out payload successful.

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
