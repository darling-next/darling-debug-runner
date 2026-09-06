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

SIGINT and SIGTERM request cancellation through the runner's normal cleanup
path and produce `RESULT=cancelled` with a non-zero exit status. Cancellation
wakes the runner even with a long polling interval and skips GDB/capture hooks
so the owner can shut down promptly. A configured `--terminate-command` must
succeed and the managed child must exit before cleanup is reported complete;
failure is reported without falling back to a process-group kill.

For prefix-backed commands, use `darling` or supply the prefix owner's
`--terminate-command` explicitly. The generic `run` fallback cannot infer
dependencies such as guests needing a live RPC server during termination.
