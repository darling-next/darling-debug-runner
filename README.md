# darling-debug-runner

This repository owns the standalone runner source. A West workspace vendors it
at `tools/darling-debug-runner`; in that layout the stable entry point is
`scripts/dwdiag`, which builds the host runner when needed and prints its
tool/binary provenance. Even invoking the shim for help may build it.

The binary has two interfaces:

- `run`, `darling`, `capture` and `signal`: host-command supervision, process
  capture and explicit signaling.
- `diag`: installed-image identity, workload execution and diagnostic analysis.
  The shim supplies `diag`, so `scripts/dwdiag cycle ...` corresponds to
  `target/release/darling-debug-runner diag cycle ...`.

See the West workspace's `docs/tooling.md` for the complete diagnostic command
roster, and `docs/environment.md` for source, state and lane ownership.
Examples below run from the workspace manifest.
`B`, `R`, `P`, source, fixture and log variables denote explicit paths:

| Variable | Meaning |
|---|---|
| `B` / `DWDIAG_BUILD` | Configured normal product build, not runtime authority |
| `R` / global `--runtime-root` | Immutable ordinary product installation |
| `P` / `DWDIAG_PREFIX` | Writable guest state, disjoint from `R` |
| `DW_STATE_ROOT` | Owned durable state, logs, bundles and evidence |

Use absolute paths. Select `R` explicitly (or with `DARLING_RUNTIME_ROOT`),
rather than relying on ambient launcher discovery. Runtime paths are
`R/bin/darling`, `R/bin/darlingserver` and `R/libexec/darling`; neither `P/bin`
nor system libraries copied into `P` provide a runtime. Keep raw prefix spelling
for the product's no-follow and `..` checks.

Set `TMPDIR` to an existing owned directory beneath `DW_STATE_ROOT` before
invocation. Automatically named runner logs otherwise use host temporary
storage; explicit bundle/evidence paths do not relocate them. Pass this run's
log paths to analysis commands: newest-log discovery can select another run.

## Host command supervision and capture

Build the host binary from this crate with `cargo build --release` when using it
directly. This does not build or install Darling.

The companion workspace owns evidence storage, provenance and prefix lifecycle
authorities. Both the sibling West-project and vendored source layouts are
recognized. Set `DWDIAG_WORKSPACE` explicitly for any other layout; an invalid
explicit selection is an error rather than a fallback to a different workspace.

```sh
tools/darling-debug-runner/target/release/darling-debug-runner run \
  --name example --bundle-root "$DW_STATE_ROOT/bundles" \
  --timeout-seconds 60 -- sleep 120
```

`run` starts an isolated process group, supervises timeout/stall triggers and
writes a debug bundle. Preparation, capture, termination and cleanup hooks are
explicit options. An unsuccessful command is `RESULT=failed`, not a stall, and
returns nonzero. A bundle path alone is not proof that every requested capture
succeeded; inspect the command result, capture output and missing/error files.

SIGINT/SIGTERM request cooperative cancellation even during a long poll interval.
The runner executes termination and cleanup before returning. A successful
`--terminate-command` must also let the managed child exit within five seconds;
a zero hook status alone is not cleanup proof. `--forward-output` replays the
closed stdout/stderr logs after execution, while managed jobs register those
logs for live observation before starting the workload.

`run` is prefix-agnostic: ambient `DPREFIX` does not acquire a lease or promise
product shutdown. An inner managed command, such as `west darling-bootstrap`,
owns its own lifecycle. Do not wrap that command in an independent outer prefix
lock. A direct launcher invocation needs a caller-owned shared prefix lease,
explicit `--env DPREFIX="$P"` and normal product shutdown through cleanup.
Global runtime selection alone does not set an arbitrary command's prefix.

Use the prefix-aware `darling` subcommand when the runner should own that
lifecycle. Pass `--dprefix "$P"` explicitly (the default is `~/.darling`). It
uses the ordinary installed launcher, shuts down prior guest state before the
run, retains ownership through hooks and cleanup, and checks product shutdown.
`--darling` selects an installed launcher, not an artifact to stage. This route
does not install a server. `--leave-running-on-stall` deliberately retains the
failed incarnation for inspection; arrange explicit owned cleanup before reuse.

Managed ownership uses a persistent external per-prefix sibling lease, distinct
from `P/.lifecycle.lock`. Never delete it or overlap owners. Nested managed
controllers borrow a validated locked descriptor, not just an environment
marker; runtime children must not retain it. Rootless is the normal product
default; no legacy mode-variable triplet or setuid change is required.
Lifecycle helpers receive the prefix as an explicit argument and do not inherit
`DPREFIX` or `DARLING_PREFIX`; only runtime children advertise guest-state
ownership through those environment markers.

### Capturing an identified process

```sh
tools/darling-debug-runner/target/release/darling-debug-runner capture \
  --pid "$HOST_PID" --bundle-root "$DW_STATE_ROOT/bundles" \
  --gdb --gdb-cwd "$SOURCE_ROOT" --gdb-executable "$R/bin/darlingserver"
```

`capture` observes an existing process; it neither launches a workload nor owns
prefix shutdown. Plain `/proc` snapshots are read-only observations. GDB attach
can stop/resume the target and perturb timing; it is not a passive read. `signal`
is an explicit host-process mutation, not a prefix cleanup operation.

Add `--tree` to capture descendants. During `run` or `darling`, use
`--capture-gdb --capture-tree` for timeout/stall captures. `--gdb-namespace` adds
a namespace-local GDB attach; inspect its output and permissions rather than
assuming attach succeeded. Namespace entry selects the host-visible PID, while
the debugger attaches using the PID visible inside that namespace.

For automatic target selection, `--capture-pattern` matches argv,
`--capture-exe mldr` distinguishes the loader from a pre-exec launcher, and
`--capture-comm` can distinguish a guest program from a guest shell sharing that
loader. Prefer an observed raw-Linux `host_pid=` from the workload over heuristic
matches. An emulated Darwin PID is not a host capture handle.

Ordinary snapshots may occur after a faulting process has exited.
`--capture-on-fatal` attaches early and waits for a fatal signal; merely adding
`--gdb-ex 'handle ...'` does not do that. GDB, ptrace and any noninteractive
privilege/namespace prerequisites must be available. `--capture-on-line` and
`--capture-on-state` provide explicit capture triggers. Silence detection needs
`--stall-log` and its pattern; existing logs are followed from their current end.
Use `--terminate-command` when the command has its own safe shutdown mechanism.

`--gdb-command-file FILE` passes a real GDB script to that pre-attached
debugger with `-x`, so breakpoint conditions and capture logic are not limited
to command-line `-ex` expressions. It requires `--capture-gdb` and
`--capture-on-fatal`; other modes would ignore it and are refused. The fatal
bundle records `fatal-identity-PID.txt` before attaching, with the process start
time, parent PID, executable and command line, so a stop is attributable to one
incarnation even if the PID is later reused. An unreadable identity is written
to the same file as `identity=unavailable` with its error, never as an empty
success; `fatal-identity-error.txt` records a file-write failure.

With `--capture-on-line`, stdout and stderr are followed independently unless an
explicit `--stall-log` is selected. In fatal mode the marker arms the debugger;
it does not terminate the workload at readiness. `--capture-exact` retains the
separate exact-process/core capture contract used by the managed test executor.

`diag unwind --pid HOST_PID --catch SIGNAL` resumes the attached target once
and captures the actual stopped inferior, including a faulting fork child.
Its saved `inferior-pid`, maps and stack bytes refer to that same process.
A failed debugger session or missing stack capture returns nonzero; a signal
line alone is not successful capture. The exact-capture integration script
also reads archived payloads through the companion workspace's verified reader.

These are host captures, not server-state queries through the C++ debugging ABI.
No Rust darling-debug client or LLDB glue is shipped; see the workspace's
`docs/darling-debugger.md` for debugger availability.

`signal --pid HOST_PID --signal TERM` is explicit operator signaling, not prefix
ownership or normal shutdown. On Linux an individual target is pinned with a
pidfd; group mode retains process-group semantics. Prove target ownership first
and check its actual exit afterwards. This mode creates no evidence bundle and
does not turn rescue cleanup into a production PASS.

For an identity already verified through a pinned Linux process handle, use
`signal --pidfd FD --signal TERM`. Pin first, verify that process's identity,
then inherit the same open descriptor into the helper (for example with
Python's `subprocess` `pass_fds`). A descriptor number in another process is not
enough. The helper duplicates that handle with close-on-exec and never reopens
the PID; an exited handle fails rather than selecting a replacement process.
This option is mutually exclusive with PID, pattern and process-group selection.

## Diagnostics: `diag`

Diagnostics return **0** for success/PASS, **1** for a finding or acceptance
failure, **2** for usage errors, and **3** for tool errors. Use `--json` where
supported; not every command/option implements JSON, and command rc alone does
not prove guest acceptance or capture completeness.

## Publishing a complete installed image

Configure the normal product build with absolute `CMAKE_INSTALL_PREFIX=R` and
default `COMPONENTS=stock`. Publication builds ALL and performs the complete
normal CMake install, including install hooks. New source bytes require a fresh
configured `R`; never rewrite an already published image.

```sh
scripts/dwdiag --runtime-root "$R" deploy --build "$B"
```

`deploy` invokes `mise run west darling-build --build-dir B --runtime-root R
--install --with-test-data`. This includes optional lower test data; the ring
workload binary itself belongs to the normal stock CLI installation.
It has no `--prefix` or `--artifact` option and does not install a selected
component set, repair live files or stop/copy/retry into guest state.

For a libsystem_kernel change, dyld must be built with it because dyld includes
a static emulation path. Both must be consumed from the same complete image.
The build-only diagnostic is useful for checking these artifacts:

```sh
DWDIAG_BUILD="$B" scripts/dwdiag build --expect '[sigexc-in '
```

Its default targets are `libsystem_kernel.dylib,dyld`; `--expect` checks strings
in both built files. A present string is not proof the probe executed, and this
command does not publish runtime bytes. A changed source/build cannot identify
what an already running server loaded.

## Installing the workload fixture: `--asset`

`prefix` stages test inputs, never runtime components. By default it copies
`R/libexec/darling/usr/bin/<guest-command-basename>` from the selected installed
image to `P/private/var/tmp/...`, then compares source/destination SHA-256.
Missing installed input fails: there is no ambient build-tree refresh or
continue-on-missing-fixture path.

```sh
scripts/dwdiag --runtime-root "$R" prefix --prefix "$P"
# Or stage an explicitly selected custom fixture:
scripts/dwdiag --runtime-root "$R" prefix --prefix "$P" \
  --asset "$FIXTURE=private/var/tmp/ring_mach_msg_test" \
  --guest-command /private/var/tmp/ring_mach_msg_test
```

`SOURCE=DESTINATION` destinations may be prefix-relative or absolute inside
`P`, but must remain under guest `/private/var/tmp`, without `..` or symlink
traversal. The prefix must be absolute and have no symlink ancestors. Parent
directories are created; `ASSET-INSTALL MATCH` records the digest and
`ASSET-CHECK` names the guest/host paths. Do not put fixtures in `P/usr/bin`:
guest `/usr/bin` can resolve through `/Volumes/SystemRoot` to the host instead.

Finish the previous lifecycle owner before staging. The tool holds the shared
lease for asset mutation and requires an idle prefix, then releases it before
the workload harness takes ownership. `--bootstrap --build B` explicitly runs
ordinary bootstrap first; add `--no-build` to consume an existing installation.
`--guest-toolchain` requires `--bootstrap`; use the real
`darling-command-line-tools` toolchain for guest compilation. No `--mode` means
stop after preparation; an explicit mode runs the workload through the harness.

<a id="diag-cycle----build-deploy-run-and-say-which-instruments-fired"></a>

### `diag cycle` -- build, publish a complete image, run and census

```sh
DWDIAG_BUILD="$B" DWDIAG_PREFIX="$P" \
  scripts/dwdiag --runtime-root "$R" cycle \
  --mode basic --args 20 --wait 400 --repeat 3 --probe sigexc-in,native-exit
```

The normal path publishes the complete image, stages its installed fixture and
runs separate workloads. `--target` adds build-only targets before complete
publication; it does not narrow the install. Further runs of an already
published image use `cycle --skip-build`, which performs no build/install and
rejects `--target`. `--repeat` reuses that image, not a new deployment per run.

`--probe` selects instrument reporting and implies `--fresh`. The census reports
fired/silent registered instruments, not inferred code coverage. `--fresh`
requires evidence in the run's own log that the workload executed, and fails
when it is absent. It is diagnostic execution policy, not guest environment or
a verdict-cache override: this path does not invoke West test's verdict cache.
Retain distinct logs and freshness witnesses for repeated runs.

Default-off diagnostic options:

- `--capture-wchan`: samples prefix-owned host processes once a second,
  including the boot wait. On failure it prints sample count, each PID's last
  observed state and the last eight raw samples. The buffer resets for each
  iteration and is bounded; it is not a complete process history. No samples
  does not prove no process blocked, and host sampling is not zero-perturbation.
- `--gap-seconds N`: spaces workload runs; it is neither proof of cleanup nor a
  remedy for overlapping lifecycle owners.
- `--freeze-on-fail`: retains the failed incarnation and stops the series for
  inspection. Follow the harness's printed cleanup procedure before reuse.
- `--provenance`: reports selected mutable build identity separately from the
  immutable installed-image receipt. `--require-canonical` refuses unverified
  installed bytes or dirty/unknown recorded source provenance; it does not
  replace a completed workload oracle.

### `diag watch` -- kernel signal dispositions against the run log

```sh
DWDIAG_PREFIX="$P" scripts/dwdiag --runtime-root "$R" watch \
  --mode basic --args 20 --pattern ring_mach_msg_test
```

Unlike `capture` or `processes`, `watch` launches a fresh workload cycle against
the existing installation (no build/install), then samples the discovered
host target's `SigCgt`, `SigBlk` and log size. Prefer its workload-declared
`host_pid=` or an explicit `--pid` over argv discovery. Counts/transitions are
observations, not a completion oracle; this is not an attach-only observer.

## The verdict reports the workload's own exit status

```sh
scripts/dwdiag --runtime-root "$R" verdict --prefix "$P" \
  --mode sem_timed --args "300 1" --wait 400 --repeat 3
scripts/dwdiag --runtime-root "$R" suite --prefix "$P" --wait-base 400 \
  --require-zero-creations --retry-failed-rows false \
  --record-evidence "$DW_STATE_ROOT/evidence/suite.json" \
  -- 'sem_ready 2 :: sem_block 100 1 :: basic 20'
```

Stage the fixture first. `verdict` and `suite` delegate lifecycle to the boot
harness (`--boot-runner`, default `scripts/darling-boot-run.sh` relative to the
caller). Prerequisite checks inspect selected guest upper/installed lower paths;
they do not create missing inputs or prove guest execution.

PASS requires the workload's own completed `RING_MACH_TEST mode=... pass=1`
oracle, not its start line, log growth or an instrument hit. The guest wrapper
prints `__DWDIAG_RC`; classification distinguishes `CRASH <SIG>` (`128+N`),
`EXIT rc=N`, `HANG` (no exit status), `NO-RUN`, and boot failures. Inspect the
reported reason and original log. A rescue cleanup or oracle hit cannot turn
failed product shutdown into clean acceptance. The cycle stops before another
prefix-backed run after a reported lifecycle failure.

### `--repeat N`: retain the whole distribution

`verdict --repeat N` prints each run's verdict and a `STABILITY` summary; success
requires every run to pass. Retain every `LOG=` path and verdict rather than
promoting one passing observation to repeatability. Suite retries are separate
attempts (`ROW-RETRY`); preserve both attempts even if the final row passes.

## Watchdogs: `--wait-base` must cover the workload's own duration

`verdict --wait`, `cycle --wait` and `suite --wait-base` set the harness watchdog,
not a polling interval. Choose the limit for the workload and machine, retaining
it with the verdict. A `WATCHDOG?` hint means measurement may have ended too
early; it is not a demonstrated product deadlock. No fixed duration guarantees
completion for every workload.

`suite --record-evidence PATH` writes a **new standalone** workload-evidence
receipt with runtime fingerprint and suite results. It requires an existing
parent and unused filename. It never modifies the immutable installation
receipt; there is no `--record-receipt` option. Preserve original logs and cleanup
evidence alongside the summary.

## Self-attributing run logs (`RUN-ENV` / `[dwdiag-env ...]`)

`cycle`, `verdict` and `env --prefix P` report the selected installed-image
fingerprint and guest prefix. Compare the run's own digests before interpreting
differences. `RUN-ENV` covers a fixed diagnostic subset, not every mapped image.
A build-tree hash is not installation identity; establish missing identity
independently or mark it unknown.

The CLI `installation_identity` summarizes receipt/path/SHA, artifact count,
source revision/dirty state and provenance; it is not an inventory dump. The
schema-2 installation receipt inventories the complete actual image, including
normal install-hook files and actual CMake manifest hashes. Mutable build or
source-review identity cannot substitute for installed-image evidence.

Source review is tracked-only: untracked files are excluded and not collected.
Stage explicit new owned files before review/package; unstaged tracked diffs
are included. There are no `--tracked-only` or `--stage-new-files` switches.
Retain the receipt, `source-review.json`, manifest, tracked working/staged diffs
and index/SHA identity. This is not untracked-byte backup or portable Git closure.

## `diag witness` — which instruments spoke, and which stayed silent

```sh
scripts/dwdiag witness --log "$RUN_LOG" --json
```

The `INSTRUMENTS` registry in `src/diag.rs` defines the census, hit counts and
sample lines. Keep that registry aligned with instrument output. A zero means
no matched record in the selected input, not that the code never ran. Disabled
probes, exhausted budgets, missing streams or unreadable input are not measured
absence of behavior. `courier` distinguishes unmeasured transport rows from
measured zero; retain its instrumentation/identity warnings.

## `diag evidence` — which bytes of a run's logs are actually that run's

```sh
scripts/dwdiag evidence --state-dir "$JOB_STATE" --json
scripts/dwdiag job --state-dir "$JOB_STATE"
```

For managed jobs, `evidence-manifest` records the run start, prefix and registered
logs' pre-run offsets. The job's `rc` file supplies the end window. The job's own
log is read from zero; registered logs contribute their scoped suffix, while
unregistered files must belong to the run's time window. No manifest means no
guessed log selection.

| State | Meaning | Empty census is a measured zero? |
|---|---|---|
| `measured` | Registered windows readable and complete | Yes |
| `partial` | A registered log rotated/truncated past its saved offset | No |
| `unavailable` | Registered log missing or unreadable | No |
| `no-evidence` | Instrument records only outside the run's window | No |
| `unscoped` | No manifest; no log guessed/read | No |

`job` prints the state first and performs the census only for measured/partial
selection. These managed-job manifests are not a guarantee about generic `run`
bundle layout. Finalized `.zst` payloads can be read through their logical raw
paths by the runner; preserve missing-item reasons and original metadata.

Top-level `run`, `darling` and `capture` apply the shared
`scripts/darling-evidence.py compress --recursive` policy to their new owned
bundle after capture writers, hooks and tracers close. The external live job
log stays raw. Control metadata stays plain; beneficial diagnostic payloads
retain logical paths through immutable verified indexes. `storage-report.jsonl`,
`summary-storage-errors.txt` and `summary-storage-status.txt` record policy
decisions and failures. `STORAGE=processed` does not claim every file compressed:
the helper may retain small, incompressible or still-written files with reasons.
Explicit `--leave-running-on-stall` defers archival instead of finalizing live
output. `RESULT` remains the command/capture verdict; a storage error returns
tool-error status 3 only when that verdict otherwise succeeded. Existing
same-name bundle paths are refused rather than reused or overwritten.

## Progress, crash decoding and process ownership

```sh
scripts/dwdiag progress --log "$RUN_LOG" --guest-log "$GUEST_LOG" \
  --server-log "$SERVER_LOG" --mode basic
scripts/dwdiag crash --log "$RUN_LOG" --binary "$IMAGE"
scripts/dwdiag symbolize --binary "$IMAGE" --addr "$IMAGE_VIRTUAL_ADDRESS"
scripts/dwdiag processes --prefix "$P" --list --json
```

`progress` joins workload, loader, published/serviced plane operations, wake
channels, courier misses and crash evidence. `--min-plane-publishes N` is an
explicit baseline tripwire, not proof of a healthy boot. Old/unknown wake labels
are not doorbell evidence. Missing gated courier records do not prove no bundle
was lost. Server stderr may live in `P/private/var/log/dserver.log`, not the
workload log. Prefer this run's explicit `--server-log`, or verify that the
announced run-derived path and time boundary match the captured run. If no
matching log is available, report missing server evidence; never replace it
with an unrelated prefix or an ambient default.
Counts from separate clocks do not establish interleaved event ordering.

`IMAGE` must be the actual reporting image; a verified server reporter uses
`R/bin/darlingserver`. Marker spelling alone does not establish that identity.

`crash` can attribute guest fatal-handler PCs and stack candidates through the
captured mappings. Stack words that resolve to symbols remain candidates, not
necessarily a backtrace. It also decodes server crash signals and log backtrace
offsets against the supplied binary. `symbolize`/`crash` use host symbol and
disassembly tools; inspect their errors. An inlined or absent anchor such as
`dserver_crash_probe` may prevent offset derivation: do not fit an arbitrary base
to make the result look plausible. `symbolize --addr` takes an image virtual
address, not an ASLR runtime PC or raw file offset; account for mappings, Mach-O
segments and universal slices before using it.

`processes` is a read-only census, not shutdown or ownership acquisition. It
identifies a prefix through retained directory descriptors (device/inode) or
explicit `DPREFIX`/`DARLING_PREFIX` environment, excluding its own PID and
ancestor chain. Executable path, process name and argv alone do not establish
prefix ownership when installations are shared. It reports exe/argv as context
and returns nonzero for observed owners. Inaccessible `/proc` state and races
limit observation: a zero census alone is not lifecycle cleanup proof. Reuse
requires the lifecycle owner's completed shutdown and cleanup evidence.

## Source-owned regression references

These references describe existing checks, not results from this documentation
change:

- `src/diag.rs` unit tests exercise registry/sample matching, diagnostic parsing,
  workload evidence and test-asset destination restrictions.
- `src/evidence.rs` tests cover compressed logical-path reading, seekable core
  access and corrupt archive errors.
- `../../tests/run-dwdiag-runner-tests-contract.sh` builds/tests the host crate
  and drives the five evidence states through synthetic managed-job fixtures;
  it is not guest runtime acceptance.

Guest/workload acceptance still requires exercised commands, actual image
identity, completed workload oracles and owned cleanup. No source-only check or
historical PASS establishes those facts for a new image.
