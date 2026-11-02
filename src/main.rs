mod exact;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getpgid};
use regex::Regex;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct Cancellation {
    reader: UnixStream,
    signals: [signal_hook::SigId; 2],
}

impl Cancellation {
    fn install() -> Result<Self> {
        let (reader, writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        let interrupt = signal_hook::low_level::pipe::register(
            signal_hook::consts::SIGINT,
            writer.try_clone()?,
        )?;
        let terminate =
            match signal_hook::low_level::pipe::register(signal_hook::consts::SIGTERM, writer) {
                Ok(id) => id,
                Err(error) => {
                    signal_hook::low_level::unregister(interrupt);
                    return Err(error.into());
                }
            };
        Ok(Self {
            reader,
            signals: [interrupt, terminate],
        })
    }

    fn requested(&mut self) -> Result<bool> {
        match self.reader.read(&mut [0]) {
            Ok(1) => Ok(true),
            Ok(_) => bail!("cancellation pipe closed"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn wait(&self, seconds: u64) -> Result<()> {
        let mut fds = [PollFd::new(self.reader.as_fd(), PollFlags::POLLIN)];
        let timeout = PollTimeout::try_from(Duration::from_secs(seconds))?;
        match poll(&mut fds, timeout) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        for id in self.signals {
            signal_hook::low_level::unregister(id);
        }
    }
}

#[derive(Parser)]
#[command(about = "Run and capture local or Darling debugging experiments")]
struct Cli {
    /// Ordinary product installation, independent of writable guest state.
    #[arg(long, global = true)]
    runtime_root: Option<PathBuf>,
    #[command(subcommand)]
    command: RunnerCommand,
}

mod diag;

static RUNTIME_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

fn select_runtime_root(path: PathBuf) -> Result<()> {
    let path = expand_home(&path);
    let absolute = if path.is_absolute() { path } else { std::env::current_dir().context("resolving relative runtime root")?.join(path) };
    let selected = fs::canonicalize(&absolute).unwrap_or(absolute);
    let _ = RUNTIME_ROOT.set(selected);
    Ok(())
}

pub(crate) fn runtime_root() -> Result<&'static Path> {
    if RUNTIME_ROOT.get().is_none() {
        if let Some(root) = std::env::var_os("DARLING_RUNTIME_ROOT") {
            select_runtime_root(PathBuf::from(root))?;
        } else {
            let launcher = std::env::var_os("DARLING_LAUNCHER").map(PathBuf::from).or_else(|| {
                std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths)
                    .map(|path| path.join("darling")).find(|path| fs::metadata(path)
                        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0).unwrap_or(false)))
            }).context("no installed Darling selected; pass --runtime-root ROOT")?;
            let launcher = fs::canonicalize(expand_home(&launcher)).context("resolve installed launcher")?;
            if launcher.file_name().and_then(|name| name.to_str()) != Some("darling")
                || launcher.parent().and_then(Path::file_name).and_then(|name| name.to_str()) != Some("bin") {
                bail!("cannot identify an ordinary installation from {}; pass --runtime-root", launcher.display());
            }
            select_runtime_root(launcher.parent().and_then(Path::parent).context("launcher installation root")?.to_path_buf())?;
        }
    }
    Ok(RUNTIME_ROOT.get().context("installed runtime root")?.as_path())
}

pub(crate) fn installed_runtime_root() -> Result<&'static Path> {
    let root = runtime_root()?;
    let launcher = root.join("bin/darling");
    if !launcher.is_file() || fs::metadata(&launcher)?.permissions().mode() & 0o111 == 0
        || !root.join("bin/darlingserver").is_file() || !root.join("libexec/darling").is_dir() {
        bail!("incomplete ordinary Darling installation at {}", root.display());
    }
    Ok(root)
}

#[derive(Subcommand)]
enum RunnerCommand {
    /// Capture an arbitrary host command. The caller owns any guest prefix lifecycle;
    /// ambient DPREFIX never acquires a lease (the command may itself be a lifecycle owner).
    Run(RunArgs),
    Darling(DarlingArgs),
    Capture(CaptureArgs),
    Signal(SignalArgs),
    /// Inspect runtime identity, workload evidence, processes, traces and debugging artifacts.
    #[command(subcommand)]
    Diag(diag::DiagCommand),
}

#[derive(Args)]
struct CommonArgs {
    #[command(flatten)]
    exact: exact::ExactArgs,
    #[arg(long)]
    name: String,
    #[arg(long, default_value = "~/work/darling-debug")]
    bundle_root: PathBuf,
    #[arg(long)]
    cwd: Option<PathBuf>,
    #[arg(long, default_value_t = 600)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 3)]
    poll_seconds: u64,
    #[arg(long, value_parser = parse_key_value)]
    env: Vec<(String, String)>,
    /// Replay captured stdout and stderr for enclosing test runners.
    #[arg(long)]
    forward_output: bool,
    #[arg(long)]
    stall_log: Option<PathBuf>,
    #[arg(long)]
    stall_pattern: Option<String>,
    #[arg(long)]
    stall_after_output: Option<String>,
    #[arg(long)]
    stall_seconds: Option<u64>,
    #[arg(long)]
    capture_command: Option<String>,
    #[arg(long)]
    prepare_command: Option<String>,
    #[arg(long)]
    capture_gdb: bool,
    #[arg(long)]
    capture_tree: bool,
    /// Also capture GDB from inside the target's PID namespace.
    #[arg(long)]
    gdb_namespace: bool,
    #[arg(long)]
    gdb_executable: Option<PathBuf>,
    #[arg(long)]
    gdb_cwd: Option<PathBuf>,
    #[arg(long)]
    gdb_ex: Vec<String>,
    /// GDB command file passed with `-x` to the pre-attached fatal debugger. This can define
    /// breakpoint conditions that a command-line `-ex` cannot. Only `--capture-on-fatal` uses it.
    #[arg(long)]
    gdb_command_file: Option<PathBuf>,
    #[arg(long)]
    capture_pattern: Option<String>,
    /// Also require the matched process's /proc/PID/exe basename to equal this. The Darling launcher
    /// carries the guest argv too and `exec`s the loader in the SAME pid, so a cmdline-only match
    /// attaches to the launcher and the attach is lost at exec (MEASURED). `mldr` selects the loader.
    #[arg(long)]
    capture_exe: Option<String>,
    /// Also require /proc/PID/comm to equal this. Every guest process is the same host loader binary,
    /// so an exe check cannot tell the guest program from a guest shell; comm carries the guest name
    /// for a normal guest program and the shell's own name for a shell (MEASURED).
    #[arg(long)]
    capture_comm: Option<String>,
    /// Record the out-of-band futex trace for THIS run into this file, with the probe the reader expects
    /// (`probes/futex.bt`, embedded in the binary). It needs root: `sudo -n bpftrace` must work without a password.
    /// The trace is what makes "who woke whom" answerable at all -- a /proc syscall snapshot is one instant.
    #[arg(long)]
    futex_trace_out: Option<PathBuf>,
    /// Capture as soon as this REGEX appears in the watch log (or in the workload's own output when
    /// no --stall-log is given), instead of waiting for silence. A workload that fails by its own
    /// timeout prints a last line and then tears itself down, and a stall detector armed after that
    /// point captures nothing: this names the marker instead.
    #[arg(long)]
    capture_on_line: Option<String>,
    /// Capture when the target's threads are in a state you name, instead of when a log goes quiet.
    /// Grammar: `state=<S|D|R>`, `wchan=<substring>`, `syscall=<number>`, `all-waiting=<seconds>`.
    /// Example: --capture-on-state 'all-waiting=20' catches "every thread is parked and has been for
    /// twenty seconds", which is what a hang looks like from outside and cannot be seen in a log.
    #[arg(long)]
    capture_on_state: Option<String>,
    /// Attach the debugger as soon as the capture pattern matches and KEEP it attached, so a fatal
    /// signal (SIGILL/SIGSEGV/SIGABRT/SIGBUS) is caught where it happens. All other capture triggers
    /// are evaluated after a stall or after the workload exits; a process killed by a signal is
    /// already gone at that point, which is exactly the case this exists for (MEASURED: XCB_RC=132,
    /// "Illegal instruction (core dumped)", and no stack from any post-mortem path).
    #[arg(long)]
    capture_on_fatal: bool,
    #[arg(long, default_value_t = 2)]
    capture_snapshots: usize,
    #[arg(long, default_value_t = 3)]
    capture_interval_seconds: u64,
    #[arg(long)]
    cleanup_command: Option<String>,
    #[arg(long)]
    terminate_command: Option<String>,
    #[arg(long)]
    leave_running_on_stall: bool,
    /// pgrep -f pattern; as soon as a process matches, attach `strace -f` to it
    /// (writes rpctrace.log). Detached + flushed before any gdb capture.
    #[arg(long)]
    attach_strace: Option<String>,
    #[arg(long, default_value = "sendmsg,recvmsg")]
    attach_strace_expr: String,
    #[arg(long, default_value_t = 64)]
    attach_strace_str: usize,
    #[arg(long, default_value_t = 50)]
    attach_strace_poll_ms: u64,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct DarlingArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Explicit ordinary installed launcher (otherwise --runtime-root / DARLING_RUNTIME_ROOT / PATH).
    #[arg(long)]
    darling: Option<PathBuf>,
    #[arg(long, default_value = "~/.darling")]
    dprefix: PathBuf,
}

#[derive(Args)]
struct CaptureArgs {
    #[command(flatten)]
    exact: exact::ExactArgs,
    #[arg(long, conflicts_with = "pattern")]
    pid: Option<u32>,
    #[arg(long, conflicts_with = "pid")]
    pattern: Option<String>,
    #[arg(long, default_value = "~/work/darling-debug")]
    bundle_root: PathBuf,
    #[arg(long, default_value = "capture")]
    name: String,
    #[arg(long)]
    gdb: bool,
    #[arg(long)]
    tree: bool,
    /// Also capture GDB from inside the target's PID namespace.
    #[arg(long)]
    gdb_namespace: bool,
    #[arg(long)]
    gdb_executable: Option<PathBuf>,
    #[arg(long)]
    gdb_cwd: Option<PathBuf>,
    #[arg(long)]
    gdb_ex: Vec<String>,
    #[arg(long, default_value_t = 2)]
    snapshots: usize,
    #[arg(long, default_value_t = 3)]
    interval_seconds: u64,
}

#[derive(Args)]
struct SignalArgs {
    #[arg(long, conflicts_with = "pattern")]
    pid: Option<u32>,
    #[arg(long, conflicts_with = "pid")]
    pattern: Option<String>,
    /// Linux: inherited, caller-verified pidfd; never resolve its PID again.
    #[arg(long, value_parser = clap::value_parser!(i32).range(0..),
        conflicts_with_all = ["pid", "pattern", "group"])]
    pidfd: Option<i32>,
    #[arg(long)]
    group: bool,
    #[arg(long, default_value = "TERM")]
    signal: String,
}

struct StallDetector {
    log: PathBuf,
    pattern: Regex,
    after_output: Option<Regex>,
    stall_for: Duration,
    offset: u64,
    events: u64,
    last_event: Instant,
    armed: bool,
}

impl StallDetector {
    fn from_args(args: &CommonArgs) -> Result<Option<Self>> {
        let Some(log) = &args.stall_log else {
            // Silence detection without a log to watch used to mean "no detector", so the flags were
            // accepted and did nothing. Refusing is the honest answer: the caller asked for a capture
            // on silence and would otherwise receive a run with no detector and no explanation.
            if args.stall_pattern.is_some() || args.stall_seconds.is_some() {
                bail!("--stall-pattern/--stall-seconds were given without --stall-log: silence can only be detected in a log, so name the log to watch (or drop the stall options)");
            }
            return Ok(None);
        };
        let pattern = args
            .stall_pattern
            .as_ref()
            .context("--stall-pattern is required with --stall-log")?;
        let seconds = args
            .stall_seconds
            .context("--stall-seconds is required with --stall-log")?;
        let log = expand_home(log);
        let offset = fs::metadata(&log).map_or(0, |metadata| metadata.len());
        let pattern = Regex::new(pattern).context("invalid --stall-pattern")?;
        // A pattern that matches the empty string (for example `^`) reports an event on every poll,
        // because an empty tail still matches -- so the detector can never see silence and silently
        // never fires. Refuse it instead of leaving a capture that was asked for inert.
        if pattern.is_match("") {
            bail!("--stall-pattern {pattern} matches the empty string, so it can never detect silence; use a pattern that appears only while the run is making progress");
        }
        Ok(Some(Self {
            log,
            pattern,
            after_output: args
                .stall_after_output
                .as_ref()
                .map(|value| Regex::new(value))
                .transpose()
                .context("invalid --stall-after-output")?,
            stall_for: Duration::from_secs(seconds),
            offset,
            events: 0,
            last_event: Instant::now(),
            armed: args.stall_after_output.is_none(),
        }))
    }

    fn poll(&mut self, stdout: &Path, stderr: &Path) -> Result<bool> {
        if !self.armed {
            let mut output = fs::read_to_string(stdout).unwrap_or_default();
            output.push_str(&fs::read_to_string(stderr).unwrap_or_default());
            self.armed = match &self.after_output {
                // No marker named: watch from the start. Requiring one made --stall-pattern and
                // --stall-seconds inert unless --stall-after-output was also given, so a capture
                // that was asked for produced an empty bundle and said nothing about why.
                None => true,
                Some(pattern) => pattern.is_match(&output),
            };
            if self.armed {
                self.last_event = Instant::now();
            }
        }

        if let Ok(mut file) = File::open(&self.log) {
            let len = file.metadata()?.len();
            if len < self.offset {
                self.offset = 0;
            }
            file.seek(SeekFrom::Start(self.offset))?;
            let mut new_text = String::new();
            file.read_to_string(&mut new_text)?;
            self.offset = file.stream_position()?;
            // Only appended text can be progress: counting matches in an empty tail made `^` refresh
            // the timer every poll (see from_args), which is how a real stall hid from the detector.
            let new_events = if new_text.is_empty() {
                0
            } else {
                self.pattern.find_iter(&new_text).count() as u64
            };
            if new_events > 0 {
                self.events += new_events;
                self.last_event = Instant::now();
            }
        }

        Ok(self.armed && self.last_event.elapsed() >= self.stall_for)
    }
}

fn parse_key_value(value: &str) -> Result<(String, String), String> {
    value
        .split_once('=')
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .ok_or_else(|| "expected KEY=VALUE".to_owned())
}


/// Read the bytes a file gained since `offset` and report whether the pattern matches them. Used by
/// the marker trigger so both output streams are watched without duplicating the seek bookkeeping.
fn marker_seen(path: &Path, pattern: &Regex, offset: &mut u64) -> Result<bool> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len < *offset {
        *offset = 0;
    }
    let _ = file.seek(SeekFrom::Start(*offset));
    let mut text = String::new();
    if file.read_to_string(&mut text).is_err() {
        return Ok(false);
    }
    *offset = file.stream_position().unwrap_or(*offset);
    Ok(pattern.is_match(&text))
}

fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if (text == "~" || text.starts_with("~/"))
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(text.trim_start_matches("~/"));
    }
    path.to_owned()
}

fn make_bundle(root: &Path, name: &str) -> Result<PathBuf> {
    let safe_name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut bundle = expand_home(root);
    fs::create_dir_all(&bundle)?;
    bundle.push(format!(
        "{}-{safe_name}",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    fs::create_dir(&bundle).with_context(|| format!(
        "creating a new owned bundle {}; existing paths are never reused",
        bundle.display(),
    ))?;
    Ok(bundle)
}

/// Locate the workspace-owned lifecycle and evidence authorities in either
/// supported source layout: vendored under tools/ or the sibling West project.
pub(crate) fn workspace_root() -> Result<PathBuf> {
    let valid = |root: &Path| {
        root.join("west.yml").is_file()
            && root.join("scripts/darling-evidence.py").is_file()
            && root.join("west_commands/test_prefix.py").is_file()
    };
    if let Some(root) = std::env::var_os("DWDIAG_WORKSPACE") {
        let root = PathBuf::from(root);
        if !valid(&root) {
            bail!("DWDIAG_WORKSPACE does not contain the workspace authorities");
        }
        return Ok(root);
    }
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Some(root) = source.parent().and_then(Path::parent)
        && valid(root)
    {
        return Ok(root.to_path_buf());
    }
    if let Some(parent) = source.parent() {
        let root = parent.join("darling-workspace");
        if valid(&root) {
            return Ok(root);
        }
    }
    bail!("workspace authorities unavailable; set DWDIAG_WORKSPACE")
}

/// Apply the shared storage policy only after this bundle's capture writers close.
/// Its index, byte verification and writer census remain Python-owned authorities.
fn finalize_bundle_storage(bundle: &Path, command_result: &str, retained_live: bool) -> Result<bool> {
    let metadata = bundle.join("summary-storage-status.txt");
    if retained_live {
        fs::write(&metadata, format!(
            "state=deferred\ncommand_result={command_result}\nreason=explicit live-payload retention; bundle is not finalized\n",
        ))?;
        println!("STORAGE=deferred reason=live-payload-retained metadata={}", metadata.display());
        return Ok(true);
    }

    // JSONL and summary-prefixed files are protected metadata, so the helper
    // never selects its own still-open output as an archival payload.
    let report = bundle.join("storage-report.jsonl");
    let errors = bundle.join("summary-storage-errors.txt");
    let outcome = Command::new("python3")
        .arg("-B")
        .arg(workspace_root()?.join("scripts/darling-evidence.py"))
        .args(["compress", "--recursive"])
        .arg(bundle)
        .stdin(Stdio::null())
        .stdout(File::create(&report)?)
        .stderr(File::create(&errors)?)
        .status();
    let (state, helper_status, successful) = match outcome {
        Ok(status) => (
            if status.success() { "processed" } else { "incomplete" },
            status.to_string(),
            status.success(),
        ),
        Err(error) => ("unavailable", format!("cannot start shared storage helper: {error}"), false),
    };
    fs::write(&metadata, format!(
        "state={state}\ncommand_result={command_result}\nhelper_status={helper_status}\nreport={}\nerrors={}\n",
        report.display(), errors.display(),
    ))?;
    println!("STORAGE={state} report={} errors={} metadata={}",
        report.display(), errors.display(), metadata.display());
    Ok(successful)
}

fn shell_hook(command: &str, bundle: &Path, pid: u32) -> std::io::Result<std::process::ExitStatus> {
    let mut hook = Command::new("/bin/bash");
    hook.args(["-lc", command])
        .env("BUNDLE", bundle)
        .env("TARGET_PID", pid.to_string());
    inherit_owner_lease(&mut hook);
    hook.status()
}

fn find_pid(pid: Option<u32>, pattern: Option<&str>) -> Result<u32> {
    if let Some(pid) = pid {
        return Ok(pid);
    }
    let pattern = pattern.context("provide --pid or --pattern")?;
    let output = Command::new("pgrep")
        .args(["-f", pattern])
        .output()
        .context("failed to run pgrep")?;
    let self_pid = std::process::id();
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|candidate| *candidate != self_pid)
        .filter_map(|candidate| {
            fs::read(format!("/proc/{candidate}/cmdline"))
                .ok()
                .map(|cmdline| (candidate, cmdline.len()))
        })
        .min_by_key(|(_, command_length)| *command_length)
        .map(|(candidate, _)| candidate)
        .with_context(|| format!("no process matched {pattern:?}"))
}

fn find_pid_in_tree(root: u32, pattern: &str, exe: Option<&str>, comm: Option<&str>) -> Result<u32> {
    let pattern = Regex::new(pattern).context("invalid process pattern")?;
    process_tree(root)
        .into_iter()
        .filter_map(|pid| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .map(|cmdline| (pid, cmdline))
        })
        .filter(|(_, cmdline)| {
            pattern.is_match(&String::from_utf8_lossy(cmdline).replace('\0', " "))
        })
        .filter(|(pid, _)| match comm {
            None => true,
            Some(name) => fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|value| value.trim().to_owned())
                .is_some_and(|value| value == name),
        })
        .filter(|(pid, _)| match exe {
            None => true,
            Some(name) => fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
                .is_some_and(|base| base == name),
        })
        .min_by_key(|(_, cmdline)| cmdline.len())
        .map(|(pid, _)| pid)
        .with_context(|| format!("no process in tree rooted at {root} matched {pattern:?}"))
}

/// Every process in the tree matching the pattern (and the optional exe/comm filters). The single-pid
/// resolver picks the shortest cmdline, which is the WRONG process when the loader and a guest shell
/// share the guest command line (MEASURED: the fatal attach landed on a guest bash twice). A fatal-signal
/// capture can afford to hold all candidates: the one that faults prints the stack and the others:
/// detach when the run ends.
fn find_pids_in_tree(root: u32, pattern: &str, exe: Option<&str>, comm: Option<&str>) -> Result<Vec<u32>> {
    let pattern = Regex::new(pattern).context("invalid process pattern")?;
    Ok(process_tree(root)
        .into_iter()
        .filter_map(|pid| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .ok()
                .map(|cmdline| (pid, cmdline))
        })
        .filter(|(_, cmdline)| {
            pattern.is_match(&String::from_utf8_lossy(cmdline).replace('\0', " "))
        })
        .filter(|(pid, _)| match comm {
            None => true,
            Some(name) => fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|value| value.trim().to_owned())
                .is_some_and(|value| value == name),
        })
        .filter(|(pid, _)| match exe {
            None => true,
            Some(name) => fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .and_then(|path| path.file_name().map(|n| n.to_string_lossy().into_owned()))
                .is_some_and(|base| base == name),
        })
        .map(|(pid, _)| pid)
        .collect())
}

fn arm_fatal_gdb(
    args: &CommonArgs,
    bundle: &Path,
    root: u32,
    armed: &mut Vec<(u32, std::process::Child)>,
) -> Result<()> {
    let pattern = args.capture_pattern.as_deref().unwrap_or("");
    let pids = find_pids_in_tree(root, pattern, args.capture_exe.as_deref(), args.capture_comm.as_deref())?;
    for pid in pids {
        if armed.iter().any(|(existing, _)| *existing == pid) {
            continue;
        }
        // Capture identity once, before the fault can destroy the /proc entry and before the
        // debugger attach is attempted: a failed attach must not lose the process attribution.
        let identity_path = bundle.join(format!("fatal-identity-{pid}.txt"));
        match process_identity(pid) {
            Ok(report) => {
                if let Err(error) = fs::write(&identity_path, report) {
                    let _ = fs::write(
                        bundle.join("fatal-identity-error.txt"),
                        format!("pid {pid}: writing {}: {error}\n", identity_path.display()),
                    );
                }
            }
            Err(error) => {
                let unavailable = format!("pid={pid}\nidentity=unavailable\nerror={error:#}\n");
                if let Err(write_error) = fs::write(&identity_path, unavailable) {
                    let _ = fs::write(
                        bundle.join("fatal-identity-error.txt"),
                        format!(
                            "pid {pid}: identity unavailable ({error:#}); writing {}: {write_error}\n",
                            identity_path.display()
                        ),
                    );
                }
            }
        }
        let out = bundle.join(format!("gdb-fatal-{pid}.txt"));
        match spawn_fatal_gdb(
            pid,
            &out,
            args.gdb_namespace,
            args.gdb_executable.as_deref(),
            args.gdb_cwd.as_deref(),
            &args.gdb_ex,
            args.gdb_command_file.as_deref(),
        ) {
            Ok(child) => armed.push((pid, child)),
            Err(error) => {
                let _ = fs::write(bundle.join("fatal-attach-error.txt"), format!("pid {pid}: {error}\n"));
            }
        }
    }
    Ok(())
}

/// The parts of a live process's identity that attribute a debugger stop to one workload
/// incarnation: the start time from /proc/PID/stat (stable against pid reuse), plus the executable
/// and command line. Reads are reported as explicit `unavailable` lines rather than empty values,
/// because an empty string would make an unreadable process look successfully identified.
fn process_identity(pid: u32) -> Result<String> {
    let stat_path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(&stat_path)
        .with_context(|| format!("reading {stat_path}"))?;
    let (ppid, starttime) = parse_process_stat(&stat)
        .with_context(|| format!("parsing process identity from {stat_path}"))?;
    let ppid = ppid
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_owned());
    let mut report = format!("pid={pid}\nstarttime={starttime}\nppid={ppid}\n");
    match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => report.push_str(&format!("exe={}\n", path.display())),
        Err(error) => report.push_str(&format!("exe=unavailable error={error}\n")),
    }
    match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => {
            let cmdline = String::from_utf8_lossy(&bytes).replace('\0', " ");
            report.push_str(&format!("cmdline={}\n", cmdline.trim_end()));
        }
        Err(error) => report.push_str(&format!("cmdline=unavailable error={error}\n")),
    }
    Ok(report)
}

/// Field 4 (ppid) and field 22 (starttime, in clock ticks since boot) of /proc/PID/stat.
/// The comm field may contain spaces and parentheses, so the split is at its final `)`.
fn parse_process_stat(stat: &str) -> Option<(Option<u32>, u64)> {
    let (_, tail) = stat.rsplit_once(')')?;
    let mut fields = tail.split_whitespace();
    let _state = fields.next()?;
    let ppid = fields.next().and_then(|value| value.parse().ok());
    let starttime = fields.nth(17)?.parse().ok()?;
    Some((ppid, starttime))
}

fn command_to_file(mut command: Command, output: &Path) {
    if let Ok(file) = File::create(output) {
        let _ = command
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .status();
    }
}

fn process_tree(root: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            let Some(ppid) = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|value| value.trim().parse::<u32>().ok())
            else {
                continue;
            };
            children.entry(ppid).or_default().push(pid);
        }
    }

    let mut result = Vec::new();
    let mut seen = HashSet::new();
    let mut pending = vec![root];
    while let Some(pid) = pending.pop() {
        if !seen.insert(pid) {
            continue;
        }
        result.push(pid);
        if let Some(descendants) = children.get(&pid) {
            pending.extend(descendants);
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn capture_process_tree(
    root: u32,
    bundle: &Path,
    gdb: bool,
    gdb_namespace: bool,
    gdb_executable: Option<&Path>,
    gdb_cwd: Option<&Path>,
    gdb_ex: &[String],
    snapshots: usize,
    interval: Duration,
) -> Result<()> {
    let pids = process_tree(root);
    fs::create_dir_all(bundle)?;
    fs::write(
        bundle.join("tree-pids.txt"),
        pids.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )?;

    let pid_list = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut ps = Command::new("ps");
    ps.args([
        "-p",
        &pid_list,
        "-o",
        "pid,ppid,pgid,sid,stat,etime,wchan:32,comm,args",
        "--forest",
    ]);
    command_to_file(ps, &bundle.join("ps-tree.txt"));

    for pid in pids {
        capture_target(
            pid,
            &bundle.join(format!("pid-{pid}")),
            gdb,
            gdb_namespace,
            gdb_executable,
            gdb_cwd,
            gdb_ex,
            snapshots,
            interval,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn capture_target(
    pid: u32,
    bundle: &Path,
    gdb: bool,
    gdb_namespace: bool,
    gdb_executable: Option<&Path>,
    gdb_cwd: Option<&Path>,
    gdb_ex: &[String],
    snapshots: usize,
    interval: Duration,
) -> Result<()> {
    fs::create_dir_all(bundle)?;
    fs::write(bundle.join("target-pid.txt"), format!("{pid}\n"))?;

    let mut ps = Command::new("ps");
    ps.args([
        "-p",
        &pid.to_string(),
        "-Lo",
        "pid,ppid,pgid,sid,tid,stat,etime,wchan:32,comm,args",
    ]);
    command_to_file(ps, &bundle.join("ps-target.txt"));

    for name in [
        "status",
        "cmdline",
        "wchan",
        "syscall",
        "stack",
        "maps",
        "mountinfo",
    ] {
        let source = PathBuf::from(format!("/proc/{pid}/{name}"));
        let destination = bundle.join(format!("proc-{name}.txt"));
        if fs::copy(&source, &destination).is_err() {
            let mut sudo = Command::new("sudo");
            sudo.args(["-n", "cat"]).arg(source);
            command_to_file(sudo, &destination);
        }
    }

    for index in 1..=snapshots {
        for task in fs::read_dir(format!("/proc/{pid}/task"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let tid = task.file_name().to_string_lossy().into_owned();
            for name in ["comm", "wchan", "stack", "syscall"] {
                let source = task.path().join(name);
                let destination = bundle.join(format!("snapshot-{index}-tid-{tid}-{name}.txt"));
                if fs::copy(&source, &destination).is_err() {
                    let mut sudo = Command::new("sudo");
                    sudo.args(["-n", "cat"]).arg(source);
                    command_to_file(sudo, &destination);
                }
            }
        }
        if gdb {
            let command = gdb_command(pid, None, gdb_executable, gdb_cwd, gdb_ex);
            command_to_file(command, &bundle.join(format!("gdb-{index}.txt")));

            if gdb_namespace {
                let namespace_pid = namespace_pid(pid).unwrap_or(pid);
                let command =
                    gdb_command(namespace_pid, Some(pid), gdb_executable, gdb_cwd, gdb_ex);
                command_to_file(command, &bundle.join(format!("gdb-namespace-{index}.txt")));
            }
        }
        if index < snapshots {
            thread::sleep(interval);
        }
    }
    Ok(())
}

fn namespace_pid(pid: u32) -> Option<u32> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .next_back()?
        .parse()
        .ok()
}

/// Hold the target with the debugger and let it run: `continue` returns only when a fatal signal
/// arrives, and the batch then prints every thread's stack. Attached before the fault, which is the
/// only moment a stack is still obtainable.
fn spawn_fatal_gdb(
    pid: u32,
    output: &Path,
    gdb_namespace: bool,
    executable: Option<&Path>,
    cwd: Option<&Path>,
    expressions: &[String],
    command_file: Option<&Path>,
) -> Result<std::process::Child> {
    let mut command = Command::new("sudo");
    command.arg("-n");
    let attach_pid = if gdb_namespace {
        namespace_pid(pid).context("cannot read the target's namespace PID")?
    } else {
        pid
    };
    if gdb_namespace {
        command
            .args([
                "nsenter",
                "--target",
                &pid.to_string(),
                "--pid",
                "--mount",
                "--",
            ])
            .args(["gdb", "-q"]);
    } else {
        command.args(["gdb", "-q"]);
    }
    if let Some(cwd) = cwd {
        command.current_dir(expand_home(cwd));
    }
    if let Some(executable) = executable {
        command.arg(expand_home(executable));
    }
    command.args(["-p", &attach_pid.to_string(), "-batch", "-ex", "set pagination off"]);
    if let Some(file) = command_file {
        command.arg("-x").arg(expand_home(file));
    }
    for signal in ["SIGILL", "SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE"] {
        command.args(["-ex", &format!("handle {signal} stop print nopass")]);
    }
    command.args(["-ex", "continue", "-ex", "info threads", "-ex", "thread apply all bt full"]);
    for expression in expressions {
        command.args(["-ex", expression]);
    }
    let file = File::create(output)?;
    command
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::from(file))
        .spawn()
        .context("failed to start the pre-attached debugger")
}

fn gdb_command(
    pid: u32,
    namespace_target: Option<u32>,
    executable: Option<&Path>,
    cwd: Option<&Path>,
    expressions: &[String],
) -> Command {
    let mut command = Command::new("timeout");
    command.args(["30s", "sudo", "-n"]);
    if let Some(target) = namespace_target {
        command
            .args([
                "nsenter",
                "--target",
                &target.to_string(),
                "--pid",
                "--mount",
                "--",
            ])
            .args(["gdb", "-q"]);
    } else {
        command.args(["gdb", "-q"]);
    }
    if let Some(cwd) = cwd {
        command.current_dir(expand_home(cwd));
    }
    if let Some(executable) = executable {
        command.arg(expand_home(executable));
    }
    command.args(["-p", &pid.to_string(), "-batch"]).args([
        "-ex",
        "set pagination off",
        "-ex",
        "info threads",
        "-ex",
        "thread apply all bt full",
    ]);
    for expression in expressions {
        command.args(["-ex", expression]);
    }
    command
}

fn terminate_group(child: &mut Child) -> Result<String> {
    let pgid = Pid::from_raw(child.id() as i32);
    let pids = process_tree(child.id());
    let mut lines = Vec::new();

    match killpg(pgid, Signal::SIGTERM) {
        Ok(()) => lines.push("sent SIGTERM to process group".to_owned()),
        Err(error) => lines.push(format!("SIGTERM failed: {error}")),
    }
    for pid in &pids {
        if *pid != std::process::id() {
            let _ = nix::sys::signal::kill(Pid::from_raw(*pid as i32), Signal::SIGTERM);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            lines.push(format!("child exited after SIGTERM: {status}"));
            return Ok(lines.join("\n") + "\n");
        }
        thread::sleep(Duration::from_millis(100));
    }

    match killpg(pgid, Signal::SIGKILL) {
        Ok(()) => lines.push("sent SIGKILL to process group".to_owned()),
        Err(error) => lines.push(format!("SIGKILL failed: {error}")),
    }
    for pid in &pids {
        if *pid != std::process::id() {
            let _ = nix::sys::signal::kill(Pid::from_raw(*pid as i32), Signal::SIGKILL);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            lines.push(format!("child exited after SIGKILL: {status}"));
            return Ok(lines.join("\n") + "\n");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let remaining: Vec<u32> = pids
        .into_iter()
        .filter(|pid| Path::new(&format!("/proc/{pid}")).exists())
        .collect();
    if remaining.is_empty() {
        lines.push("process tree gone after SIGKILL; child was not reaped yet".to_owned());
    } else {
        lines.push(format!(
            "processes still alive after SIGKILL: {remaining:?}"
        ));
    }
    Ok(lines.join("\n") + "\n")
}

/// The probe program, embedded so the binary always carries the one its own reader expects. The file is
/// `probes/futex.bt`; keeping it as `include_str!` means a run cannot use a stale copy from somewhere else.
const FUTEX_PROBE_TEXT: &str = include_str!("../probes/futex.bt");

/// The out-of-band futex probe, running for the duration of the workload.
///
/// WHY A PROBE AND NOT A SNAPSHOT: a /proc syscall snapshot is one instant, so it can never show who woke whom.
/// The program is `probes/futex.bt` embedded in the binary, so the tool always carries the probe its own reader
/// expects, and its output is exactly the schema `dwdiag futex --futex-trace` parses.
struct FutexProbe {
    child: Option<Child>,
    path: PathBuf,
}

impl FutexProbe {
    fn spawn(path: &Path) -> Result<Self> {
        let path = expand_home(path);
        let file = File::create(&path).with_context(|| format!("cannot create {}", path.display()))?;
        // bpftrace diagnostics go to their own file rather than a pipe: a pipe nobody reads fills up and blocks the
        // probe, which would look exactly like a run with no futex activity.
        let err_path = path.with_extension("stderr");
        let err = File::create(&err_path).ok();
        let mut command = Command::new("sudo");
        command.args(["-n", "bpftrace", "-q", "-e", FUTEX_PROBE_TEXT]);
        command.stdout(Stdio::from(file));
        command.stderr(match err {
            Some(handle) => Stdio::from(handle),
            None => Stdio::null(),
        });
        let child = command
            .spawn()
            .context("cannot start bpftrace: --futex-trace-out needs `sudo -n bpftrace` to work")?;
        Ok(Self {
            child: Some(child),
            path,
        })
    }

    /// Stop the probe so it flushes, and say how much it recorded.
    ///
    /// SIGINT, not SIGKILL: bpftrace flushes its output on a normal signal, and a trace that silently ends early is
    /// the very failure this path exists to remove. The same reason it runs on Drop -- a run that fails early must
    /// not leave a root-owned probe behind.
    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = nix::sys::signal::kill(Pid::from_raw(child.id() as i32), Signal::SIGINT);
        let _ = child.wait();
        let lines = fs::read_to_string(&self.path)
            .map(|text| text.lines().count())
            .unwrap_or(0);
        println!("FUTEX-TRACE-OUT {} lines={lines}", self.path.display());
    }
}

#[cfg(unix)]
impl Drop for FutexProbe {
    fn drop(&mut self) {
        self.stop();
    }
}

struct StraceAttacher {
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    handle: thread::JoinHandle<()>,
}

/// Refuse a strace capture BEFORE the workload runs, when a trace on this host cannot work.
///
/// MEASURED, twice in one session: `strace` was asked to attach to a guest process and failed with
/// `ptrace(PTRACE_SEIZE, ...): Operation not permitted`, and a whole-run `strace -f` around the boot STALLED it --
/// so each attempt cost a full run and produced nothing, and "strace says nothing" was then rediscovered by the
/// next reader. Both are knowable before the run: `strace` must exist, and an attach to a process that is not a
/// descendant of the tracer needs `ptrace_scope == 0` (or CAP_SYS_PTRACE). The check MEASURES the permission with a
/// throwaway target instead of reading the policy file alone, because the policy cannot say whether `sudo -n` will
/// actually hand this user root.
fn strace_preflight() -> Result<()> {
    let present = Command::new("strace")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !present {
        bail!(
            "--attach-strace was requested but `strace` is not runnable on PATH (install it, e.g. `apt install \
             strace`, or drop --attach-strace). Refused before the workload runs, so the run is not spent on a \
             capture that cannot be taken"
        );
    }
    let scope = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    // A throwaway target that is OUR child but NOT strace's: the same relation a real attach has, so the probe
    // measures the permission the capture will need.
    let mut probe = Command::new("sleep")
        .arg("3")
        .spawn()
        .context("cannot spawn the attach probe (`sleep 3`)")?;
    let outcome = Command::new("sudo")
        .args(["-n", "strace", "-f", "-e", "trace=write", "-p", &probe.id().to_string(), "-o", "/dev/null"])
        .output();
    let _ = probe.kill();
    let _ = probe.wait();
    match outcome {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => bail!(
            "--attach-strace cannot work on this host and is refused BEFORE the workload runs. The permission probe \
             (`sudo -n strace -f -p <probe>`) failed with status {}: {}\n  yama/ptrace_scope={} -- 1 or 2 means an \
             attach to a process that is not a descendant of the tracer is EPERM unless the tracer holds \
             CAP_SYS_PTRACE (root).\n  Fix one of: make `sudo -n` work for this user; `sysctl \
             kernel.yama.ptrace_scope=0`; or start the target as a child of the traced command instead of attaching \
             to it. A whole-run `strace -f` is the third trap: MEASURED, it stalls the boot, so it is not an \
             alternative here.",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim().replace('\n', " | "),
            if scope.is_empty() { "unreadable".to_string() } else { scope }
        ),
        Err(error) => bail!(
            "--attach-strace cannot even run its permission probe (`sudo -n strace ...`): {error}. Refused before the \
             workload runs; make `sudo -n` work or drop --attach-strace"
        ),
    }
}

impl StraceAttacher {
    /// Poll for the earliest process matching `pattern` and attach `strace -f`
    /// to it, logging the configured syscalls to `bundle/rpctrace.log`.
    fn spawn(
        root_pid: u32,
        pattern: String,
        expr: String,
        str_len: usize,
        poll: Duration,
        deadline: Instant,
        bundle: PathBuf,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let child: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
        let stop_t = stop.clone();
        let child_t = child.clone();
        let handle = thread::spawn(move || {
            let log = bundle.join("rpctrace.log");
            let status = bundle.join("attach-strace.txt");
            while !stop_t.load(Ordering::Relaxed) && Instant::now() < deadline {
                let found = find_pid_in_tree(root_pid, &pattern, None, None).ok();
                if let Some(pid) = found {
                    let mut command = Command::new("sudo");
                    command
                        .args([
                            "-n",
                            "strace",
                            "-f",
                            "-ttt",
                            "-i",
                            "-yy",
                            "-e",
                            &format!("trace={expr}"),
                            "-s",
                            &str_len.to_string(),
                            "-p",
                            &pid.to_string(),
                            "-o",
                        ])
                        .arg(&log);
                    // strace's OWN words go into the bundle: a refused attach (EPERM) prints there and exits at
                    // once, and without this the only evidence is an empty rpctrace.log that reads like "the target
                    // did nothing" -- the exact silent-void this tool exists to remove.
                    let err_path = bundle.join("attach-strace.err");
                    if let Ok(f) = File::create(&err_path) {
                        command.stderr(f);
                    }
                    match command.spawn() {
                        Ok(mut handle) => {
                            let _ = fs::write(
                                &status,
                                format!("attached target_pid={pid} strace_pid={}\n", handle.id()),
                            );
                            // A refused attach exits almost immediately. Wait a moment, and if it is already gone,
                            // replace the status file with the real answer instead of leaving "attached" standing.
                            thread::sleep(Duration::from_millis(700));
                            if let Ok(Some(exit)) = handle.try_wait() {
                                let why = fs::read_to_string(&err_path).unwrap_or_default();
                                let _ = fs::write(
                                    &status,
                                    format!(
                                        "strace DIED immediately (status {exit}) for target_pid={pid}: {}\n",
                                        why.trim().replace('\n', " | ")
                                    ),
                                );
                                return;
                            }
                            *child_t.lock().unwrap() = Some(handle);
                        }
                        Err(error) => {
                            let _ = fs::write(&status, format!("strace spawn failed: {error}\n"));
                        }
                    }
                    return;
                }
                thread::sleep(poll);
            }
            let _ = fs::write(&status, "target never appeared before deadline\n");
        });
        Self {
            stop,
            child,
            handle,
        }
    }

    /// Stop polling and detach strace via SIGINT so it flushes its log cleanly.
    /// Must run before any gdb capture (a process can only have one tracer).
    fn detach(self) {
        self.stop.store(true, Ordering::Relaxed);
        // The poller may still be spawning or publishing its tracer handle.
        // Join it first so no writer can appear after we take the final handle.
        let _ = self.handle.join();
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = nix::sys::signal::kill(Pid::from_raw(child.id() as i32), Signal::SIGINT);
            let _ = child.wait();
        }
    }
}

fn register_output_logs(bundle: &Path) -> Result<()> {
    let Some(state) = std::env::var_os("WEST_JOB_STATE_DIR") else {
        return Ok(());
    };
    let directory = PathBuf::from(state).join("activity-logs.d");
    fs::create_dir_all(&directory)?;
    let name = format!(
        "runner-{}-{}",
        std::process::id(),
        Utc::now()
            .timestamp_nanos_opt()
            .context("registration timestamp out of range")?
    );
    let temporary = directory.join(format!("{name}.tmp"));
    let published = directory.join(format!("{name}.logs"));
    let result = (|| -> Result<()> {
        let mut output = File::create_new(&temporary)?;
        for name in ["stdout.log", "stderr.log"] {
            output.write_all(b"file\0")?;
            output.write_all(bundle.join(name).as_os_str().as_bytes())?;
            output.write_all(b"\0")?;
        }
        drop(output);
        fs::rename(&temporary, published)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.context("publishing west-job output logs")
}

fn spawn(
    args: &CommonArgs,
    bundle: &Path,
    command: &[String],
    extra_env: &HashMap<String, String>,
) -> Result<Child> {
    let program = command.first().context("missing command")?;
    let stdout = File::create(bundle.join("stdout.log"))?;
    let stderr = File::create(bundle.join("stderr.log"))?;
    register_output_logs(bundle)?;
    let mut process = Command::new(program);
    process
        .args(&command[1..])
        .envs(args.env.iter().cloned())
        .envs(extra_env)
        .stdout(stdout)
        .stderr(stderr);
    if OWNER_LEASE_FD.get().is_some() {
        // This payload is a runtime child, not a nested lifecycle owner.
        process.env_remove("WEST_TEST_PREFIX_LEASE").env_remove("WEST_TEST_PREFIX_LEASE_FD");
    }
    if let Some(cwd) = &args.cwd {
        process.current_dir(expand_home(cwd));
    }
    // SAFETY: setsid is async-signal-safe and does not access parent memory.
    unsafe {
        process.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::other)?;
            Ok(())
        });
    }
    process.spawn().context("failed to spawn command")
}

fn run_experiment(
    args: &CommonArgs,
    command: Vec<String>,
    extra_env: HashMap<String, String>,
) -> Result<(PathBuf, &'static str)> {
    let mut cancellation = Cancellation::install()?;
    let bundle = make_bundle(&args.bundle_root, &args.name)?;
    fs::write(
        bundle.join("command.txt"),
        format!("{}\n", command.join(" ")),
    )?;
    let mut env_lines: Vec<String> = std::env::vars()
        .chain(args.env.iter().cloned())
        .chain(
            extra_env
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        )
        .map(|(key, value)| {
            if args.exact.capture_exact {
                format!("{key}=<redacted>")
            } else {
                format!("{key}={value}")
            }
        })
        .collect();
    env_lines.sort();
    fs::write(bundle.join("env.txt"), env_lines.join("\n") + "\n")?;
    if let Some(command) = &args.prepare_command {
        let _ = shell_hook(command, &bundle, 0);
    }
    // Validate the observation plan before anything is spawned or prepared: an invalid plan that is
    // discovered afterwards leaves a payload running with no way to explain what was asked for.
    if args.capture_snapshots == 0 {
        bail!("--capture-snapshots 0 asks for no snapshots, which silently skips all thread and debugger evidence; use at least 1");
    }
    if !args.capture_gdb
        && (args.gdb_namespace
            || args.gdb_executable.is_some()
            || args.gdb_cwd.is_some()
            || args.gdb_command_file.is_some()
            || !args.gdb_ex.is_empty())
    {
        bail!("--gdb-namespace/--gdb-executable/--gdb-cwd/--gdb-command-file/--gdb-ex were given without --capture-gdb, so they would be ignored; add --capture-gdb or drop them");
    }
    if args.capture_on_fatal && !args.capture_gdb {
        bail!("--capture-on-fatal needs --capture-gdb: the fatal-signal catch IS the debugger attach");
    }
    if args.gdb_command_file.is_some() && !args.capture_on_fatal {
        bail!("--gdb-command-file is only used by the --capture-on-fatal debugger; add --capture-on-fatal or drop it");
    }
    if args.capture_on_fatal && args.capture_pattern.is_none() {
        bail!("--capture-on-fatal needs --capture-pattern so the debugger knows which process to hold");
    }
    if args.capture_on_line.is_some() && args.stall_log.is_none() {
        println!("NOTE --capture-on-line watches the workload's stdout and stderr (no --stall-log named)");
    }
    // A trace that cannot be taken must be refused HERE, not after a run has been spent on it.
    if args.attach_strace.is_some() {
        strace_preflight()?;
    }
    println!("BUNDLE={}", bundle.display());
    std::io::stdout().flush()?;
    let mut detector = StallDetector::from_args(args)?;
    let marker_pattern = match &args.capture_on_line {
        Some(p) => Some(Regex::new(p).context("invalid --capture-on-line")?),
        None => None,
    };
    let state_expr = match &args.capture_on_state {
        Some(e) => Some(StateTrigger::parse(e)?),
        None => None,
    };
    let mut futex_probe = match args.futex_trace_out.as_ref() {
        Some(path) => Some(FutexProbe::spawn(path)?),
        None => None,
    };
    let mut child = spawn(args, &bundle, &command, &extra_env)?;
    fs::write(bundle.join("pid.txt"), format!("{}\n", child.id()))?;
    // The run window, in the SAME format the job owner writes and the readers already parse. Without it a trace
    // cannot be attributed to this run at all: `dwdiag futex --futex-trace` refuses an unattributable trace on
    // purpose, because a trace from another run reads exactly like this one.
    let run_start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    fs::write(
        bundle.join("evidence-manifest"),
        format!("version=1\nstart={run_start}\n"),
    )?;
    let stdout = bundle.join("stdout.log");
    let stderr = bundle.join("stderr.log");
    let deadline = Instant::now() + Duration::from_secs(args.timeout_seconds);
    let strace = args.attach_strace.as_ref().map(|pattern| {
        StraceAttacher::spawn(
            child.id(),
            pattern.clone(),
            args.attach_strace_expr.clone(),
            args.attach_strace_str,
            Duration::from_millis(args.attach_strace_poll_ms),
            deadline,
            bundle.clone(),
        )
    });
    let result;
    let marker_log = args.stall_log.clone();
    let mut marker_offset: u64 = 0;
    let mut stdout_marker_offset: u64 = 0;
    let mut stderr_marker_offset: u64 = 0;
    let mut state_quiet_since: Option<Instant> = None;
    // The interesting process is usually NOT there when the run starts: the linker is spawned by a
    // shell inside the guest, so its host process (whose cmdline carries the guest path) appears only
    // later. A pattern resolved once at startup therefore matched nothing and the trigger silently
    // watched the wrapping shell instead -- a real capture fired on the wrong process and looked
    // plausible. Resolve per poll, and say when the pattern matches nothing.
    let mut target_note: Option<String> = None;
    let mut fatal_gdb: Vec<(u32, std::process::Child)> = Vec::new();
    let mut marker_pattern_armed = false;

    loop {
        if cancellation.requested()? {
            fs::write(bundle.join("cancelled.txt"), "cancellation requested\n")?;
            result = "cancelled";
            break;
        }
        if let Some(status) = child.try_wait()? {
            fs::write(bundle.join("exit-status.txt"), format!("{status}\n"))?;
            result = if status.success() { "exited" } else { "failed" };
            break;
        }
        if Instant::now() >= deadline {
            fs::write(bundle.join("timeout.txt"), "hard timeout\n")?;
            result = "timeout";
            break;
        }
        let state_target = match args.capture_pattern.as_deref() {
            Some(pattern) => match find_pid_in_tree(child.id(), pattern, args.capture_exe.as_deref(), args.capture_comm.as_deref()) {
                Ok(pid) => {
                    target_note = None;
                    pid
                }
                Err(_) => {
                    target_note = Some(format!(
                        "capture-pattern {pattern:?} matched no process in the tree; watching pid {} instead",
                        child.id()
                    ));
                    child.id()
                }
            },
            None => child.id(),
        };
        if args.capture_on_fatal
            && (args.capture_on_line.is_none() || marker_pattern_armed)
            && target_note.is_none()
        {
            arm_fatal_gdb(&args, &bundle, child.id(), &mut fatal_gdb)?;
        }
        if let Some(expr) = &state_expr {
            // STATE IS A BETTER TRIGGER THAN TEXT for a hang: a workload that stops working may print
            // nothing at all, and its state is readable from /proc without touching the measured path.
            // The predicate is named by the caller (see StateTrigger), and when it fires the matching
            // threads are written out, so the capture is not a guess about why it fired.
            if let Some(threads) = expr.matches(state_target) {
                let mut report = format!("trigger={}\ntarget_pid={state_target}\n", expr.describe());
                if let Some(note) = &target_note {
                    report.push_str(&format!("note={note}\n"));
                }
                for t in &threads {
                    report.push_str(&format!(
                        "pid={} tid={} state={} wchan={} syscall={}\n",
                        t.pid, t.tid, t.state, t.wchan, t.syscall
                    ));
                }
                fs::write(bundle.join("state.txt"), report)?;
                result = "state";
                break;
            }
            match state_quiet_since {
                Some(_) => {}
                None => state_quiet_since = Some(Instant::now()),
            }
        }
        if let Some(pattern) = &marker_pattern {
            // Both streams matter: a marker a workload writes to stderr is as much a fact as one on
            // stdout, and watching only stdout lost it. An explicitly named log still wins.
            if let Some(watch) = marker_log.as_ref() {
                if let Ok(mut file) = File::open(watch) {
                    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
                    if len < marker_offset {
                        marker_offset = 0;
                    }
                    let _ = file.seek(SeekFrom::Start(marker_offset));
                    let mut text = String::new();
                    if file.read_to_string(&mut text).is_ok() {
                        marker_offset = file.stream_position().unwrap_or(marker_offset);
                        if pattern.is_match(&text) {
                            fs::write(bundle.join("marker.txt"), "capture requested by --capture-on-line\n")?;
                            if args.capture_on_fatal {
                                // The marker is the point where the target is the loader, not the
                                // launcher that exec'd it in the same pid. Attaching here avoids the
                                // exec race entirely (MEASURED: an early attach saw
                                // "executing new program: mldr" and lost the inferior).
                                arm_fatal_gdb(&args, &bundle, child.id(), &mut fatal_gdb)?;
                                marker_pattern_armed = true;
                            }
                            if !(args.capture_on_fatal && marker_pattern_armed) {
                                result = "marker";
                                break;
                            }
                        }
                    }
                }
            } else {
                let mut fired = false;
                for (watch, offset) in [
                    (&stdout, &mut stdout_marker_offset),
                    (&stderr, &mut stderr_marker_offset),
                ] {
                    if marker_seen(watch, pattern, offset)? {
                        fired = true;
                        break;
                    }
                }
                if fired {
                    fs::write(bundle.join("marker.txt"), "capture requested by --capture-on-line\n")?;
                    if args.capture_on_fatal {
                        marker_pattern_armed = true;
                        arm_fatal_gdb(args, &bundle, child.id(), &mut fatal_gdb)?;
                    } else {
                        result = "marker";
                        break;
                    }
                }
            }
        }
        if detector
            .as_mut()
            .is_some_and(|value| value.poll(&stdout, &stderr).unwrap_or(false))
        {
            let events = detector.as_ref().map_or(0, |value| value.events);
            fs::write(bundle.join("stall.txt"), format!("events={events}\n"))?;
            result = "stall";
            break;
        }
        cancellation.wait(args.poll_seconds)?;
    }

    // The workload is over, so the probe is stopped first: it flushes on SIGINT and reports how much it recorded.
    if let Some(probe) = futex_probe.as_mut() {
        probe.stop();
    }
    // Close the run window. It is written here rather than at startup because the end is only known now, and a
    // window without an end can only be checked from its start.
    let run_end = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let manifest_path = bundle.join("evidence-manifest");
    if let Ok(text) = fs::read_to_string(&manifest_path) {
        let _ = fs::write(
            &manifest_path,
            format!("{text}end={run_end}\n"),
        );
    }

    // Detach strace (flushing rpctrace.log) before any gdb capture: a process
    // can only have a single tracer at a time.
    if let Some(strace) = strace {
        strace.detach();
    }

    {
        // The workload is over. If a debugger already stopped on a signal its dump is complete; the
        // others attached to processes that never faulted, and those processes are going away with the
        // run anyway.
        let mut armed: Vec<u32> = Vec::new();
        for (pid, mut child) in fatal_gdb.drain(..) {
            let _ = child.kill();
            let _ = child.wait();
            armed.push(pid);
        }
        let _ = fs::write(bundle.join("fatal-targets.txt"),
            armed.iter().map(u32::to_string).collect::<Vec<_>>().join("\n") + "\n");
    }
    if !matches!(result, "exited" | "failed") {
        if let Some(stall_log) = &args.stall_log {
            let stall_log = expand_home(stall_log);
            let _ = fs::copy(stall_log, bundle.join("stall-log.txt"));
        }
        if result != "cancelled" && args.exact.capture_exact {
            let selected = match args.capture_pattern.as_deref() {
                Some(pattern) => find_pid_in_tree(
                    child.id(), pattern, args.capture_exe.as_deref(), args.capture_comm.as_deref(),
                ),
                None => Ok(child.id()),
            };
            let capture_result = match selected {
                Ok(pid) => {
                    let pids = if args.capture_tree {
                        process_tree(pid)
                    } else {
                        vec![pid]
                    };
                    exact::capture(&pids, &bundle, &args.exact)
                }
                Err(_) if args.exact.capture_prefix.is_some() => {
                    exact::capture(&[], &bundle, &args.exact)
                }
                Err(error) => Err(error),
            };
            let report = match capture_result {
                Ok(complete) => format!("complete={complete}\n"),
                Err(error) => format!("incomplete: {error:#}\n"),
            };
            let _ = fs::write(bundle.join("exact-status.txt"), report);
        }
        let _ = capture_process_tree(
            child.id(),
            &bundle.join("guarded-tree"),
            false,
            false,
            None,
            None,
            &[],
            1,
            Duration::from_secs(0),
        );
        // --capture-tree used to do NOTHING unless --capture-gdb was also given: a capture that was
        // asked for produced no directory and said nothing about why. The /proc tree is exactly what
        // a hang needs (per-thread wchan/syscall/stack at the moment it stops), and it does not need
        // the debugger, so the tree is captured whenever it is asked for, with gdb only when asked.
        if result != "cancelled" && (args.capture_tree || args.capture_gdb) {
            let capture_pid = args
                .capture_pattern
                .as_deref()
                .and_then(|pattern| find_pid_in_tree(
                    child.id(), pattern, args.capture_exe.as_deref(), args.capture_comm.as_deref(),
                ).ok())
                .unwrap_or(child.id());
            if args.capture_tree {
                capture_process_tree(
                    capture_pid,
                    &bundle.join("capture-tree"),
                    args.capture_gdb,
                    args.gdb_namespace,
                    args.gdb_executable.as_deref(),
                    args.gdb_cwd.as_deref(),
                    &args.gdb_ex,
                    args.capture_snapshots,
                    Duration::from_secs(args.capture_interval_seconds),
                )?;
            } else {
                capture_target(
                    capture_pid,
                    &bundle.join("capture"),
                    true,
                    args.gdb_namespace,
                    args.gdb_executable.as_deref(),
                    args.gdb_cwd.as_deref(),
                    &args.gdb_ex,
                    args.capture_snapshots,
                    Duration::from_secs(args.capture_interval_seconds),
                )?;
            }
        }
        if result != "cancelled" && let Some(command) = &args.capture_command {
            let _ = shell_hook(command, &bundle, child.id());
        }
        if result != "stall" || !args.leave_running_on_stall {
            if let Some(command) = &args.terminate_command {
                let status = shell_hook(command, &bundle, child.id())
                    .context("failed to execute terminate-command")?;
                if !status.success() {
                    fs::write(bundle.join("cleanup-status.txt"),
                        format!("authority=terminate-hook state=hook-failed status={status} product_shutdown_verified=false\n"))?;
                    bail!("terminate-command failed: {status}; owner cleanup is incomplete");
                }
                let cleanup_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(child_status) = child.try_wait()? {
                        fs::write(bundle.join("cleanup-status.txt"),
                            format!("authority=terminate-hook state=hook-completed status={status} child_status={child_status} product_shutdown_verified=false external_rescue=unknown\n"))?;
                        break;
                    }
                    if Instant::now() >= cleanup_deadline {
                        fs::write(bundle.join("cleanup-status.txt"),
                            "authority=terminate-hook state=child-still-running product_shutdown_verified=false\n")?;
                        bail!("terminate-command returned but the managed child is still running");
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            } else {
                fs::write(
                    bundle.join("cleanup-status.txt"),
                    format!("authority=host-process-group state=externally-rescued product_shutdown_verified=false\n{}", terminate_group(&mut child)?),
                )?;
            }
        }
    }
    if (result != "stall" || !args.leave_running_on_stall)
        && let Some(command) = &args.cleanup_command
    {
        let _ = shell_hook(command, &bundle, child.id());
    }
    if args.forward_output {
        std::io::copy(
            &mut File::open(bundle.join("stdout.log"))?,
            &mut std::io::stdout().lock(),
        )?;
        std::io::copy(
            &mut File::open(bundle.join("stderr.log"))?,
            &mut std::io::stderr().lock(),
        )?;
    }
    Ok((bundle, result))
}

fn darling_command(args: &DarlingArgs, darling: &Path, dprefix: &Path) -> Result<(Vec<String>, HashMap<String, String>)> {
    let mut env = HashMap::new();
    env.insert("DPREFIX".to_owned(), dprefix.display().to_string());
    let mut command = vec![
        darling.display().to_string(),
        "shell".to_owned(),
        "/bin/bash".to_owned(),
        "-lc".to_owned(),
    ];
    command.push(
        args.common
            .command
            .iter()
            .map(|argument| shell_escape::escape(Cow::Borrowed(argument.as_str())).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    );
    Ok((command, env))
}

fn selected_darling(args: &DarlingArgs) -> Result<PathBuf> {
    if let Some(launcher) = &args.darling {
        let launcher = fs::canonicalize(expand_home(launcher)).context("resolve --darling")?;
        let root = launcher.parent().and_then(Path::parent).context("installed launcher root")?;
        if launcher.file_name().and_then(|name| name.to_str()) != Some("darling")
            || launcher.parent().and_then(Path::file_name).and_then(|name| name.to_str()) != Some("bin") {
            bail!("--darling must identify ROOT/bin/darling from an ordinary installation");
        }
        if RUNTIME_ROOT.get().is_none() {
            select_runtime_root(root.to_path_buf())?;
        }
        if installed_runtime_root()? != root {
            bail!("--darling and --runtime-root select different installations");
        }
        return Ok(launcher);
    }
    Ok(installed_runtime_root()?.join("bin/darling"))
}

static OWNER_LEASE_FD: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

// Only owner helpers/hooks inherit the descriptor. All other execs see CLOEXEC.
pub(crate) fn inherit_owner_lease(command: &mut Command) {
    if let Some(&fd) = OWNER_LEASE_FD.get() {
        unsafe {
            command.pre_exec(move || {
                let flags = nix::libc::fcntl(fd, nix::libc::F_GETFD);
                if flags < 0 || nix::libc::fcntl(fd, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// Use the shared Python lifecycle owner, borrowing only its validated inherited
/// descriptor. Runtime/debugger execs close it; known owner hooks retain it.
pub(crate) struct PrefixScope {
    child: Child,
}

impl PrefixScope {
    pub(crate) fn acquire(prefix: &Path, runtime: &Path, require_idle: bool) -> Result<Self> {
        if std::env::var_os("WEST_TEST_PREFIX_LEASE").is_some() {
            let fd: i32 = std::env::var("WEST_TEST_PREFIX_LEASE_FD")
                .unwrap_or_else(|_| "8".to_string()).parse().context("prefix lease descriptor")?;
            if fd < 3 { bail!("prefix lease descriptor must not be a standard stream"); }
            unsafe {
                let flags = nix::libc::fcntl(fd, nix::libc::F_GETFD);
                if flags < 0 || nix::libc::fcntl(fd, nix::libc::F_SETFD, flags | nix::libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error()).context("protecting owner lease descriptor");
                }
            }
            let _ = OWNER_LEASE_FD.set(fd);
        }
        let workspace = workspace_root()?;
        // The controller gets its prefix by argv, not guest ownership markers.
        let mut helper = Command::new("python3");
        helper.env_remove("DPREFIX").env_remove("DARLING_PREFIX");
        helper.args(["-B", "-c", r#"
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from west_commands.test_prefix import PrefixLifecycleOwner, validate_borrowed_prefix_lease
from west_commands.prefix_repair import cleanup_prefix_mounts, darling_init_pid_is_usable
from west_commands.runtime_install import resolve_runtime
p = Path(sys.argv[2])
validate_borrowed_prefix_lease(sys.argv[2])
r = resolve_runtime(sys.argv[3])
log = lambda message: print(message, file=sys.stderr, flush=True)
owner = PrefixLifecycleOwner(
    resolve_launcher=lambda _: str(r.launcher),
    prefix_env=lambda raw: r.environment(raw),
    cleanup_mounts=cleanup_prefix_mounts,
    init_pid_is_usable=darling_init_pid_is_usable,
    inf=log, err=log, wrn=log,
)
with owner.locked(sys.argv[2]) as lease_fd:
    os.set_inheritable(lease_fd, False)
    # Shutdown launches runtime children, not nested lifecycle owners.
    os.environ.pop("WEST_TEST_PREFIX_LEASE", None)
    os.environ.pop("WEST_TEST_PREFIX_LEASE_FD", None)
    r.environment(sys.argv[2])
    if sys.argv[4] == "idle" and owner.process_snapshot(p):
        raise RuntimeError("guest state is still owned by live runtime processes")
    print("LEASED", flush=True)
    action = sys.stdin.readline().strip()
    if action == "shutdown" or (sys.argv[4] == "lifecycle" and action != "retain"):
        sys.exit(0 if owner.shutdown(p) else 1)
"#])
            .arg(workspace).arg(prefix).arg(runtime).arg(if require_idle { "idle" } else { "lifecycle" })
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        inherit_owner_lease(&mut helper);
        let mut child = helper.spawn().context("starting shared prefix lifecycle owner")?;
        let mut ready = String::new();
        use std::io::BufRead as _;
        std::io::BufReader::new(child.stdout.take().context("prefix owner stdout")?)
            .read_line(&mut ready)?;
        if ready.trim() != "LEASED" {
            let status = child.wait()?;
            bail!("shared prefix owner refused {}: {status}", prefix.display());
        }
        Ok(Self { child })
    }

    fn shutdown(&mut self) -> Result<bool> {
        use std::io::Write as _;
        writeln!(self.child.stdin.as_mut().context("prefix owner stdin")?, "shutdown")?;
        self.child.stdin.take();
        Ok(self.child.wait()?.success())
    }
}

impl Drop for PrefixScope {
    fn drop(&mut self) {
        self.child.stdin.take();
        let _ = self.child.wait();
    }
}

fn prepare_darling(darling: &Path, dprefix: &Path) -> Result<()> {
    if !diag::prefix_processes(&dprefix).is_empty() {
        let status = Command::new(darling).env("DPREFIX", &dprefix).arg("shutdown").status()?;
        if !status.success() || !diag::prefix_processes(&dprefix).is_empty() {
            bail!("product shutdown did not stop the selected guest prefix {}", dprefix.display());
        }
    }
    Ok(())
}

/// The stream the CALLER is actually watching.
///
/// A long run duplicates stdout/stderr into a transcript so its output cannot be lost; but then the caller sees NOTHING,
/// which is its own defect: MEASURED, `dwdiag prefix`/`verdict` output was grepped from stdout and matched nothing while
/// the answer sat in the transcript, twice leading to "the tool was silent" conclusions that were wrong. Essentials --
/// stage lines, verdict rows, denial lines, hash checks, the final rc -- are therefore written HERE as well.
static ORIGINAL_STDOUT: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

pub fn say(message: &str) {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    if let Some(fd) = ORIGINAL_STDOUT.get() {
        let mut f = unsafe { std::fs::File::from_raw_fd(*fd) };
        let _ = writeln!(f, "{message}");
        let _ = f.flush();
        std::mem::forget(f);
    } else {
        println!("{message}");
    }
}

/// Print the part of a long run that a caller actually asks for: stage lines, hash checks, verdict rows, denial lines,
/// the suite table and the final verdict. The transcript next to it still holds EVERYTHING.
fn echo_essentials(path: &std::path::Path) {
    const KEEP: &[&str] = &[
        "PREFIX-STAGE", "PREFIX-INSTALL", "PREFIX-INSTALLED", "PREFIX-ENV",
        "VERDICT", "LOG=", "DENIAL", "MARKER", "SUITE", "MATCH", "MISMATCH",
        "COURIER", "WAKES", "PROGRESS", "ERROR", "error:", "Failed", "failed",
    ];
    let Ok(text) = std::fs::read_to_string(path) else { return };
    let mut printed = 0usize;
    for line in text.lines() {
        if KEEP.iter().any(|k| line.contains(k)) {
            say(line);
            printed += 1;
        }
    }
    say(&format!("ESSENTIALS {printed} line(s) from {}", path.display()));
}

#[cfg(target_os = "linux")]
fn signal_pidfd(descriptor: &std::os::fd::OwnedFd, signal: Signal) -> Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe {
        nix::libc::syscall(nix::libc::SYS_pidfd_send_signal,
            descriptor.as_raw_fd(), signal as i32,
            std::ptr::null::<nix::libc::siginfo_t>(), 0)
    } < 0 {
        return Err(std::io::Error::last_os_error())
            .context("signal pinned process descriptor");
    }
    Ok(())
}

fn main() -> Result<ExitCode> {
    // MEASURED defect: `dwdiag progress ... | head -4` panicked with `failed printing to stdout: Broken pipe (os error
    // 32)`, because Rust starts every process with SIGPIPE ignored. A diagnostic whose output is paged or truncated is
    // ordinary use, so restore the default disposition and let the kernel terminate the process the way any other CLI
    // would, instead of reporting a panic that says nothing about the transport under test.
    unsafe {
        nix::sys::signal::signal(
            nix::sys::signal::Signal::SIGPIPE,
            nix::sys::signal::SigHandler::SigDfl,
        )
        .expect("failed to restore the default SIGPIPE disposition");
    }
    // EVERYTHING THIS PROCESS PRINTS ALSO GOES TO A FILE, announced first.
    //
    // MEASURED: a gate that booted a prefix and ran a workload for 265 seconds produced NO output at all through a
    // pipeline -- not in the calling script's own failure path, not with the output echoed back. A diagnostic whose
    // result can be lost while it runs cannot be used to decide anything, and the caller cannot even tell a silent
    // failure from a lost one. Child processes inherit these descriptors, so the boot harness and the guest tooling are
    // captured too, and the announcement is written to the ORIGINAL stdout so it survives the redirection.
    // PARSE FIRST. MEASURED: with the transcript installed before parsing, `dwdiag prefix --artifact …` (a flag that had
    // been lost from the build) answered `error: unexpected argument '--artifact' found` INTO THE TRANSCRIPT, so the
    // caller saw a bare TRANSCRIPT= line and nothing else -- a usage error is an answer and must reach the caller.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            print!("{e}");
            return Ok(if e.use_stderr() { ExitCode::from(2) } else { ExitCode::SUCCESS });
        }
    };
    if let Some(root) = cli.runtime_root.as_ref() {
        select_runtime_root(root.clone())?;
    }
    let mut transcript_path: Option<PathBuf> = None;
    {
        use std::io::Write;
        let path = std::env::var("DWDIAG_TRANSCRIPT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(format!("/tmp/dwdiag-transcript-{}.out", std::process::id()))
            });
        // `--help` and `--version` are ANSWERS, not run output: redirecting them into a file would hide the one thing
        // the caller asked for. MEASURED: with the redirect unconditional, `dwdiag prefix --help` printed nothing to the
        // terminal at all.
        let wants_help = std::env::args()
            .any(|a| matches!(a.as_str(), "-h" | "--help" | "-V" | "--version" | "help"));
        if !wants_help {
            // The transcript exists for runs whose output can be LOST while they run -- a boot plus a workload under a
        // watchdog. For the short diagnostics the answer IS the output, and redirecting it hides the one thing the
        // caller asked for: MEASURED, `dwdiag symbolize` refused loudly with `Error: base symbol not found: 0` and I read
        // an empty terminal, concluding the tool was silent. Answers go to the terminal; only long runs get a transcript.
        let long_run = std::env::args().any(|a| matches!(a.as_str(), "verdict" | "suite" | "prefix" | "replay"))
            || std::env::var("DWDIAG_TRANSCRIPT").is_ok();
        if long_run {
        if let Ok(file) = std::fs::File::create(&path) {
                // Keep a duplicate of the CALLER's stdout for `say()`, then redirect.
                {
                    use std::os::fd::IntoRawFd;
                    if let Ok(d) = nix::unistd::dup(std::io::stdout()) {
                        let _ = ORIGINAL_STDOUT.set(d.into_raw_fd());
                    }
                }
                // Announce on the ORIGINAL stdout first, then redirect: the announcement must reach the caller even though
                // everything printed afterwards (including by the children) lands in the transcript.
                transcript_path = Some(path.clone());
                println!("TRANSCRIPT={}", path.display());
                let _ = std::io::stdout().flush();
                let _ = nix::unistd::dup2_stdout(&file);
                let _ = nix::unistd::dup2_stderr(&file);
            }
        }
        }
    }
    // The diagnostics do not run an experiment and do not produce a bundle: they answer a question and report it with
    // their OWN exit code (0 ok/PASS, 1 finding, 2 usage, 3 tool error), so a caller can compose them without parsing
    // human output. That is why they are dispatched before the bundle machinery.
    //
    // After a long run the ESSENTIALS are echoed to the caller from the transcript. Without this the caller sees only
    // the transcript's path: MEASURED, output was grepped from stdout and matched nothing while the answer sat in the
    // file, twice producing a wrong "the tool was silent" conclusion. The transcript still holds everything; this is
    // the part a person or a script actually asks for.
    if let RunnerCommand::Diag(cmd) = cli.command {
        let code = match diag::dispatch(cmd) {
            Ok(code) => code,
            // AN ERROR MUST REACH THE CALLER, NOT ONLY THE TRANSCRIPT. MEASURED: a long-run command has stdout and
            // stderr redirected into its transcript by design, so `dwdiag prefix --artifact <unknown-name>` failed with
            // its reason visible only inside the file and the caller read `TRANSCRIPT=...` plus `ESSENTIALS 0 line(s)`
            // as "nothing to do" -- the same silent-answer defect this file already fixed for clap's usage errors, one
            // layer further in. The reason is written to the stream the caller is watching, and the exit code is a
            // failure so a script cannot mistake it for success.
            Err(e) => {
                say(&format!("ERROR: {e:#}"));
                if let Some(p) = transcript_path.as_deref() {
                    echo_essentials(p);
                }
                return Ok(ExitCode::from(3));
            }
        };
        if let Some(p) = transcript_path.as_deref() {
            echo_essentials(p);
        }
        return Ok(code);
    }
    // The run/capture path announces its bundle before the payload starts, so the announcement is
    // available for a hang instead of only for a finished run; do not print a second, later copy.
    let announced_early = matches!(cli.command, RunnerCommand::Run(_) | RunnerCommand::Capture(_));
    let (owns_bundle, can_retain_payload) = match &cli.command {
        RunnerCommand::Run(args) => (true, args.common.leave_running_on_stall),
        RunnerCommand::Darling(args) => (true, args.common.leave_running_on_stall),
        RunnerCommand::Capture(_) => (true, false),
        RunnerCommand::Signal(_) => (false, false),
        RunnerCommand::Diag(_) => unreachable!("diag dispatched before the bundle machinery"),
    };
    let (bundle, result) = match cli.command {
        RunnerCommand::Run(args) => {
            let command = args.common.command.clone();
            run_experiment(&args.common, command, HashMap::new())?
        }
        RunnerCommand::Darling(mut args) => {
            let darling = selected_darling(&args)?;
            let dprefix = expand_home(&args.dprefix);
            // This route itself owns a lifecycle, unlike generic `run`. Reexec
            // under the shared CLI so nested managed hooks can borrow the lease.
            if std::env::var_os("WEST_TEST_PREFIX_LEASE").is_none() {
                let owner = workspace_root()?.join("west_commands/test_prefix.py");
                let error = Command::new("python3").arg("-B").arg(owner)
                    .arg("--prefix").arg(&dprefix).arg("--")
                    .arg(std::env::current_exe()?).args(std::env::args_os().skip(1)).exec();
                return Err(error).context("entering shared prefix lifecycle owner");
            }
            let mut scope = PrefixScope::acquire(&dprefix, installed_runtime_root()?, false)?;
            prepare_darling(&darling, &dprefix)?;
            if args.common.stall_log.is_none()
                && (args.common.stall_pattern.is_some() || args.common.stall_seconds.is_some())
            {
                args.common.stall_log = Some(dprefix.join("private/var/log/dserver.log"));
            }
            if args.common.terminate_command.is_none() {
                args.common.terminate_command = Some(format!(
                    "DPREFIX={} {} shutdown",
                    shell_escape::escape(Cow::Owned(dprefix.display().to_string())),
                    shell_escape::escape(Cow::Owned(
                        darling.display().to_string()
                    ))
                ));
            }
            let (command, env) = darling_command(&args, &darling, &dprefix)?;
            let outcome = run_experiment(&args.common, command, env);
            if args.common.leave_running_on_stall
                && matches!(&outcome, Ok((_, "stall"))) {
                use std::io::Write as _;
                writeln!(scope.child.stdin.as_mut().context("prefix owner stdin")?, "retain")?;
                outcome?
            } else {
                let clean = scope.shutdown()?;
                let (bundle, result) = outcome?;
                fs::write(bundle.join("prefix-cleanup-status.txt"),
                    format!("authority=shared-prefix-owner product_shutdown_verified={clean}\n"))?;
                (bundle, if clean { result } else { "failed" })
            }
        }
        RunnerCommand::Capture(args) => {
            let pid = if args.exact.capture_prefix.is_some()
                && args.pid.is_none()
                && args.pattern.is_none()
            {
                None
            } else {
                Some(find_pid(args.pid, args.pattern.as_deref())?)
            };
            let bundle = make_bundle(&args.bundle_root, &args.name)?;
            println!("BUNDLE={}", bundle.display());
            std::io::stdout().flush()?;
            let exact_complete = if args.exact.capture_exact {
                let pids = pid
                    .map(|pid| {
                        if args.tree {
                            process_tree(pid)
                        } else {
                            vec![pid]
                        }
                    })
                    .unwrap_or_default();
                exact::capture(&pids, &bundle, &args.exact)?
            } else {
                true
            };
            if let Some(pid) = pid.filter(|_| args.tree) {
                capture_process_tree(
                    pid,
                    &bundle,
                    args.gdb,
                    args.gdb_namespace,
                    args.gdb_executable.as_deref(),
                    args.gdb_cwd.as_deref(),
                    &args.gdb_ex,
                    args.snapshots,
                    Duration::from_secs(args.interval_seconds),
                )?;
            } else if let Some(pid) = pid {
                capture_target(
                    pid,
                    &bundle,
                    args.gdb,
                    args.gdb_namespace,
                    args.gdb_executable.as_deref(),
                    args.gdb_cwd.as_deref(),
                    &args.gdb_ex,
                    args.snapshots,
                    Duration::from_secs(args.interval_seconds),
                )?;
            }
            (bundle, if exact_complete { "captured" } else { "capture-incomplete" })
        }
        // unreachable: the diagnostics are dispatched before this match, and they own their exit codes
        RunnerCommand::Diag(_) => unreachable!("diag dispatched before the bundle machinery"),
        RunnerCommand::Signal(args) => {
            let signal_name = if args.signal.starts_with("SIG") {
                args.signal
            } else {
                format!("SIG{}", args.signal)
            };
            let signal: Signal = signal_name
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid signal: {signal_name}"))?;
            if let Some(pidfd) = args.pidfd {
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::{FromRawFd, OwnedFd};
                    let descriptor = unsafe {
                        nix::libc::fcntl(pidfd, nix::libc::F_DUPFD_CLOEXEC, 0)
                    };
                    if descriptor < 0 {
                        return Err(std::io::Error::last_os_error())
                            .context(format!("duplicate inherited pidfd={pidfd}"));
                    }
                    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
                    signal_pidfd(&descriptor, signal)?;
                    println!("SIGNAL pidfd={pidfd} signal={signal:?} group=false");
                }
                #[cfg(not(target_os = "linux"))]
                bail!("--pidfd requires Linux");
            } else {
                let pid = find_pid(args.pid, args.pattern.as_deref())?;
                if args.group {
                    let pgid = getpgid(Some(Pid::from_raw(pid as i32)))?;
                    killpg(pgid, signal)?;
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::fd::{FromRawFd, OwnedFd};
                        let descriptor = unsafe {
                            nix::libc::syscall(nix::libc::SYS_pidfd_open, pid as i32, 0)
                        } as i32;
                        if descriptor < 0 {
                            return Err(std::io::Error::last_os_error())
                                .context(format!("pin signal target pid={pid}"));
                        }
                        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
                        signal_pidfd(&descriptor, signal)?;
                    }
                    #[cfg(not(target_os = "linux"))]
                    nix::sys::signal::kill(Pid::from_raw(pid as i32), signal)?;
                }
                println!("SIGNAL pid={pid} signal={signal:?} group={}", args.group);
            }
            (PathBuf::from("."), "signaled")
        }
    };
    if owns_bundle && !announced_early {
        println!("BUNDLE={}", bundle.display());
    }
    println!("RESULT={result}");
    let storage_ok = if owns_bundle {
        match finalize_bundle_storage(&bundle, result, result == "stall" && can_retain_payload) {
            Ok(successful) => successful,
            Err(error) => {
                eprintln!("STORAGE=unavailable bundle={} reason={error:#}; inspect retained raw/indexed payloads",
                    bundle.display());
                false
            }
        }
    } else {
        true
    };
    if matches!(result, "exited" | "captured" | "signaled") {
        Ok(if storage_ok { ExitCode::SUCCESS } else { ExitCode::from(3) })
    } else {
        bail!("{result}")
    }
}

/// A named state predicate over the target's threads.
///
/// It exists because "the workload stopped working" is a fact about /proc, not about text: a hang can
/// print nothing, and the condition worth capturing is "these threads are parked and stay parked".
/// The grammar is deliberately tiny and each variant says what it means in `describe`, so a capture
/// never fires for an unnamed reason.
struct StateTrigger {
    kind: StateTriggerKind,
}

enum StateTriggerKind {
    State(String),
    Wchan(String),
    Syscall(String),
    AllWaiting(u64),
}

struct ThreadState {
    pid: u32,
    tid: u32,
    state: String,
    wchan: String,
    syscall: String,
}

impl StateTrigger {
    fn parse(expr: &str) -> Result<Self> {
        let (key, value) = expr
            .split_once('=')
            .with_context(|| format!("expected KEY=VALUE in --capture-on-state, got {expr:?}"))?;
        let kind = match key {
            "state" => {
                // A state letter nobody can match is a predicate that silently never fires.
                let valid = ["R", "S", "D", "T", "t", "Z", "X", "x", "I", "W"];
                if !valid.contains(&value) {
                    bail!("--capture-on-state state={value:?} is not a process state letter; use one of R S D T t Z X x I W");
                }
                StateTriggerKind::State(value.to_owned())
            }
            "wchan" => {
                if value.is_empty() {
                    bail!("--capture-on-state wchan= is empty, so it would match any wchan");
                }
                StateTriggerKind::Wchan(value.to_owned())
            }
            "syscall" => {
                if value.parse::<i64>().is_err() {
                    bail!("--capture-on-state syscall={value:?} is not a number");
                }
                StateTriggerKind::Syscall(value.to_owned())
            }
            "all-waiting" => StateTriggerKind::AllWaiting(
                value
                    .parse()
                    .with_context(|| format!("--capture-on-state all-waiting expects seconds, got {value:?}"))?,
            ),
            other => bail!("unknown --capture-on-state key {other:?}; use state, wchan, syscall or all-waiting"),
        };
        Ok(Self { kind })
    }

    fn describe(&self) -> String {
        match &self.kind {
            StateTriggerKind::State(v) => format!("state={v}"),
            StateTriggerKind::Wchan(v) => format!("wchan contains {v}"),
            StateTriggerKind::Syscall(v) => format!("syscall={v}"),
            StateTriggerKind::AllWaiting(v) => {
                format!("all {v}s: every thread of a multi-threaded target waiting")
            }
        }
    }

    fn matches(&self, pid: u32) -> Option<Vec<ThreadState>> {
        let threads = sample_threads(pid);
        if threads.is_empty() {
            return None;
        }
        match &self.kind {
            StateTriggerKind::State(v) => {
                let hits: Vec<_> = threads.into_iter().filter(|t| &t.state == v).collect();
                (!hits.is_empty()).then_some(hits)
            }
            StateTriggerKind::Wchan(v) => {
                let hits: Vec<_> = threads.into_iter().filter(|t| t.wchan.contains(v.as_str())).collect();
                (!hits.is_empty()).then_some(hits)
            }
            StateTriggerKind::Syscall(v) => {
                let hits: Vec<_> = threads.into_iter().filter(|t| &t.syscall == v).collect();
                (!hits.is_empty()).then_some(hits)
            }
            StateTriggerKind::AllWaiting(seconds) => {
                // A single-threaded process waiting for its child is normal (a compiler driver sits in
                // pipe_read while the linker runs), so a target with one thread is never "stuck"; the
                // hang this catches is a workload whose WORKERS are parked.
                if threads.len() < 2 {
                    // The condition cannot hold, so the interval that was being timed is broken and
                    // must restart: leaving it intact let a later multi-threaded wait inherit elapsed
                    // time from before, i.e. report a duration that was not continuous.
                    *all_waiting_since(pid) = None;
                    return None;
                }
                let all = threads.iter().all(|t| is_waiting(&t.state, &t.wchan));
                if !all {
                    *all_waiting_since(pid) = None;
                    return None;
                }
                let since = all_waiting_since(pid);
                let started = since.get_or_insert_with(Instant::now);
                (started.elapsed() >= Duration::from_secs(*seconds)).then_some(threads)
            }
        }
    }
}

/// When the "everyone waiting" condition started holding, keyed by pid. A module-level map is enough
/// here: one run captures one target at a time, and the value is reset the moment the condition breaks.
fn all_waiting_since(pid: u32) -> &'static mut Option<Instant> {
    static mut SINCE: Option<(u32, Option<Instant>)> = None;
    unsafe {
        match SINCE {
            Some((p, _)) if p != pid => SINCE = Some((pid, None)),
            None => SINCE = Some((pid, None)),
            _ => {}
        }
        if let Some((_, ref mut since)) = SINCE {
            since
        } else {
            unreachable!()
        }
    }
}

fn is_waiting(state: &str, wchan: &str) -> bool {
    if state.starts_with('D') || state.starts_with('S') {
        return true;
    }
    // A guest thread parked in an ulock wait can still be reported as running while it sits in the
    // server, so the wchan is the honest half of the test.
    let parked = [
        "futex", "ulock", "poll", "ep_poll", "wait", "pause", "do_sys",
    ];
    parked.iter().any(|p| wchan.contains(p))
}

fn sample_threads(pid: u32) -> Vec<ThreadState> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    let mut tids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    tids.sort_unstable();
    for tid in tids {
        let base = PathBuf::from(format!("/proc/{pid}/task/{tid}"));
        let state = fs::read_to_string(base.join("stat"))
            .ok()
            .and_then(|s| {
                // state is the field after the comm in parentheses
                s.rsplit_once(')').map(|(_, rest)| {
                    rest.split_whitespace().next().unwrap_or("?").to_string()
                })
            })
            .unwrap_or_else(|| "?".into());
        let wchan = fs::read_to_string(base.join("wchan"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".into());
        let syscall = fs::read_to_string(base.join("syscall"))
            .ok()
            .and_then(|s| s.split_whitespace().next().map(|v| v.to_string()))
            .unwrap_or_else(|| "?".into());
        out.push(ThreadState { pid, tid, state, wchan, syscall });
    }
    out
}

#[cfg(test)]
mod identity_tests {
    use super::parse_process_stat;

    #[test]
    fn stat_identity_splits_after_the_final_comm_parenthesis() {
        let mut fields = vec!["S".to_owned(), "42".to_owned()];
        fields.extend(std::iter::repeat_n("0".to_owned(), 17));
        fields.push("777".to_owned());
        let stat = format!("123 (a name) with spaces) {}\n", fields.join(" "));
        assert_eq!(parse_process_stat(&stat), Some((Some(42), 777)));
    }

    #[test]
    fn a_stat_line_without_enough_fields_has_no_identity() {
        assert_eq!(parse_process_stat("123 (cat) S 1"), None);
        assert_eq!(parse_process_stat("123 cat S 1"), None);
    }
}

