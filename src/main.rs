use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getpgid};
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(about = "Run and capture local or Darling debugging experiments")]
struct Cli {
    #[command(subcommand)]
    command: RunnerCommand,
}

#[derive(Subcommand)]
enum RunnerCommand {
    Run(RunArgs),
    Darling(DarlingArgs),
    Capture(CaptureArgs),
    Signal(SignalArgs),
}

#[derive(Args)]
struct CommonArgs {
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
    gdb_executable: Option<PathBuf>,
    #[arg(long)]
    gdb_cwd: Option<PathBuf>,
    #[arg(long)]
    gdb_ex: Vec<String>,
    #[arg(long)]
    capture_pattern: Option<String>,
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
    #[arg(long, default_value = "~/work/darling-prefix/bin/darling")]
    darling: PathBuf,
    #[arg(long, default_value = "~/.darling")]
    dprefix: PathBuf,
    #[arg(long)]
    install_server: Option<PathBuf>,
}

#[derive(Args)]
struct CaptureArgs {
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
        Ok(Some(Self {
            log,
            pattern: Regex::new(pattern).context("invalid --stall-pattern")?,
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
            self.armed = self
                .after_output
                .as_ref()
                .is_some_and(|pattern| pattern.is_match(&output));
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
            let new_events = self.pattern.find_iter(&new_text).count() as u64;
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

fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(text.trim_start_matches("~/"));
        }
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
    let bundle = expand_home(root).join(format!(
        "{}-{safe_name}",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    fs::create_dir_all(&bundle)?;
    Ok(bundle)
}

fn shell_hook(command: &str, bundle: &Path, pid: u32) {
    let _ = Command::new("/bin/bash")
        .args(["-lc", command])
        .env("BUNDLE", bundle)
        .env("TARGET_PID", pid.to_string())
        .status();
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

fn command_to_file(mut command: Command, output: &Path) {
    if let Ok(file) = File::create(output) {
        let _ = command
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .status();
    }
}

fn capture_target(
    pid: u32,
    bundle: &Path,
    gdb: bool,
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
            let mut command = Command::new("timeout");
            command.args(["30s", "sudo", "-n", "gdb", "-q"]);
            if let Some(cwd) = gdb_cwd {
                command.current_dir(expand_home(cwd));
            }
            if let Some(executable) = gdb_executable {
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
            for expression in gdb_ex {
                command.args(["-ex", expression]);
            }
            command_to_file(command, &bundle.join(format!("gdb-{index}.txt")));
        }
        if index < snapshots {
            thread::sleep(interval);
        }
    }
    Ok(())
}

fn terminate_group(child: &Child) {
    let _ = killpg(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
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
    let mut process = Command::new(program);
    process
        .args(&command[1..])
        .envs(args.env.iter().cloned())
        .envs(extra_env)
        .stdout(stdout)
        .stderr(stderr);
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
    let bundle = make_bundle(&args.bundle_root, &args.name)?;
    fs::write(
        bundle.join("command.txt"),
        format!("{}\n", command.join(" ")),
    )?;
    if let Some(command) = &args.prepare_command {
        shell_hook(command, &bundle, 0);
    }
    let mut detector = StallDetector::from_args(args)?;
    let mut child = spawn(args, &bundle, &command, &extra_env)?;
    fs::write(bundle.join("pid.txt"), format!("{}\n", child.id()))?;
    let stdout = bundle.join("stdout.log");
    let stderr = bundle.join("stderr.log");
    let deadline = Instant::now() + Duration::from_secs(args.timeout_seconds);
    let result;

    loop {
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
        if detector
            .as_mut()
            .is_some_and(|value| value.poll(&stdout, &stderr).unwrap_or(false))
        {
            let events = detector.as_ref().map_or(0, |value| value.events);
            fs::write(bundle.join("stall.txt"), format!("events={events}\n"))?;
            result = "stall";
            break;
        }
        thread::sleep(Duration::from_secs(args.poll_seconds));
    }

    if !matches!(result, "exited" | "failed") {
        if let Some(stall_log) = &args.stall_log {
            let stall_log = expand_home(stall_log);
            let _ = fs::copy(stall_log, bundle.join("stall-log.txt"));
        }
        if args.capture_gdb {
            let capture_pid = find_pid(None, args.capture_pattern.as_deref()).unwrap_or(child.id());
            capture_target(
                capture_pid,
                &bundle.join("capture"),
                true,
                args.gdb_executable.as_deref(),
                args.gdb_cwd.as_deref(),
                &args.gdb_ex,
                args.capture_snapshots,
                Duration::from_secs(args.capture_interval_seconds),
            )?;
        }
        if let Some(command) = &args.capture_command {
            shell_hook(command, &bundle, child.id());
        }
        if result != "stall" || !args.leave_running_on_stall {
            if let Some(command) = &args.terminate_command {
                shell_hook(command, &bundle, child.id());
            } else {
                terminate_group(&child);
            }
        }
    }
    if (result != "stall" || !args.leave_running_on_stall)
        && let Some(command) = &args.cleanup_command
    {
        shell_hook(command, &bundle, child.id());
    }
    Ok((bundle, result))
}

fn darling_command(args: &DarlingArgs) -> Result<(Vec<String>, HashMap<String, String>)> {
    let darling = expand_home(&args.darling);
    let dprefix = expand_home(&args.dprefix);
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

fn prepare_darling(args: &DarlingArgs) -> Result<()> {
    let darling = expand_home(&args.darling);
    let dprefix = expand_home(&args.dprefix);
    let _ = Command::new(&darling)
        .env("DPREFIX", &dprefix)
        .arg("shutdown")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    thread::sleep(Duration::from_secs(3));
    if let Some(server) = &args.install_server {
        let destination = darling
            .parent()
            .context("invalid --darling path")?
            .join("darlingserver");
        fs::copy(expand_home(server), destination).context("failed to install darlingserver")?;
    }
    Ok(())
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    let (bundle, result) = match cli.command {
        RunnerCommand::Run(args) => {
            let command = args.common.command.clone();
            run_experiment(&args.common, command, HashMap::new())?
        }
        RunnerCommand::Darling(mut args) => {
            prepare_darling(&args)?;
            let dprefix = expand_home(&args.dprefix);
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
                        expand_home(&args.darling).display().to_string()
                    ))
                ));
            }
            let (command, env) = darling_command(&args)?;
            run_experiment(&args.common, command, env)?
        }
        RunnerCommand::Capture(args) => {
            let pid = find_pid(args.pid, args.pattern.as_deref())?;
            let bundle = make_bundle(&args.bundle_root, &args.name)?;
            capture_target(
                pid,
                &bundle,
                args.gdb,
                args.gdb_executable.as_deref(),
                args.gdb_cwd.as_deref(),
                &args.gdb_ex,
                args.snapshots,
                Duration::from_secs(args.interval_seconds),
            )?;
            (bundle, "captured")
        }
        RunnerCommand::Signal(args) => {
            let pid = find_pid(args.pid, args.pattern.as_deref())?;
            let signal_name = if args.signal.starts_with("SIG") {
                args.signal
            } else {
                format!("SIG{}", args.signal)
            };
            let signal: Signal = signal_name
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid signal: {signal_name}"))?;
            if args.group {
                let pgid = getpgid(Some(Pid::from_raw(pid as i32)))?;
                killpg(pgid, signal)?;
            } else {
                nix::sys::signal::kill(Pid::from_raw(pid as i32), signal)?;
            }
            (PathBuf::from("."), "signaled")
        }
    };
    println!("BUNDLE={}", bundle.display());
    println!("RESULT={result}");
    if matches!(result, "exited" | "captured" | "signaled") {
        Ok(ExitCode::SUCCESS)
    } else {
        bail!("{result}")
    }
}
