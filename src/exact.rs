use anyhow::{Context, Result};
use clap::Args;
use std::fs::{self, File, Permissions};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

#[derive(Args)]
pub struct ExactArgs {
    /// Capture cores and identity-verified mapped files before termination. May contain secrets.
    #[arg(long)]
    pub capture_exact: bool,
    /// Include processes owned by this exact Darling prefix, including detached loaders.
    #[arg(long, requires = "capture_exact")]
    pub capture_prefix: Option<PathBuf>,
    /// Total exact-capture deadline, shared by all selected processes (plus 2s kill grace).
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub exact_timeout_seconds: u64,
    /// Total exact-capture storage budget, including cores, files, metadata and debugger output.
    #[arg(long, default_value_t = 512, value_parser = clap::value_parser!(u64).range(16..=65536))]
    pub exact_max_mib: u64,
}

// Drain continuously even after the retention limit: the debugger must never block on logging.
fn drain(mut input: impl Read, limit: usize) -> (Vec<u8>, u64) {
    let mut kept = Vec::new();
    let mut discarded = 0;
    let mut buffer = [0; 8192];
    while let Ok(count) = input.read(&mut buffer) {
        if count == 0 {
            break;
        }
        let retain = count.min(limit - kept.len());
        kept.extend_from_slice(&buffer[..retain]);
        discarded += (count - retain) as u64;
    }
    (kept, discarded)
}

pub fn capture(pids: &[u32], bundle: &Path, args: &ExactArgs) -> Result<bool> {
    let directory = bundle.join("exact");
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, Permissions::from_mode(0o700))?;
    let directory = fs::canonicalize(directory)?;
    fs::write(
        directory.join("worker.py"),
        include_str!("exact_capture.py"),
    )?;
    if let Some(prefix) = &args.capture_prefix {
        let prefix = fs::canonicalize(crate::expand_home(prefix))
            .context("cannot resolve exact-capture prefix")?;
        if !prefix.is_dir() {
            anyhow::bail!("exact-capture prefix is not a directory");
        }
        fs::write(directory.join("prefix.bin"), prefix.as_os_str().as_bytes())?;
    }
    // Numeric configuration only; paths never become shell or debugger command expressions.
    let config = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        unsafe { nix::libc::getuid() },
        unsafe { nix::libc::getgid() },
        args.exact_max_mib * 1024 * 1024,
        args.exact_timeout_seconds,
        pids.len(),
        pids.iter()
            .take(128)
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    );
    fs::write(directory.join("config.txt"), config)?;
    fs::write(
        directory.join("manifest.json"),
        "{\"complete\":false,\"error\":\"debugger has not completed capture\"}\n",
    )?;
    let output = File::create(directory.join("gdb.txt"))?;
    let error_output = output.try_clone()?;
    // Run timeout *inside* sudo so its kill escalation can always signal the privileged debugger.
    // GDB's ptrace relationship is released by the kernel even if escalation kills it.
    let spawned = Command::new("sudo")
        .args(["-n", "timeout", "--signal=TERM", "--kill-after=2s"])
        .arg(format!("{}s", args.exact_timeout_seconds))
        .args([
            "gdb",
            "-nx",
            "-nh",
            "-q",
            "-batch",
            "-iex",
            "set auto-load off",
            "-x",
            "worker.py",
        ])
        .current_dir(&directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            fs::write(
                directory.join("status.txt"),
                format!("incomplete: {error}\n"),
            )?;
            return Ok(false);
        }
    };
    let stdout = child.stdout.take().context("missing debugger stdout")?;
    let stderr = child.stderr.take().context("missing debugger stderr")?;
    let stdout = thread::spawn(move || drain(stdout, 512 * 1024));
    let stderr = thread::spawn(move || drain(stderr, 512 * 1024));
    let status = child.wait()?;
    let (stdout, dropped_out) = stdout
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panicked"))?;
    let (stderr, dropped_err) = stderr
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panicked"))?;
    use std::io::Write;
    (&output).write_all(&stdout)?;
    (&error_output).write_all(&stderr)?;
    let complete = status.success() && directory.join("complete").is_file();
    fs::write(
        directory.join("status.txt"),
        format!(
            "complete={complete}\ndebugger_status={status}\nlog_discarded_bytes={}\n",
            dropped_out + dropped_err
        ),
    )?;
    Ok(complete)
}
