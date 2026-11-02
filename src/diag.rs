//! Diagnostics that were previously a pile of shell scripts, folded into ONE composable CLI.
//!
//! WHY THEY LIVE HERE. The guest/runtime work needs four things constantly, and each of them was a separate script with
//! its own quoting rules, its own idea of a verdict and its own exit code (MEASURED: two workloads that never finished
//! were reported PASS by a harness whose marker matched the workload's START line; a crash was resolved by hand five
//! times; a denial's caller was derived by hand every time; and a cleanup killed its own caller because a grandparent
//! was inside a cmdline filter). They also all need the same two primitives -- `llvm-nm` symbolization and reading a
//! run log -- so they belong in one binary with:
//!
//!   * one verdict rule (`RING_MACH_TEST mode=<M> ... pass=1`, absence is FAIL/HANG, never PASS);
//!   * `--json` on every subcommand, so a caller can compose them instead of scraping human output;
//!   * stable exit codes: 0 ok/PASS, 1 verdict or acceptance failure, 2 usage, 3 tool error.
//!
//! They deliberately DELEGATE instead of reimplementing: the boot/prefix harness stays the one implementation of
//! stopping and starting a prefix (`--boot-runner`), and `llvm-nm`/`objdump` stay the one implementation of reading a
//! symbol table and a disassembly, because a second implementation of either would be a second source of truth for
//! something the toolchain already answers.

use anyhow::{Context, Result, bail};
use clap::Args;
use regex::Regex;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::os::unix::ffi::OsStrExt;

#[path = "evidence.rs"]
mod stored_evidence;

// ----------------------------------------------------------------------------------------------------------------
// shared: symbolization
// ----------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Symbol {
    addr: u64,
    name: String,
}


/// Parse one `llvm-nm -n` line. The NAME is the whole remainder after the type character, because an
/// Objective-C method name contains spaces: `... t -[NSFileCoordinator(Internal) submitIntent:...]`.
/// Taking a whitespace token truncated it to `-[NSFileCoordinator(Internal)`, and the name-keyed dedup
/// then dropped every later method of the same category.
fn parse_nm_line(line: &str) -> Option<(u64, &str)> {
    let line = line.trim_start();
    let sep = line.find(char::is_whitespace)?;
    let addr_text = &line[..sep];
    if addr_text.is_empty() || !addr_text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let addr = u64::from_str_radix(addr_text, 16).ok()?;
    let rest = line[sep..].trim_start();
    let mut chars = rest.chars();
    chars.next()?; // type character
    let name = chars.as_str().trim_start();
    if name.is_empty() {
        return None;
    }
    Some((addr, name))
}

fn parse_nm_text(text: &str) -> Vec<Symbol> {
    let mut syms = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let Some((addr, name)) = parse_nm_line(line) else {
            continue;
        };
        // Keep same-named symbols at different addresses. Dedup on the whole (address, name) pair, never on
        // the name alone: category methods and block helpers legitimately share a name or a truncated
        // prefix, and dropping the later one made `locate` attribute a frame to the wrong method. The set
        // borrows the name from `text`; only a unique symbol allocates its owned copy on push.
        if !seen.insert((addr, name)) {
            continue;
        }
        syms.push(Symbol {
            addr,
            name: name.to_owned(),
        });
    }
    syms
}

fn load_symbols(binary: &Path) -> Result<Vec<Symbol>> {
    let (input, _materialized) = stored_evidence::for_tool(binary)?;
    let out = Command::new("llvm-nm")
        .arg("-n")
        .arg(input.as_os_str())
        .output()
        .with_context(|| format!("running llvm-nm on {}", binary.display()))?;
    if !out.status.success() {
        bail!(
            "llvm-nm failed for {}: {}",
            binary.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let syms = parse_nm_text(&text);
    if syms.is_empty() {
        bail!("no symbols in {}", binary.display());
    }
    Ok(syms)
}

/// `symbol + offset` for an address inside the image: the nearest symbol at or below it.
fn locate(syms: &[Symbol], target: u64) -> Option<(usize, u64)> {
    let mut best: Option<(usize, u64)> = None;
    for (i, s) in syms.iter().enumerate() {
        if s.addr <= target && best.map(|(_, a)| a < s.addr).unwrap_or(true) {
            best = Some((i, s.addr));
        }
    }
    best.map(|(i, a)| (i, target - a))
}

#[cfg(test)]
mod nm_parser_tests {
    use super::*;

    // Exact lines from `llvm-nm -n` on the deployed Foundation (default output, measured byte-identical to
    // --arch=x86_64). The first method and the sibling methods share the truncated prefix that the old
    // 3rd-whitespace-token parser produced.
    const NM: &str = r#"
000000000002e220 t -[NSFileCoordinator(Internal) submitIntent:onQueue:withBlock:]
000000000002ebc0 t ___62-[NSFileCoordinator(Internal) submitIntent:onQueue:withBlock:]_block_invoke
000000000002f430 t -[NSFileCoordinator(Internal) submitNotificationForURL:ofType:withDetails:]
000000000002f5b0 t -[NSFileCoordinator(Internal) submitCancellationWithToken:]
                 U _CFAbsoluteTimeGetCurrent
(for architecture x86_64):
"#;

    #[test]
    fn full_objc_names_and_category_siblings_survive_parsing() {
        let syms = parse_nm_text(NM);
        let intent = syms
            .iter()
            .find(|s| s.addr == 0x2e220)
            .expect("submitIntent symbol");
        assert_eq!(
            intent.name,
            "-[NSFileCoordinator(Internal) submitIntent:onQueue:withBlock:]"
        );
        let notification = syms
            .iter()
            .find(|s| s.addr == 0x2f430)
            .expect("sibling method was dropped by name collision");
        assert_eq!(
            notification.name,
            "-[NSFileCoordinator(Internal) submitNotificationForURL:ofType:withDetails:]"
        );

        // The saved main-thread return address 0x2e89d is the first wait in submitIntent.
        let (idx, off) = locate(&syms, 0x2e89d).expect("first wait site");
        assert_eq!(syms[idx].name, intent.name);
        assert_eq!(off, 0x67d);
        // The second wait's return address must stay inside the same method.
        let (idx, off) = locate(&syms, 0x2e9c9).expect("second wait site");
        assert_eq!(syms[idx].name, intent.name);
        assert_eq!(off, 0x7a9);
        // A sibling method after the category prefix is not attributed to submitIntent.
        let (idx, off) = locate(&syms, 0x2f500).expect("notification method");
        assert_eq!(syms[idx].name, notification.name);
        assert_eq!(off, 0xd0);
    }
}

/// Minimal but CORRECT JSON string escaping. MEASURED: the disassembly was interpolated with only quote/backslash and
/// `\n` handled, so a raw tab or any control character made the whole document unparseable -- a tool that emits
/// "json" a consumer cannot parse is worse than one that emits text, because the consumer trusted it.
fn jesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn symbol_name(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

/// A JSON STRING: `jesc` escapes the content and this is what puts the QUOTES on it.
///
/// MEASURED, on this very command: composing objects from pre-encoded values while passing bare `jesc` output
/// produced `{"core":/tmp/core.1}` -- text that looks like JSON to a human and that no parser accepts, which is the
/// one outcome a `--json` mode must never have. `jesc` stays as it is because the long hand-written `format!`
/// objects elsewhere already supply their own quotes.
fn jstr(s: &str) -> String {
    format!("\"{}\"", jesc(s))
}

// ----------------------------------------------------------------------------------------------------------------
// symbolize
// ----------------------------------------------------------------------------------------------------------------

/// Build the runtime the way the rule requires: the two compilations of the same loader code (libsystem_kernel and
/// the dyld image) are built TOGETHER, because building one leaves the other stale -- a mistake this session made
/// and measured. Replaces the long ninja invocation plus its error grep and artifact listing, which was retyped at
/// every iteration; the build tree comes from the environment so a caller does not retype a path.
#[derive(Args, Debug)]
/// Which build tree actually CONSUMES a source file, answered before a build is attempted.
///
/// MEASURED COST OF NOT ASKING: this stage edited the darlingserver's thread creator, ran `ninja darlingserver`,
/// read `ninja: no work to do`, and only then discovered that the build tree holds ZERO rules referencing that
/// source file -- the target imports a prebuilt binary, so the probe could never appear in any run. A cycle that
/// requests it would have deployed and measured the OLD runtime and reported "the instrument stayed silent",
/// which is exactly the class of false negative this tool exists to prevent.
pub struct SourceArgs {
    /// Build tree to inspect. Taken from DWDIAG_BUILD when the flag is absent.
    #[arg(long)]
    build: Option<PathBuf>,
    /// Source files whose consumption must be proven.
    #[arg(long = "source")]
    sources: Vec<PathBuf>,
    /// Report immutable installed-image provenance and separately identify the selected mutable build.
    ///
    /// This reports identity, not a source repair or a guest acceptance result. Recorded source and
    /// manifest provenance belong to the installed image; a later build cannot redefine them.
    /// Workspace source review excludes untracked bytes. Stage explicit new owned source files
    /// before source check/package rather than treating a review package as a complete checkout.
    #[arg(long)]
    provenance: bool,
    /// Writable guest state, reported separately from the selected installation.
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// Manifest workspace for source identity. Taken from DWDIAG_WORKSPACE.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Require verified installed bytes and recorded clean source/manifest provenance.
    #[arg(long)]
    require_canonical: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct BuildArgs {
    /// Build tree. Taken from DWDIAG_BUILD when the flag is absent, so a caller does not retype a path.
    #[arg(long)]
    build: Option<PathBuf>,
    #[arg(long = "target", value_delimiter = ',', default_value = "libsystem_kernel.dylib,dyld")]
    targets: Vec<String>,
    /// Substrings that must be present in a built artifact, checked after the build. A probe whose string is absent
    /// from the artifact cannot fire, and a silent probe that is really an absent probe is this session's most
    /// expensive measurement mistake.
    #[arg(long = "expect", value_delimiter = ',')]
    expect: Vec<String>,
    #[arg(long, default_value = "src/external/xnu/darling/src/libsystem_kernel/libsystem_kernel.dylib")]
    kernel: PathBuf,
    #[arg(long, default_value = "src/external/dyld/dyld")]
    dyld: PathBuf,
    #[arg(long)]
    json: bool,
}

/// A path argument that may come from the environment: the caller then writes `dwdiag diag cycle --mode basic`
/// instead of spelling a build tree and a prefix at every iteration, while the tool still refuses to guess.
fn required_path(flag: &str, value: Option<PathBuf>, var: &str) -> Result<PathBuf> {
    match value {
        Some(p) => Ok(p),
        None => std::env::var(var)
            .map(PathBuf::from)
            .with_context(|| format!("{flag} or {var} is required")),
    }
}

fn artifact_facts(path: &Path, expect: &[String]) -> (String, u64, Vec<(String, u64)>) {
    let stamp = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let secs = d.as_secs() as i64;
            let tod = secs % 86400;
            format!("{:02}:{:02}:{:02}", tod / 3600, (tod % 3600) / 60, tod % 60)
        })
        .unwrap_or_else(|_| "absent".to_string());
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let hits = expect
        .iter()
        .map(|tag| {
            let found = Command::new("strings")
                .arg(path)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains(tag.as_str()))
                .unwrap_or(false);
            (tag.clone(), if found { 1u64 } else { 0u64 })
        })
        .collect();
    (stamp, size, hits)
}

fn run_build(args: BuildArgs) -> Result<ExitCode> {
    let build = required_path("--build", args.build.clone(), "DWDIAG_BUILD")?;
    let out = Command::new("ninja")
        .args(&args.targets)
        .current_dir(&build)
        .output()
        .with_context(|| format!("running ninja in {}", build.display()))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let errors: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("error:"))
        .take(6)
        .collect();
    let rc = out.status.code().unwrap_or(-1);
    println!(
        "BUILD targets={} rc={} errors={}",
        args.targets.join(","),
        rc,
        errors.len()
    );
    for line in errors.iter().take(3) {
        println!("  {}", line.trim());
    }
    let mut missing: Vec<String> = Vec::new();
    for path in [&args.kernel, &args.dyld] {
        let full = build.join(path);
        let (stamp, size, hits) = artifact_facts(&full, &args.expect);
        let cells: Vec<String> = hits
            .iter()
            .map(|(tag, n)| {
                if *n == 0 {
                    missing.push(tag.clone());
                }
                format!("{tag}={n}")
            })
            .collect();
        println!(
            "  artifact {} stamp={} bytes={} {}",
            full.display(),
            stamp,
            size,
            cells.join(" ")
        );
    }
    if !missing.is_empty() {
        missing.sort();
        missing.dedup();
        println!("BUILD-EXPECT-MISSING {}", missing.join(","));
    }
    if rc != 0 || !missing.is_empty() {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

/// Publish the complete normal product installation into the selected immutable runtime root.
#[derive(clap::Args, Debug)]
pub struct DeployArgs {
    /// Configured normal product build; publishing always installs the complete image.
    #[arg(long)]
    build: Option<PathBuf>,
}

/// Publish through the normal immutable product build/install authority.
fn run_deploy(a: DeployArgs) -> Result<ExitCode> {
    let build = required_path("--build", a.build, "DWDIAG_BUILD")?;
    let runtime = crate::runtime_root()?;
    let status = Command::new("mise")
        .args(["run", "west", "darling-build", "--build-dir"]).arg(&build)
        .arg("--runtime-root").arg(runtime).arg("--install").arg("--with-test-data")
        .status().context("publishing ordinary Darling installation")?;
    println!("INSTALL runtime-root={} build={} rc={}", runtime.display(), build.display(), status.code().unwrap_or(-1));
    Ok(if status.success() { ExitCode::SUCCESS } else { ExitCode::from(3) })
}

/// Publish or explicitly reuse an installed image, run a workload and report instrument observations.
#[derive(Args, Debug)]
pub struct CycleArgs {
    /// Configured product build (default DWDIAG_BUILD); optional with --skip-build.
    #[arg(long)]
    build: Option<PathBuf>,
    /// Writable guest state (default DWDIAG_PREFIX), separate from the runtime installation.
    #[arg(long)]
    prefix: Option<PathBuf>,
    #[arg(long, default_value = "basic")]
    mode: String,
    #[arg(long, default_value = "")]
    args: String,
    #[arg(long, default_value_t = 1)]
    repeat: u64,
    #[arg(long, default_value_t = 90)]
    wait: u64,
    #[arg(long)]
    skip_build: bool,
    /// Additional build-only targets before the complete normal product install.
    #[arg(long = "target", value_delimiter = ',')]
    targets: Vec<String>,
    #[arg(long = "env", value_parser = parse_kv, num_args = 0..)]
    env: Vec<(String, String)>,
    /// Instrument tags to report per run; omitted reports every registered instrument that fired.
    #[arg(long = "probe", value_delimiter = ',')]
    probe: Vec<String>,
    /// DIAGNOSTIC EXECUTION POLICY, not guest environment: require that the run actually executed the
    /// workload and FAIL the command when the log carries no evidence of it. `--probe` implies it. This is
    /// deliberately separate from `--env`, which is product/guest environment and must never carry
    /// execution-policy switches.
    #[arg(long)]
    fresh: bool,
    #[arg(long)]
    json: bool,
    /// Host-side capture of /proc/<pid>/wchan for prefix processes, sampled once a second while the run
    /// proceeds. WHY THIS EXISTS: the boot failure this was written for leaves no guest evidence and its
    /// rate moves when the guest is instrumented, so the only non-perturbing question left is where the
    /// host threads of the prefix are blocked DURING the failure. It prints how many samples it took, so
    /// silence can never be mistaken for "nothing was blocked".
    #[arg(long)]
    capture_wchan: bool,
    /// Seconds to wait between runs. WHY: runs back-to-back keep the HOST filesystem journal busy, and a
    /// host-I/O stall is the leading candidate for this workload's boot flap -- a gap is the cheapest way to
    /// test that without touching the guest at all. Also stops one run's teardown from overlapping the next
    /// run's boot, which is a distinct piece of friction this option removes.
    #[arg(long, default_value_t = 0)]
    gap_seconds: u64,
    /// DIAGNOSTIC: leave the prefix and its processes ALIVE when a run fails, so the failing incarnation can
    /// be inspected instead of destroyed. The cycle stops at the first frozen failure, because the prefix is
    /// held by that run and a following run would collide with it.
    #[arg(long)]
    freeze_on_fail: bool,
    /// Print selected source and immutable installed-image provenance after the series.
    ///
    /// Run evidence must identify the actual installed image. A mutable build or source-review package
    /// cannot replace installation identity or an exercised guest result.
    #[arg(long)]
    provenance: bool,
    /// Refuse unverified installed bytes or dirty/unknown recorded source provenance.
    /// Use it for runs that will close a Bead, declare FINAL acceptance, or start the next milestone.
    #[arg(long)]
    require_canonical: bool,
}

fn run_cycle(args: CycleArgs) -> Result<ExitCode> {
    let build = if args.skip_build {
        args.build.clone().or_else(|| std::env::var_os("DWDIAG_BUILD").map(PathBuf::from))
    } else { Some(required_path("--build", args.build.clone(), "DWDIAG_BUILD")?) };
    let prefix = required_path("--prefix", args.prefix.clone(), "DWDIAG_PREFIX")?;
    if args.skip_build {
        if !args.targets.is_empty() {
            bail!("--skip-build runs an existing image and cannot build --target inputs");
        }
        crate::installed_runtime_root()?;
        println!("CYCLE existing-image runtime-root={} (no build/install)", crate::runtime_root()?.display());
    } else {
        let build = build.as_ref().context("normal installation requires --build")?;
        if !args.targets.is_empty() {
            let status = Command::new("mise").args(["run", "west", "darling-build", "--build-dir"])
                .arg(build).arg("--targets").args(&args.targets).status()?;
            if !status.success() { return Ok(ExitCode::from(3)); }
        }
        let rc = run_deploy(DeployArgs { build: Some(build.clone()) })?;
        if rc != ExitCode::SUCCESS {
            println!("CYCLE aborted at normal installation");
            return Ok(rc);
        }
    }
    let rc = run_prefix(PrefixArgs {
        prefix: prefix.clone(), build: None, bootstrap: false,
        guest_toolchain: None, no_build: true, asset: Vec::new(),
        env: args.env.clone(), mode: String::new(), args: String::new(),
        guest_command: "/private/var/tmp/ring_mach_msg_test".to_string(),
        wait: args.wait, json: false,
    })?;
    if rc != ExitCode::SUCCESS { return Ok(rc); }
    // FRESHNESS IS A WITNESS, NOT A STATEMENT, AND THIS PATH HAS NO VERDICT CACHE TO BYPASS.
    // MEASURED (2026-09-29), correcting an earlier claim of this very tool: `cycle` launches
    // `scripts/darling-boot-run.sh` through setsid and that script never invokes `west test`, so the
    // framework's identity-keyed verdict cache -- which does reuse a zero verdict -- is not in this call
    // chain at all. What looked like a cached 15-second PASS was a genuinely fast passing workload: its log
    // held 1637 port-operation lines, the workload's own RING_MACH_TEST_DURATION line and rc=0. Injecting
    // WEST_TEST_VERDICT_CACHE here therefore controlled nothing and is removed; what replaces it is a
    // witness read OUT OF THE RUN'S OWN LOG (workload progress lines, the workload's result line, and the
    // rc), and --fresh makes the absence of that witness a FAILURE instead of a plausible-looking pass.
    let require_fresh = args.fresh || !args.probe.is_empty();
    let run_env = args.env.clone();
    let va = VerdictArgs {
        prefix: Some(prefix.clone()),
        mode: args.mode.clone(),
        args: args.args.clone(),
        wait: args.wait,
        env: run_env,
        boot_runner: PathBuf::from("scripts/darling-boot-run.sh"),
        // The guest-visible path where the tool installs the fixture asset. MEASURED: /usr/bin resolves
        // through /Volumes/SystemRoot to the HOST's /usr/bin, so a fixture deployed into the prefix is
        // invisible there -- and a run of the OLD /usr/bin copy silently looked like a run of the new one.
        guest_command: "/private/var/tmp/ring_mach_msg_test".to_string(),
        guest_symbols: None,
        log: None,
        repeat: 1,
        list_modes: false,
        freeze_on_fail: args.freeze_on_fail,
        json: args.json,
    };
    /* HOST-SIDE WCHAN SAMPLER (see the flag). Started before the runs and stopped after the loop, so the
     * window covers the harness' own boot wait -- which is exactly the window a boot failure occupies. */
    let wchan_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wchan_samples: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    if args.capture_wchan {
        let stop = wchan_stop.clone();
        let store = wchan_samples.clone();
        let sampled_prefix = prefix.clone();
        std::thread::spawn(move || {
            let mut n: u64 = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                n += 1;
                if let Ok(rd) = std::fs::read_dir("/proc") {
                    for e in rd.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if !name.bytes().all(|b| b.is_ascii_digit()) {
                            continue;
                        }
                        let cmd = std::fs::read(format!("/proc/{name}/cmdline")).unwrap_or_default();
                        let cmds = String::from_utf8_lossy(&cmd).replace('\0', " ");
                        if !process_owns_prefix(name.parse().unwrap_or(0), &sampled_prefix) {
                            continue;
                        }
                        let wchan = std::fs::read_to_string(format!("/proc/{name}/wchan"))
                            .unwrap_or_else(|_| "?".to_string());
                        let stat = std::fs::read_to_string(format!("/proc/{name}/stat"))
                            .unwrap_or_default();
                        let state = stat.split_whitespace().nth(2).unwrap_or("?").to_string();
                        let cut = cmds.len().min(90);
                        if let Ok(mut g) = store.lock() {
                            g.push(format!(
                                "s={n} pid={name} state={state} wchan={} cmd={}",
                                wchan.trim(),
                                &cmds[..cut]
                            ));
                            if g.len() > 8000 {
                                g.drain(0..2000);
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        });
    }
    let mut worst = ExitCode::SUCCESS;
    for i in 1..=args.repeat {
        // MEASURED flaw this resets: across a --repeat series the sampler accumulated every run's samples, so
        // `distinct-pids` on a failure mixed runs and could not say which process belonged to WHICH run.
        if args.capture_wchan {
            if let Ok(mut g) = wchan_samples.lock() {
                g.clear();
            }
        }
        if args.gap_seconds > 0 && i > 1 {
            std::thread::sleep(std::time::Duration::from_secs(args.gap_seconds));
        }
        let tag = format!("r{i}");
        let v = run_one_workload(&va, &tag)?;
        println!(
            "CYCLE[{i}/{}] mode={} verdict={} denied={} created={} rc={}",
            args.repeat,
            v.mode,
            v.verdict,
            v.denied,
            v.created,
            v.rc.map(|r| r.to_string()).unwrap_or_else(|| "-".to_string())
        );
        if !v.ok() {
            worst = ExitCode::from(1);
            if args.capture_wchan {
                let g = wchan_samples.lock().unwrap();
                println!("CAPTURE-WCHAN samples={} prefix={}", g.len(), prefix.display());
                /* THE TAIL ALONE WAS NOT ENOUGH (measured): the first catch of this flag printed the last 24
                 * samples, and by then every guest process of the prefix had exited, so all it showed was the
                 * harness shell waiting in do_wait -- true, and useless. What answers "where was it blocked"
                 * is each pid's LAST observed state, plus when it was last seen, so the reader can tell a
                 * process that waited for 300 seconds from one that vanished in the first second. */
                let mut last: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
                for line in g.iter() {
                    if let (Some(pid), _) = (line.split("pid=").nth(1).and_then(|s| s.split_whitespace().next()), ()) {
                        last.insert(pid.to_string(), line.clone());
                    }
                }
                println!("CAPTURE-WCHAN distinct-pids={}", last.len());
                for (_, line) in last.iter() {
                    println!("CAPTURE-WCHAN last {line}");
                }
                for line in g.iter().rev().take(8).collect::<Vec<_>>().iter().rev() {
                    println!("CAPTURE-WCHAN tail {line}");
                }
            }
            // A FROZEN FAILURE HOLDS THE PREFIX. Continuing would start the next run against a prefix this one
            // owns and is the exact collision the one-prefix-at-a-time rule forbids, so the loop stops and says
            // so, with the log that has to be inspected before any cleanup.
            if args.freeze_on_fail {
                println!(
                    "CYCLE-FROZEN run={tag} prefix={} log={} -- inspect now, then clean up with the harness' printed command",
                    prefix.display(),
                    v.log.display()
                );
                break;
            }
            if v.verdict.contains("harness or product shutdown") {
                println!("CYCLE-LIFECYCLE-FAIL log={}; stopping before another prefix-backed run", v.log.display());
                break;
            }
        }
        // The witness, read from the log the run itself produced. `workload_lines` counts the workload's own
        // progress marks (its iteration/port marks and its start line); `result` is the last line that looks
        // like a result. A run with no progress lines executed nothing that can be classified, whatever its
        // verdict says, and an execution policy that demands freshness makes that a failure.
        let mut workload_lines = 0u64;
        let mut result = String::new();
        if let Ok(text) = read_log_lossy(&v.log) {
            for line in text.lines() {
                if line.contains("[rmmt]") || line.contains("ITER ") || line.contains("pc-entry")
                    || line.contains("SEM-SITE") || line.contains("make_port") || line.contains("drop_port")
                {
                    workload_lines += 1;
                }
                if line.contains("RING_MACH_TEST") || line.contains("__DWDIAG_RC=") {
                    result = line.trim().chars().take(120).collect();
                }
            }
        }
        println!(
            "FRESHNESS run={} log={} result={} workload_lines={} cache=none-in-this-path",
            tag,
            v.log.display(),
            if result.is_empty() { "<absent>" } else { result.as_str() },
            workload_lines
        );
        if require_fresh && workload_lines == 0 {
            println!("FRESHNESS-SUSPECT run={} log={} -- the log carries no workload execution evidence", tag, v.log.display());
            worst = ExitCode::from(1);
        }
        if let Ok(text) = read_log_lossy(&v.log) {
            let census = witness_census(&text);
            let wanted: Vec<(String, u64, String)> = census
                .into_iter()
                .filter(|(name, _, _)| args.probe.is_empty() || args.probe.iter().any(|p| p == name))
                .collect();
            let fired: Vec<String> = wanted
                .iter()
                .filter(|(_, n, _)| *n > 0)
                .map(|(name, n, _)| format!("{name}={n}"))
                .collect();
            let silent: Vec<String> = wanted
                .iter()
                .filter(|(_, n, _)| *n == 0)
                .map(|(name, _, _)| name.clone())
                .collect();
            println!("  instruments fired=[{}] silent=[{}] log={}", fired.join(" "), silent.join(" "), v.log.display());
        }
    }

    if args.provenance || args.require_canonical {
        let workspace = std::env::var("DWDIAG_WORKSPACE").ok().map(PathBuf::from);
        let (canonical, reasons, lines) = provenance_report(
            build.as_deref(),
            Some(prefix.as_path()),
            workspace.as_deref(),
        );
        for l in &lines {
            println!("{l}");
        }
        if canonical {
            println!("PROVENANCE-CANONICAL series={} runs={}", args.mode, args.repeat);
        } else {
            println!(
                "PROVENANCE-NON-CANONICAL series={} runs={} reasons={} -- these verdicts are diagnostic, not product evidence",
                args.mode,
                args.repeat,
                reasons.join(",")
            );
            if args.require_canonical {
                println!("PROVENANCE-REFUSED: a run that must support a product claim needs canonical provenance");
                return Ok(ExitCode::from(2));
            }
        }
    }

    Ok(worst)
}

/// Watch a RUNNING guest's kernel signal dispositions, because that is where the evidence for the silent
/// SIGSEGV death lives and a shell around it could not be made reliable: the discovery loop that worked by
/// hand matched the harness's command line first, and the sampling loop written in bash took a second per
/// pass, so a two-second workload yielded two samples and no transition.
///
/// Discovery uses the handle that is actually observable from the host -- a process whose exe is the
/// prefix's loader AND whose cmdline names the guest path -- and then samples ONLY that process, at the
/// requested rate, recording SigCgt against the run log's size so a transition can be held against the
/// log's own marks. `cycle` runs underneath with --probe, so the run is fresh and not a cached verdict.
#[derive(Args, Debug)]
pub struct WatchArgs {
    #[arg(long)]
    build: Option<PathBuf>,
    #[arg(long)]
    prefix: Option<PathBuf>,
    #[arg(long, default_value = "basic")]
    mode: String,
    #[arg(long, default_value = "")]
    args: String,
    #[arg(long, default_value_t = 1)]
    repeat: u64,
    /// Guest path fragment that identifies the process to watch, matched against the host cmdline together
    /// with the loader exe. Ignored when --pid is given.
    #[arg(long, default_value = "ring_mach_msg_test")]
    pattern: String,
    /// Watch EXACTLY this host pid, taken from the workload's own raw `host_pid=` mark. This is the
    /// structural fix for a discovery loop that matched the shell, an early loader or the final workload
    /// interchangeably: the identity comes from the running workload itself, not from a /proc heuristic.
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long, default_value_t = 200)]
    hz: u64,
    #[arg(long)]
    json: bool,
}

fn newest_run_log() -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir("/tmp").ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("dwdiag-verdict-") || !name.ends_with(".log") {
            continue;
        }
        let Ok(md) = entry.metadata() else { continue };
        let Ok(mt) = md.modified() else { continue };
        if best.as_ref().map(|(t, _)| mt > *t).unwrap_or(true) {
            best = Some((mt, entry.path()));
        }
    }
    best.map(|(_, p)| p)
}

/// A cheap signature of the process's ADDRESS SPACE: how many mappings it has and the base of its first
/// libsystem_kernel mapping. An exec swaps the whole map, so a change here is the visible mark of "a new
/// image" -- which is what is needed to line the loss of a kernel signal disposition up against the exec
/// that Linux performs it on. Cheaper and more robust than comparing probe addresses across processes.
/// SigCgt as seen ACROSS the process's threads: the leader's value, the OR of every thread's, and how many
/// threads were read. Linux signal actions are process-wide, so these should agree -- and the moment they do
/// not, "the leader's SigCgt has no SIGSEGV bit" stops being a fact about the process and becomes a fact
/// about which thread the install landed on, which is exactly the question left open.
fn sigcgt_across_threads(pid: &str) -> (String, String, usize) {
    let leader = sig_line(pid, "SigCgt:").unwrap_or_default();
    let mut any: u64 = 0;
    let mut n = 0usize;
    if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for e in entries.flatten() {
            let tid = e.file_name().to_string_lossy().into_owned();
            if let Some(v) = sig_line(&tid_path(pid, &tid), "SigCgt:") {
                if let Ok(bits) = u64::from_str_radix(v.trim(), 16) {
                    any |= bits;
                    n += 1;
                }
            }
        }
    }
    (leader, format!("{any:016x}"), n)
}

fn tid_path(pid: &str, tid: &str) -> String {
    format!("/proc/{pid}/task/{tid}/status")
}

fn maps_signature(pid: &str) -> String {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return String::new();
    };
    let mut lines = 0u64;
    let mut base = String::new();
    for line in text.lines() {
        lines += 1;
        if base.is_empty() && line.contains("libsystem_kernel") {
            if let Some(range) = line.split_whitespace().next() {
                base = range.split('-').next().unwrap_or("").to_string();
            }
        }
    }
    format!("{lines}:{base}")
}

fn sig_line(pid: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Report immutable install provenance through the workspace receipt authority.
/// Mutable selected builds are identified separately, never substituted for the installed image.
fn provenance_report(
    build: Option<&Path>, prefix: Option<&Path>, workspace: Option<&Path>,
) -> (bool, Vec<String>, Vec<String>) {
    let mut lines = Vec::new();
    let mut reasons = Vec::new();
    if let Some(build) = build {
        lines.push(format!("PROVENANCE selected-build={} (mutable, not installed-image authority)", build.display()));
        let cache = build.join("CMakeCache.txt");
        if let Some(digest) = sha256_file(&cache) {
            lines.push(format!("PROVENANCE selected-build-cache-sha256={digest}"));
        }
    }
    let root = match crate::installed_runtime_root() {
        Ok(root) => root,
        Err(error) => return (false, vec![format!("installation:unavailable:{error}")], lines),
    };
    lines.push(format!("PROVENANCE runtime-root={} guest-prefix={}", root.display(),
        prefix.map(|path| path.display().to_string()).unwrap_or_else(|| "<unset>".to_string())));
    let default_workspace = crate::workspace_root().ok();
    let Some(workspace) = workspace.or(default_workspace.as_deref()) else {
        return (false, vec!["workspace:receipt-authority-unavailable".to_string()], lines);
    };
    let script = r#"import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / 'west_commands'))
from deploy_receipt import read_receipt, verify_receipt
root = Path(sys.argv[2])
receipt = read_receipt(root)
if receipt is None:
    print('PROVENANCE install-receipt=absent identity=unknown/unverified')
    raise SystemExit(1)
problems, notes = verify_receipt(receipt)
for problem in problems[:8]:
    print('PROVENANCE integrity-problem=' + problem.label + ': ' + problem.message)
for note in notes:
    print('PROVENANCE ' + note)
source = receipt.get('source', {})
workspace = receipt.get('workspace', {})
build = receipt.get('build', {})
print('PROVENANCE recorded-source=' + json.dumps({key: value for key, value in source.items() if key != 'gitlinks'}, sort_keys=True, separators=(',', ':')))
links = source.get('gitlinks', [])
for row in links[:8]:
    print('PROVENANCE recorded-gitlink=' + json.dumps(row, sort_keys=True, separators=(',', ':')))
if len(links) > 8:
    print('PROVENANCE recorded-gitlinks-omitted=' + str(len(links) - 8) + '; full identity in ' + str(root / '.darling-deploy-receipt.json'))
print('PROVENANCE recorded-workspace=' + json.dumps(workspace, sort_keys=True, separators=(',', ':')))
print('PROVENANCE recorded-build=' + str(build.get('directory')) + ' cache-sha256=' + str(build.get('cache_sha256')))
identities = [source, workspace, *source.get('gitlinks', [])]
clean = all(row.get('dirty') is False and row.get('untracked') == 0 for row in identities)
known = bool(source.get('revision')) and bool(workspace.get('manifest_commit'))
links_match = all(row.get('revision') == row.get('gitlink_revision') for row in source.get('gitlinks', []))
raise SystemExit(0 if not problems and clean and known and links_match else 1)
"#;
    match Command::new("python3").args(["-B", "-c", script]).arg(workspace).arg(root).output() {
        Ok(output) => {
            lines.extend(String::from_utf8_lossy(&output.stdout).lines().map(str::to_string));
            if !output.status.success() {
                reasons.push("installation:unverified-or-noncanonical-recorded-provenance".to_string());
                lines.extend(String::from_utf8_lossy(&output.stderr).lines().take(8).map(|line| format!("PROVENANCE authority-error={line}")));
            }
        }
        Err(error) => reasons.push(format!("installation:receipt-authority-unavailable:{error}")),
    }
    (reasons.is_empty(), reasons, lines)
}

fn sha256_file(path: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new("sha256sum").arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|s| s.to_string())
}

/// Answer "does this build tree compile this file?" from the build graph itself.
///
/// The check is deliberately about the GENERATED build graph, not about timestamps: a target that imports a
/// prebuilt artifact looks up to date whatever a source tree says, so the only honest question is whether any
/// rule in `build.ninja` mentions the file at all. Exit code 3 means "do not trust a run that claims to exercise
/// this source", which is how a silent no-op probe becomes a refusal instead of a measurement.
fn run_source_check(args: SourceArgs) -> Result<ExitCode> {
    let build = required_path("--build", args.build.clone(), "DWDIAG_BUILD")?;
    let mut rows: Vec<(String, usize)> = Vec::new();
    let mut missing = 0usize;
    for src in &args.sources {
        let name = src
            .file_name()
            .and_then(|s| s.to_str())
            .context("source path has no file name")?
            .to_string();
        let mut rules = 0usize;
        for entry in std::fs::read_dir(&build)
            .with_context(|| format!("reading the build tree {}", build.display()))?
        {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let fname = match path.file_name().and_then(|s| s.to_str()) {
                Some(f) => f,
                None => continue,
            };
            if !fname.ends_with(".ninja") {
                continue;
            }
            if let Ok(text) = read_log_lossy(&path) {
                rules += text.matches(&name).count();
            }
        }
        if rules == 0 {
            missing += 1;
        }
        rows.push((name, rules));
    }
    if args.json {
        let items: Vec<String> = rows
            .iter()
            .map(|(n, c)| format!("{{\"file\":\"{n}\",\"rules\":{c}}}"))
            .collect();
        println!(
            "{{\"build\":\"{}\",\"sources\":[{}]}}",
            build.display(),
            items.join(",")
        );
    } else {
        for (name, rules) in &rows {
            if *rules == 0 {
                println!(
                    "SOURCE-UNBUILT file={name} rules=0 build={} -- no rule in this build tree mentions it; \
a run here would exercise the OLD artifact, not this source",
                    build.display()
                );
            } else {
                println!("SOURCE-CONSUMED file={name} rules={rules} build={}", build.display());
            }
        }
    }

    if args.provenance || args.require_canonical {
        let prefix = args
            .prefix
            .clone()
            .or_else(|| std::env::var("DWDIAG_PREFIX").ok().map(PathBuf::from));
        let workspace = args
            .workspace
            .clone()
            .or_else(|| std::env::var("DWDIAG_WORKSPACE").ok().map(PathBuf::from));
        let (canonical, reasons, lines) =
            provenance_report(Some(&build), prefix.as_deref(), workspace.as_deref());
        if args.json {
            let items: Vec<String> = lines.iter().map(|line| jstr(line)).collect();
            println!(
                "{{\"provenance\":\"{}\",\"reasons\":[{}],\"fields\":[{}]}}",
                if canonical { "CANONICAL" } else { "NON-CANONICAL" },
                reasons
                    .iter()
                    .map(|r| format!("{:?}", r))
                    .collect::<Vec<_>>()
                    .join(","),
                items.join(",")
            );
        } else {
            for l in &lines {
                println!("{l}");
            }
            if canonical {
                println!("PROVENANCE-CANONICAL build={}", build.display());
            } else {
                println!("PROVENANCE-NON-CANONICAL build={} reasons={}", build.display(), reasons.join(","));
            }
        }
        if args.require_canonical && !canonical {
            return Ok(ExitCode::from(2));
        }
    }
    if missing > 0 {
        return Ok(ExitCode::from(3));
    }
    Ok(ExitCode::SUCCESS)
}

fn run_watch(args: WatchArgs) -> Result<ExitCode> {
    let build = args.build.clone().or_else(|| std::env::var_os("DWDIAG_BUILD").map(PathBuf::from));
    let prefix = required_path("--prefix", args.prefix.clone(), "DWDIAG_PREFIX")?;
    let loader_suffix = "/mldr";

    // The run underneath: probes force a fresh run, which is the whole point.
    let run_prefix = prefix.clone();
    let run_build = build.clone();
    let mode = args.mode.clone();
    let run_args = args.args.clone();
    let repeat = args.repeat;
    let runner = std::thread::spawn(move || {
        run_cycle(CycleArgs {
            build: run_build,
            prefix: Some(run_prefix),
            mode,
            args: run_args,
            repeat,
            wait: 90,
            skip_build: true,
            targets: Vec::new(),
            env: Vec::new(),
            probe: vec!["wait4".to_string()],
            fresh: true,
            json: false,
            capture_wchan: false,
            gap_seconds: 0,
            freeze_on_fail: false,
            provenance: false,
            require_canonical: false,
        })
    });

    let pattern = args.pattern.clone();
    // The workload DECLARES its own host identity: its start line carries host_pid= from a raw Linux getpid,
    // which is the only value an outside observer can match in /proc. Prefer that over any /proc heuristic --
    // the heuristic matched the shell, an early loader and the final workload interchangeably, and the guest's
    // emulated pid is not the host's. --pid still wins when the caller has a pid in hand.
    let pinned = args.pid.map(|p| p.to_string());
    let period = std::time::Duration::from_millis((1000 / args.hz.max(1)).max(1));
    let start = std::time::Instant::now();
    let mut consumed: Vec<String> = Vec::new();
    let mut target: Option<String> = pinned.clone();
    if let Some(p) = &target {
        println!("WATCH pinned host pid={p} (from the workload's own host_pid= mark)");
    }
    let mut last: Option<String> = None;
    let mut samples = 0u64;
    let mut transitions = 0u64;
    while !runner.is_finished() || target.is_some() {
        if target.is_none() {
            // 1. the workload's own declaration, read from the newest run log
            if let Some(log) = newest_run_log() {
                if let Ok(text) = read_log_lossy(&log) {
                    if let Some(idx) = text.rfind("host_pid=") {
                        let tail = &text[idx + "host_pid=".len()..];
                        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
                        // A declaration belongs to ONE run: the previous run's pid must never be picked up
                        // again, because pids are reused and the log keeps its old lines.
                        if !digits.is_empty()
                            && consumed.last().map(|c| c != &digits).unwrap_or(true)
                            && std::path::Path::new(&format!("/proc/{digits}")).exists()
                        {
                            println!("WATCH declared host pid={digits} (from the workload's own host_pid= mark)");
                            consumed.push(digits.clone());
                            target = Some(digits);
                            continue;
                        }
                    }
                }
            }
            // 2. the /proc heuristic, and only as a LAST RESORT: the declaration above is the identity the
            // workload itself reports, and the heuristic matched the shell twice while a workload was starting.
            if start.elapsed() < std::time::Duration::from_secs(90) {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for e in entries.flatten() {
                    let pid = e.file_name().to_string_lossy().into_owned();
                    if !pid.chars().all(|c| c.is_ascii_digit()) {
                        continue;
                    }
                    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    if !exe.ends_with(loader_suffix) || !process_owns_prefix(pid.parse().unwrap_or(0), &prefix) {
                        continue;
                    }
                    let cmd = std::fs::read(format!("/proc/{pid}/cmdline"))
                        .map(|b| b.iter().map(|c| if *c == 0 { ' ' } else { *c as char }).collect::<String>())
                        .unwrap_or_default();
                    if cmd.contains(&pattern) {
                        println!("WATCH target pid={pid} exe={exe}");
                        target = Some(pid);
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        let pid = target.clone().unwrap();
        match (sig_line(&pid, "SigCgt:"), sig_line(&pid, "SigBlk:")) {
            (Some(cgt), Some(blk)) => {
                samples += 1;
                let (leader, any, nthreads) = sigcgt_across_threads(&pid);
                let sig = format!("{cgt}|{blk}|{leader}|{any}|{nthreads}");
                let maps = maps_signature(&pid);
                let key = format!("{sig}|{maps}");
                if last.as_deref() != Some(key.as_str()) {
                    let size = newest_run_log()
                        .and_then(|p| std::fs::metadata(p).ok())
                        .map(|m| m.len())
                        .unwrap_or(0);
                    println!(
                        "WATCH t={}.{:03}s pid={} SigCgt={} SigBlk={} leader={} any={} threads={} maps={} logsize={}",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis(),
                        pid,
                        cgt,
                        blk,
                        leader,
                        any,
                        nthreads,
                        maps,
                        size
                    );
                    transitions += 1;
                    last = Some(key);
                }
            }
            _ => {
                println!("WATCH pid={pid} gone after {samples} samples, {transitions} transition(s)");
                if pinned.is_some() {
                    break;   // an explicit --pid is a single target and a single lifetime
                }
                target = None;
                continue;    // a declared identity belongs to one run; the next run declares its own
            }
        }
        std::thread::sleep(period);
    }
    let rc = runner.join().unwrap_or(Ok(ExitCode::from(1)));
    println!("WATCH done samples={samples} transitions={transitions}");
    rc
}

#[derive(Args, Debug)]
pub struct SymbolizeArgs {
    /// Image to symbolize against (a Mach-O dylib or an ELF binary).
    #[arg(long)]
    binary: PathBuf,
    /// Symbol the reported offset is measured from.
    #[arg(long)]
    base_symbol: Option<String>,
    /// Offset from `--base-symbol`, e.g. 0x27a09.
    #[arg(long)]
    delta: Option<String>,
    /// An absolute address inside the image instead of a base+delta pair.
    #[arg(long)]
    addr: Option<String>,
    /// Also list this many symbols above and below the resolved one.
    #[arg(long, default_value_t = 0)]
    near: usize,
    #[arg(long)]
    json: bool,
}

fn parse_hex(s: &str) -> Result<u64> {
    let t = s.trim().trim_start_matches("0x");
    u64::from_str_radix(t, 16).with_context(|| format!("not a hex value: {s}"))
}

fn run_symbolize(args: SymbolizeArgs) -> Result<ExitCode> {
    let syms = load_symbols(&args.binary)?;
    let target = match (&args.addr, &args.base_symbol, &args.delta) {
        (Some(a), _, _) => parse_hex(a)?,
        (None, Some(b), Some(d)) => {
            let base = syms
                .iter()
                .find(|s| symbol_name(&s.name) == symbol_name(b))
                .with_context(|| format!("base symbol not found: {b}"))?;
            base.addr + parse_hex(d)?
        }
        _ => bail!("need --addr or (--base-symbol and --delta)"),
    };
    let (idx, off) = locate(&syms, target).context("target is below the first symbol")?;
    let loc = format!("{} + 0x{:x}", symbol_name(&syms[idx].name), off);
    if args.json {
        let near: Vec<String> = if args.near == 0 {
            Vec::new()
        } else {
            let lo = idx.saturating_sub(args.near);
            let hi = (idx + args.near + 1).min(syms.len());
            syms[lo..hi]
                .iter()
                .map(|s| format!("0x{:08x} {}", s.addr, symbol_name(&s.name)))
                .collect()
        };
        println!(
            "{{\"binary\":\"{}\",\"target\":\"0x{:x}\",\"symbol\":\"{}\",\"offset\":\"0x{:x}\",\"location\":\"{}\",\"near\":[{}]}}",
            args.binary.display(),
            target,
            symbol_name(&syms[idx].name),
            off,
            loc,
            near.iter()
                .map(|n| format!("\"{n}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
    } else {
        println!("binary={}", args.binary.display());
        println!("target=0x{target:x}");
        println!("LOCATION: {loc}");
        if args.near > 0 {
            let lo = idx.saturating_sub(args.near);
            let hi = (idx + args.near + 1).min(syms.len());
            for (i, s) in syms[lo..hi].iter().enumerate() {
                let mark = if lo + i == idx { "  <== target" } else { "" };
                println!("  0x{:08x} {}{}", s.addr, symbol_name(&s.name), mark);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ----------------------------------------------------------------------------------------------------------------
// crash
// ----------------------------------------------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct CrashArgs {
    /// Optional: required only for the loader-side `dserver-CRASH` line. A GUEST fatal signal is symbolized from the
    /// log alone, because the handler dumps /proc/self/maps at the moment of death and that names the image.
    #[arg(long)]
    binary: Option<PathBuf>,
    /// A run log containing a `dserver-CRASH` line.
    #[arg(long)]
    log: Option<PathBuf>,
    /// The crash line itself, when it is already in hand.
    #[arg(long)]
    line: Option<String>,
    /// Bytes of disassembly to show on each side of the faulting instruction.
    #[arg(long, default_value_t = 160)]
    context: u64,
    /// Prefix whose deployed images are identified for this crash record.
    ///
    /// WHY: this investigation reversed guest/server crash attribution twice, and both times the answer came
    /// from asking which image actually contains the reporting symbol. That question belongs in the output of
    /// the command that reads the crash, not in the head of whoever reads it next. Taken from DWDIAG_PREFIX
    /// when the flag is absent.
    #[arg(long)]
    prefix: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Default)]
struct CrashLine {
    sig: String,
    addr: String,
    self_: Option<u64>,
    pc: Option<u64>,
    stack: Vec<u64>,
    frames: Vec<u64>,
    raw: String,
}

fn parse_crash_line(line: &str) -> CrashLine {
    let mut c = CrashLine {
        raw: line.trim().to_string(),
        ..Default::default()
    };
    // EVERY marker is parsed out of EVERY comma-field. MEASURED: a first-match-else chain left `addr` empty, because
    // `sig=` and `addr=` appear in the SAME field of a real line (`[dserver-CRASH sig=b addr=0x0`) -- the parse looked
    // right, produced a parseable document, and silently dropped a field. Independent extraction is the fix.
    for field in line.split(',') {
        let field = field.trim();
        if let Some(i) = field.find("sig=") {
            c.sig = field[i + 4..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
        }
        if let Some(i) = field.find("addr=") {
            c.addr = field[i + 5..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
        }
        if let Some(i) = field.find("self=") {
            let v = field[i + 5..].split_whitespace().next().unwrap_or("");
            c.self_ = u64::from_str_radix(v.trim_start_matches("0x"), 16).ok();
        }
        if let Some(i) = field.find("pc=0x") {
            let v = field[i + 5..].split_whitespace().next().unwrap_or("");
            c.pc = u64::from_str_radix(v, 16).ok();
        }
        // The server's caller chain: values are offsets from the address of its own crash probe (printed as
        // `self=`), space separated so the whole list stays inside this one comma field. dwdiag converts each
        // delta into a file offset by adding the probe's file address, which is a symbol it already has.
        if let Some(i) = field.find("bt=0x") {
            for tok in field[i + 5..].split_whitespace() {
                let t = tok.trim_start_matches("0x");
                if let Ok(v) = u64::from_str_radix(t, 16) {
                    c.frames.push(v);
                }
            }
        }
        if let Some(i) = field.find('w') {
            let rest = &field[i + 1..];
            if let Some(eq) = rest.find('=') {
                let v = rest[eq + 1..].trim_start_matches("0x");
                if let Ok(w) = u64::from_str_radix(v.split_whitespace().next().unwrap_or(""), 16) {
                    c.stack.push(w);
                }
            }
        }
    }
    // the parsed line is the RETURN value: MEASURED, an earlier splice of this function dropped the trailing expression
    // and the compiler reported "mismatched types" -- a reminder that a source edit is a change like any other.
    c
}

// Proactive signal decoding (user directive): "sig=6" is an abbreviation every reader has to look up, and the
// answer changes the diagnosis completely -- 6 is an abort, which in C++ means an uncaught exception reached
// std::terminate, while 11 is a null/freed dereference. MEASURED need: a plane-path abort was printed as "sig=6"
// and the meaning had to be reconstructed by hand.
fn sig_meaning(sig: &str) -> Option<&'static str> {
    let digits: String = sig.chars().filter(|c| c.is_ascii_digit()).collect();
    match digits.parse::<i32>().ok()? {
        4 => Some("SIGILL: illegal instruction"),
        5 => Some("SIGTRAP: trace/breakpoint trap"),
        6 => Some(
            "SIGABRT: abort() -- in C++ almost always an uncaught exception reaching std::terminate, or an explicit abort()",
        ),
        7 => Some("SIGBUS: bus error (misaligned or unmapped access)"),
        8 => Some("SIGFPE: arithmetic exception"),
        11 => Some("SIGSEGV: invalid memory reference (null, freed, or wrong-object pointer)"),
        _ => None,
    }
}

/// Which signals carry a fault ADDRESS that IS the instruction pointer.
///
/// MEASURED NEED: the DEPLOYED handler in this prefix prints
/// `[sigexc-fatal sig=%d code=%d addr=%p pid=%d tid=%d]` -- no rip= -- so this tool rejected every log the prefix
/// produces ("the fatal line carries no rip=") even though the handler HAD already named the owning mapping in the
/// `[sigexc-fault-map ...]` line right above it. For the synchronous traps below, the kernel's si_addr IS the
/// faulting instruction pointer; for the asynchronously raised signals (tkill: SIGABRT/SIGKILL/SIGTERM) si_addr is
/// the sender's pid, i.e. not an address at all, and resolving it would invent a symbol rather than report one.
fn addr_is_instruction_pointer(sig: i64) -> bool {
    matches!(sig, 4 /*SIGILL*/ | 5 /*SIGTRAP*/ | 8 /*SIGFPE*/ | 10 /*SIGBUS*/ | 11 /*SIGSEGV*/)
}

/// One line of a `/proc/self/maps` listing, in the shape both the handler's dump and its `[sigexc-fault-map <line>]`
/// mark carry it: `lo-hi perms offset dev inode [path]`. The path is the remainder AFTER the inode, so it is present
/// only when the line has more than five fields -- MEASURED: taking the last field unconditionally turned an
/// anonymous mapping's INODE into a path, so the tool handed "0" to llvm-nm and bailed on a fault that was simply not
/// in a file. Paths may contain spaces, so the remainder is joined rather than taken as one token.
fn parse_maps_line(l: &str) -> Option<(u64, u64, u64, String)> {
    let mut f = l.split_whitespace();
    let (Some(range), Some(_perms), Some(off)) = (f.next(), f.next(), f.next()) else { return None };
    let (Some(lo), Some(hi)) = (range.split('-').next(), range.split('-').nth(1)) else { return None };
    let (Ok(lo), Ok(hi), Ok(off)) =
        (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16), u64::from_str_radix(off, 16))
    else {
        return None;
    };
    // dev + inode consume two fields; anything left is the path (or the kernel's `[stack]`-style pseudo-name).
    let rest: Vec<&str> = f.collect();
    let path = if rest.len() > 2 { rest[2..].join(" ") } else { String::new() };
    Some((lo, hi, off, path))
}

/// Whether a mapping's name is a FILE the symbolizer can open. `/proc/self/maps` also carries pseudo-entries
/// (`[stack]`, `[heap]`, `[vdso]`, `[anon:...]`), which are names, not paths: reporting one as the image would send
/// llvm-nm after a file that does not exist and hide the real answer ("this fault is not in an image").
fn mapping_is_file(path: &str) -> bool {
    path.starts_with('/')
}

/// The newest fatal mark in a log that this tool can attribute to an image.
///
/// The log accumulates across runs AND across a single run's lifetime, so the LAST `[sigexc-fatal` line is often not
/// the fault being asked about: MEASURED, the harness's own teardown leaves `[sigexc-fatal sig=15 ...]` (SIGTERM,
/// raised by tkill, whose si_addr is the sender's pid) after the SIGILL that killed the client -- selecting the last
/// line blindly picked the teardown. The marks are scanned in order and the last ATTRIBUTABLE one wins.
///
/// Two generations of handler are accepted. Newer ones print `rip=`; the one deployed here does not, and its `addr=`
/// is the instruction pointer for every synchronous trap, so that generation is symbolized from `addr=` with the
/// provenance printed (`ip=addr=`) rather than quietly claimed to be a register.
struct FaultMark {
    sig: i64,
    addr: u64,
    ip: u64,
    ip_from_addr: bool,
    /// The thread the GUEST faulted in, as the handler printed it (`tid=%d`, decimal). It is the one field that ties
    /// a log to a core's thread, which is why `core --log` reports it next to the core's own note order. The newer
    /// handler generation prints no `tid=`, so this is an option rather than a field to fall back on.
    tid: Option<u32>,
}

fn last_fault_mark(text: &str) -> Option<FaultMark> {
    // The marks print addresses as `0x...`, and from_str_radix does NOT accept a radix prefix -- MEASURED: the tool
    // matched the right line and then reported "carries no rip=", because the parse, not the search, was wrong.
    let grab = |line: &str, key: &str| -> Option<u64> {
        line.split_whitespace().find_map(|w| {
            w.strip_prefix(key)
                .map(|v| v.trim_end_matches(']'))
                .map(|v| v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v))
                .and_then(|v| u64::from_str_radix(v, 16).ok())
        })
    };
    text.lines()
        .filter(|l| l.contains("[sigexc-fatal"))
        .filter_map(|fatal| {
            let sig = fatal
                .split_whitespace()
                .find_map(|w| w.strip_prefix("sig=").and_then(|v| v.parse::<i64>().ok()))
                .unwrap_or(0);
            let addr = grab(fatal, "addr=").unwrap_or(0);
            // `tid=%d` is DECIMAL (unlike the addresses on the same line), so it is parsed as such and never through
            // the hex helper above.
            let tid = fatal
                .split_whitespace()
                .find_map(|w| w.strip_prefix("tid=").map(|v| v.trim_end_matches(']').to_string()))
                .and_then(|v| v.parse::<u32>().ok());
            match grab(fatal, "rip=") {
                Some(rip) => Some(FaultMark { sig, addr, ip: rip, ip_from_addr: false, tid }),
                None if addr_is_instruction_pointer(sig) => {
                    Some(FaultMark { sig, addr, ip: addr, ip_from_addr: true, tid })
                }
                None => None,
            }
        })
        .last()
}

/// The mappings a log offers for symbolization, best source first.
///
/// A full `/proc/self/maps` dump (`[sigexc-maps-begin`..`[sigexc-maps-end]`) is the superset and is preferred. When
/// the handler does not dump one, its `[sigexc-fault-map <line>]` mark is still the answer to "which image owns this
/// address": the handler reads /proc/self/maps and prints the ONE line whose range contains si_addr. Taking it means
/// a fault is attributable from a log that has no dump at all, which is the state of every log this prefix writes.
fn fault_mappings(text: &str) -> Vec<(u64, u64, u64, String)> {
    let mut maps: Vec<(u64, u64, u64, String)> = Vec::new();
    let mut inside = false;
    for l in text.lines() {
        if l.contains("[sigexc-maps-begin") {
            inside = true;
            continue;
        }
        if l.contains("[sigexc-maps-end") {
            inside = false;
            continue;
        }
        if inside {
            if let Some(m) = parse_maps_line(l) {
                maps.push(m);
            }
            continue;
        }
        if let Some(rest) = l.split("[sigexc-fault-map ").nth(1) {
            if let Some(m) = parse_maps_line(rest.trim_end_matches(']')) {
                maps.push(m);
            }
        }
    }
    maps
}

/// The bytes at the faulting instruction, read from the image the mapping names.
fn fault_bytes(path: &str, offset: u64) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = stored_evidence::open(Path::new(path)).ok()?;
    f.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = [0u8; 16];
    let n = f.read(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

/// Whether the faulting bytes are a DELIBERATE trap, which is a different investigation from a memory error.
///
/// MEASURED: clang emits `ud2` for `__builtin_trap()` and for unreachable code, so `0f 0b` at the fault means the
/// code CHOSE to die there -- e.g. libsystem_c's `___abort` ends with `callq _sigprocmask; ud2`, i.e. "the abort
/// signal never arrived, trap". A SIGSEGV on a load would instead show the load, so the distinction is visible in
/// the first byte and decides whether to chase a missing symbol or an abort path.
fn decode_trap(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x0f, 0x0b, ..] => Some("ud2 (deliberate trap: __builtin_trap / unreachable)"),
        [0xcc, ..] => Some("int3 (debugger trap)"),
        [0xf4, ..] => Some("hlt"),
        _ => None,
    }
}

/// Whether a log holds a fault this tool can name an image for. Used to SELECT a log, so it must accept both handler
/// generations: a maps dump, or the single `[sigexc-fault-map` mapping line, plus a fatal mark whose address is an
/// instruction pointer.
fn log_has_symbolizable_fault(text: &str) -> bool {
    last_fault_mark(text).is_some()
        && (text.contains("[sigexc-maps-begin") || text.contains("[sigexc-fault-map"))
}

/// The mapping that owns an address: `(lo, file offset, path)`. The file offset the symbolizer needs is
/// `file_offset + (address - lo)`, which is the arithmetic a session did by hand once per run.
fn find_mapping(maps: &[(u64, u64, u64, String)], addr: u64) -> Option<(u64, u64, String)> {
    maps.iter()
        .find(|(lo, hi, _, _)| *lo <= addr && addr < *hi)
        .map(|(lo, _, off, p)| (*lo, *off, p.clone()))
}

/// The segment table of a Mach-O, so a FILE offset can be turned into the IMAGE address a symbol table uses.
///
/// WHY THIS EXISTS. The mapping in /proc/self/maps reports a FILE offset, while `llvm-nm`/`llvm-objdump` express a
/// Mach-O's symbols as IMAGE addresses (the segment vmaddrs). The two coincide only for a thin file whose __TEXT
/// starts at file 0, and MEASURED they do not here: the deployed libsystem_c.dylib is UNIVERSAL, its x86_64 slice
/// starts at file 0x1000, so the fault's file offset (0xf247f) and its image address (0xf147f) differ by exactly that
/// base -- resolving with the file offset named `regerror +0xd2f` for an instruction that is `__abort +0x15f`.
/// Reading the bytes needs the file offset; naming the symbol needs the image address.
struct MachoSegments {
    /// `(file offset in the whole file, vmaddr, size)` for every segment of the x86_64 slice.
    segs: Vec<(u64, u64, u64)>,
}

impl MachoSegments {
    /// None for anything that is not a Mach-O this can walk (a non-Mach-O, a truncated header): the caller then falls
    /// back to the image-relative address and says so, rather than inventing a base.
    fn load(path: &str) -> Option<Self> {
        let raw = stored_evidence::read(Path::new(path)).ok()?;
        if raw.len() < 32 {
            return None;
        }
        let be32 = |o: usize| -> u64 { u32::from_be_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]) as u64 };
        let be64 = |o: usize| -> u64 {
            u64::from_be_bytes([
                raw[o], raw[o + 1], raw[o + 2], raw[o + 3], raw[o + 4], raw[o + 5], raw[o + 6], raw[o + 7],
            ])
        };
        let le32 = |o: usize| -> u64 { u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]) as u64 };
        let le64 = |o: usize| -> u64 {
            u64::from_le_bytes([
                raw[o], raw[o + 1], raw[o + 2], raw[o + 3], raw[o + 4], raw[o + 5], raw[o + 6], raw[o + 7],
            ])
        };
        let mut slice = 0usize;
        // The magic is matched on its BYTES: a thin Mach-O is little-endian, so reading its first word big-endian gives
        // 0xcffaedfe, not MH_MAGIC -- MEASURED, matching the constant instead rejected every thin file.
        match [raw[0], raw[1], raw[2], raw[3]] {
            [0xca, 0xfe, 0xba, 0xbe] | [0xca, 0xfe, 0xba, 0xbf] => {
                // Universal: the x86_64 slice, because that is the guest this workspace runs and the slice whose
                // addresses llvm-nm prints first for the file.
                let n = be32(4) as usize;
                let stride = if raw[3] == 0xbf { 32 } else { 20 };
                let mut found = None;
                for i in 0..n {
                    let o = 8 + stride * i;
                    if o + stride > raw.len() {
                        break;
                    }
                    if be32(o) == 0x01000007 {
                        found = Some(if stride == 32 { be64(o + 8) } else { be32(o + 8) } as usize);
                        break;
                    }
                }
                slice = found?;
            }
            // MH_MAGIC_64 / MH_MAGIC (little-endian thin files: the bytes as the kernel writes them)
            [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] => {}
            _ => return None,
        }
        if slice + 32 > raw.len() {
            return None;
        }
        let magic = le32(slice);
        if magic != 0xfeedface && magic != 0xfeedfacf {
            return None;
        }
        let sixtyfour = magic == 0xfeedfacf;
        let ncmds = le32(slice + 16) as usize;
        let mut o = slice + 32;
        let mut segs = Vec::new();
        for _ in 0..ncmds {
            if o + 8 > raw.len() {
                break;
            }
            let cmd = le32(o);
            let cmdsize = le32(o + 4) as usize;
            if cmdsize < 8 || o + cmdsize > raw.len() {
                break;
            }
            if cmd == 0x19 && sixtyfour {
                segs.push((slice as u64 + le64(o + 40), le64(o + 24), le64(o + 48)));
            } else if cmd == 0x1 && !sixtyfour {
                segs.push((slice as u64 + le32(o + 32), le32(o + 24), le32(o + 36)));
            }
            o += cmdsize;
        }
        if segs.is_empty() { None } else { Some(Self { segs }) }
    }

    /// The image address that a file offset belongs to, when a segment contains it.
    fn image_addr(&self, file_offset: u64) -> Option<u64> {
        self.segs
            .iter()
            .find(|(fabs, _, size)| *fabs <= file_offset && file_offset < *fabs + *size)
            .map(|(fabs, vmaddr, _)| vmaddr + (file_offset - *fabs))
    }
}

/// One parse per image, because the caller chain asks about the same dylib repeatedly and re-reading a 1.5 MB
/// universal file for every stack word is work with no answer in it.
#[derive(Default)]
struct MachoSegmentCache {
    by_path: BTreeMap<String, Option<MachoSegments>>,
}

impl MachoSegmentCache {
    fn image_addr(&mut self, path: &str, file_offset: u64) -> Option<u64> {
        self.by_path
            .entry(path.to_string())
            .or_insert_with(|| MachoSegments::load(path))
            .as_ref()
            .and_then(|m| m.image_addr(file_offset))
    }
}

/// Symbolize a GUEST fatal signal from a run log, with no hand-work: the handler writes
/// `[sigexc-fatal sig=... addr=... rip=... rsp=... rbp=...]` and dumps `/proc/self/maps` between
/// `[sigexc-maps-begin` and `[sigexc-maps-end]`, so the faulting instruction pointer can be attributed to an image and
/// resolved to a symbol by the tool itself. MEASURED need: doing this by hand took a parser, an offset computation and
/// a symbol lookup, and the same arithmetic had to be redone for every run.
///
/// The handler this prefix DEPLOYS writes the older mark -- `[sigexc-fatal sig code addr pid tid]` with no rip= --
/// plus `[sigexc-fault-map <the one maps line containing si_addr>]`, so both generations are accepted here: the
/// mapping comes from a dump when there is one and from the fault-map mark otherwise, and the instruction pointer is
/// `rip=` when present and `addr=` on the synchronous traps otherwise. Both facts are printed as they were obtained.
fn symbolize_guest_fault(text: &str, json: bool, link: Option<&CoreLink>) -> Result<ExitCode> {
    let mark = last_fault_mark(text).context(
        "no [sigexc-fatal line this tool can symbolize: need rip=, or addr= on a synchronous trap \
         (SIGILL/SIGSEGV/SIGBUS/SIGTRAP/SIGFPE)",
    )?;
    let FaultMark { sig, addr, ip, ip_from_addr, .. } = mark;
    let rip = ip;

    let maps = fault_mappings(text);
    let (lo, file_off, path) = find_mapping(&maps, rip)
        .with_context(|| format!("ip={rip:#x} is in no mapping this log records"))?;

    if ip_from_addr {
        println!(
            "GUEST-FAULT sig={sig} addr={addr:#x} ip=addr={rip:#x} (no rip= on the mark: the fault address is the \
             instruction pointer for {} and the handler named the mapping it falls in)",
            signal_name(sig as i32)
        );
    } else {
        println!("GUEST-FAULT sig={sig} addr={addr:#x} rip={rip:#x}");
    }

    // ONE parse per image: the caller chain below asks about the same dylib repeatedly.
    let mut segcache = MachoSegmentCache::default();
    // THE CALLERS ABOVE THE FAULT: the handler also dumps stack words, and each one that lands in a mapped, named
    // image is a candidate return address. Reporting them makes "who called into this function" one command instead of
    // a stack walk performed by hand, which is how the earlier crashes were chased.
    let stack: Vec<u64> = text
        .lines()
        .filter_map(|l| {
            let i = l.find("[sigexc-stack ")?;
            let rest = &l[i..];
            let v = rest.split("v=").nth(1)?.trim_end_matches(']').trim();
            u64::from_str_radix(v.strip_prefix("0x").unwrap_or(v), 16).ok()
        })
        .collect();
    if !stack.is_empty() {
        println!("GUEST-STACK {} word(s)", stack.len());
        let mut shown = 0;
        for (wi, w) in stack.iter().enumerate() {
            if *w == 0 {
                continue;
            }
            // ANY mapping counts, anonymous included. MEASURED: requiring a mapping with a PATH suppressed every
            // candidate and the caller list came out empty on a log that clearly had 33 stack words -- a filter that
            // silently discards the answer it exists to find. Anonymous regions are printed as such, so the first
            // pass through a real chain has something to follow.
            let Some((lo, hi, foff, p)) =
                maps.iter().find(|(lo, hi, _, _)| *lo <= *w && *w < *hi).map(|(a, b, c, d)| (*a, *b, *c, d.clone()))
            else {
                continue;
            };
            if !mapping_is_file(&p) {
                // An anonymous region, or one of the kernel's pseudo-entries. Both are printed as what they are: a
                // word that lands there has no image to name, which is an answer.
                let name = if p.is_empty() { "anonymous" } else { p.as_str() };
                println!("GUEST-CALLER w{wi}={w:#x} <{name} mapping {lo:#x}-{hi:#x}>");
                continue;
            }
            let target = foff + (*w - lo);
            // The same file-offset/image-address split as the fault itself: `locate` wants the image address.
            let caller_addr = segcache.image_addr(&p, target).unwrap_or(target - foff);
            // NO FILTER AND NO INVERTED PREDICATE. MEASURED: an edit-time rewrite of this very expression dropped its
            // leading `!`, so retain() KEPT the numeric local labels and threw the real names away -- the caller list
            // then reported "0 symbols loaded" for images that llvm-nm resolves. Names are printed as the table has
            // them; a reader can see a numeric label instead of the row being silently deleted.
            let Ok(syms) = load_symbols(Path::new(&p)) else { continue };
            let file = Path::new(&p).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
            match locate(&syms, caller_addr) {
                Some((idx, delta)) => println!(
                    "GUEST-CALLER w{wi}={w:#x} {}+{:#x} ({file} file offset {target:#x})",
                    symbol_name(&syms[idx].name),
                    delta
                ),
                // No symbol is still an answer: it says the word lands in a mapped image at an offset with no name in
                // the table, which is what a stripped region or a data word looks like.
                None => println!(
                    "GUEST-CALLER w{wi}={w:#x} <no symbol, {} symbols loaded> ({file} file offset {target:#x})",
                    syms.len()
                ),
            }
            shown += 1;
            if shown >= 8 {
                break;
            }
        }
    }
    let target = file_off + (rip - lo);
    if !mapping_is_file(&path) {
        // Naming WHAT the fault is in, rather than only that it is not in a file: `[stack]`/`[heap]`/`[vdso]` and an
        // anonymous region are different answers, and the difference is the whole question when a fault is a bad
        // pointer rather than a bad instruction.
        println!("GUEST-IMAGE {path} base={lo:#x} file_offset={target:#x}");
        let what = if path.is_empty() { "an anonymous mapping".to_string() } else { format!("the {path} mapping") };
        bail!("the faulting mapping is {what}: no image to symbolize");
    }
    // THE FILE OFFSET AND THE IMAGE ADDRESS ARE NOT THE SAME NUMBER, and each is needed where it belongs: the bytes
    // are read at the file offset, the symbol is named from the image address.
    let image_addr = segcache.image_addr(&path, target).unwrap_or(rip - lo);
    println!("GUEST-IMAGE {path} base={lo:#x} file_offset={target:#x} image_addr={image_addr:#x}");
    let mut syms = load_symbols(Path::new(&path))?;
    // NUMERIC NAMES ARE LOCAL LABELS, NOT FUNCTIONS. MEASURED: the lookup returned "1106 +0x80bf0" for an address a
    // hand computation resolved to "_fgetln+0x11a" -- the nearest symbol happened to be an unnamed local label, which
    // is worse than useless because it looks like an answer. Drop them before locating.
    syms.retain(|s| {
        let n = symbol_name(&s.name);
        let numeric_label = !n.is_empty() && n.chars().all(|c| c.is_ascii_digit() || c == '.');
        !numeric_label
    });
    match locate(&syms, image_addr) {
        // locate returns (INDEX, base) -- not a name. MEASURED: destructuring it as (name, base) printed an index as if
        // it were a symbol, which is how the output read "1106 +0x80bf0" for an address llvm-nm resolves to
        // "_fgetln+0x11a".
        // locate returns (index, DELTA) -- the second element is already the offset from that symbol, so subtracting
        // again produced "fgetln +0x80bf0" for an address that is fgetln+0x11a.
        Some((idx, delta)) => {
            println!(
                "GUEST-SYMBOL {} +{:#x} (image addr {:#x}, file offset {:#x})",
                symbol_name(&syms[idx].name),
                delta,
                image_addr,
                target
            );
        }
        None => println!("GUEST-SYMBOL <none> (image addr {:#x}, file offset {:#x})", image_addr, target),
    }
    // WHAT THE INSTRUCTION IS, not just where it lives. The mapping names the image and the symbol table names the
    // function; the first bytes say whether the code TRAPPED ON PURPOSE, which is the difference between chasing an
    // abort path and chasing a bad pointer.
    let bytes = fault_bytes(&path, target);
    let hex = bytes
        .as_deref()
        .map(|b| b.iter().take(8).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let trap = bytes.as_deref().and_then(decode_trap).unwrap_or("");
    match (&bytes, trap) {
        (None, _) => println!("GUEST-INSN <unreadable: cannot open {path} at file offset {target:#x}>"),
        (Some(_), "") => println!("GUEST-INSN {hex}"),
        (Some(_), t) => println!("GUEST-INSN {hex} -- {t}"),
    }
    if json {
        println!(
            "{{\"sig\":{sig},\"addr\":\"{addr:#x}\",\"ip\":\"{rip:#x}\",\"ip_from_addr\":{ip_from_addr},\
             \"image\":\"{}\",\"base\":\"{lo:#x}\",\"file_offset\":\"{target:#x}\",\"image_addr\":\"{image_addr:#x}\",\
             \"insn\":\"{}\",\"trap\":\"{}\",\"core\":{}}}",
            jesc(&path),
            jesc(&hex),
            jesc(trap),
            link.map(core_link_json).unwrap_or_else(|| "null".to_string())
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// The newest verdict log that actually CONTAINS something this command can symbolize. MEASURED: taking simply the
/// newest log picked one written by a binary that predates the rip/rsp instrumentation, so the obvious invocation
/// failed on a log that had nothing to do with the question. Scanning a few candidates and naming the one chosen turns
/// "it did not work" into "here is the log I read".
fn newest_usable_crash_log() -> Option<String> {
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in fs::read_dir("/tmp").ok()? {
        let Ok(e) = entry else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        if !(name.starts_with("dwdiag-verdict-") && name.ends_with(".log")) {
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        let Ok(mtime) = md.modified() else { continue };
        candidates.push((mtime, e.path()));
    }
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in candidates.iter().take(8) {
        let Ok(text) = read_log_lossy(path) else { continue };
        // Both handler generations count, and for the same reason: a log whose fatal mark cannot be attributed to an
        // image is a log this command has nothing to say about. MEASURED: requiring `rip=` AND a maps dump rejected
        // every log this prefix writes, because the deployed handler prints neither -- it prints the ONE mapping line
        // it looked up, which is enough to name the image.
        if log_has_symbolizable_fault(&text) {
            println!("CRASH-LOG {} (newest log with a symbolized fault)", path.display());
            return Some(text);
        }
    }
    None
}

/// The core a run left, DISCOVERED from `core_pattern` rather than assumed.
///
/// MEASURED need: a log whose marks show a signal death says the guest faulted, and says nothing about the OPERANDS
/// -- the masked lock owner, the once word, the thread's own TSD identity. Those live in one instant of the process,
/// which only a core keeps, so the command that reads the fault has to name the core and the command that reads the
/// operands. The directory is derived from the pattern (`/tmp/t4cores/core.%p` is a SETTING, not a constant) and the
/// comparison against the log's own mtime is printed, because an earlier run's core sits in the same directory and
/// reading it as this run's is how evidence gets misattributed.
struct CoreLink {
    pattern: CorePattern,
    newest: Option<(PathBuf, u64)>,
    newer_than_log: Option<bool>,
}

fn core_link(log: Option<&Path>) -> CoreLink {
    let pattern = core_pattern();
    let newest = if pattern.piped { None } else { newest_core_sized(&pattern.dir, &pattern.prefix) };
    let log_mtime = log.and_then(|p| fs::metadata(stored_evidence::resolve(p)).ok()).and_then(|m| m.modified().ok());
    let newer_than_log = match (&newest, log_mtime) {
        (Some((p, _)), Some(t)) => fs::metadata(p).ok().and_then(|m| m.modified().ok()).map(|c| c >= t),
        _ => None,
    };
    CoreLink { pattern, newest, newer_than_log }
}

fn say_core_link(l: &CoreLink, log: Option<&Path>) {
    if l.pattern.piped {
        crate::say(&format!(
            "CRASH-CORE piped: core_pattern={} starts with '|', so the kernel PIPES the dump to a handler and keeps \
             no file; `dwdiag cores on` installs a file pattern",
            l.pattern.pattern
        ));
        return;
    }
    crate::say(&format!(
        "CRASH-CORE pattern={} (read from /proc/sys/kernel/core_pattern, not assumed) dir={} name-prefix={:?}",
        l.pattern.pattern,
        l.pattern.dir.display(),
        l.pattern.prefix
    ));
    match &l.newest {
        Some((p, size)) => {
            crate::say(&format!(
                "CRASH-CORE newest={} size={size} ({})",
                p.display(),
                match l.newer_than_log {
                    Some(true) => "newer than the log: it can be this run's",
                    Some(false) => "OLDER than the log: an earlier run's core sits in the same directory, so do not \
                                    read it as this run's without checking",
                    None => "no --log to compare against, so this is only the newest core in the directory",
                }
            ));
            let logarg = log.map(|p| format!(" --log {}", p.display())).unwrap_or_default();
            crate::say(&format!(
                "CRASH-CORE-NEXT the faulting frame's operands (the masked lock owner, the once word, the thread's TSD \
                 identity) are one instant and live only in that core: dwdiag core --core {}{logarg}",
                p.display()
            ));
        }
        None => crate::say(&format!(
            "CRASH-CORE none: nothing under {} whose name starts with {:?} exists, so this run left no core to read \
             (a core is written only when the crashing process's `ulimit -c` is non-zero AND the pattern names a file)",
            l.pattern.dir.display(),
            l.pattern.prefix
        )),
    }
}

fn core_link_json(l: &CoreLink) -> String {
    json_object(vec![
        ("pattern", jstr(&l.pattern.pattern)),
        ("piped_to_a_handler", l.pattern.piped.to_string()),
        ("dir", jstr(&l.pattern.dir.display().to_string())),
        ("name_prefix", jstr(&l.pattern.prefix)),
        ("newest", l.newest.as_ref().map(|(p, _)| jstr(&p.display().to_string())).unwrap_or_else(|| "null".into())),
        ("newest_size", l.newest.as_ref().map(|(_, s)| s.to_string()).unwrap_or_else(|| "null".into())),
        (
            "newest_is_newer_than_the_log",
            l.newer_than_log.map(|b| b.to_string()).unwrap_or_else(|| "null".into()),
        ),
    ])
}

fn run_crash(args: CrashArgs) -> Result<ExitCode> {
    // A guest fatal signal carries everything needed in the log itself; try that first, and when neither --log nor
    // --line is given, use the newest verdict log so the obvious invocation just works.
    let log_text = match (&args.log, &args.line) {
        (Some(log), _) => read_log_lossy(log).ok(),
        (None, None) => newest_usable_crash_log(),
        _ => None,
    };
    if let Some(text) = &log_text {
        if log_has_symbolizable_fault(text) {
            // A log whose marks show a signal death has nothing to say about the OPERANDS; the core this run left
            // does. Name it (from core_pattern) and the command that reads it, before the fault report.
            let link = core_link(args.log.as_deref());
            if !args.json {
                say_core_link(&link, args.log.as_deref());
            }
            return symbolize_guest_fault(text, args.json, Some(&link));
        }
    }
    // The core the run left, when this log's own marks show a signal death: filled in by the log path below and
    // reported in both the text and the JSON form of the dserver-CRASH record.
    let mut dserver_core_link: Option<CoreLink> = None;
    let line = match (&args.line, &args.log) {
        (Some(l), _) => l.clone(),
        (None, Some(log)) => {
            let text =
                read_log_lossy(log).with_context(|| format!("reading {}", log.display()))?;
            // The SAME linkage as the symbolized-fault path: a log whose own marks show a signal death names the core
            // that run left and the command that reads the operands out of it.
            dserver_core_link = if last_fault_mark(&text).is_some() {
                let link = core_link(Some(log));
                if !args.json {
                    say_core_link(&link, Some(log));
                }
                Some(link)
            } else {
                None
            };
            let fatal_marks = text.lines().filter(|l| l.contains("[sigexc-fatal")).count();
            text.lines()
                .find(|l| l.contains("dserver-CRASH"))
                .map(|l| l.to_string())
                .with_context(|| {
                    // A log whose guest fault cannot be attributed is a DIFFERENT answer from a log with no guest
                    // fault at all, and naming which is the point of the command. MEASURED: after the constant-string
                    // fix the client stopped dying entirely and the only fatal mark left was the harness's teardown
                    // SIGTERM; the old message read "no dserver-CRASH line", which sounds like a missing loader crash
                    // rather than "this run had no fault".
                    if fatal_marks > 0 {
                        format!(
                            "no dserver-CRASH line in {}, and no attributable guest fault either: {fatal_marks} \
                             [sigexc-fatal line(s), none with rip= or with addr= on a synchronous trap \
                             (SIGILL/SIGSEGV/SIGBUS/SIGTRAP/SIGFPE) -- a teardown SIGTERM is not a fault",
                            log.display()
                        )
                    } else {
                        format!("no dserver-CRASH line and no [sigexc-fatal line in {}", log.display())
                    }
                })?
        }
        _ => bail!("need --line or --log"),
    };
    let crash = parse_crash_line(&line);
    let binary = args
        .binary
        .as_ref()
        .context("a dserver-CRASH line is written by the SERVER: pass --binary pointing at the darlingserver binary (the loader image does not contain this probe, and pointing at it produced two wrong answers in one session)")?;
    let syms = load_symbols(binary)?;

    // The probe reports `self` (a known symbol's runtime address) precisely so that the runtime pc can be turned into an
    // offset inside the FILE; without that subtraction the number is only meaningful to the process that printed it.
    let file_target = match (crash.self_, crash.pc) {
        (Some(s), Some(pc)) => {
            let self_file = syms
                .iter()
                .find(|s| symbol_name(&s.name).contains("dserver_crash_probe"))
                .map(|s| s.addr)
                .context(
                    "dserver_crash_probe not in the symbol table: cannot derive the file offset",
                )?;
            Some(self_file + (pc.saturating_sub(s)))
        }
        _ => crash.pc,
    };

    // HONESTY BOUND (perf#30, doc section 253). The anchor subtraction assumes the faulting pc belongs to THIS binary.
    // MEASURED: a `std::length_error` throw made the pc land in libstdc++, the subtraction produced a huge number, and
    // `locate` still returned a symbol -- the output claimed `LOCATION: end + 0x1b6f...`, a location that cannot exist.
    // An answer that cannot be checked is worse than no answer, so a target outside the binary's own symbol range is
    // reported as such instead of being matched to the nearest symbol.
    let (min_sym, max_sym) = match (syms.first(), syms.last()) {
        (Some(f), Some(l)) => (f.addr, l.addr),
        _ => (0, u64::MAX),
    };
    let in_binary = file_target
        .map(|t| t >= min_sym.saturating_sub(0x1000) && t <= max_sym.saturating_add(0x1000));
    let location = match (file_target, in_binary) {
        (Some(t), Some(true)) => locate(&syms, t).map(|(i, o)| (t, i, o)),
        _ => None,
    };
    let mut stack_locs: Vec<(usize, u64, String)> = Vec::new();
    if let Some(self_runtime) = crash.self_ {
        for (i, w) in crash.stack.iter().enumerate() {
            if *w == 0 {
                continue;
            }
            let delta = w.saturating_sub(self_runtime);
            if delta < 0x80_0000 {
                if let Some((si, off)) = locate(
                    &syms,
                    syms.iter()
                        .find(|s| symbol_name(&s.name).contains("dserver_crash_probe"))
                        .map(|s| s.addr)
                        .unwrap_or(0)
                        + delta,
                ) {
                    stack_locs.push((
                        i,
                        *w,
                        format!("{} + 0x{:x}", symbol_name(&syms[si].name), off),
                    ));
                }
            }
        }
    }

    let mut disassembly = String::new();
    if let (Some(t), Some(ctx)) = (file_target, Some(args.context)) {
        let lo = t.saturating_sub(ctx);
        let hi = t + ctx;
        let (input, _materialized) = stored_evidence::for_tool(binary)?;
        let out = Command::new("objdump")
            .args([
                "-d",
                &format!("--start-address=0x{lo:x}"),
                &format!("--stop-address=0x{hi:x}"),
            ])
            .arg(input.as_os_str())
            .output()
            .context("running objdump")?;
        for l in String::from_utf8_lossy(&out.stdout).lines() {
            let mut marked = l.to_string();
            if let Some(colon) = l.find(':') {
                if let Ok(a) = u64::from_str_radix(l[..colon].trim(), 16) {
                    if a == t {
                        marked.push_str("   <=== FAULT HERE");
                    }
                }
            }
            disassembly.push_str(&marked);
            disassembly.push('\n');
        }
    }

    // Proactive enrichment (user directive): a fault whose pc is OUTSIDE this binary is still evidence, and the run
    // log usually carries the panic backtrace that says where it happened. MEASURED need: the plane-path abort
    // printed `LOCATION: <outside this binary's symbol range>` and an empty disassembly, while the log's own eleven
    // `darlingserver(+0x...)` frames named the call chain -- the tool had the information and withheld it.
    let signal_meaning = sig_meaning(&crash.sig);
    let mut backtrace_frames: Vec<(u64, String)> = Vec::new();
    let backtrace_log = args
        .log
        .clone()
        .unwrap_or_else(|| newest_verdict_log().unwrap_or_default());
    if let Ok(text) = read_log_lossy(&backtrace_log) {
        for line in text.lines() {
            let Some(open) = line.find("(+0x") else {
                continue;
            };
            let name = &line[..open];
            if !(name == "darlingserver" || name.ends_with("/darlingserver")) {
                continue;
            }
            let rest = &line[open + 4..];
            let Some(end) = rest.find(')') else { continue };
            if let Ok(off) = u64::from_str_radix(&rest[..end], 16) {
                if let Some((si, o)) = locate(&syms, off) {
                    backtrace_frames
                        .push((off, format!("{} + 0x{:x}", symbol_name(&syms[si].name), o)));
                }
            }
        }
    }
    // The server's own caller chain (`bt=`), converted from probe-relative deltas into file offsets. MEASURED need:
    // an abort raised through libc names no caller in its own fields -- the pc is outside the image -- so the chain
    // the handler captured is the only thing that says WHO reached the abort. The probe's own symbol gives the base
    // for the conversion, and a delta that resolves to nothing is reported rather than dropped.
    if !crash.frames.is_empty() {
        match syms.iter().position(|s| s.name.contains("dserver_crash_probe")) {
            Some(pi) => {
                let base = syms[pi].addr;
                for d in &crash.frames {
                    let off = base.wrapping_add(*d);
                    match locate(&syms, off) {
                        Some((si, o)) => backtrace_frames
                            .push((off, format!("{} + 0x{:x}", symbol_name(&syms[si].name), o))),
                        None => backtrace_frames
                            .push((off, format!("<no symbol at 0x{off:x}>"))),
                    }
                }
            }
            None => {
                for d in &crash.frames {
                    backtrace_frames.push((
                        *d,
                        "<probe symbol dserver_crash_probe not found; raw delta from self>".to_string(),
                    ));
                }
            }
        }
    }
    // The `addr` field of a Linux signal carries two 32-bit halves for a tgkill-raised signal; printing the halves
    // is a hypothesis, not a claim, so it is labelled as one.
    let addr_halves = {
        let a = crash.addr.trim().trim_start_matches("0x");
        u64::from_str_radix(a, 16).ok().and_then(|v| {
            if v >> 32 == 0 {
                None
            } else {
                Some((v >> 32, v & 0xffff_ffff))
            }
        })
    };

    if args.json {
        let escaped = jesc(&disassembly);
        println!(
            "{{\"crash\":\"{}\",\"sig\":\"{}\",\"addr\":\"{}\",\"location\":\"{}\",\"stack\":[{}],\"signal_meaning\":\"{}\",\"frames\":[{}],\"disassembly\":\"{}\",\"core\":{}}}",
            jesc(&crash.raw),
            jesc(&crash.sig),
            jesc(&crash.addr),
            location
                .as_ref()
                .map(|(_, i, o)| format!("{} + 0x{:x}", symbol_name(&syms[*i].name), o))
                .unwrap_or_default(),
            stack_locs
                .iter()
                .map(|(i, _, s)| format!("{{\"w\":{},\"location\":\"{}\"}}", i, s))
                .collect::<Vec<_>>()
                .join(","),
            jesc(signal_meaning.unwrap_or("")),
            backtrace_frames
                .iter()
                .map(|(off, s)| format!(
                    "{{\"offset\":\"0x{off:x}\",\"location\":\"{}\"}}",
                    jesc(s)
                ))
                .collect::<Vec<_>>()
                .join(","),
            escaped,
            dserver_core_link.as_ref().map(core_link_json).unwrap_or_else(|| "null".to_string())
        );
    } else {
        println!("crash: {}", crash.raw);
        if let Some((t, i, o)) = &location {
            println!("target=0x{t:x}");
            println!("LOCATION: {} + 0x{o:x}", symbol_name(&syms[*i].name));
        } else if crash.pc.is_some() {
            // Say WHY there is no location, instead of printing nothing (or a guess): the pc is not in this binary,
            // which is the normal case for a C++ throw, a libc abort, or a fault inside a shared library.
            println!(
                "LOCATION: <outside this binary's symbol range: the pc belongs to another object>"
            );
        }
        match signal_meaning {
            Some(m) => println!("signal: {} -- {m}", crash.sig),
            None => println!("signal: {}", crash.sig),
        }
        if let Some((hi, lo)) = addr_halves {
            println!(
                "addr-halves: high=0x{hi:x} (=pid {hi}?) low=0x{lo:x} (={lo}) -- HYPOTHESIS, unverified"
            );
        }
        if !backtrace_frames.is_empty() {
            println!(
                "--- backtrace frames from the log, resolved against {} ---",
                binary.display()
            );
            for (n, (off, sym)) in backtrace_frames.iter().enumerate() {
                println!("  #{n} +0x{off:x} -> {sym}");
            }
        }
        if !stack_locs.is_empty() {
            println!("--- stack walk ---");
            for (i, _, s) in &stack_locs {
                println!("  w{i} -> {s}");
            }
        }
        print!("--- disassembly ---\n{disassembly}");
    }
    // WHICH IMAGE OWNS THIS RECORD, printed by the command that reads it. Two wrong attributions in one
    // session happened because this question was answered by inspection instead of by output.
    if let Some(pfx) = args
        .prefix
        .clone()
        .or_else(|| std::env::var("DWDIAG_PREFIX").ok().map(PathBuf::from))
    {
        crash_identity(&pfx);
    } else {
        println!(
            "CRASH-IDENTITY prefix=<unset> -- pass --prefix or DWDIAG_PREFIX to identify which deployed image {} reports this record",
            binary.display()
        );
    }
    // A crash is a finding, not a tool error: exit 1 so a caller can branch on it without parsing.
    Ok(ExitCode::from(1))
}

/// Which deployed image a `dserver-CRASH` record belongs to, and which one can be symbolized at all.
///
/// MEASURED REASON: misattributing this record cost two wrong conclusions in one session -- first "the server
/// aborted", then "the guest aborted", and the truth was decided only by asking which image contains
/// `dserver_crash_probe`. The record itself carries no pid, tid or image, so the surrounding facts have to be
/// produced by the command that reads it. This prints them, and says `unavailable` for anything the record
/// genuinely does not contain rather than leaving the reader to guess.
fn crash_identity(prefix: &std::path::Path) {
    let Ok(root) = crate::installed_runtime_root() else {
        println!("CRASH-IDENTITY runtime-root=unavailable image-identity=unknown");
        return;
    };
    const CANDIDATES: [&str; 6] = [
        "bin/darlingserver",
        "libexec/darling/usr/libexec/shellspawn",
        "libexec/darling/usr/libexec/darling/mldr",
        "libexec/darling/usr/lib/system/libsystem_kernel.dylib",
        "libexec/darling/usr/lib/system/libdyld.dylib",
        "libexec/darling/usr/lib/dyld",
    ];
    let mut reporting = 0usize;
    for rel in CANDIDATES {
        let p = root.join(rel);
        let sha = match sha256_file(&p) {
            Some(h) => h,
            None => continue,
        };
        let has = std::process::Command::new("llvm-nm")
            .arg(&p)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("dserver_crash_probe"))
            .unwrap_or(false);
        if has {
            reporting += 1;
        }
        println!(
            "CRASH-IDENTITY image={rel} sha256={sha} reports-dserver-crash-probe={}",
            if has { "yes" } else { "no" }
        );
    }
    let server_pid = prefix_processes(prefix).into_iter().find(|pid|
        fs::read_link(format!("/proc/{pid}/exe")).map(|exe| exe == root.join("bin/darlingserver")).unwrap_or(false)
    ).map(|pid| pid.to_string());
    println!(
        "CRASH-IDENTITY prefix={} images-reporting-the-probe={} server-host-pid={} host-tid=unavailable(the crash record carries no host tid); image-root-is-shared",
        prefix.display(),
        reporting,
        server_pid.as_deref().unwrap_or("not-running")
    );
}

// ----------------------------------------------------------------------------------------------------------------
// verdict / suite
// ----------------------------------------------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct VerdictArgs {
    /// The prefix to run in. Not required with --log, which judges a log that already exists: a verdict rule must be
    /// testable against a file, and paying a full prefix boot just to re-read an old verdict is what this avoids.
    #[arg(long)]
    prefix: Option<PathBuf>,
    #[arg(long, default_value = "")]
    mode: String,
    #[arg(long, default_value = "")]
    args: String,
    #[arg(long, default_value_t = 70)]
    wait: u64,
    #[arg(long, value_parser = parse_kv)]
    env: Vec<(String, String)>,
    /// The harness that owns prefix start/stop and the run log. Reused, never reimplemented.
    #[arg(long, default_value = "scripts/darling-boot-run.sh")]
    boot_runner: PathBuf,
    /// The guest workload binary the mode is an argument of.
    ///
    /// The default is the guest-visible path, NOT `/usr/bin/ring_mach_msg_test`: the guest's `/usr/bin` resolves
    /// through `/Volumes/SystemRoot` to the HOST's `/usr/bin`, so a fixture installed inside the prefix is invisible
    /// there and the run dies with `not found` (rc=127). MEASURED COST (2026-10-04): a gate of 200 runs used the
    /// `/usr/bin` default, every run burned its full watchdog and reported `HANG (watchdog)`, and four hours of
    /// "product failures" were one wrong path. `prefix` and `suite` already default to the writable guest path.
    #[arg(long, default_value = "/private/var/tmp/ring_mach_msg_test")]
    guest_command: String,
    /// Image used to symbolize a denial's caller offset.
    #[arg(long)]
    guest_symbols: Option<PathBuf>,
    /// Judge a run log that ALREADY EXISTS instead of running a workload. The prefix is then unused, which is what
    /// makes a verdict rule testable against a file and what stops paying a full prefix boot to re-read an old verdict.
    #[arg(long)]
    log: Option<PathBuf>,
    /// How many times to run the SAME workload. A single-run verdict cannot see flake, and this session's
    /// evidence is full of one-run PASS/CRASH flips; the summary names the distribution and fails if it is not
    /// uniform. Each run gets its own log.
    #[arg(long, default_value_t = 1)]
    repeat: u64,
    /// Print the workload modes THIS prefix's fixture actually contains, with the argument shape and the marker each mode
    /// emits, then exit. The list is read out of the fixture's own strings, so it cannot drift from the binary that will
    /// run: the tool answers "what can I ask for, and what will it print" without anyone grepping a source file.
    #[arg(long)]
    list_modes: bool,
    /// DIAGNOSTIC: when the verdict fails, pass --freeze-on-fail to the boot harness so the prefix and its
    /// processes stay ALIVE for inspection (darling-debug, native stacks, host wchan). WHY THIS IS IN THE
    /// TOOL: the harness already implemented the freeze, but the tool did not forward it, so catching a
    /// failure for inspection meant abandoning the tool and reconstructing its command by hand -- and the
    /// command it builds carries one --cmd argument and the installed-image identity, which a
    /// hand-rolled invocation gets wrong. A frozen prefix is left running on purpose; clean it up with the
    /// command the harness prints.
    #[arg(long)]
    freeze_on_fail: bool,
    #[arg(long)]
    json: bool,
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) => Ok((k.to_string(), v.to_string())),
        None => Err("expected KEY=VALUE".to_string()),
    }
}

#[derive(Debug)]
pub struct Verdict {
    pub mode: String,
    pub verdict: String,
    pub denied: u64,
    pub created: u64,
    pub line: String,
    pub denial_call: Option<String>,
    pub denial_location: Option<String>,
    pub log: PathBuf,
    /// The guest workload's own exit status, as printed by the guest shell (`__DWDIAG_RC=`).
    pub rc: Option<i32>,
    /// Signal name when rc == 128 + N, so a crash is never reported as a hang.
    pub signal: Option<String>,
}

impl Verdict {
    fn ok(&self) -> bool {
        self.verdict == "PASS"
    }
}

/// 128 + N naming for the signals a guest workload actually dies of, so the verdict says the cause.
pub fn signal_name(n: i32) -> &'static str {
    match n {
        4 => "ILL",
        6 => "ABRT",
        7 => "BUS",
        8 => "FPE",
        11 => "SEGV",
        13 => "PIPE",
        15 => "TERM",
        9 => "KILL",
        _ => "SIG",
    }
}

/// Judge a run log that already exists: the result line, the verdict, and the workload's own exit status.
///
/// Split out of the run path for two reasons. First, a log must be re-judgeable WITHOUT a prefix -- re-running a
/// prefix-backed workload only to re-read its verdict costs about two minutes per attempt and was done repeatedly
/// during the acceptance work. Second, the rule below is exactly the kind that has to be testable against a file:
///
/// THE HARNESS'S OWN KILL IS NOT THE WORKLOAD'S CRASH. MEASURED: when the watchdog bound is reached the harness
/// terminates the run, the guest shell then reports 139 for the child it killed, and the verdict said CRASH SEGV --
/// sending the operator after a memory fault that never happened, while the log's last guest line and the server's
/// own stall dump both described a stranded waiter. The harness prints whether it reached the bound ("waited Ns of at
/// most Ns"), and that line decides the verdict before any signal does.
/// Read a run log as text, NEVER as strictly-valid UTF-8.
///
/// MEASURED DEFECT THIS EXISTS TO FIX: a run log carries whatever the guest and the loader wrote to fd 2, including
/// raw register/pointer dumps of probes that deliberately bypass libc. `fs::read_to_string` fails on the first
/// invalid byte, and every caller here treated that failure as "no log text": the verdict then reported NO-RUN for a
/// run that had PRINTED ITS OWN RESULT LINE, and the only visible evidence was an error buried in a transcript. A
/// diagnosis pipeline that can silently discard a passing run's evidence is worse than no pipeline, so logs are read
/// lossily and the bytes that are not text are replaced rather than allowed to erase the run.
/// Resolve the runtime prefix a DIAGNOSIS should read, in order: an explicit flag, DWDIAG_PREFIX, then the identity
/// line the run itself wrote.
///
/// MEASURED DEFECT THIS EXISTS TO FIX: several diagnostics carried a hardcoded default of /tmp/dr-on-matched, so a
/// run served by another prefix had its server-side evidence read from the WRONG prefix's log -- and an absence there
/// reads like "the server never sent it". The runs now stamp `[dwdiag-env prefix=...]` into their own log, so the log
/// can name the prefix that produced it and no diagnosis has to assume one.
fn resolve_prefix(explicit: Option<PathBuf>, log: Option<&std::path::Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p);
    }
    if let Ok(v) = std::env::var("DWDIAG_PREFIX") {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    let log = log?;
    let text = read_log_lossy(log).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.split("prefix=").nth(1) {
            let p = rest.split_whitespace().next()?.trim_end_matches(']');
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
    }
    None
}

fn read_log_lossy(path: &std::path::Path) -> std::io::Result<String> {
    let bytes = stored_evidence::read(path)?;
    Ok(String::from_utf8(bytes).unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()))
}

fn judge_run_log(text: &str, mode: &str) -> (String, String, Option<i32>) {
    // THE RUN NEVER STARTED, AND THAT IS ITS OWN VERDICT. MEASURED, PAINFULLY: a scratch prefix lost bin/shellspawn,
    // every subsequent run therefore failed to launch (the guest log carries "Failed to exec launchd: No such file or
    // directory" and "Rootless shellspawn did not become ready within 30000ms"), and this function reported HANG
    // (watchdog) or NO-RUN for ten consecutive runs -- verdicts that read as statements about the workload while the
    // workload had never executed a single instruction. Two hours of deductions were drawn from those logs before
    // the tail of one of them was read by hand. A launch failure must be named as a launch failure, so it is checked
    // BEFORE every workload-shaped rule below and short-circuits them.
    for (marker, label) in [
        ("Failed to exec launchd", "launchd"),
        ("shellspawn did not become ready", "shellspawn"),
        ("runtime prefix has no recognized stable state", "prefix-state"),
        ("no recognized stable state", "prefix-state"),
    ] {
        if text.contains(marker) {
            eprintln!("BOOT-FAIL ({label}): the run never reached the workload; verdict is about the prefix, not the test");
            return (String::new(), format!("BOOT-FAIL ({label})"), None);
        }
    }

    let line = workload_result_line(text, mode)
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    let started = text.contains(&format!("mode={mode}"));
    let rc: Option<i32> = text
        .lines()
        .filter_map(|l| l.split("__DWDIAG_RC=").nth(1))
        .filter_map(|v| v.trim().parse::<i32>().ok())
        .next_back();
    // A log whose guest reports SIGTERM and that carries no result line is a run the harness stopped: the guest's
    // own fatal line names the signal that ended it, and the workload never signals itself. This covers logs written
    // before the "waited ... of at most ..." line was added to them, and it is the same claim, spelled differently.
    // THE SHELL'S OWN REPORT OF HOW THE WORKLOAD DIED OUTRANKS THE BOUNDARY. MEASURED: a run whose guest
    // shell prints "/bin/bash: line 1: <pid> Segmentation fault: 11 (core dumped) <workload> <args>" was called
    // HANG (watchdog) by the previous form of this rule, because the harness did reach its bound afterwards --
    // but the workload had really died of SIGSEGV and the run never produced a result line. The shell's report is
    // the workload's own status, so it decides first. A `dserver-CRASH` probe line is NOT sufficient on its own:
    // it appears in passing runs too (teardown aborts the host-side image), so a PASS with a result line stays PASS.
    // THE GUEST'S OWN CRASH RECORD OUTRANKS EVERYTHING ELSE. MEASURED: with the workload's deliberate-fault hatch
    // the reporter prints "RING_MACH_TEST_CRASH sig=11 addr=0x0 pc=... " plus symbolized frames, and the verdict
    // still said HANG (watchdog) because no shell line named a signal -- the guest handler had caught the fault and
    // exited on its own. A guest-reported fault IS a crash and must be named as one.
    let guest_crash = text.lines().find_map(|l| {
        let i = l.find("RING_MACH_TEST_CRASH sig=")?;
        let rest = &l[i + "RING_MACH_TEST_CRASH sig=".len()..];
        rest.split_whitespace().next()?.parse::<i32>().ok()
    });
    let shell_signal = text.lines().find_map(|l| {
        if !(l.contains("/bin/bash: line") || l.contains("bash: line")) {
            return None;
        }
        for (word, sig) in [
            ("Segmentation fault", 11),
            ("Aborted", 6),
            ("Killed", 9),
            ("Floating point exception", 8),
            ("Bus error", 7),
        ] {
            if l.contains(word) {
                return Some((sig, word));
            }
        }
        None
    });
    let guest_terminated = text.lines().any(|l| l.contains("[sigexc-default sig=15"));
    let hit_bound = guest_terminated
        || text
        .lines()
        .filter_map(|l| {
            let r = l.trim().strip_prefix("waited ")?;
            let (a, b) = r.split_once("s of at most ")?;
            let a = a.trim().parse::<u64>().ok()?;
            let b = b.trim().trim_end_matches('s').parse::<u64>().ok()?;
            Some(a == b)
        })
        .any(|x| x);
    let verdict = if line.is_empty() {
        if let Some(sig) = guest_crash {
            format!("CRASH {} (guest reporter)", signal_name(sig))
        } else if let Some((sig, word)) = shell_signal {
            format!("CRASH {} ({word})", signal_name(sig))
        } else if hit_bound {
            "HANG (watchdog)".to_string()
        } else {
            match (started, rc) {
                (_, Some(c)) if c >= 128 => format!("CRASH {}", signal_name(c - 128)),
                // 127 is the shell's "command not found": the run never executed the thing it claims to measure, so
                // reporting `EXIT rc=127` (which reads as the workload's own exit) hides the harness mistake.
                (_, Some(127)) => "NO-RUN rc=127 (workload not found)".to_string(),
                (_, Some(c)) => format!("EXIT rc={c}"),
                (true, None) => "HANG".to_string(),
                (false, None) => "NO-RUN".to_string(),
            }
        }
    } else if line.contains("pass=1") {
        "PASS".to_string()
    } else {
        "FAIL".to_string()
    };
    (line, verdict, rc)
}

/// Installation prerequisites never live in writable guest state.
fn runtime_prereq_report(root: &Path) -> bool {
    let missing: Vec<&str> = RUNTIME_FINGERPRINT_CANDIDATES.iter().copied()
        .filter(|relative| !root.join(relative).is_file()).collect();
    if missing.is_empty() {
        println!("RUNTIME-PREREQ ok runtime-root={}", root.display());
        true
    } else {
        println!("RUNTIME-PREREQ missing runtime-root={} paths={}", root.display(), missing.join(","));
        false
    }
}

/// A shared installed executable is not prefix identity: use retained directory
/// capabilities or the launcher's explicit guest-state environment.
fn process_owns_prefix(pid: u32, prefix: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let process = PathBuf::from(format!("/proc/{pid}"));
    if let (Ok(expected), Ok(descriptors)) = (fs::metadata(prefix), fs::read_dir(process.join("fd"))) {
        if descriptors.flatten().any(|entry| fs::metadata(entry.path())
            .map(|actual| actual.is_dir() && actual.dev() == expected.dev() && actual.ino() == expected.ino())
            .unwrap_or(false)) {
            return true;
        }
    }
    let environment = fs::read(process.join("environ")).unwrap_or_default();
    environment.split(|byte| *byte == 0).any(|value| {
        value.strip_prefix(b"DPREFIX=").or_else(|| value.strip_prefix(b"DARLING_PREFIX="))
            .map(|raw| Path::new(std::ffi::OsStr::from_bytes(raw)) == prefix).unwrap_or(false)
    })
}

pub(crate) fn prefix_processes(prefix: &Path) -> Vec<u32> {
    let mut excluded = Vec::new();
    let mut pid = std::process::id();
    while pid > 1 {
        excluded.push(pid);
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { break };
        pid = stat.rsplit(')').next().and_then(|tail| tail.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok()).unwrap_or(1);
    }
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|value| value.parse::<u32>().ok()) else { continue };
            if !excluded.contains(&pid) && process_owns_prefix(pid, prefix) {
                found.push(pid);
            }
        }
    }
    found.sort_unstable();
    found
}

fn runtime_fingerprint(root: &Path) -> String {
    let parts = runtime_fingerprint_parts(root);
    let joined = parts.iter().map(|(name, digest)| format!("{name}={digest}")).collect::<Vec<_>>().join(" ");
    format!("runtime-root={} {joined}", root.display())
}

/// One ordinary installed location per component; no duplicate guest-upper copies.
const RUNTIME_FINGERPRINT_CANDIDATES: [&str; 7] = [
    "bin/darling",
    "bin/darlingserver",
    "libexec/darling/usr/libexec/darling/mldr",
    "libexec/darling/usr/lib/system/libsystem_kernel.dylib",
    "libexec/darling/usr/lib/dyld",
    "libexec/darling/usr/libexec/shellspawn",
    "libexec/darling/sbin/launchd",
];

fn runtime_fingerprint_parts(root: &Path) -> Vec<(String, String)> {
    let mut parts = Vec::new();
    for rel in RUNTIME_FINGERPRINT_CANDIDATES {
        let p = root.join(rel);
        let Ok(resolved) = fs::canonicalize(&p) else { continue };
        if !resolved.starts_with(root) { continue; }
        if let Some(digest) = sha256_file(&resolved) {
            let name = p.file_name().and_then(|name| name.to_str()).unwrap_or(rel);
            parts.push((name.to_string(), digest[..12].to_string()));
        }
    }
    parts
}

fn guest_fixture_path(prefix: &Path, guest_path: &str, runtime: Option<&Path>) -> PathBuf {
    let relative = guest_path.trim_start_matches('/');
    let upper = prefix.join(relative);
    if upper.is_file() { return upper; }
    if let Some(root) = runtime {
        let installed = root.join("libexec/darling").join(relative);
        if installed.is_file() { return installed; }
    }
    upper
}

fn completed_harness(output: &std::process::Output) -> bool {
    output.status.success() && String::from_utf8_lossy(&output.stdout).lines().rev()
        .find(|line| line.starts_with("VERDICT:")) == Some("VERDICT: PASS")
}

fn run_one_workload(args: &VerdictArgs, tag: &str) -> Result<Verdict> {
    let Some(prefix) = args.prefix.as_ref() else {
        bail!("running a workload needs --prefix; use --log to judge a log that already exists");
    };
    let runtime = crate::installed_runtime_root()?;
    if !runtime_prereq_report(runtime) {
        bail!("selected installation is missing runtime prerequisites");
    }
    // A WORKLOAD THAT IS NOT THERE IS NOT A HANG, AND ITS ABSENCE COSTS NO BOOT. The fixture is a TEST ASSET, so the
    // prefix either has it or the run cannot mean anything; checking first turns a wrong path into an immediate
    // verdict instead of a full watchdog wait followed by `HANG (watchdog)`. MEASURED (2026-10-04): 200 runs at one
    // wrong path produced 200 such verdicts and no product information at all.
    let guest_host = guest_fixture_path(prefix, &args.guest_command, Some(runtime));
    if !guest_host.is_file() {
        let log = std::env::temp_dir().join(format!(
            "dwdiag-verdict-{}-{}{}.log",
            std::process::id(),
            args.mode,
            tag
        ));
        let _ = fs::write(
            &log,
            format!(
                "workload absent: {} (a test asset; install it into the prefix, it is not part of the runtime install)\n",
                guest_host.display()
            ),
        );
        eprintln!("VERDICT-PREREQ workload=absent {}", guest_host.display());
        return Ok(Verdict {
            mode: args.mode.clone(),
            verdict: "NO-RUN (workload absent)".to_string(),
            denied: 0,
            created: 0,
            line: String::new(),
            denial_call: None,
            denial_location: None,
            log,
            rc: None,
            signal: None,
        });
    }
    let log = std::env::temp_dir().join(format!(
        "dwdiag-verdict-{}-{}{}.log",
        std::process::id(),
        args.mode,
        tag
    ));
    let _ = fs::remove_file(&log);
    // Self-attributing run: see runtime_fingerprint for the incident this exists to prevent.
    let fp = format!("prefix={} {}", prefix.display(), runtime_fingerprint(runtime));
    let env_log = log.with_extension("log.env");
    let _ = fs::write(&env_log, format!("[dwdiag-env {fp}]\n"));
    eprintln!("RUN-ENV {fp}");
    // The workload's OWN exit status is part of the observation: MEASURED, a workload that dies of SIGSEGV
    // (`EXITRC=139`) produces exactly the same evidence as a deadlock -- no result line -- and every
    // measurement drawn from "HANG" then chases a lock that does not exist. The status is printed by the
    // guest shell, so it is the guest's own answer, not the host launcher's.
    let cmd = format!(
        "{} {} {}; echo __DWDIAG_RC=$?",
        args.guest_command, args.mode, args.args
    );
    // RUN THE HARNESS IN ITS OWN SESSION, VIA THE setsid BINARY. MEASURED: the prefix teardown is group-directed
    // and killed the shell that asked for the run (rc=137 ~51 s in, twice). A pre_exec hook was tried first and
    // BROKE spawning outright (no log file was created at all), so the isolation is done here instead, where a
    // failure is visible: if setsid is missing we fall back to a direct spawn and say so.
    let use_setsid = std::path::Path::new("/usr/bin/setsid").exists()
        || std::path::Path::new("/bin/setsid").exists();
    let mut c = if use_setsid {
        let mut k = Command::new("setsid");
        k.arg(&args.boot_runner);
        k
    } else {
        Command::new(&args.boot_runner)
    };
    c.arg("--runtime-root").arg(runtime).arg("--prefix")
        .arg(prefix)
        .arg("--wait")
        .arg(args.wait.to_string())
        .arg("--log")
        .arg(&log)
        // ONE argument: MEASURED, an empty value followed by the command made the harness see an extra positional and
        // exit instantly, which the verdict then reported as NO-RUN -- a tool defect that looked like a workload that
        // failed to start.
        .arg("--cmd")
        .arg(&cmd);
    for (k, v) in &args.env {
        c.arg("--env").arg(format!("{k}={v}"));
    }
    c.arg("--status-marker").arg("__DWDIAG_RC=").arg("--poll").arg("__DWDIAG_RC=");
    c.arg("--marker").arg(format!("RING_MACH_TEST mode={} ", args.mode));
    // FREEZE IS A DIAGNOSTIC POLICY, AND IT IS PASSED THROUGH RATHER THAN REIMPLEMENTED: the harness owns the
    // prefix lifecycle, so it owns leaving the failing incarnation alive. Silence here was measured friction:
    // the only way to inspect a caught failure was to retype the harness command by hand, which loses
    // the single-argument --cmd shape this builder exists to get right.
    if args.freeze_on_fail {
        c.arg("--freeze-on-fail");
    }
    crate::inherit_owner_lease(&mut c);
    let out = c
        .output()
        .with_context(|| format!("running {}", args.boot_runner.display()))?;

    let harness_clean = completed_harness(&out);

    // Append the identity to the run's own log so the log alone answers "which build served this?".
    if log.exists() {
        use std::io::Write as _;
        if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&log) {
            let _ = writeln!(f, "[dwdiag-env {fp}]");
        }
    }

    let text = read_log_lossy(&log).unwrap_or_default();
    // PREFER THE RESULT LINE, NOT THE FIRST LINE THAT MATCHES THE PREFIX. MEASURED: a mode whose informational
    // header and result line share the `RING_MACH_TEST mode=<M>` prefix (the fsview diagnostic does exactly that)
    // made this matcher read the HEADER, find no `pass=`, and report FAIL for a run whose workload printed
    // `pass=1` and exited 0. Every other mode prints one such line, so preferring a line that carries `pass=` --
    // and otherwise the LAST match, since a result is emitted at the end -- is strictly more honest.
    let (line, mut verdict, rc) = judge_run_log(&text, &args.mode);
    if verdict == "PASS" && !harness_clean {
        verdict = "FAIL (harness or product shutdown)".to_string();
    }
    let denied = text
        .lines()
        .filter(|l| l.contains("rpc-socket-DENIED"))
        .count() as u64;
    let created = text
        .lines()
        .filter(|l| l.contains("rpc-socket] created") || l.contains("rpc-socket. created"))
        .count() as u64;
    let signal = rc
        .filter(|c| *c >= 128)
        .map(|c| signal_name(c - 128).to_string());

    let mut denial_call = None;
    let mut denial_location = None;
    if denied > 0 {
        if let Some(dl) = text.lines().find(|l| l.contains("rpc-socket-DENIED")) {
            let mut call = None;
            let mut delta = None;
            for f in dl.split_whitespace() {
                if let Some(v) = f.strip_prefix("call=") {
                    call = Some(v.to_string());
                } else if let Some(v) = f.strip_prefix("delta=") {
                    delta = Some(v.to_string());
                }
            }
            denial_call = call.clone();
            // The denial names the dependency AND its caller: `delta` is measured from `mach_driver_get_fd`, so the
            // location is one subtraction away -- which is exactly the derivation that used to be improvised by hand.
            if let (Some(d), Some(syms)) = (delta, args.guest_symbols.as_ref()) {
                if syms.exists() {
                    if let Ok(s) = load_symbols(syms) {
                        if let Some(base) = s
                            .iter()
                            .find(|s| symbol_name(&s.name) == "mach_driver_get_fd")
                        {
                            if let Ok(off) = parse_hex(&d) {
                                if let Some((i, o)) = locate(&s, base.addr + off) {
                                    denial_location =
                                        Some(format!("{} + 0x{:x}", symbol_name(&s[i].name), o));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Verdict {
        mode: args.mode.clone(),
        verdict,
        denied,
        created,
        line,
        denial_call,
        denial_location,
        log,
        rc,
        signal,
    })
}

/// Answer "what can I ask this prefix to do, and what will it print" from the FIXTURE ITSELF.
///
/// The mode names and the marker each mode emits are both already inside the workload binary as literals, so this reads
/// them out instead of keeping a list in the tool that could drift from the binary that runs. That drift is not
/// hypothetical: this session twice searched a source tree for the workload and found nothing, because the fixture is a
/// test asset installed into the prefix and its source lives in the canonical transport repository, not in every tree.
fn list_modes(args: &VerdictArgs) -> Result<ExitCode> {
    let Some(prefix) = args.prefix.as_ref() else {
        bail!("listing modes needs --prefix (the fixture lives inside a prefix)");
    };
    let host = guest_fixture_path(prefix, &args.guest_command, crate::installed_runtime_root().ok());
    if !host.is_file() {
        println!("MODES-FIXTURE absent {}", host.display());
        println!(
            "MODES: the workload fixture is a TEST ASSET; install it into the prefix (it is not part of the runtime install)"
        );
        return Ok(ExitCode::from(1));
    }
    println!("MODES-FIXTURE {}", host.display());
    let bytes = fs::read(&host).with_context(|| format!("reading {}", host.display()))?;
    // Literals of length >= 8 are printable ASCII runs; the workload's own strings are the contract.
    let mut markers: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut cur = String::new();
    for b in bytes.iter().chain(std::iter::once(&0u8)) {
        if (0x20..0x7f).contains(b) {
            cur.push(*b as char);
        } else {
            if cur.len() >= 8 && cur.contains("RING_MACH_TEST") {
                markers.push(cur.clone());
            }
            if (3..=20).contains(&cur.len())
                && cur.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && cur
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                names.push(cur.clone());
            }
            cur.clear();
        }
    }
    markers.sort();
    markers.dedup();
    names.sort();
    names.dedup();
    println!(
        "MODES-MARKERS {} (the line each workload prints; absence of it is the failure)",
        markers.len()
    );
    for m in &markers {
        println!("  {m}");
    }
    println!(
        "MODES-CANDIDATES {} (lowercase literals in the fixture; the mode is the first argument)",
        names.len()
    );
    println!("  {}", names.join(" "));
    println!(
        "MODES-USAGE dwdiag verdict --prefix <p> --mode <name> [--args '<args>'] [--wait <s>] [--repeat <n>]"
    );
    Ok(ExitCode::SUCCESS)
}

fn run_verdict(args: VerdictArgs) -> Result<ExitCode> {
    if args.list_modes {
        return list_modes(&args);
    }
    if args.mode.trim().is_empty() {
        // The tool must SAY what it needs instead of running a workload named "": list the modes it can see from the
        // fixture and stop, because that is the question an empty --mode actually asks.
        println!(
            "MODES: --mode is required; the fixture's own modes follow. Usage: --mode <name> [--args '<args>']"
        );
        let listed = list_modes(&args)?;
        let _ = listed;
        return Ok(ExitCode::from(2));
    }
    if let Some(path) = args.log.as_ref() {
        let text = read_log_lossy(path)
            .with_context(|| format!("reading the run log {}", path.display()))?;
        let (line, verdict, rc) = judge_run_log(&text, &args.mode);
        let denied = text.lines().filter(|l| l.contains("rpc-socket-DENIED")).count() as u64;
        let created = text
            .lines()
            .filter(|l| l.contains("rpc-socket] created") || l.contains("rpc-socket. created"))
            .count() as u64;
        println!("LOG={}", path.display());
        println!(
            "VERDICT mode={} verdict={} denied={} created={} rc={} :: {}",
            args.mode,
            verdict,
            denied,
            created,
            rc.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
            if line.is_empty() { "<no result line>".to_string() } else { line }
        );
        let p = summarize_progress(&text, &text, &args.mode);
        println!(
            "VERDICT-STAGE workload={} last-guest={} last-published-op={} last-served-op={} serviced={}",
            p.workload, p.last_guest, p.last_published_op, p.last_served_op, p.serviced
        );
        return Ok(ExitCode::from(u8::from(verdict != "PASS")));
    }
    let repeat = args.repeat.max(1);
    if repeat > 1 {
        let mut ok = 0usize;
        let mut verdicts: Vec<String> = Vec::with_capacity(repeat as usize);
        for i in 1..=repeat {
            let tag = format!("-r{i}");
            let v = run_one_workload(&args, &tag)?;
            // Stable, machine-readable: callers stop globbing a temp directory (MEASURED: a glob picked the
            // PREVIOUS run's log three times and the wrong process's identity twice).
            println!("LOG={}", v.log.display());
            println!(
                "VERDICT[{i}/{repeat}] mode={} verdict={} denied={} created={} rc={}",
                v.mode,
                v.verdict,
                v.denied,
                v.created,
                v.rc.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
            );
            if v.ok() {
                ok += 1;
            }
            verdicts.push(v.verdict.clone());
            if !v.ok() {
                let text = read_log_lossy(&v.log).unwrap_or_default();
                // Inspect only this run's captured output; diagnostic environment remains explicit.
                let guest = text.clone();
                // A BOOT THAT DIES OF A SIGNAL MUST EXPLAIN ITSELF IN THE SAME OUTPUT. MEASURED: the failing runs
                // printed VERDICT/VERDICT-STAGE and the crash had to be chased with a second command and a hand
                // computation. When the log carries a symbolized fault, print the fault and its caller chain here.
                if text.lines().any(|l| l.contains("[sigexc-fatal") && l.contains("rip=")) {
                    let _ = symbolize_guest_fault(&text, false, None);
                }
                let p = summarize_progress(&text, &guest, &v.mode);
                println!(
                    "VERDICT-STAGE workload={} last-guest={} last-published-op={} last-served-op={} serviced={}",
                    p.workload,
                    if p.last_guest.is_empty() {
                        "<none>"
                    } else {
                        &p.last_guest
                    },
                    if p.last_published_op.is_empty() {
                        "<none>"
                    } else {
                        &p.last_published_op
                    },
                    if p.last_served_op.is_empty() {
                        "<none>"
                    } else {
                        &p.last_served_op
                    },
                    p.serviced
                );
            }
        }
        let mut counts: Vec<(String, usize)> = Vec::new();
        for name in &verdicts {
            match counts.iter_mut().find(|(n, _)| n == name) {
                Some((_, c)) => *c += 1,
                None => counts.push((name.clone(), 1)),
            }
        }
        let dist = counts
            .iter()
            .map(|(n, c)| format!("{n}={c}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "STABILITY mode={} runs={} pass={} stable={} distribution={}",
            args.mode,
            repeat,
            ok,
            if ok == repeat as usize { "yes" } else { "no" },
            dist
        );
        return Ok(if ok == repeat as usize {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        });
    }
    let v = run_one_workload(&args, "")?;
    println!("LOG={}", v.log.display());
    if args.json {
        println!(
            "{{\"mode\":\"{}\",\"verdict\":\"{}\",\"denied\":{},\"created\":{},\"result\":\"{}\",\"denial_call\":{},\"denial_location\":{},\"rc\":{},\"signal\":{},\"log\":\"{}\"}}",
            v.mode,
            v.verdict,
            v.denied,
            v.created,
            jesc(&v.line),
            v.denial_call
                .as_ref()
                .map(|c| format!("\"{c}\""))
                .unwrap_or_else(|| "null".into()),
            v.denial_location
                .as_ref()
                .map(|c| format!("\"{c}\""))
                .unwrap_or_else(|| "null".into()),
            v.rc.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
            v.signal
                .as_ref()
                .map(|c| format!("\"{c}\""))
                .unwrap_or_else(|| "null".into()),
            jesc(&v.log.display().to_string())
        );
    } else {
        let extra = match (&v.denial_call, &v.denial_location) {
            (Some(c), Some(l)) => format!(" first-denial={c} caller={l}"),
            (Some(c), None) => format!(" first-denial={c}"),
            _ => String::new(),
        };
        println!(
            "VERDICT mode={} verdict={} denied={} created={} rc={}{} :: {}",
            v.mode,
            v.verdict,
            v.denied,
            v.created,
            v.rc.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
            extra,
            if v.line.is_empty() {
                "<no result line>"
            } else {
                &v.line
            }
        );
        // perf#30: a DENIAL is a migration signal even when the row passed. MEASURED: `sem_gap 5000 1` passed 3/3
        // while one run reported `denied=1`, and the tool printed the denial's call site only for non-PASS rows --
        // so the one fact needed to remove the remaining datagram dependency was hidden by a green verdict.
        if v.denied > 0 {
            let extra = match (&v.denial_call, &v.denial_location) {
                (Some(c), Some(l)) => format!(" first-denial={c} caller={l}"),
                (Some(c), None) => format!(" first-denial={c}"),
                _ => String::new(),
            };
            println!("DENIAL denied={}{} verdict={}", v.denied, extra, v.verdict);
        }
        // COMPOSED, not repeated: a non-PASS verdict is useless without the stage, and reading it out of two logs by
        // hand is exactly the work this tool exists to remove (doc section 230 -- the stall was found by grepping
        // `[mldr-ctl]` and `process-control-service` by hand, three runs in a row).
        if v.verdict != "PASS" {
            let text = read_log_lossy(&v.log).unwrap_or_default();
            // Inspect only this run's captured output; diagnostic environment remains explicit.
            let guest = text.clone();
            // The SAME self-explanation as the other verdict path: a run that dies of a signal must name the fault and its
            // callers in this output, not only in a second command.
            if text.lines().any(|l| l.contains("[sigexc-fatal") && l.contains("rip=")) {
                let _ = symbolize_guest_fault(&text, false, None);
            }
            let p = summarize_progress(&text, &guest, &v.mode);
            println!(
                "VERDICT-STAGE workload={} last-guest={} last-published-op={} last-served-op={} serviced={}",
                p.workload,
                if p.last_guest.is_empty() {
                    "<none>"
                } else {
                    &p.last_guest
                },
                if p.last_published_op.is_empty() {
                    "<none>"
                } else {
                    &p.last_published_op
                },
                if p.last_served_op.is_empty() {
                    "<none>"
                } else {
                    &p.last_served_op
                },
                p.serviced
            );
        }
    }
    Ok(if v.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

#[derive(Args, Debug)]
pub struct SuiteArgs {
    /// Runtime prefix. Taken from DWDIAG_PREFIX when the flag is absent -- MEASURED FRICTION: `cycle` honoured the
    /// variable but `suite` demanded the flag, so a run started with the prefix exported died on clap's usage error
    /// and looked like a tool failure instead of a missing argument.
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// Base watchdog in seconds; a mode whose arguments name a longer delay gets that added.
    #[arg(long, default_value_t = 60)]
    wait_base: u64,
    #[arg(long, value_parser = parse_kv)]
    env: Vec<(String, String)>,
    /// Fail the run if any row created a per-thread socket.
    #[arg(long)]
    require_zero_creations: bool,
    #[arg(long, default_value = "scripts/darling-boot-run.sh")]
    boot_runner: PathBuf,
    #[arg(long)]
    guest_symbols: Option<PathBuf>,
    #[arg(long)]
    json: bool,
    /// `MODE [ARGS]` chunks separated by `::`.
    #[arg(last = true, required = true)]
    modes: Vec<String>,
    /// Retry a row that did not pass, once, announcing both verdicts. Row-level flake has decided suite verdicts
    /// here (measured), and a retry that is printed is evidence, not silence.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    retry_failed_rows: bool,
    /// Write a new standalone workload-evidence receipt; never mutate installed-image provenance.
    #[arg(long)]
    record_evidence: Option<PathBuf>,
}

fn split_chunks(modes: &[String]) -> Vec<String> {
    let joined = modes.join(" ");
    joined
        .split("::")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn record_workload_evidence(path: &Path, root: &Path, verdict: &str) -> Result<()> {
    use std::io::Write as _;
    let evidence = format!("{{\"schema_version\":1,\"runtime_root\":{},\"runtime_fingerprint\":{},\"runtime_verdict\":{verdict}}}\n",
        jstr(&root.display().to_string()), jstr(&runtime_fingerprint(root)));
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)
        .with_context(|| format!("create workload evidence {}", path.display()))?;
    file.write_all(evidence.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn run_suite(args: SuiteArgs) -> Result<ExitCode> {
    let chunks = split_chunks(&args.modes);
    let mut rows: Vec<Verdict> = Vec::new();
    let mut failures = 0usize;
    for chunk in &chunks {
        let mut it = chunk.split_whitespace();
        let mode = it.next().unwrap_or_default().to_string();
        let margs = it.collect::<Vec<_>>().join(" ");
        let mut extra = 0u64;
        for a in margs.split_whitespace() {
            if let Ok(n) = a.parse::<u64>() {
                if n > 1000 {
                    extra = extra.max(n / 1000);
                }
            }
        }
        let va = VerdictArgs {
            prefix: Some(required_path("--prefix", args.prefix.clone(), "DWDIAG_PREFIX")?),
            mode: mode.clone(),
            args: margs.clone(),
            wait: args.wait_base + extra,
            env: args.env.clone(),
            boot_runner: args.boot_runner.clone(),
    guest_command: "/private/var/tmp/ring_mach_msg_test".to_string(),
            guest_symbols: args.guest_symbols.clone(),
            repeat: 1,
            list_modes: false,
            json: false,
            freeze_on_fail: false,
            log: None,
        };
        let mut v = run_one_workload(&va, "")?;
        if v.verdict.contains("harness or product shutdown") {
            failures += 1;
            println!("ROW-LIFECYCLE-FAIL mode={} log={}; no retry or next prefix-backed row", v.mode, v.log.display());
            rows.push(v);
            break;
        }
        // perf#30: a row that is not PASS is retried ONCE, and both verdicts are printed. MEASURED: two acceptance
        // rows failed in one suite run (`sem_gap 5000 1` HANG, `basic 20` NO-RUN) and then passed 3/3 and 4/4 when
        // run individually -- i.e. the row-level flake, not the workload, decided the suite verdict. The retry is
        // announced, never silent: hiding the first verdict would be the same defect as a verdict that cannot fail.
        if !v.ok() && args.retry_failed_rows {
            let first = v.verdict.clone();
            let v2 = run_one_workload(&va, "-retry")?;
            if !args.json {
                println!(
                    "ROW-RETRY mode={} first={} retry={}",
                    va.mode, first, v2.verdict
                );
            }
            if v2.ok() {
                v = v2;
            } else {
                v = v2;
            }
        }
        if v.verdict.contains("harness or product shutdown") {
            failures += 1;
            rows.push(v);
            break;
        }
        if !v.ok() {
            failures += 1;
        }
        if args.require_zero_creations && v.created != 0 {
            failures += 1;
        }
        // A ROW KILLED BY THE WATCHDOG IS NOT A WORKLOAD FAILURE. MEASURED: the suite's watchdog is the base wait
        // alone, the basic mode needs about 200 s of work, and its first attempt died by SIGTERM at that boundary
        // with no result line -- printed as a plain failed row, which is exactly the confusion this tool exists to
        // remove (only the automatic retry let the suite pass). A signal death with no result line is the harness
        // stopping a run that was still working, so it is named as such and the wait used is shown next to it.
        let watchdog = v.line.is_empty()
            && (v.verdict.contains("watchdog")
                || v.verdict.contains("SIGTERM")
                || v.verdict.contains("SIGKILL"));
        let shown_verdict = if watchdog { "WATCHDOG?".to_string() } else { v.verdict.clone() };
        if !args.json {
            println!(
                "{:<28} {:<9} {:<8} {:<8} {}",
                format!("{} {}", v.mode, margs).trim(),
                shown_verdict,
                v.denied,
                v.created,
                if watchdog {
                    format!("<no result line; killed at the wait boundary with wait={}s -- raise --wait-base>", va.wait)
                } else if v.line.is_empty() {
                    "<no result line>".to_string()
                } else {
                    v.line.clone()
                }
            );
        }
        rows.push(v);
    }
    let pass = failures == 0;
    if let Some(path) = &args.record_evidence {
        let rows_json: Vec<String> = rows
            .iter()
            .map(|v| {
                format!(
                    "{{\"mode\":\"{}\",\"verdict\":\"{}\",\"denied\":{},\"created\":{}}}",
                    jesc(&v.mode), jesc(&v.verdict), v.denied, v.created
                )
            })
            .collect();
        let verdict = format!(
            "{{\"kind\":\"acceptance-suite\",\"verdict\":\"{}\",\"rows\":{},\"failures\":{},\"retry_failed_rows\":{},\"require_zero_creations\":{},\"detail\":[{}]}}",
            if pass { "PASS" } else { "FAIL" },
            rows.len(),
            failures,
            args.retry_failed_rows,
            args.require_zero_creations,
            rows_json.join(",")
        );
        record_workload_evidence(path, crate::installed_runtime_root()?, &verdict)?;
        println!(
            "EVIDENCE-RECORD {} verdict={} rows={} failures={}",
            path.display(),
            if pass { "PASS" } else { "FAIL" },
            rows.len(),
            failures
        );
    }
    if args.json {
        let rows: Vec<String> = rows
            .iter()
            .map(|v| {
                format!(
                    "{{\"mode\":\"{}\",\"verdict\":\"{}\",\"denied\":{},\"created\":{}}}",
                    v.mode, v.verdict, v.denied, v.created
                )
            })
            .collect();
        println!(
            "{{\"rows\":[{}],\"failures\":{},\"require_zero_creations\":{},\"verdict\":\"{}\"}}",
            rows.join(","),
            failures,
            args.require_zero_creations,
            if pass { "PASS" } else { "FAIL" }
        );
    } else {
        println!(
            "SUITE rows={} failures={} require_zero_creations={}",
            rows.len(),
            failures,
            args.require_zero_creations as u8
        );
        println!("SUITE-VERDICT {}", if pass { "PASS" } else { "FAIL" });
    }
    Ok(if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

// ----------------------------------------------------------------------------------------------------------------
// `progress`: WHERE a run stopped. MEASURED need (doc sections 227/230): every stall this cycle cost a manual grep
// over a boot log and a guest loader log, and the answer was always one of a handful of shapes -- the workload's own
// result line is absent, the guest loader's last `[mldr-ctl]` line says which op it published or which stage it
// reached, and the server's last `process-control-service` line says which op it actually serviced. That difference
// (published vs serviced) is the whole diagnosis, so it belongs in the tool and not in a shell pipeline.

#[derive(Args, Debug)]
pub struct ProgressArgs {
    /// The standalone run log the boot harness wrote; managed jobs use --state-dir instead.
    #[arg(long, required_unless_present = "state_dir")]
    log: Option<PathBuf>,
    /// The guest loader diagnostic file (`MLDR_DIAG_LOG`), when the run enabled one.
    #[arg(long)]
    guest_log: Option<PathBuf>,
    /// The prefix this run used, when it must not be read out of the log. The server-identity comparison below is
    /// only meaningful against the prefix the run actually served from.
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// A REGRESSION TRIPWIRE, not a proof: fail (exit 2) when fewer plane publishes were seen than this. MEASURED
    /// need: two broken boots showed `plane-publishes=6` where a healthy boot shows 40+, and noticing that required
    /// remembering the healthy number -- the tool must say it instead of leaving it to the reader.
    #[arg(long, default_value_t = 0)]
    min_plane_publishes: u64,
    /// The workload's mode, used to look for its own machine-readable result line.
    #[arg(long, default_value = "")]
    mode: String,
    #[arg(long)]
    json: bool,
    /// The server's OWN log. MEASURED: the server's stderr never appears in the run log -- it goes to the prefix's
    /// private/var/log/dserver.log -- so several of this session's conclusions were drawn from an absence that meant
    /// "not captured" rather than "not produced". Reading it here makes "the server sent it" and "the guest received
    /// it" two facts in one report instead of a guess.
    /// Server log to search. Otherwise use explicit --prefix, then this run's recorded prefix.
    /// Without either, server evidence is unavailable; ambient/default prefixes are never read.
    #[arg(long)]
    server_log: Option<PathBuf>,
    /// Select finalized managed-job evidence and its persisted identity; never read mutable prefix history.
    #[arg(long, conflicts_with_all = ["log", "guest_log", "server_log"])]
    state_dir: Option<PathBuf>,
}

#[derive(Debug, Default)]
pub struct Progress {
    pub workload: String,
    pub result: String,
    pub last_guest: String,
    pub last_published_op: String,
    pub last_served_op: String,
    pub serviced: u64,
    pub denied: u64,
    pub created: u64,
    pub first_denial_call: String,
}

fn scalar(prefix: &str) -> Option<String> {
    // "op=5 pid=917234" -> the value of `op`, for any whitespace-separated KEY=VALUE in an unstructured line.
    // A bare key with no `=` (`after-seed`) is returned as-is, because that IS the stage name.
    if !prefix.contains('=') {
        return Some(prefix.to_string());
    }
    prefix.split_once('=').map(|(_, v)| v.to_string())
}

/// The workload's OWN result line for a mode: the matching line that carries `pass=`, else the LAST matching line.
/// MEASURED: the fsview diagnostic prints an informational header and a result line that both carry the mode
/// prefix. The verdict rule read the header and reported FAIL for a run whose workload printed pass=1 and exited
/// 0, and the progress summary printed the header as PROGRESS-RESULT. One selection rule, used by both.
fn workload_result_line<'a>(text: &'a str, mode: &str) -> Option<&'a str> {
    let prefix = if mode.is_empty() {
        "RING_MACH_TEST mode=".to_string()
    } else {
        format!("RING_MACH_TEST mode={mode} ")
    };
    let matches: Vec<&str> = text.lines().filter(|l| l.contains(&prefix)).collect();
    matches
        .iter()
        .rev()
        .find(|l| l.contains("pass="))
        .or_else(|| matches.last())
        .copied()
}

fn summarize_progress(run: &str, guest: &str, mode: &str) -> Progress {
    let mut p = Progress::default();
    if let Some(l) = workload_result_line(run, mode) {
        p.workload = "present".to_string();
        p.result = l.trim().to_string();
    } else if run.contains("RING_MACH_TEST mode=") {
        p.workload = "other-mode".to_string();
    } else {
        p.workload = "absent".to_string();
    }
    p.denied = run
        .lines()
        .filter(|l| l.contains("rpc-socket-DENIED"))
        .count() as u64;
    p.created = run
        .lines()
        .filter(|l| l.contains("rpc-socket] created") || l.contains("rpc-socket. created"))
        .count() as u64;
    if let Some(dl) = run.lines().find(|l| l.contains("rpc-socket-DENIED")) {
        for f in dl.split_whitespace() {
            if let Some(v) = f.strip_prefix("call=") {
                p.first_denial_call = v.to_string();
            }
        }
    }
    // The server side: last serviced op, and the count. `process-control-service ... op=N ...` is the line that proves
    // the server DID see and answer the request the guest may still be waiting on.
    for l in run
        .lines()
        .filter(|l| l.contains("process-control-service"))
    {
        p.serviced += 1;
        for f in l.split_whitespace() {
            if let Some(v) = f.strip_prefix("op=") {
                p.last_served_op = v.to_string();
            }
        }
    }
    // The guest side: the LAST `[mldr-ctl]` line that says what is being waited for. MEASURED DEFECT, fixed here: the
    // first version tested `head == "seq"` against a line whose first token is `seq=7`, so the stage rule could never
    // fire and the tool reported a `planeloop BEGIN` from early in the boot as the "last" line -- an instrument that
    // silently does nothing is indistinguishable from no instrument, which is the class this project keeps recording.
    // Lines are therefore classified by the key BEFORE `=`, and a priority decides which one survives: a stage line
    // beats a spin, and a timeout beats everything (it is the current, terminal state).
    let mut best: (u8, String) = (0, String::new());
    for l in guest.lines().filter(|l| l.contains("[mldr-ctl]")) {
        let rest = l.split("[mldr-ctl]").nth(1).unwrap_or("").trim();
        let head = rest.split_whitespace().next().unwrap_or("");
        let kind = head.split('=').next().unwrap_or("");
        let mut pid = String::new();
        for w in rest.split_whitespace() {
            if let Some(v) = w.strip_prefix("pid=") {
                pid = v.to_string();
            }
        }
        let (prio, rendered) = match kind {
            "request" => {
                let mut op = String::new();
                for w in rest.split_whitespace() {
                    if let Some(v) = w.strip_prefix("op=") {
                        op = v.to_string();
                    }
                }
                p.last_published_op = op.clone();
                (1u8, format!("published op={op} pid={pid}"))
            }
            "planeloop" => {
                let mut op = String::new();
                let mut mine = String::new();
                for w in rest.split_whitespace() {
                    if let Some(v) = w.strip_prefix("op=") {
                        op = v.to_string();
                    } else if let Some(v) = w.strip_prefix("mine=") {
                        mine = v.to_string();
                    }
                }
                (2, format!("waiting op={op} mine={mine} pid={pid}"))
            }
            "iter" => (
                0,
                format!(
                    "spin {}",
                    rest.split_whitespace()
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            ),
            "plane-request" if rest.contains("TIMEOUT") => (9, format!("TIMEOUT {}", rest)),
            "seq" => {
                // `seq=N after-<stage> pid=... image=...` -- the bootstrap stage names, which is what a stall is read
                // against when the workload never speaks.
                let stage = rest
                    .split_whitespace()
                    .find(|w| w.starts_with("after-") || w.starts_with("before-"));
                match stage {
                    Some(st) => (5, format!("{st} pid={pid}")),
                    None => (1, format!("seq {}", rest)),
                }
            }
            _ => (0, rest.to_string()),
        };
        if prio >= best.0 {
            best = (prio, rendered);
        }
    }
    // FALLBACK TO THE REAL MARKER FAMILY. The classifier above only reads `[mldr-ctl]` lines, but the loader and the
    // kernel emit bracketed marks of other families -- [fd-courier-conn], [plane-doorbell], [dring-adopt], [open-*],
    // [pc-*], [drop-op-*], [rmmt]. MEASURED: a run with 1418 lines of real guest activity printed last-guest=<none>,
    // because none of that activity is `[mldr-ctl]`; the stage then had to be found by hand. When the structured rule
    // finds nothing, name the LAST bracketed line instead of nothing: an unnamed stall is indistinguishable from an
    // absent guest.
    if best.1.is_empty() {
        if let Some(l) = guest
            .lines()
            .rev()
            .find(|l| l.trim_start().starts_with('[') && l.contains(']'))
        {
            let mut s = l.trim().to_string();
            s.truncate(96);
            best = (1, s);
        }
    }
    p.last_guest = best.1;
    let _ = scalar("");
    p
}

#[derive(clap::Args, Debug)]
pub struct WitnessArgs {
    /// The run log to census. Defaults to the newest `dwdiag` verdict log in the temp directory.
    #[arg(long)]
    log: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Subcommand, Debug)]
pub enum CoresAction {
    /// Report whether a crash would leave anything readable: the size limit, the pattern, and the directory.
    Status,
    /// Point core_pattern at a FILE under --dir, remembering the previous value so `off` can restore it.
    On,
    /// Restore the previous core_pattern.
    Off,
}

#[derive(clap::Args, Debug)]
pub struct CoresArgs {
    #[command(subcommand)]
    action: CoresAction,
    /// Directory cores are written into (created if missing). Global so it is accepted after the action, which is
    /// where a user types it.
    #[arg(long, global = true, default_value = "/tmp/t4cores")]
    dir: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct CoreArgs {
    /// The core file to read. Without it, the newest `core.*` under --dir is used.
    #[arg(long)]
    core: Option<PathBuf>,
    /// Directory holding cores when --core is not given.
    #[arg(long, default_value = "/tmp/t4cores")]
    dir: PathBuf,
    /// Prefix whose images resolve the faulting address. Defaults to DWDIAG_PREFIX.
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// The guest log whose `[sigexc-fatal ...]` marks name the signal and the FAULTING THREAD as the guest saw them.
    /// A core says which thread the KERNEL dumped from; the log says which thread the GUEST faulted in, and this
    /// command compares the two out loud instead of assuming they agree.
    #[arg(long)]
    log: Option<PathBuf>,
    /// Also print gdb's own view of the core, verbatim, under a CORE-TRACES-GDB label. It is usually useless on a
    /// guest core (no symbols or unwind information for the guest's images), and seeing that is the point.
    #[arg(long)]
    traces: bool,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct LoopsArgs {
    /// The run log to read. Defaults to the newest `dwdiag` verdict log in the temp directory.
    #[arg(long)]
    log: Option<PathBuf>,
    /// Also read this guest manifest log. Both are censused together, because the spinning markers and the
    /// run's own progress lines live in different files.
    #[arg(long)]
    guest_log: Option<PathBuf>,
    /// A pattern must repeat at least this many times to be reported.
    #[arg(long, default_value_t = 8)]
    min: usize,
    /// A pattern is "at the tail" when its LAST occurrence is inside the final fraction of the file.
    #[arg(long, default_value_t = 0.25)]
    tail_frac: f64,
    /// How many lines at the end of the log are examined for repetition and variety. Low variety is a spin
    /// finding only when a reported repeating pattern and repeated tail lines are both present.
    #[arg(long, default_value_t = 30)]
    tail_len: usize,
    /// A repeating tail is called a SPIN when it holds at most this many DISTINCT lines. The default is measured:
    /// the spinning log ended with 6 distinct lines in its last 30, while the exited process's tail had 14.
    #[arg(long, default_value_t = 8)]
    spin_max_distinct: usize,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct TrapArgs {
    /// Kernel log to read. Defaults to `dmesg` (through `sudo -n` when passwordless), falling back to
    /// `journalctl -k`, because that is where a guest that dies of a host-delivered signal is reported.
    #[arg(long)]
    kernel_log: Option<PathBuf>,
    /// Prefix whose images resolve the reported address. Defaults to DWDIAG_PREFIX.
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// Only report traps whose process name contains this.
    #[arg(long)]
    process: Option<String>,
    /// How many of the newest traps to report.
    #[arg(long, default_value_t = 10)]
    limit: usize,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct WaitsArgs {
    /// The run log to read. Defaults to the newest `dwdiag` verdict log in the temp directory.
    #[arg(long)]
    log: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct CoreLockArgs {
    /// The core file to read. Without it, the newest `core.*` under --dir is used.
    #[arg(long)]
    core: Option<PathBuf>,
    /// Directory holding cores when --core is not given.
    #[arg(long, default_value = "/tmp/t4cores")]
    dir: PathBuf,
    /// Skip the per-thread self-token census (which needs one reader per thread).
    #[arg(long)]
    no_tokens: bool,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct FutexArgs {
    /// The capture bundle to read; `dwdiag run`/`capture` prints it as `BUNDLE=<dir>`. Both the workload's tree
    /// (`capture-tree`) and the daemonized server's tree (`guarded-tree`) are read, because the two halves of a
    /// shared futex normally live in different processes.
    #[arg(long)]
    bundle: PathBuf,
    /// An out-of-band futex trace recorded during the SAME run as the bundle, one event per line:
    ///
    ///   WAIT pid=<n> tid=<n> uaddr=<hex> ts_ns=<n>
    ///   WAKE pid=<n> tid=<n> uaddr=<hex> woke=<n> ts_ns=<n>
    ///
    /// It is required for the wake half, and no snapshot can replace it: a syscall snapshot is a MOMENT, so it says
    /// who is waiting now and never who woke whom. The trace is REFUSED when a pid is not one the bundle captured or
    /// when an event falls outside the bundle's run window, because a trace from another run reads exactly like this
    /// one and would silently answer a question about a run it never saw.
    #[arg(long)]
    futex_trace: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct RingArgs {
    /// A run log, or the dump itself: the `dtape.ering …` lines are selected from it, wherever they appear.
    #[arg(long)]
    log: PathBuf,
    #[arg(long)]
    json: bool,
}

// THE REGISTRY. One entry per instrument this project ships, with the line it writes and why it exists. Adding an
// instrument without adding it here stops the census from being a census, so the list is the point of the command:
// `witness` answers "which of these spoke", and names the ones that did not.
const INSTRUMENTS: &[(&str, &str, &str)] = &[
    (
        "ulock-wait-park",
        r"^\[ulock-wait-park\] ",
        "server: the moment a thread is QUEUED on a ulock -- object address, operation, owner_tid and waiter_tid, so a stall has a named object instead of a last log line",
    ),
    (
        "ulock-wait-cleanup",
        r"^\[ulock-wait-cleanup\] ",
        "server: an ABORTED wait -- the waiter left the queue without being woken; a cleanup with no matching wake is how a requeue shows up",
    ),
    (
        "ulock-wake-entry",
        r"^\[ulock-wake-entry\] ",
        "server: a wake REQUEST that reached an object with waiters -- the only point that separates 'nobody asked to wake it' from 'asked and found nobody'",
    ),
    (
        "ulock-wake",
        r"^\[ulock-wake\] ",
        "server: a wake that RAN, with how many waiters it moved (woke=0 means it ran and nothing moved)",
    ),
    (
        "ulock-wake-nobody",
        r"^\[ulock-wake-nobody\] ",
        "server: a wake that found NO waiters at all",
    ),
    (
        "ulock-wake-enoent",
        r"^\[ulock-wake-enoent\] ",
        "server: a wake for an object the server never saw -- the wake and the wait disagree about identity",
    ),
    (
        "ulock-wake-late",
        r"^\[ulock-wake-late\] ",
        "server: a wake that arrived after the owner had already changed -- the handoff race, visible as a value instead of inferred",
    ),
    (
        "dthread-mask",
        r"^\[dthread-mask ",
        "loader: the kernel signal mask of a NEWLY created guest thread -- a header that inherits a blocked SIGSEGV makes the fault undeliverable there",
    ),
    (
        "sigexc-deliver",
        r"^\[sigexc-deliver ",
        "guest: the FINAL dispatch of a delivered signal -- the point every delivery path reaches, unlike a probe in the function prologue",
    ),
    (
        "fault",
        r"^\[fault sig=11 ",
        "guest: the FAULT ITSELF -- si_addr (the address that faulted) and gregs.rip (where execution was), printed inside the handler the host disposition points at",
    ),
    (
        "segvdisp",
        r"^\[segvdisp ",
        "guest: the HOST disposition of SIGSEGV read with a raw rt_sigaction query next to the point where the workload stops",
    ),
    (
        "wait4",
        r"^\[wait4 ",
        "guest: the pid the host reaped and its RAW host status -- a signaled child is signum|0x80, and the pid names the dying process",
    ),
    (
        "guest-handler",
        r"^\[guest-handler ",
        "guest: the kernel ENTERED the wrapper that runs the guest's own handler -- for a fatal SIGSEGV this fires when the fault reached the guest",
    ),
    (
        "sigsegv-mask",
        r"^\[sigsegv-mask ",
        "guest: mask transitions carrying Darwin's SIGSEGV bit -- a block with no matching unblock means the forced default action",
    ),
    (
        "sigexc-setup",
        r"^\[sigexc-setup ",
        "guest: the ONE place that installs Darling's delivery handler for every signal -- did it run for this process",
    ),
    (
        "setrestart",
        r"^\[setrestart ",
        "guest: the install of Darling's delivery handler for a guest-requested signal -- ret is the kernel's answer",
    ),
    (
        "sigact",
        r"^\[sigact ",
        "guest: every transition of SIGSEGV's disposition on the HOST (req=0 is SIG_DFL, req=1 is SIG_IGN) -- names who removed the handler",
    ),
    (
        "native-exit",
        r"^\[native-exit ",
        "guest: the boundary where the guest hands ITS OWN exit status to the host -- a 139 here would mean the guest decided it",
    ),
    (
        "sem-site",
        r"^SEM-SITE ",
        "guest: who calls the semaphore family, with which name/address, and from which thread",
    ),
    (
        "iter-marks",
        r"^ITER [0-9]+ ",
        "guest workload: per-iteration progress, names the iteration that stopped",
    ),
    (
        "stall-dump",
        r"stall-dump idle_ms=",
        "server: parked threads, their calls, and their wait-timer state",
    ),
    (
        "ring-dump",
        r"dtape\.ering (dump|seq=)",
        "server: the in-memory event ring dumped when the counters stop",
    ),
    (
        "plane-refuse",
        r"plane-refuse",
        "server: a plane request refused at the op that refused it",
    ),
    (
        "dtape-msgq",
        r"dtape\.msgq event=",
        "server: msgq park/send/post/wake order",
    ),
    (
        "dtape-timer",
        r"dtape\.wait_timer event=",
        "server: wait-timer prepare/expire/unblock",
    ),
    (
        "rpc-begin",
        r"rpc\.[a-z_0-9]+\.begin",
        "server: an RPC request the server began",
    ),
    (
        "rpc-reply",
        r"rpc\.[a-z_0-9]+\.reply",
        "server: an RPC reply the server enqueued (begin without reply is a stall)",
    ),
    (
        "crash",
        r"dserver-CRASH",
        "server: the crash probe, with its fault address and stack walk",
    ),
    (
        "workload-stall",
        r"RING_MACH_TEST_STALL",
        "guest workload: its own watchdog fired",
    ),
    (
        "execpath-after",
        r"after-execpath",
        "server: the post-exec completion-store barrier",
    ),
    // Added 2026-09-27 with the per-thread-socket removal and the diagnostics that closed the silent-death
    // investigation. Each one is an instrument that was added to the tree and therefore has to be counted here, or
    // `witness` reports a live instrument as silent (the failure this registry exists to prevent).
    (
        "sigexc",
        r"\[sigexc-(fatal|default) sig=",
        "guest: the fault translator reporting a fatal/returned raw signal",
    ),
    (
        "plane-slow",
        r"\[plane-slow op=",
        "guest: a process-control request the server did not complete in time",
    ),
    (
        "modrefs",
        r"\[modrefs-(entry|exit) ",
        "guest: the mach_port_mod_refs trap around its impl and its exit code",
    ),
    (
        "allocprobe",
        r"\[allocprobe\]",
        "guest: an allocation-path probe taken while a lock-free path was suspected",
    ),
    (
        "ring-trace-gen",
        r"RING_TRACE gen (ENTER|EXIT) callnum=",
        "guest: the generated-call trampoline's enter/exit pair",
    ),
    (
        "iter-drop",
        r"ITER [0-9]+ tid=[0-9]+ drop_",
        "guest workload: which drop path an iteration took",
    ),
    (
        "rpc-socket-denied",
        r"\[rpc-socket-DENIED\] ",
        "guest: a caller that has no lane and no plane op, and the call it is (the removal's own instrument)",
    ),
    (
        "checkout-path",
        r"\[checkout-path\] ",
        "guest: a thread-exit checkout that could not be published, with the state that prevented it",
    ),
    (
        "checkin-path",
        r"\[checkin-path\] ",
        "guest: a checkin that could not be published, with the state that prevented it",
    ),
    (
        "release-drops-pending",
        r"\[release-drops-pending\] site=",
        "guest/server: a completed request whose slot was released while still pending, by site",
    ),
    (
        "plane-reclaim",
        r"\[plane-reclaim\] ",
        "guest: a PENDING slot older than the publisher's generation was taken back -- the case-G path, whose absence in a clean run is the expected reading",
    ),
    (
        "plane-claim-iter",
        r"\[plane-claim-iter ",
        "guest: the rotation of the plane slot, behind the plane-steps switch -- silent unless DARLING_GUEST_PLANE_STEPS is on",
    ),
    (
        "completion-discarded",
        r"process-control-stale-completion",
        "server: a completion dropped because the slot no longer carries the sequence it answers -- the server half of case G",
    ),
];

/// Count each registered instrument's lines in `text`, and keep one sample per instrument for the human to read.
pub fn witness_census(text: &str) -> Vec<(String, u64, String)> {
    INSTRUMENTS
        .iter()
        .map(|(name, pat, _why)| {
            let re = Regex::new(pat).expect("instrument pattern is a literal of this file");
            let mut count = 0u64;
            let mut sample = String::new();
            for line in text.lines() {
                if re.is_match(line) {
                    count += 1;
                    if sample.is_empty() {
                        let mut t: String = line.chars().take(140).collect();
                        if line.chars().count() > 140 {
                            t.push('…');
                        }
                        sample = t;
                    }
                }
            }
            ((*name).to_string(), count, sample)
        })
        .collect()
}

fn newest_verdict_log() -> Option<PathBuf> {
    let dir = std::env::temp_dir();
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(&dir).ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("dwdiag-verdict-") || !name.ends_with(".log") {
            continue;
        }
        let Ok(md) = entry.metadata() else { continue };
        let Ok(mtime) = md.modified() else { continue };
        if best.as_ref().map(|(t, _)| mtime > *t).unwrap_or(true) {
            best = Some((mtime, entry.path()));
        }
    }
    best.map(|(_, p)| p)
}

fn wfield<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("{key}=");
    let pos = line.find(&pat)? + pat.len();
    let rest = &line[pos..];
    let end = rest
        .find(|c: char| c == ' ' || c == '\n' || c == '\t')
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn wnum(line: &str, key: &str) -> Option<u64> {
    let v = wfield(line, key)?;
    if let Some(hex) = v.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        v.parse::<u64>().ok()
    }
}

#[derive(Default, Debug)]
struct WaitObject {
    op: u64,
    owner: u64,
    parks: usize,
    cleanups: usize,
    waiters: Vec<u64>,
    wake_entry: usize,
    wake: usize,
    woke: u64,
    wake_nobody: usize,
    wake_enoent: usize,
    wake_late: usize,
}

fn op_name(op: u64) -> &'static str {
    match op & 0xff {
        1 => "UL_COMPARE_AND_WAIT",
        2 => "UL_UNFAIR_LOCK",
        3 => "UL_COMPARE_AND_WAIT_SHARED",
        5 => "UL_UNFAIR_LOCK64_SHARED",
        _ => "UL_OTHER",
    }
}

// WHY THIS IS A COMMAND AND NOT A GREP. The server already emits the whole wait/wake
// vocabulary for ulocks -- wait-park (who waits, who owns), wait-cleanup, wake-entry,
// wake, wake-nobody, wake-enoent, wake-late -- and nothing consumed it as a whole, so every
// investigation rebuilt this table by hand under time pressure. It answers the one question a
// stall turns on: for each object, was a wake ever issued for it at all, and if it was, did the
// server have anybody to wake? A "waiters exist and no wake was ever issued" object is a
// different defect from "wake issued and nobody found", and only this join tells them apart.
/// Whether the process a park line describes is still there, matched by the THREAD IDS the record
/// carries rather than by the pid alone.
///
/// A pid can be reused, and the contract fixture proved the bare pid is not enough: its pid 100 IS a
/// live process on this host, so `/proc/100` existed and a park logged by something else was
/// reported as present. The ids in these records are host ids, so requiring one of them to still be
/// a thread of that pid is the check that means "this is the same process".
fn proc_matches(pid: u64, tids: &[u64]) -> bool {
    if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
        return false;
    }
    if tids.is_empty() {
        return true;
    }
    tids.iter()
        .any(|t| std::path::Path::new(&format!("/proc/{pid}/task/{t}")).exists())
}

fn run_waits(args: WaitsArgs) -> Result<ExitCode> {
    let log = match args.log {
        Some(p) => p,
        None => newest_verdict_log()
            .context("no `dwdiag-verdict-*.log` in the temp directory; pass --log")?,
    };
    let text = read_log_lossy(&log).with_context(|| format!("reading {}", log.display()))?;

    let mut objs: BTreeMap<(u64, u64), WaitObject> = BTreeMap::new();
    let mut lines_seen = 0usize;

    for line in text.lines() {
        if !line.contains("[ulock-") {
            continue;
        }
        let pid = match wnum(line, "pid") {
            Some(p) => p,
            None => continue,
        };
        let addr = match wnum(line, "addr") {
            Some(a) => a,
            None => continue,
        };
        lines_seen += 1;
        let e = objs.entry((pid, addr)).or_default();
        if line.contains("[ulock-wait-park]") {
            e.op = wnum(line, "op").unwrap_or(e.op);
            e.parks += 1;
            if let Some(o) = wnum(line, "owner_tid") {
                if o != 0 {
                    e.owner = o;
                }
            }
            if let Some(w) = wnum(line, "waiter_tid") {
                if !e.waiters.contains(&w) {
                    e.waiters.push(w);
                }
            }
        } else if line.contains("[ulock-wait-cleanup]") {
            e.cleanups += 1;
            if let Some(w) = wnum(line, "waiter_tid") {
                e.waiters.retain(|x| *x != w);
            }
        } else if line.contains("[ulock-wake-entry]") {
            e.wake_entry += 1;
        } else if line.contains("[ulock-wake]") {
            e.wake += 1;
            e.woke += wnum(line, "woke").unwrap_or(0);
        } else if line.contains("[ulock-wake-nobody]") {
            e.wake_nobody += 1;
        } else if line.contains("[ulock-wake-enoent]") {
            e.wake_enoent += 1;
        } else if line.contains("[ulock-wake-late]") {
            e.wake_late += 1;
        }
    }

    let verdict_of = |e: &WaitObject| -> &'static str {
        if e.parks == 0 {
            return "NO-WAITERS";
        }
        if e.waked_any() {
            return if e.woke > 0 { "WOKEN" } else { "WAKE-NO-EFFECT" };
        }
        if e.wake_nobody > 0 || e.wake_enoent > 0 || e.wake_late > 0 {
            return "WAKE-MISSED-THE-WAITER";
        }
        "NEVER-WOKEN"
    };

    if args.json {
        let mut out = String::from("{\"log\":\"");
        out.push_str(&jesc(&log.display().to_string()));
        out.push_str("\",\"objects\":[");
        for (i, (k, e)) in objs.iter().enumerate() {
            let (pid, addr) = *k;
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"pid\":{},\"addr\":\"{:#x}\",\"op\":\"{}\",\"owner_tid\":{},\"waiters\":[{}],\"parks\":{},\"cleanups\":{},\"wake_entry\":{},\"wake\":{},\"woke\":{},\"wake_nobody\":{},\"wake_enoent\":{},\"wake_late\":{},\"verdict\":\"{}\"}}",
                pid, addr, op_name(e.op), e.owner,
                e.waiters.iter().map(|w| w.to_string()).collect::<Vec<_>>().join(","),
                e.parks, e.cleanups, e.wake_entry, e.wake, e.woke, e.wake_nobody, e.wake_enoent,
                e.wake_late, verdict_of(e)
            ));
        }
        out.push_str("]}");
        println!("{out}");
        return Ok(ExitCode::SUCCESS);
    }

    crate::say(&format!("WAITS log={} objects={}", log.display(), objs.len()));
    for (k, e) in &objs {
        let (pid, addr) = *k;
        crate::say(&format!(
            "OBJECT pid={} addr={:#x} op={} owner_tid={} waiters=[{}] parks={} cleanups={} wake_entry={} wake={} woke={} wake_nobody={} wake_enoent={} wake_late={} verdict={}",
            pid, addr, op_name(e.op), e.owner,
            e.waiters.iter().map(|w| w.to_string()).collect::<Vec<_>>().join(","),
            e.parks, e.cleanups, e.wake_entry, e.wake, e.woke, e.wake_nobody, e.wake_enoent,
            e.wake_late, verdict_of(e)
        ));
    }

    let stalling: Vec<_> = objs
        .iter()
        .filter(|(_, e)| {
            // "nobody asked to wake it" is a DIFFERENT defect from "a wake was issued and the
            // server found nobody", so an object in the second class is never reported here.
            e.parks > 0
                && !e.waiters.is_empty()
                && !e.waked_any()
                && e.wake_nobody == 0
                && e.wake_enoent == 0
                && e.wake_late == 0
        })
        .collect();
    let still_there = |e: &WaitObject, pid: u64| -> bool {
        let mut tids: Vec<u64> = e.waiters.clone();
        if e.owner != 0 { tids.push(e.owner); }
        proc_matches(pid, &tids)
    };
    for (k, e) in &stalling {
        let (pid, addr) = **k;
        crate::say(&format!(
            "WAITS-STALL pid={} addr={:#x} op={} owner_tid={} waiters=[{}] reason=no-wake-was-ever-issued-for-this-object proc={}",
            pid, addr, op_name(e.op), e.owner,
            e.waiters.iter().map(|w| w.to_string()).collect::<Vec<_>>().join(","),
            if still_there(e, pid) { "present" } else { "absent" }
        ));
    }
    // A stall line reads the LOG, so it describes a park that HAPPENED. Measured: a run where the
    // linker died instead of stalling still printed WAITS-STALL, because the park was logged before
    // it died. Saying whether that process is still there is the difference between a lock problem
    // to fix and history, and getting it wrong sends the next investigation at a dead process.
    let absent = stalling.iter().filter(|(k, e)| !still_there(e, k.0)).count();
    if !stalling.is_empty() && absent == stalling.len() {
        crate::say(&format!(
            "WAITS-NOTE all {} stalling object(s) belong to processes that are gone from /proc; those parks were logged when they happened -- history, not a current stall",
            stalling.len()
        ));
    }

    // A cycle is a waiter that holds the object another waiter is blocked on. Reported only when
    // both directions are present in the same object set, so a one-sided wait is never called one.
    for (k, o) in &objs {
        let (pid, addr) = *k;
        if o.owner == 0 || o.waiters.is_empty() {
            continue;
        }
        let owner_waits_on = objs
            .iter()
            .find(|(_, v)| v.waiters.contains(&o.owner))
            .map(|(k, _)| *k);
        if let Some((pid2, addr2)) = owner_waits_on {
            if let Some(o2) = objs.get(&(pid2, addr2)) {
                if o2.owner != 0
                    && o2.owner != o.owner
                    && o.waiters.contains(&o2.owner)
                    && o2.waiters.contains(&o.owner)
                {
                    crate::say(&format!(
                        "WAITS-CYCLE pid={} addr={:#x} owner={} <-> pid={} addr={:#x} owner={} each waits on the object the other holds",
                        pid, addr, o.owner, pid2, addr2, o2.owner
                    ));
                }
            }
        }
    }

    crate::say(&format!(
        "WAITS-VERDICT objects={} ulock_lines={} stalling={}",
        objs.len(),
        lines_seen,
        stalling.len()
    ));
    Ok(ExitCode::SUCCESS)
}

impl WaitObject {
    fn waked_any(&self) -> bool {
        self.wake_entry > 0 || self.wake > 0 || self.woke > 0
    }
}


// WHY THIS EXISTS. Host gdb cannot walk a Darwin-ABI guest frame: attached to a stopped guest
// it resolves only the loader's syscall trampoline, and a hand recovery from `/proc/<tid>/maps`
// reads the wrong region twice over ([stack] names only the main thread; startstack is zero for
// non-leaders). MEASURED, three times, before this was written. What does work is starting from
// the debugger's own per-thread rsp and reading the words above it: the return addresses live
// there, and the ones that fall inside the guest's own images can be symbolized directly. This
// turns "the ld is stuck" into "the ld is stuck in <function>", which is the fact the T4 stall
// has been missing.
#[derive(clap::Args, Debug)]
pub struct UnwindArgs {
    /// Host pid of the stopped guest process to unwind.
    #[arg(long)]
    pid: u32,
    /// Only keep addresses inside images whose path contains this substring. Default: every
    /// image that is not a host library (libc/ld.so/libpthread/...).
    #[arg(long)]
    image: Option<String>,
    /// How many bytes above each thread's rsp to scan.
    #[arg(long, default_value_t = 524288)]
    window: usize,
    /// Stop after this many distinct addresses per thread.
    #[arg(long, default_value_t = 12)]
    max: usize,
    /// Catch a fatal signal instead of unwinding a stopped process: attach, arm `handle SIGx stop
    /// print nopass`, resume the target (SIGCONT, for a target held by MLDR_STOP_AT_START) and
    /// report the signal, the registers and the stacks when it arrives. This is the only way to see
    /// the trap half of a failure whose victim lives a few hundred milliseconds.
    #[arg(long, value_name = "SIGNAL")]
    catch: Option<String>,
    /// Seconds to wait for the caught signal before giving up.
    #[arg(long, default_value_t = 180)]
    catch_timeout: u64,
    /// Scan stack words instead of following frame pointers, including callers built without them.
    /// Reported addresses are candidates, not a backtrace.
    #[arg(long)]
    scan: bool,
    #[arg(long)]
    json: bool,
}

fn sudo_prefix() -> Vec<&'static str> {
    // `sudo -n` where it is available and passwordless, otherwise nothing: the caller may already
    // be root, and a read that fails must say why rather than silently return no frames.
    let ok = Command::new("sudo")
        .args(["-n", "true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok { vec!["sudo", "-n"] } else { vec![] }
}

fn unwind_registers(pid: u32, sudo: &[&str]) -> Result<Vec<(u64, u64, u64, u64)>> {
    let mut cmd = Command::new(sudo.first().copied().unwrap_or("gdb"));
    if !sudo.is_empty() {
        cmd.arg(sudo[1]).arg("timeout").arg("90").arg("gdb");
    }
    let out = cmd
        .arg("-p").arg(pid.to_string())
        .args(["-batch", "-ex", "set pagination off", "-ex", "thread apply all info registers rsp rip rbp"])
        .output()
        .context("running gdb")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    let mut cur: Option<u64> = None;
    let (mut rsp, mut rip, mut rbp) = (0u64, 0u64, 0u64);
    let mut have_rsp = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Thread ") {
            if let (Some(t), true) = (cur, have_rsp) {
                rows.push((t, rsp, rip, rbp));
            }
            have_rsp = false;
            rsp = 0; rip = 0; rbp = 0;
            // "Thread 3 (Thread 0x.. (LWP 1234) ..."
            cur = rest
                .split("LWP ")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|s| s.parse::<u64>().ok());
            continue;
        }
        let t = line.trim();
        if let Some(v) = t.strip_prefix("rsp") {
            if let Some(hex) = v.split_whitespace().next().and_then(|h| h.strip_prefix("0x")) {
                if let Ok(x) = u64::from_str_radix(hex, 16) { rsp = x; have_rsp = true; }
            }
        } else if let Some(v) = t.strip_prefix("rip") {
            if let Some(hex) = v.split_whitespace().next().and_then(|h| h.strip_prefix("0x")) {
                if let Ok(x) = u64::from_str_radix(hex, 16) { rip = x; }
            }
        } else if let Some(v) = t.strip_prefix("rbp") {
            if let Some(hex) = v.split_whitespace().next().and_then(|h| h.strip_prefix("0x")) {
                if let Ok(x) = u64::from_str_radix(hex, 16) { rbp = x; }
            }
        }
    }
    if let (Some(t), true) = (cur, have_rsp) { rows.push((t, rsp, rip, rbp)); }
    if rows.is_empty() {
        // Say WHAT gdb said. A bare "no registers" cannot distinguish a dead process, a refused
        // attach and a gdb command that asked a question in batch mode, and those need different
        // actions.
        let err = String::from_utf8_lossy(&out.stderr);
        let so = String::from_utf8_lossy(&out.stdout);
        let show = |t: &str| -> String {
            let t = t.trim();
            let mut s = t.chars().take(600).collect::<String>();
            if t.len() > 600 { s.push_str(" ...[truncated]"); }
            s
        };
        bail!(
            "gdb reported no per-thread registers for pid {pid} (exit={:?})\n--- gdb stderr ---\n{}\n--- gdb stdout ---\n{}",
            out.status.code(),
            show(&err),
            show(&so)
        );
    }
    Ok(rows)
}

fn unwind_maps(pid: u32) -> Result<Vec<(u64, u64, bool, u64, String)>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("reading /proc/{pid}/maps"))?;
    Ok(parse_maps_text(&text))
}

fn parse_maps_text(text: &str) -> Vec<(u64, u64, bool, u64, String)> {
    let mut v = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(perm), Some(off)) = (it.next(), it.next(), it.next()) else { continue };
        let (Some(a), Some(b)) = (range.split('-').next(), range.split('-').nth(1)) else { continue };
        let (Ok(lo), Ok(hi), Ok(foff)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16),
                                          u64::from_str_radix(off, 16)) else { continue };
        let path = line.splitn(6, ' ').nth(5).unwrap_or("").trim().to_string();
        v.push((lo, hi, perm.contains('x'), foff, path));
    }
    v
}

/// The candidate return addresses on a stack image, in DEPTH order.
///
/// The scan walks upward from `rsp`, so the result is ordered by depth -- the deepest (innermost)
/// frame first. Sorting these values would order them by code address instead and turn a call chain
/// into a set, which is the bug this function exists to keep out of the callers; it is separate from
/// symbolization so that ordering is testable without a symbolizer or a live process.
fn stack_words(mem: &[u8], maps: &[(u64, u64, bool, u64, String)]) -> Vec<u64> {
    let image_of = |addr: u64| -> Option<&(u64, u64, bool, u64, String)> {
        maps.iter().find(|(lo, hi, x, _, _)| *x && *lo <= addr && addr < *hi)
    };
    let mut seen: Vec<u64> = Vec::new();
    let mut off = 0usize;
    while off + 8 <= mem.len() {
        let v = u64::from_le_bytes(mem[off..off + 8].try_into().unwrap());
        // De-duplication keeps the FIRST occurrence, which is the innermost one, so a repeated
        // return address stays where its deepest frame is.
        if !seen.contains(&v) && image_of(v).is_some() {
            seen.push(v);
        }
        off += 8;
    }
    seen
}

/// The real call chain, walked through the frame-pointer chain.
///
/// MEASURED need: scanning for words that land in an executable mapping does NOT produce a chain --
/// an unwind of the T4 linker printed gr_attach_lane -> __dserver_plane_request_once ->
/// dserver_rpc_explicit_ulock_wake -> dserver_rpc_explicit_debug_list_processes ->
/// _dispatch_source_xref_dispose, which mixes SERVER-side function names into a guest stack and is
/// not a call sequence any thread could run. Those words are pointers and data that merely look like
/// code. The guest closure is built -O0, so rbp is a real frame pointer and [rbp] / [rbp+8] walk the
/// chain the way a debugger would.
///
/// Validation is the point, not the walk: the chain only grows upward from rsp, every word must be
/// 8-aligned and above rsp, and the walk stops at the first word that is not an address inside an
/// executable guest image -- so a garbage word cannot invent a caller.
fn fp_chain(mem: &[u8], base: u64, rbp: u64, rsp: u64, maps: &[(u64, u64, bool, u64, String)],
            image_ok: &dyn Fn(&str) -> bool, max: usize) -> Vec<u64> {
    let read = |addr: u64| -> Option<u64> {
        if addr < base { return None; }
        let off = (addr - base) as usize;
        if off + 8 > mem.len() { return None; }
        Some(u64::from_le_bytes(mem[off..off + 8].try_into().unwrap()))
    };
    let in_image = |addr: u64| {
        maps.iter().any(|(lo, hi, x, _, p)| *x && *lo <= addr && addr < *hi && image_ok(p))
    };
    let mut out = Vec::new();
    let mut fp = rbp;
    while fp > rsp && fp % 8 == 0 && out.len() < max {
        let (Some(next), Some(ret)) = (read(fp), read(fp + 8)) else { break };
        if !in_image(ret) { break; }
        out.push(ret);
        if next <= fp { break; }
        fp = next;
    }
    out
}

/// Frames from a raw stack image. Shared by the live unwinder and by catch mode, which has the
/// stack as a file rather than as memory, so both paths answer the same question the same way.
fn scan_stack(mem: &[u8], maps: &[(u64, u64, bool, u64, String)],
              image_ok: &dyn Fn(&str) -> bool, max: usize,
              segments: &mut MachoSegmentCache) -> Vec<(u64, String, String)> {
    let image_of = |addr: u64| -> Option<(u64, u64, u64, String)> {
        maps.iter()
            .find(|(lo, hi, x, _, _)| *x && *lo <= addr && addr < *hi)
            .map(|(lo, hi, _, foff, p)| (*lo, *hi, *foff, p.clone()))
    };
    let mut frames = Vec::new();
    for v in stack_words(mem, maps) {
        let (lo, _, foff, path) = image_of(v).unwrap();
        if !image_ok(&path) { continue; }
        // Two filters, both stated because a filter that is not stated is a guess: the word must
        // resolve to a symbol at all, and it must not sit in the image's first 16 KiB, which is
        // the Mach-O header and load commands -- bytes that live in an executable mapping and
        // otherwise arrive as "frames" like image_base+2.
        if v < lo + 0x4000 { continue; }
        // The mapping reports a FILE offset; the symbol table wants the IMAGE address. For a UNIVERSAL
        // guest image those differ by the slice base (MEASURED: libswiftCore.dylib's x86_64 slice starts at
        // file 0x4000, and resolving with the file offset named `-[__SwiftValue + 0x289` for an instruction
        // that is `_swift_getObjectType + 0x19`). MachoSegments turns one into the other; when it cannot
        // read the image the old arithmetic is kept, so a non-Mach-O frame still resolves.
        let sym_addr = segments
            .image_addr(&path, foff + (v - lo))
            .unwrap_or(v - lo + foff);
        if let Some(sym) = unwind_symbolize(sym_addr, &path) {
            frames.push((v, path.clone(), sym));
        }
        if frames.len() >= max { break; }
    }
    frames
}

fn unwind_is_hostish(path: &str) -> bool {
    const HOST: [&str; 8] = ["libc.so", "ld-linux", "libpthread.so", "libm.so", "libdl.so",
                             "linux-vdso", "libgcc_s", "libstdc++"];
    let base = path.rsplit('/').next().unwrap_or(path);
    HOST.iter().any(|h| base.contains(h))
}

fn unwind_symbolize(addr: u64, binary: &str) -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let out = Command::new(exe)
        .args(["diag", "symbolize", "--binary", binary, "--addr", &format!("{addr:#x}")])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // `symbolize` prints a header (`binary=`, `target=`) and then the answer as
    // `LOCATION: <symbol> + <offset>`. Taking the FIRST non-empty line -- which is the header --
    // was the bug: every frame came out as `binary=/path`, and stripped images looked identical
    // to resolved ones. Only a `LOCATION:` line is an answer.
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("LOCATION: ") {
            return Some(rest.trim().to_string());
        }
        if line.trim().starts_with("ERROR") {
            return None;
        }
    }
    None
}

/// Turn crash dumps on or off, and SAY what the state is, because a crash with cores off leaves nothing to read
/// and that state is invisible otherwise: `ulimit -c` was 0 here and `core_pattern` piped to apport, so every
/// fatal fault was unreadable while looking exactly like a fault with no information available.
///
/// MEASURED: both settings were reachable (the kernel accepted a file pattern, and a throwaway host process then
/// produced a real `ELF 64-bit LSB core file, x86-64`). This command exists so turning them on is a step with a
/// name instead of a paragraph of shell in a document.
fn run_cores(args: CoresArgs) -> Result<ExitCode> {
    const PATTERN: &str = "/proc/sys/kernel/core_pattern";
    let saved = args.dir.join("previous-core-pattern");
    let ulimit_line = std::fs::read_to_string("/proc/self/limits").unwrap_or_default()
        .lines().find(|l| l.starts_with("Max core file size")).unwrap_or("").trim().to_string();
    let show = |note: &str| {
        let pattern = std::fs::read_to_string(PATTERN).unwrap_or_else(|_| "<unreadable>".into());
        crate::say(&format!("CORES {note} dir={}", args.dir.display()));
        crate::say(&format!("CORES-PATTERN {}", pattern.trim()));
        crate::say(&format!("CORES-LIMIT {ulimit_line}"));
    };
    match args.action {
        CoresAction::Status => {
            show("status");
            let pattern = std::fs::read_to_string(PATTERN).unwrap_or_default();
            // A leading '|' means the kernel PIPES the core to a program instead of writing a file, and that is the
            // only thing that decides it. Testing for '%' was wrong and said "a file" about apport's own pattern,
            // which contains %p -- so the one state this command exists to detect was the one it mis-reported.
            crate::say(if pattern.trim_start().starts_with('|') {
                "CORES-VERDICT dumps are PIPED to a handler (pattern starts with '|'), so no file is kept; run `dwdiag cores on`"
            } else {
                "CORES-VERDICT dumps are written to a file; a crash will leave a core to read"
            });
        }
        CoresAction::On => {
            std::fs::create_dir_all(&args.dir).with_context(|| format!("creating {}", args.dir.display()))?;
            let prev = std::fs::read_to_string(PATTERN).unwrap_or_default();
            let _ = std::fs::write(&saved, prev.trim());
            let want = format!("{}/core.%p", args.dir.display());
            let sudo = sudo_prefix();
            let mut cmd = Command::new(sudo.first().copied().unwrap_or("sh"));
            if !sudo.is_empty() { cmd.arg(sudo[1]); }
            let status = cmd.arg("sh").arg("-c")
                .arg(format!("echo {want} > {PATTERN}"))
                .status().context("writing core_pattern")?;
            if !status.success() {
                bail!("could not write {PATTERN} (passwordless sudo unavailable?)");
            }
            show("on");
            crate::say("CORES-NOTE `ulimit -c unlimited` must ALSO be set in the process that will crash (it is inherited by the launcher and the guest); a file pattern alone still writes nothing");
        }
        CoresAction::Off => {
            let prev = std::fs::read_to_string(&saved).unwrap_or_default();
            if prev.trim().is_empty() { bail!("no saved pattern at {}", saved.display()); }
            let sudo = sudo_prefix();
            let mut cmd = Command::new(sudo.first().copied().unwrap_or("sh"));
            if !sudo.is_empty() { cmd.arg(sudo[1]); }
            let status = cmd.arg("sh").arg("-c").arg(format!("echo '{}' > {PATTERN}", prev.trim()))
                .status().context("restoring core_pattern")?;
            if !status.success() { bail!("could not restore {PATTERN}"); }
            show("off");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Turn a path a GUEST saw into the path the host can open.
///
/// MEASURED need, twice: a guest reports its own view (`/Volumes/SystemRoot/home/...`), and those paths CONTAIN the
/// prefix, so they map to a real file with no search. Doing this by hand in two separate places is how the same
/// mistake gets made twice -- a guest path handed straight to a symbolizer resolves nothing.
///
/// Every candidate is EXISTENCE-CHECKED, so a wrong guess resolves NOTHING instead of symbolizing an unrelated file:
/// the guest view stripped of its mount root, then the path as the host sees it, then that same path under the
/// prefix (a prefix is the guest's filesystem root, so a guest-absolute path lives at `<prefix>V`). MEASURED over
/// the cores in /tmp/t4cores: the host-visible candidate is the one that answers, because Darling's guest processes
/// carry host paths in their own maps -- the prefix candidates only add paths that used to resolve to nothing.
fn guest_path_to_host(p: &str, prefix: Option<&std::path::Path>) -> Option<PathBuf> {
    const GUEST_ROOT: &str = "/Volumes/SystemRoot";
    let under_prefix = |v: &str| -> Option<PathBuf> {
        let px = prefix?;
        let cand = px.join(v.trim_start_matches('/'));
        if cand.exists() { return Some(cand); }
        None
    };
    if let Some(rest) = p.strip_prefix(GUEST_ROOT) {
        let cand = PathBuf::from(rest);
        if cand.exists() { return Some(cand); }
        if let Some(hit) = under_prefix(rest) { return Some(hit); }
    }
    if p.starts_with('/') {
        let cand = PathBuf::from(p);
        if cand.exists() { return Some(cand); }
        if let Some(hit) = under_prefix(p) { return Some(hit); }
    }
    None
}

// ====================================================================================================================
// CORE READING: one layer, shared by `core` and `identity`.
//
// WHY ONE LAYER. The last investigation read a core by hand: `readelf -n` REFUSED its 64-bit note on this host
// ("Cannot decode 64-bit note in 32-bit build"), the mappings came out of gdb's `info proc mappings` text, the
// faulting image's base was subtracted by hand (once wrongly, which briefly symbolized the wrong function), and the
// per-thread census was greps over `thread apply all p/x` that silently dropped lines and produced a WRONG count.
// The kernel's own notes need none of that, and they are all here in ONE file that the two commands read the same
// way: NT_PRSTATUS carries every thread's registers (`rip`, `rbp`, `rsp`, `gs_base`), NT_SIGINFO the terminating
// signal, NT_FILE the mapping table, NT_PRPSINFO the command line.
//
// The file is read where it is needed and never whole. MEASURED: a real core here is 670 MB, and the previous
// NT_FILE parser pulled all of it into memory to look at a note that lives in the first 90 KB.
// ====================================================================================================================

/// The x86-64 general registers in `user_regs_struct` (= `elf_gregset_t`) order, which is the order an NT_PRSTATUS
/// note stores them in.
///
/// MEASURED against gdb's `info registers` on /tmp/t4cores/core.127004: `rip` 0x763d6c1131dd, `rbp` 0x7fffffdfd610,
/// `rsp` 0x7fffffdfd580, `rdi` 0x763d5799d988, `rcx` 0x100, `rdx` 0x101 and `gs_base` 0x763d6f130060 read from the
/// note all equal gdb's values, and `*(unsigned long*)($gs_base+24)` is the same 0x103 the existing core-lock reader
/// reports for that thread. So these are the kernel's layout, not a transcription that happens to work once.
const GPR: [&str; 27] = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi",
    "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
];
const GPR_COUNT: usize = 27;
const GPR_RIP: usize = 16;
const GPR_RBP: usize = 4;
const GPR_RSP: usize = 19;
const GPR_GS_BASE: usize = 22;
/// An NT_PRSTATUS descriptor: the prstatus fields, then the whole register set. The note is padded to 336 bytes but
/// only the first 328 are fields (the last is `pr_fpvalid` plus padding), which is why the size is CHECKED before
/// the registers are read instead of assumed.
const PRSTATUS_REGS_AT: usize = 112;
const PRSTATUS_BYTES: usize = PRSTATUS_REGS_AT + GPR_COUNT * 8;
/// `pr_pid`: the LWP, which is how every other part of this tool names a thread.
const PRSTATUS_PID_AT: usize = 32;
/// `pr_psargs`: the first 80 bytes of the command line gdb would print as "Core was generated by ...".
const PRPSINFO_PSARGS_AT: usize = 56;
const PRPSINFO_PSARGS_LEN: usize = 80;

const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
const NT_FILE: u32 = 0x4649_4c45;
const NT_SIGINFO: u32 = 0x5349_4749;

/// `__TSD_MACH_THREAD_SELF` as libdispatch reads it: slot 3 of the thread's TSD block, i.e. the word at
/// `$gs_base+24` on x86-64. ONE constant, because `identity`, `core` and the existing core-lock reader must mean the
/// same word; the address is printed next to every value so a reader can check it.
const TSD_SELF_SLOT: u64 = 3;
const TSD_SLOT_BYTES: u64 = 8;

fn tsd_self_addr(gs_base: u64) -> u64 {
    gs_base + TSD_SELF_SLOT * TSD_SLOT_BYTES
}

#[derive(Debug, Clone, Copy)]
struct Regs {
    v: [u64; GPR_COUNT],
}

impl Regs {
    fn get(&self, name: &str) -> Option<u64> {
        GPR.iter().position(|n| *n == name).map(|i| self.v[i])
    }
    fn rip(&self) -> u64 { self.v[GPR_RIP] }
    fn rsp(&self) -> u64 { self.v[GPR_RSP] }
    fn rbp(&self) -> u64 { self.v[GPR_RBP] }
    fn gs_base(&self) -> u64 { self.v[GPR_GS_BASE] }
}

/// One thread of a core: the LWP the kernel recorded and the register file it saved.
///
/// The note also carries `pr_cursig` and `pr_info.si_signo`, and neither identifies the faulting thread: MEASURED on
/// /tmp/t4cores/core.127004, where all 28 notes carry si_signo=4/pr_cursig=4 -- the kernel fills the DUMPED signal
/// into every thread's status. Note ORDER is what says which thread died, and only on the first PT_NOTE.
#[derive(Debug, Clone, Copy)]
struct CoreThread {
    lwp: u32,
    regs: Regs,
}

/// A `PT_LOAD` of the core: which target addresses it covers, and how many bytes the dump actually carries.
#[derive(Debug, Clone, Copy)]
struct LoadSeg {
    vaddr: u64,
    memsz: u64,
    file_off: u64,
    filesz: u64,
}

/// `NT_SIGINFO`: the signal the dump was taken for, and how it arrived.
#[derive(Debug, Clone, Copy)]
struct CoreSignal {
    signo: i32,
    errno: i32,
    code: i32,
    addr: u64,
}

/// Which scale NT_FILE's `start`/`end` are in. Linux writes pages, but MEASURED on /tmp/t4cores/core.127004 the
/// ranges are already BYTE addresses while the file offset is a page number -- so the scale is decided from the core
/// itself (every entry fits inside a PT_LOAD under exactly one of the two) instead of being pinned to one kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapScale {
    Bytes,
    Pages,
}

/// An address resolved against a core's own mapping table.
#[derive(Debug, Clone)]
struct Resolved {
    /// The mapping's start: the image's load base in the target.
    base: u64,
    /// The path as the core records it -- what has to be shown when the file cannot be opened.
    name: String,
    /// The path on THIS host, after de-virtualization.
    host: PathBuf,
    /// Whether that host path exists. A mapping table naming an image nobody has is a different answer from a
    /// faulting address that is in no image at all, and both must be sayable.
    exists: bool,
    /// The FILE offset inside the image: what the bytes at this address are read at.
    file_off: u64,
}

/// A core file, opened once and read only where it is needed.
struct CoreFile {
    size: u64,
    file: fs::File,
    loads: Vec<LoadSeg>,
    /// In note order. MEASURED: the kernel writes the thread it dumped FROM first, and gdb calls that same one
    /// "Current thread" (both were LWP 127004 on core.127004).
    threads: Vec<CoreThread>,
    sig: Option<CoreSignal>,
    /// NT_FILE entries with every offset ALREADY in bytes: `(start, end, file_offset, path)`.
    maps: Vec<(u64, u64, u64, String)>,
    scale: MapScale,
    /// The page size the NT_FILE note declared (1 for a gdb-written core, 0x1000 for the kernel's), kept so the
    /// unit the offsets were normalized with is part of what this reader can print.
    file_page: u64,
    /// `(entries inside a PT_LOAD under bytes, under pages)`, so the scale choice can be PRINTED instead of asserted.
    inside: (usize, usize),
    /// `NT_PRPSINFO`'s command-line bytes.
    args: String,
}

fn read_at(file: &mut fs::File, off: u64, n: usize) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(off)).with_context(|| format!("seeking to {off:#x}"))?;
    let mut buf = vec![0u8; n];
    file.read_exact(&mut buf).with_context(|| format!("reading {n} byte(s) at {off:#x}"))?;
    Ok(buf)
}

fn le_u32(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

fn le_u64(b: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}

/// Walk the notes of one `PT_NOTE`. Kept separate from the file so the kernel's note layout can be tested against a
/// buffer this code builds -- the alternative is a command whose only test is a multi-hundred-megabyte core, which is
/// the same reason the existing core-lock parser is separate from its gdb run.
fn parse_core_notes(
    notes: &[u8],
    threads: &mut Vec<CoreThread>,
    sig: &mut Option<CoreSignal>,
    maps: &mut Vec<(u64, u64, u64, String)>,
    file_page: &mut u64,
    args: &mut String,
) {
    let mut off = 0usize;
    while off + 12 <= notes.len() {
        let (nsz, dsz, ntype) = match (le_u32(&notes[off..]), le_u32(&notes[off + 4..]), le_u32(&notes[off + 8..])) {
            (Some(a), Some(b), Some(c)) => (a as usize, b as usize, c),
            _ => break,
        };
        let doff = off + 12 + (nsz + 3) / 4 * 4;
        let Some(desc) = notes.get(doff..doff + dsz) else { break };
        match ntype {
            NT_PRSTATUS => {
                let lwp = le_u32(&desc[PRSTATUS_PID_AT.min(desc.len())..]).unwrap_or(0);
                if desc.len() >= PRSTATUS_BYTES {
                    let mut v = [0u64; GPR_COUNT];
                    for (i, slot) in v.iter_mut().enumerate() {
                        *slot = le_u64(&desc[PRSTATUS_REGS_AT + i * 8..]).unwrap_or(0);
                    }
                    threads.push(CoreThread { lwp, regs: Regs { v } });
                }
            }
            NT_SIGINFO => {
                // `siginfo_t`: si_signo, si_errno, si_code, then the union -- whose first member is `si_addr` for
                // every synchronous trap, and a pid for the asynchronously raised signals.
                let (signo, errno, code) = (
                    le_u32(desc).map(|v| v as i32).unwrap_or(0),
                    le_u32(&desc[4.min(desc.len())..]).map(|v| v as i32).unwrap_or(0),
                    le_u32(&desc[8.min(desc.len())..]).map(|v| v as i32).unwrap_or(0),
                );
                let addr = le_u64(&desc[16.min(desc.len())..]).unwrap_or(0);
                *sig = Some(CoreSignal { signo, errno, code, addr });
            }
            NT_FILE => {
                let (Some(count), page) = (le_u64(desc).map(|v| v as usize), le_u64(&desc[8.min(desc.len())..])) else {
                    off = doff + dsz;
                    off = (off + 3) / 4 * 4;
                    continue;
                };
                // The note's SECOND word is the unit its file offsets are in, and it is the only honest way to read
                // them: MEASURED, the kernel writes page_size=0x1000 with file offsets in PAGES while gdb's `gcore`
                // writes page_size=1 with file offsets in BYTES. Multiplying by the declared unit is correct for
                // both; assuming 4096 made every gcore file offset 4096x too large (which is how a `CORE-INSN` came
                // back empty on a core gdb wrote).
                if let Some(p) = page {
                    *file_page = p;
                }
                let mut ents: Vec<(u64, u64, u64)> = Vec::with_capacity(count.min(1 << 20));
                for i in 0..count {
                    let e = 16 + i * 24;
                    let (Some(a), Some(b), Some(c)) = (
                        le_u64(&desc[e.min(desc.len())..]),
                        le_u64(&desc[(e + 8).min(desc.len())..]),
                        le_u64(&desc[(e + 16).min(desc.len())..]),
                    ) else {
                        break;
                    };
                    ents.push((a, b, c));
                }
                // Paths follow the entries, NUL-terminated and NOT padded: an off-by-four in this walk is what
                // turns a mapping's inode into a filename, so a missing NUL simply ends the list.
                let mut names: Vec<String> = Vec::with_capacity(ents.len());
                let mut p = 16 + count * 24;
                for _ in 0..ents.len() {
                    let Some(rel) = desc.get(p..).and_then(|rest| rest.iter().position(|c| *c == 0)) else { break };
                    names.push(String::from_utf8_lossy(&desc[p..p + rel]).into_owned());
                    p += rel + 1;
                }
                for ((a, b, c), n) in ents.into_iter().zip(names) {
                    maps.push((a, b, c, n));
                }
            }
            NT_PRPSINFO => {
                let end = (PRPSINFO_PSARGS_AT + PRPSINFO_PSARGS_LEN).min(desc.len());
                if end > PRPSINFO_PSARGS_AT {
                    let raw = &desc[PRPSINFO_PSARGS_AT..end];
                    let cut = raw.iter().position(|c| *c == 0).unwrap_or(raw.len());
                    if args.is_empty() {
                        *args = String::from_utf8_lossy(&raw[..cut]).trim().to_string();
                    }
                }
            }
            _ => {}
        }
        off = doff + dsz;
        off = (off + 3) / 4 * 4;
    }
}

impl CoreFile {
    /// Open a core and read what its notes say, refusing anything this reader cannot read correctly.
    ///
    /// The refusals are the point: an ELF that is not a core, a 32-bit note (the host's own `readelf` refuses those
    /// on this machine, so this reader says so in its own words), or a core with no NT_PRSTATUS is reported as such
    /// instead of producing an empty census that reads like "nothing to see".
    fn open(path: &Path) -> Result<Self> {
        if std::env::consts::ARCH != "x86_64" {
            bail!(
                "the core reader decodes the x86-64 register note (NT_PRSTATUS / elf_gregset_t) and x86-64 TSD \
                 addressing; this host is {}", std::env::consts::ARCH
            );
        }
        let mut file = stored_evidence::open(path).with_context(|| format!("opening {}", path.display()))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if size < 64 {
            bail!("{} is {size} bytes, shorter than an ELF header (64): nothing here can be a core", path.display());
        }
        let head = read_at(&mut file, 0, 64)?;
        if &head[..4] != b"\x7fELF" {
            bail!("{} is not an ELF file (no ELF magic): a core is an ELF, and this reader reads those", path.display());
        }
        if head[4] != 2 || head[5] != 1 {
            bail!(
                "{} is ELF class {} data {}: this reader decodes 64-bit little-endian cores only (the host's own \
                 `readelf -n` refuses exactly this note, which is why the notes are read here)", path.display(), head[4], head[5]
            );
        }
        let e_type = u16::from_le_bytes(head[16..18].try_into().unwrap());
        if e_type != 4 {
            bail!("{} is ELF type {e_type}, not ET_CORE (4): it has no thread notes to read", path.display());
        }
        let e_phoff = le_u64(&head[0x20..]).unwrap_or(0);
        let e_phentsize = u16::from_le_bytes(head[0x36..0x38].try_into().unwrap()) as u64;
        let e_phnum = u16::from_le_bytes(head[0x38..0x3a].try_into().unwrap()) as u64;
        if e_phentsize < 56 || e_phnum == 0 {
            bail!("{} has an empty program header table ({e_phnum} entries of {e_phentsize} bytes)", path.display());
        }
        let table = read_at(&mut file, e_phoff, (e_phnum * e_phentsize) as usize)
            .with_context(|| format!("reading the program headers of {}", path.display()))?;
        let mut loads: Vec<LoadSeg> = Vec::new();
        let mut note_ranges: Vec<(u64, u64)> = Vec::new();
        for i in 0..e_phnum {
            let p = (i * e_phentsize) as usize;
            let Some(chunk) = table.get(p..p + 56) else { break };
            let p_type = le_u32(chunk).unwrap_or(0);
            let (p_offset, p_vaddr, p_filesz, p_memsz) = (
                le_u64(&chunk[8..]).unwrap_or(0),
                le_u64(&chunk[16..]).unwrap_or(0),
                le_u64(&chunk[32..]).unwrap_or(0),
                le_u64(&chunk[40..]).unwrap_or(0),
            );
            match p_type {
                1 => loads.push(LoadSeg { vaddr: p_vaddr, memsz: p_memsz, file_off: p_offset, filesz: p_filesz }),
                4 => note_ranges.push((p_offset, p_filesz)),
                _ => {}
            }
        }
        let mut threads: Vec<CoreThread> = Vec::new();
        let mut sig = None;
        let mut maps: Vec<(u64, u64, u64, String)> = Vec::new();
        let mut file_page = 0u64;
        let mut args = String::new();
        for (off, len) in note_ranges {
            let notes = read_at(&mut file, off, len as usize)
                .with_context(|| format!("reading the notes of {}", path.display()))?;
            parse_core_notes(&notes, &mut threads, &mut sig, &mut maps, &mut file_page, &mut args);
        }
        if threads.is_empty() {
            bail!(
                "{} has no NT_PRSTATUS note: it is an ELF core without a thread's registers, so there is no faulting \
                 thread to report", path.display()
            );
        }
        // Which scale NT_FILE's ranges are in, MEASURED from this core: the mapping table lists the process's VMAs,
        // so under the correct scale every entry sits inside a PT_LOAD of the dump. (An earlier version scored the
        // two scales by how many backtrace frames landed in files that exist, which needed a stack first and could
        // not tell the scales apart for a single address -- exactly how the wrong scale named a wrong function.)
        let inside = |pages: bool| -> usize {
            maps.iter()
                .filter(|(s, e, _, _)| {
                    let (start, end) = if pages { (s * 0x1000, e * 0x1000) } else { (*s, *e) };
                    loads.iter().any(|l| l.vaddr <= start && end <= l.vaddr + l.memsz)
                })
                .count()
        };
        let (bytes_inside, pages_inside) = (inside(false), inside(true));
        let scale = if pages_inside > bytes_inside { MapScale::Pages } else { MapScale::Bytes };
        // Normalize every offset to BYTES once, here, so no caller can pick the wrong unit: the ranges are scaled by
        // the measurement above (this core's own PT_LOADs), and the file offsets by the unit the note DECLARES
        // (`file_page`, 1 for gdb's gcore and 0x1000 for the kernel). A core with no NT_FILE keeps an empty table.
        for m in maps.iter_mut() {
            if scale == MapScale::Pages {
                m.0 *= 0x1000;
                m.1 *= 0x1000;
            }
            m.2 *= file_page.max(1);
        }
        Ok(CoreFile { size, file, loads, threads, sig, maps, scale, file_page, inside: (bytes_inside, pages_inside), args })
    }

    /// The faulting thread. The kernel writes a note for EVERY thread and marks them all with the dumped signal, so
    /// the signal cannot identify it; the thread at the head of the first PT_NOTE is the one the dump was taken FROM
    /// (gdb's "Current thread"). `want_lwp` -- the tid the guest log's own mark carries -- outranks that, because the
    /// log says which thread the GUEST faulted in, and the two are compared out loud rather than assumed equal.
    fn faulting(&self, want_lwp: Option<u32>) -> &CoreThread {
        if let Some(w) = want_lwp {
            if let Some(t) = self.threads.iter().find(|t| t.lwp == w) {
                return t;
            }
        }
        &self.threads[0]
    }

    /// The image that owns a target address, through the core's OWN mapping table.
    fn resolve(&self, addr: u64, prefix: Option<&Path>) -> Option<Resolved> {
        let (base, file_off, name) = resolve_in_core(&self.maps, addr)?;
        let host_hit = guest_path_to_host(&name, prefix);
        let exists = host_hit.is_some();
        let host = host_hit.unwrap_or_else(|| PathBuf::from(&name));
        Some(Resolved { base, name, host, exists, file_off })
    }

    /// Read the target's memory, but ONLY where the core carries it. A missing page is an ANSWER, not an error to
    /// paper over: the kernel does not dump clean file-backed pages, so the instruction at a code fault is usually
    /// absent (which is why those bytes are read from the image file) while a thread's TLS block is present.
    fn read_mem(&mut self, vaddr: u64, n: usize) -> Result<Vec<u8>, String> {
        let seg = self
            .loads
            .iter()
            .find(|l| l.vaddr <= vaddr && vaddr + n as u64 <= l.vaddr + l.memsz)
            .copied()
            .ok_or_else(|| format!("{vaddr:#x} is in no PT_LOAD of this core"))?;
        let delta = vaddr - seg.vaddr;
        if delta + n as u64 > seg.filesz {
            return Err(format!(
                "{vaddr:#x} is in a mapping the dump did not carry ({} of {} bytes present): the kernel skips pages \
                 it does not have to write", seg.filesz, seg.memsz
            ));
        }
        read_at(&mut self.file, seg.file_off + delta, n).map_err(|e| format!("{e:#}"))
    }

    fn read_u64(&mut self, vaddr: u64) -> Result<u64, String> {
        let b = self.read_mem(vaddr, 8)?;
        Ok(u64::from_le_bytes(b[..8].try_into().unwrap()))
    }

    /// Whether the dump covers this address at all, for the case where no NT_FILE entry owns it: an address inside an
    /// ANONYMOUS mapping is a different answer from one the core's tables never mention, and both must be sayable.
    fn carried(&self, addr: u64) -> bool {
        self.loads.iter().any(|l| l.vaddr <= addr && addr < l.vaddr + l.memsz)
    }
}

/// One symbolization per (image, VM address): `symbolize` shells out to this tool again, which parses the image with
/// `llvm-nm`, and a stack walk asks about the same call sites while the identity census asks about the same
/// instruction pointer on many threads. `None` is cached too -- "this address has no symbol" is an answer.
#[derive(Default)]
struct SymCache {
    by: BTreeMap<(String, u64), Option<String>>,
}

/// An address in a guest image, in the two spaces that matter: the FILE offset (where the bytes are read) and the VM
/// address the symbol table uses.
struct ImageAddr {
    vm: u64,
    /// Whether the file-offset-to-VM conversion was COMPUTED from the image's load commands. MEASURED why this is
    /// reported instead of assumed: an unconverted offset names a confidently WRONG function (`__os_once + 0x5e` for
    /// `_os_unfair_lock_unlock_slow + 0x10e`), so a non-Mach-O image (a host core's libc) says "unconverted".
    converted: bool,
    symbol: Option<String>,
}

fn image_addr_of(res: &Resolved, cache: &mut SymCache) -> ImageAddr {
    let key = res.host.display().to_string();
    let converted_vm = macho_vmaddr_for_fileoff(&key, res.file_off);
    let converted = converted_vm.is_some();
    let vm = converted_vm.unwrap_or(res.file_off);
    let symbol = cache.by.entry((key.clone(), vm)).or_insert_with(|| unwind_symbolize(vm, &key)).clone();
    ImageAddr { vm, converted, symbol }
}

/// One frame of the caller chain, read out of the core's memory.
#[derive(Debug, Clone)]
struct CoreFrame {
    fp: u64,
    ret: u64,
    image: Option<Resolved>,
}

/// Walk the frame-pointer chain in the CORE's memory and map every return address through the CORE's own NT_FILE
/// table -- never through gdb's symbol tables, because a guest's frames are exactly what a host gdb cannot see.
///
/// The validation is what keeps a data word from inventing a caller: the chain must ASCEND, each frame pointer must
/// be 8-aligned, and the walk stops at the first return address that lands in no mapped image. The stop comes back
/// with its REASON, so "the chain ends here" and "this reader cannot see further" stay different answers instead of
/// both reading as a short list. Returning the contested frame (with no image) is deliberate: the reader sees where
/// it stopped instead of a silently truncated stack.
fn core_fp_chain(c: &mut CoreFile, rbp: u64, rsp: u64, prefix: Option<&Path>, max: usize) -> (Vec<CoreFrame>, String) {
    let mut out: Vec<CoreFrame> = Vec::new();
    if rbp == 0 {
        return (out, "rbp is 0: this thread carries no frame pointer chain".to_string());
    }
    if rbp % 8 != 0 {
        return (out, format!("rbp {rbp:#x} is not 8-aligned, so it is not a frame pointer"));
    }
    let mut fp = rbp;
    loop {
        if out.len() >= max {
            return (out, format!("stopped at the {max}-frame cap"));
        }
        let next = match c.read_u64(fp) {
            Ok(v) => v,
            Err(e) => return (out, format!("the frame pointer at {fp:#x} is unreadable ({e})")),
        };
        let ret = match c.read_u64(fp + 8) {
            Ok(v) => v,
            Err(e) => return (out, format!("the return address at {:#x} is unreadable ({e})", fp + 8)),
        };
        let image = c.resolve(ret, prefix);
        let has_image = image.is_some();
        out.push(CoreFrame { fp, ret, image });
        if !has_image {
            return (out, format!("return address {ret:#x} is in no mapped image, so the walk ends there"));
        }
        if next == 0 {
            return (out, "the next frame pointer is 0: the outermost frame".to_string());
        }
        if next <= fp {
            return (out, format!("the next frame pointer {next:#x} does not ascend past {fp:#x} (a corrupt chain)"));
        }
        // The saved frame pointer must live above the stack pointer that was live in this frame. This is the check
        // that rejects a "chain" made of data words: `rsp` only bounds the INNERMOST frame, so the first step is
        // bounded here and later steps by the ascent rule above.
        if out.len() == 1 && fp < rsp {
            return (out, format!("the frame pointer {fp:#x} is below rsp {rsp:#x}, so it is not this thread's frame"));
        }
        fp = next;
    }
}

/// The dispatch_once operands at the trap: the once word, the lock owner it names, and the pointer they were read
/// through, each with the register it came from.
struct OnceOperands {
    predicate_reg: &'static str,
    predicate: u64,
    word: u64,
    word_reg: Option<&'static str>,
    owner: u64,
    owner_reg: &'static str,
}

/// The registers worth reading as a predicate POINTER, in the ABI's argument order first: a core is a snapshot of one
/// instruction, and the arguments of the function it died in are the first place to look for them.
const ONCE_POINTER_REGS: [&str; 14] =
    ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rbx", "r10", "r11", "r12", "r13", "r14", "r15"];

/// Locate the once protocol's operands in a thread's register file.
///
/// The rule is STATED because this cannot be a DWARF lookup: the guest's libdispatch carries no debug info, and a
/// core is one instant, so the register file is the only place the operands can come from. The once word is a small
/// nonzero value whose low bits are set (the "an owner is in progress" encoding of `dispatch_once_t`) and whose
/// masked form `word & !3` is the lock owner the code compares against -- so a register that POINTS AT such a word,
/// together with the register holding its masked form, names `(predicate, once word, masked owner)`. MEASURED on
/// /tmp/t4cores/core.127004: rdi points at 0x101, rcx holds 0x100 = 0x101 & !3, and rdx holds the word itself -- the
/// three values the hand diagnosis recorded. A register file that matches nothing returns None, so the caller prints
/// `unavailable` with its reason instead of a plausible number.
fn once_operands<F: FnMut(u64) -> Option<u64>>(regs: &Regs, mut read: F) -> Option<OnceOperands> {
    for name in ONCE_POINTER_REGS {
        let Some(p) = regs.get(name) else { continue };
        if p < 0x1000 {
            continue;
        }
        let Some(word) = read(p) else { continue };
        // A value this reader will call a once word: nonzero, small (the protocol stores counts and encoded thread
        // ids, so a full 64-bit word is a pointer, not a word), and naming an owner (the low bits set).
        if word == 0 || word >> 32 != 0 || word & 0x3 == 0 {
            continue;
        }
        let owner = word & !0x3;
        if owner == 0 || owner == p {
            continue;
        }
        let partner = ONCE_POINTER_REGS
            .iter()
            .copied()
            .find(|q| *q != name && regs.get(q) == Some(owner))?;
        let word_reg = ONCE_POINTER_REGS.iter().copied().find(|q| *q != name && regs.get(q) == Some(word));
        return Some(OnceOperands { predicate_reg: name, predicate: p, word, word_reg, owner, owner_reg: partner });
    }
    None
}

/// What an `si_code` says about HOW a signal arrived, which is a different question from which signal it is.
///
/// MEASURED on /tmp/t4cores/core.127004: its SIGILL carries `si_code = -6` (SI_TKILL) -- a signal SENT by a thread
/// -- and not the CPU's own illegal-opcode code (ILL_ILLOPN = 2). That is the difference between "the ud2 trapped
/// here" and "the fault was already handled and the death was raised by code", and the signal NAME cannot show it.
fn sig_code_meaning(signo: i32, code: i32) -> Option<&'static str> {
    match (signo, code) {
        (_, -6) => Some("SI_TKILL: a THREAD sent this signal (tgkill/raise), so this is not the CPU's own trap code"),
        (_, -1) => Some("SI_QUEUE: sent with sigqueue"),
        (_, 0) => Some("SI_USER: sent by kill()"),
        (4, 1) => Some("ILL_ILLOPC: illegal opcode"),
        (4, 2) => Some("ILL_ILLOPN: the CPU trapped on an illegal opcode (a ud2 was executed)"),
        (4, 3) => Some("ILL_ILLADR: illegal addressing mode"),
        (4, 4) => Some("ILL_ILLTRP: illegal trap"),
        (4, 5) => Some("ILL_PRVOPC: privileged opcode"),
        (4, 6) => Some("ILL_PRVREG: privileged register"),
        (4, 8) => Some("ILL_BADSTK: internal stack error"),
        (11, 1) => Some("SEGV_MAPERR: the address is not mapped"),
        (11, 2) => Some("SEGV_ACCERR: no permission for the address"),
        _ => None,
    }
}

/// The first bytes of an instruction, bounded, as the hex a reader compares against a disassembly.
fn hex_bytes(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

/// The signal's name as it is SPOKEN. `signal_name` returns the bare name for the signals a workload dies of ("ILL"),
/// so prefixing it is what makes "SIGILL" -- and a signal this tool has no name for is printed as its number rather
/// than as a made-up `SIGSIG`.
fn sig_label(signo: i32) -> String {
    match signal_name(signo) {
        n if n != "SIG" => format!("SIG{n}"),
        _ => format!("{signo}"),
    }
}

fn basename_of(p: &Path) -> String {
    p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string())
}

/// `"k":v` pairs joined into one JSON object, with `v` already encoded (a string through `jesc`).
///
/// A reader that has to count placeholders in a `format!` with a dozen of them is how an object whose fields do not
/// line up with its values gets shipped, and the consumers of `--json` here are scripts. One function keeps the two
/// commands' objects honest, and the contract parses both with a real JSON parser.
fn json_object(pairs: Vec<(&str, String)>) -> String {
    let body = pairs.into_iter().map(|(k, v)| format!("\"{k}\":{v}")).collect::<Vec<_>>().join(",");
    format!("{{{body}}}")
}

/// gdb's own view of a core, for the `--traces` flag, printed VERBATIM and labelled as the debugger's.
///
/// MEASURED: on a guest core gdb's backtrace is usually useless (`#0 ... in ?? ()`, then pointers) because it has no
/// symbols or unwind information for the guest's Mach-O images. Seeing that is what the flag is for; the alternative
/// is a reader assuming the debugger's frames are the answer. Nothing here PARSES gdb's output.
fn core_gdb_traces(core: &fs::File) -> Vec<String> {
    let out = Command::new("gdb")
        .args(["-batch", "-nx", "-iex", "set debuginfod enabled off"])
        .arg("-c")
        .arg(stored_evidence::descriptor_path(core))
        .args(["-ex", "info threads", "-ex", "bt"])
        .output();
    match out {
        Ok(o) if !o.stdout.is_empty() => {
            String::from_utf8_lossy(&o.stdout).lines().map(|l| l.to_string()).collect()
        }
        Ok(o) => vec![format!("<gdb produced no output (exit status {:?})>", o.status.code())],
        Err(e) => vec![format!("<gdb could not be run: {e}>")],
    }
}

/// The newest core under a directory, matched by the filename prefix a `core_pattern` produces. Shared, so "the
/// newest core" cannot come to mean three different things in three commands.
fn newest_core(dir: &Path, prefix: &str) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for e in fs::read_dir(dir).ok()?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with(prefix) {
            continue;
        }
        let Ok(t) = e.metadata().and_then(|m| m.modified()) else { continue };
        if best.as_ref().map(|(bt, _)| t > *bt).unwrap_or(true) {
            best = Some((t, e.path()));
        }
    }
    best.map(|(_, p)| p)
}

/// The newest core under a directory and its size, for a caller that has to report what it found.
fn newest_core_sized(dir: &Path, prefix: &str) -> Option<(PathBuf, u64)> {
    let p = newest_core(dir, prefix)?;
    let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
    Some((p, size))
}

/// Where the kernel would write a core, DISCOVERED from `core_pattern` rather than assumed.
///
/// MEASURED need: the pattern on this host is `/tmp/t4cores/core.%p`, which is a setting, not a constant -- a
/// hardcoded directory is how a crash report names a core that does not exist while the real one sits elsewhere. A
/// pattern starting with `|` pipes the dump to a handler and keeps no file at all, which is a different answer.
struct CorePattern {
    pattern: String,
    piped: bool,
    dir: PathBuf,
    /// The literal part of the filename before the first `%`: everything a produced file's name must start with.
    prefix: String,
}

fn core_pattern() -> CorePattern {
    let pattern = fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap_or_else(|_| "<unreadable>".into());
    let pattern = pattern.trim().to_string();
    if pattern.starts_with('|') {
        return CorePattern { pattern, piped: true, dir: PathBuf::from("."), prefix: String::new() };
    }
    // The kernel expands %p/%e/%t in the last path component; everything before the first `%` is literal.
    let (dir, file) = match pattern.rfind('/') {
        Some(i) => (PathBuf::from(&pattern[..i.max(1)]), pattern[i + 1..].to_string()),
        None => (PathBuf::from("."), pattern.clone()),
    };
    let prefix = file.split('%').next().unwrap_or("").to_string();
    CorePattern { pattern, piped: false, dir, prefix }
}

/// Translate a FILE OFFSET in a Mach-O into the VM ADDRESS the symbol tables use.
///
/// MEASURED defect, twice in one session: NT_FILE reports file offsets, and `symbolize`/`llvm-nm` address by VM
/// address. For `libsystem_platform.dylib` they differ by a constant (file_offset = vmaddr + 0x1000), so a core
/// fault at file offset 0x3a9e was reported as `__os_once + 0x5e` when the truth was VM 0x2a9e =
/// `_os_unfair_lock_unlock_slow + 0x10e`. Both names looked plausible, which is why this is computed from the load
/// commands instead of assumed equal.
fn macho_vmaddr_for_fileoff(image: &str, file_off: u64) -> Option<u64> {
    let data = stored_evidence::read(Path::new(image)).ok()?;
    let magic = u32::from_be_bytes(data.get(0..4)?.try_into().ok()?);
    // MEASURED: Darling's dylibs are UNIVERSAL (`cafe babe`, 2 architectures), so a thin-only parser returns None
    // for exactly the images that matter and the conversion silently does not happen. A fat slice's segment file
    // offsets are relative to the SLICE, which is also why the shift here is a constant: the x86_64 slice starts
    // 0x1000 into the file. Try every slice and take the one whose range actually contains the offset, so the
    // architecture never has to be assumed.
    if magic == 0xcafe_babe {
        let n = u32::from_be_bytes(data.get(4..8)?.try_into().ok()?) as usize;
        for i in 0..n {
            let a = 8 + i * 20;
            let off = u32::from_be_bytes(data.get(a + 8..a + 12)?.try_into().ok()?) as u64;
            if let Some(v) = thin_vmaddr_for_fileoff(&data, off, file_off, true) { return Some(v); }
        }
        return None;
    }
    thin_vmaddr_for_fileoff(&data, 0, file_off, false)
}

/// Resolve the VM address inside ONE Mach-O image. `slice_relative` says the segment file offsets are relative to
/// the slice start (`slice_base`), which is how a universal slice records them.
fn thin_vmaddr_for_fileoff(data: &[u8], slice_base: u64, file_off: u64, slice_relative: bool) -> Option<u64> {
    let magic = u32::from_le_bytes(data.get(slice_base as usize..slice_base as usize + 4)?.try_into().ok()?);
    if magic != 0xfeed_facf { return None; } // 64-bit thin Mach-O only
    let base = slice_base as usize;
    let ncmds = u32::from_le_bytes(data.get(base + 16..base + 20)?.try_into().ok()?) as usize;
    let mut off = base + 32;
    for _ in 0..ncmds {
        let cmd = u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?);
        let cmdsize = u32::from_le_bytes(data.get(off + 4..off + 8)?.try_into().ok()?) as usize;
        if cmdsize == 0 { return None; }
        if cmd == 0x19 { // LC_SEGMENT_64
            let vmaddr = u64::from_le_bytes(data.get(off + 24..off + 32)?.try_into().ok()?);
            let fileoff = u64::from_le_bytes(data.get(off + 40..off + 48)?.try_into().ok()?);
            let filesize = u64::from_le_bytes(data.get(off + 48..off + 56)?.try_into().ok()?);
            let seg_start = if slice_relative { slice_base + fileoff } else { fileoff };
            if seg_start <= file_off && file_off < seg_start.saturating_add(filesize) {
                return Some(vmaddr + (file_off - seg_start));
            }
        }
        off += cmdsize;
    }
    None
}

/// Resolve an address against core mappings: which image, where it starts, and the offset inside that file.
///
/// MEASURED scale quirk, and it is the difference between a right and a wrong function name: the kernel writes
/// NT_FILE's start/end as BYTE addresses (0x7dc012b27000, not a page number) while its file_offset is in PAGES (1
/// for the first mapped page), and gdb's `gcore` writes BOTH in bytes with the note's page field set to 1. Both
/// conventions are handled where they belong -- `CoreFile::open` normalizes every entry to bytes using the note's
/// own declared unit -- so this function only ever sees bytes, and a caller cannot pick the wrong scale.
/// Returns `(mapping base, file offset, image path as the core records it)`, because an "image address" is relative
/// to the base and a reader that cannot see it cannot check the arithmetic -- getting exactly that subtraction wrong
/// by hand is what once symbolized the wrong function.
///
/// De-virtualization is NOT done here: a caller that has a prefix has to be able to say so, and the path a core
/// records has to stay visible for the case where no prefix resolves it (`CoreFile::resolve` does both).
fn resolve_in_core(maps: &[(u64, u64, u64, String)], addr: u64) -> Option<(u64, u64, String)> {
    for (start, enda, file_off, name) in maps {
        if *start <= addr && addr < *enda {
            return Some((*start, file_off + (addr - start), name.clone()));
        }
    }
    None
}

/// Parse an address argument that may be hex (`0x…`, or bare hex) or decimal. A bare value with letters is hex
/// (the addresses in a core are printed hex everywhere else in this tool), and `MappingsArgs::read` uses `:` as the
/// separator so a bare hex length keeps working.
fn parse_addr_arg(s: &str) -> Result<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).with_context(|| format!("not a hex address: {s}"));
    }
    if let Ok(v) = t.parse::<u64>() {
        return Ok(v);
    }
    u64::from_str_radix(t, 16).with_context(|| format!("not an address (decimal or hex): {s}"))
}

/// `ADDR:LEN` for `--read`. The separator is explicit so a bare hex address (which may contain letters that are also
/// not digits) is unambiguous, and a missing separator is refused rather than guessed.
fn parse_read_arg(s: &str) -> Result<(u64, usize)> {
    let (a, l) = s
        .split_once(':')
        .with_context(|| format!("--read wants ADDR:LEN (hex addresses, length in bytes), got {s:?}"))?;
    let addr = parse_addr_arg(a)?;
    let len: usize = l
        .trim()
        .parse()
        .with_context(|| format!("--read length is not a byte count: {l:?}"))?;
    Ok((addr, len))
}

/// Print a CORE's OWN mapping table. See the `Mappings` variant for the measured reason this is a command.
fn run_mappings(args: MappingsArgs) -> Result<ExitCode> {
    let path = match args.core.clone() {
        Some(p) => p,
        None => newest_core(&args.dir, "core").with_context(|| {
            format!(
                "no --core given and no core.* under {}: cores are OFF unless the crashing process had \
                 `ulimit -c unlimited` AND core_pattern names a FILE (a leading `|` pipes them to a handler and keeps \
                 nothing) -- `dwdiag cores status` reports both",
                args.dir.display()
            )
        })?,
    };
    let prefix = resolve_prefix(args.prefix.clone(), None);
    let mut c = CoreFile::open(&path)?;
    let size = c.size;
    let maps_count = c.maps.len();
    let scale = c.scale;
    let file_page = c.file_page;
    let (bytes_inside, pages_inside) = c.inside;
    let scale_word = match scale {
        MapScale::Pages => "pages",
        MapScale::Bytes => "bytes",
    };
    let unit_word = if file_page == 1 {
        "bytes (the note declares page_size=1)"
    } else {
        "the note's declared page size"
    };
    let owner = match args.addr.as_deref() {
        Some(raw) => {
            let addr = parse_addr_arg(raw)?;
            Some((addr, resolve_in_core(&c.maps, addr)))
        }
        None => None,
    };
    let read = match args.read.as_deref() {
        Some(raw) => {
            let (addr, len) = parse_read_arg(raw)?;
            let bytes = c.read_mem(addr, len);
            Some((addr, len, bytes))
        }
        None => None,
    };
    if maps_count == 0 {
        // An EMPTY table is stated, not printed as zero rows: a core with no NT_FILE and a core whose table was
        // parsed wrongly must not look the same, and only the first is what this says.
        let line = format!(
            "MAPPINGS-EMPTY core={} size={size} source=NT_FILE: this core carries no NT_FILE note, so no mapping \
             table can be printed (the note is what lists the process's VMAs; a dump that predates the process's \
             mappings has none)",
            path.display()
        );
        crate::say(&line);
        return Ok(ExitCode::SUCCESS);
    }
    if args.json {
        let rows: Vec<String> = c
            .maps
            .iter()
            .map(|(start, end, off, name)| {
                let host = guest_path_to_host(name, prefix.as_deref());
                json_object(vec![
                    ("start", format!("\"{start:#x}\"")),
                    ("end", format!("\"{end:#x}\"")),
                    ("file_offset", format!("\"{off:#x}\"")),
                    ("name", jstr(name)),
                    (
                        "host",
                        host.as_ref().map(|h| jstr(&h.display().to_string())).unwrap_or_else(|| "null".into()),
                    ),
                    (
                        "host_exists",
                        host.as_ref().map(|h| h.exists().to_string()).unwrap_or_else(|| "null".into()),
                    ),
                ])
            })
            .collect();
        let owner_obj = match &owner {
            Some((addr, Some((base, off, name)))) => json_object(vec![
                ("addr", format!("\"{addr:#x}\"")),
                ("base", format!("\"{base:#x}\"")),
                ("file_offset", format!("\"{off:#x}\"")),
                ("name", jstr(name)),
            ]),
            Some((addr, None)) => json_object(vec![
                ("addr", format!("\"{addr:#x}\"")),
                ("name", "null".to_string()),
                ("reason", jstr("the address is in no mapping this core's NT_FILE lists")),
            ]),
            None => "null".to_string(),
        };
        let read_obj = match &read {
            Some((addr, len, Ok(bytes))) => json_object(vec![
                ("addr", format!("\"{addr:#x}\"")),
                ("len", len.to_string()),
                ("bytes", jstr(&hex_bytes(bytes))),
            ]),
            Some((addr, len, Err(why))) => json_object(vec![
                ("addr", format!("\"{addr:#x}\"")),
                ("len", len.to_string()),
                ("bytes", "null".to_string()),
                ("reason", jstr(why)),
            ]),
            None => "null".to_string(),
        };
        let doc = json_object(vec![
            ("core", jstr(&path.display().to_string())),
            ("size", size.to_string()),
            ("source", jstr("NT_FILE")),
            ("count", maps_count.to_string()),
            ("range_scale", jstr(scale_word)),
            ("file_offset_unit", jstr(unit_word)),
            ("inside_as_bytes", bytes_inside.to_string()),
            ("inside_as_pages", pages_inside.to_string()),
            ("rows", format!("[{}]", rows.join(","))),
            ("owner", owner_obj),
            ("read", read_obj),
        ]);
        crate::say(&doc);
        return Ok(ExitCode::SUCCESS);
    }
    crate::say(&format!("MAPPINGS core={} size={size}", path.display()));
    crate::say(&format!(
        "MAPPINGS-COUNT source=NT_FILE count={maps_count} range-scale={scale_word} (decided from this core: \
         {bytes_inside} of {maps_count} entries fall inside a PT_LOAD as bytes, {pages_inside} as pages) \
         file-offset-unit={unit_word}"
    ));
    for (start, end, off, name) in &c.maps {
        let host = guest_path_to_host(name, prefix.as_deref());
        let mut line = format!("MAPPINGS-ROW start={start:#x} end={end:#x} file_off={off:#x} name={name}");
        if let Some(h) = host.as_ref() {
            let here = h.display().to_string();
            if &here != name {
                line.push_str(&format!(" host={here}"));
                if !h.exists() {
                    line.push_str(" host-absent=1");
                }
            }
        }
        crate::say(&line);
    }
    if let Some((addr, found)) = &owner {
        match found {
            Some((base, off, name)) => crate::say(&format!(
                "MAPPINGS-OWNER addr={addr:#x} base={base:#x} file_off={off:#x} name={name}"
            )),
            None => crate::say(&format!(
                "MAPPINGS-OWNER addr={addr:#x} none: the address is in no mapping this core's NT_FILE lists"
            )),
        }
    }
    if let Some((addr, len, bytes)) = &read {
        match bytes {
            Ok(b) => crate::say(&format!("MAPPINGS-READ addr={addr:#x} len={len} bytes={}", hex_bytes(b))),
            Err(why) => crate::say(&format!("MAPPINGS-READ addr={addr:#x} len={len} unavailable: {why}")),
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Print the run's artifact identity line. The candidate table lives in `runtime_fingerprint_parts` so this and
/// `verdict`'s line can never describe different sets of files.
fn run_env(args: EnvArgs) -> Result<ExitCode> {
    let root = crate::installed_runtime_root()?;
    let prefix = resolve_prefix(args.prefix, None).or_else(|| std::env::var_os("DPREFIX").map(PathBuf::from));
    let parts = runtime_fingerprint_parts(root);
    let complete = parts.len() == RUNTIME_FINGERPRINT_CANDIDATES.len();
    if args.json {
        let mut pairs: Vec<(&str, String)> = parts.iter().map(|(name, digest)| (name.as_str(), jstr(digest))).collect();
        pairs.push(("runtime_root", jstr(&root.display().to_string())));
        pairs.push(("prefix", prefix.as_ref().map(|path| jstr(&path.display().to_string())).unwrap_or_else(|| "null".to_string())));
        pairs.push(("complete", complete.to_string()));
        crate::say(&json_object(pairs));
    } else {
        let joined = parts.iter().map(|(name, digest)| format!("{name}={digest}")).collect::<Vec<_>>().join(" ");
        crate::say(&format!("RUN-ENV runtime-root={} prefix={} {joined}", root.display(),
            prefix.as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| "<unset>".to_string())));
        if !complete { eprintln!("RUN-ENV incomplete: {} of {} installed components hashed", parts.len(), RUNTIME_FINGERPRINT_CANDIDATES.len()); }
    }
    Ok(if complete { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

/// Read a CORE, because it is the one artifact that still has the faulting thread in it.
///
/// MEASURED why this exists next to `trap`. A guest's `ud2` is a NATIVE instruction: the code runs on the host CPU,
/// so Darling never sees it as a syscall and cannot report it. Four other routes were measured blind on the same
/// crash: `dmesg` is silent because the guest installs its own handler, the loader's fault witness armed 8 times
/// and never fired, the guest masks SIGSEGV on that path, and a gdb catch waits for a signal the guest swallows.
/// A core needs none of that machinery: it is written by the kernel and carries NT_PRSTATUS (every thread's
/// registers), NT_SIGINFO (the signal and how it arrived), NT_FILE (the mappings) and NT_PRPSINFO (the command line).
/// It is also normally OFF here (`ulimit -c 0`, `core_pattern` -> apport), which is why crashes have been unreadable;
/// this command says so instead of returning nothing.
///
/// WHAT IT REPORTS, all of it from those notes: the terminating signal and the faulting thread; the faulting
/// instruction pointer mapped to its image (load base + in-image address) and symbolized; the instruction there
/// (enough to say `ud2`); the faulting frame's OPERANDS where the register file locates them, marked best-effort;
/// and the caller chain walked through the core's own frame pointers and mapped through the core's own mapping table.
///
/// The notes are read HERE rather than through `gdb` or `readelf`: the host's `readelf -n` REFUSES this note
/// ("Cannot decode 64-bit note in 32-bit build") and gdb's `bt` cannot unwind a guest frame at all, while the notes
/// hold everything above in a few kilobytes.
fn run_core(args: CoreArgs) -> Result<ExitCode> {
    let core = match &args.core {
        Some(p) => p.clone(),
        None => match newest_core(&args.dir, "core") {
            Some(p) => p,
            None => {
                // Name WHY there is nothing to read. A silent empty result is what made this class of crash look
                // like a missing feature rather than a disabled one -- and WHERE the kernel would have written it is
                // part of the answer, so the pattern's own directory is read instead of assumed to be this one.
                let ulimit = std::fs::read_to_string("/proc/self/limits").unwrap_or_default()
                    .lines().find(|l| l.starts_with("Max core file size")).unwrap_or("Max core file size: <unknown>").to_string();
                let pat = core_pattern();
                crate::say(&format!("CORE-NONE dir={} ({})", args.dir.display(), ulimit.trim()));
                crate::say(&format!("CORE-NOTE core_pattern={} wrote into {} -- a crash leaves nothing unless the pattern names a file (a leading '|' pipes the dump to a handler) and the crashing process's size limit is non-zero", pat.pattern, pat.dir.display()));
                if !pat.piped && pat.dir != args.dir {
                    crate::say(&format!("CORE-NOTE-HINT the pattern does not write into {}: a core from a crash under it would be under {}", args.dir.display(), pat.dir.display()));
                }
                return Ok(ExitCode::SUCCESS);
            }
        },
    };
    if !stored_evidence::resolve(&core).is_file() { bail!("no such core: {}", core.display()); }

    let mut c = CoreFile::open(&core)?;
    let prefix_owned = args.prefix.clone().or_else(|| {
        std::env::var("DWDIAG_PREFIX").ok().filter(|s| !s.is_empty()).map(PathBuf::from)
    });
    let prefix = prefix_owned.as_deref();

    // The guest log, when given, is where the FAULTING THREAD and the signal as the GUEST saw them are written,
    // while the core is where that thread's registers are. Reading both in one command is the point: neither alone
    // says which thread faulted AND what it was executing.
    let log_text = match &args.log {
        Some(p) => Some(read_log_lossy(p).with_context(|| format!("reading {}", p.display()))?),
        None => None,
    };
    let mark = log_text.as_deref().and_then(last_fault_mark);
    let want_tid = mark.as_ref().and_then(|m| m.tid);
    let (faulting_lwp, regs) = {
        let t = c.faulting(want_tid);
        (t.lwp, t.regs)
    };
    let (rip, rsp, rbp, gs_base) = (regs.rip(), regs.rsp(), regs.rbp(), regs.gs_base());
    let how_faulting = match want_tid {
        Some(w) if w == faulting_lwp => format!("the log's own tid={w}"),
        Some(w) => format!("lwp {w} from the log is not in this core; fell back to note order"),
        None => "note order (no --log: the first NT_PRSTATUS is the thread the kernel dumped from)".to_string(),
    };

    let mut cache = SymCache::default();
    let fault = c.resolve(rip, prefix);
    let fault_addr = fault.as_ref().map(|f| image_addr_of(f, &mut cache));
    // The instruction bytes come from the IMAGE, never from the core: the kernel does not dump clean file-backed
    // pages, so the page this thread died on is normally absent -- and reading them from the image is what the log
    // path does too, so "what instruction is at this address" has one answer for both commands.
    let insn_bytes = match &fault {
        Some(f) if f.exists => fault_bytes(&f.host.display().to_string(), f.file_off),
        _ => None,
    };
    let insn_hex = insn_bytes.as_deref().map(hex_bytes).unwrap_or_default();
    let trap = insn_bytes.as_deref().and_then(decode_trap).unwrap_or("");

    // The operands. A core is one instant and the guest's libdispatch carries no debug info, so this is a
    // BEST-EFFORT read of the register file with a stated rule (`once_operands`); when the faulting frame is
    // demonstrably NOT a once wait, it is not attempted at all, and when nothing matches, the reason is printed.
    let fault_symbol = fault_addr.as_ref().and_then(|a| a.symbol.clone());
    let symbol_is_once = fault_symbol.as_deref().map(|s| s.contains("dispatch_once"));
    let operands = match symbol_is_once {
        Some(false) => None,
        _ => once_operands(&regs, |a| c.read_u64(a).ok()),
    };
    let operand_why = if operands.is_some() {
        String::new()
    } else if symbol_is_once == Some(false) {
        format!(
            "the faulting frame is {}, which is not a dispatch_once wait, and this reader knows the once protocol's \
             operand encoding only", fault_symbol.clone().unwrap_or_else(|| "<?>".into())
        )
    } else {
        "no register points at a value whose low bits name an owner that another register also holds, which is the \
         encoding this reader looks for".to_string()
    };
    let tsd = c.read_u64(tsd_self_addr(gs_base)).map_err(|e| {
        format!(
            "{e}; the identity word is slot {TSD_SELF_SLOT} at $gs_base + {} = {:#x}",
            TSD_SELF_SLOT * TSD_SLOT_BYTES, tsd_self_addr(gs_base)
        )
    });

    // The caller chain, through the core's own frame pointers and its own NT_FILE table.
    let (frames, walk_stop) = core_fp_chain(&mut c, rbp, rsp, prefix, 64);
    let walk: Vec<(CoreFrame, Option<ImageAddr>)> = frames
        .into_iter()
        .map(|f| {
            let a = f.image.as_ref().map(|im| image_addr_of(im, &mut cache));
            (f, a)
        })
        .collect();
    let anon_hint = c.carried(rip) && fault.is_none();
    let threads = c.threads.len();
    let maps_count = c.maps.len();
    let (bytes_inside, pages_inside) = c.inside;
    let file_page = c.file_page;
    let scale = c.scale;
    let sig = c.sig;
    let size = c.size;
    let generated_by = c.args.clone();

    let sig_line = match sig {
        Some(s) => format!(
            "CORE-SIGNAL sig={} {} (NT_SIGINFO si_signo={} si_code={} si_errno={} si_addr={:#x})",
            s.signo, sig_label(s.signo), s.signo, s.code, s.errno, s.addr
        ),
        None => "CORE-SIGNAL unknown: this core carries no NT_SIGINFO note".to_string(),
    };
    let fault_line = match (&fault, &fault_addr) {
        (Some(f), Some(a)) if !f.exists => format!(
            "CORE-FAULT image={} base={:#x} file+{:#x} exists=NO: the core names this image and no such file is on \
             this host, so there is nothing to symbolize; pass --prefix if the guest tree is mounted elsewhere",
            f.name, f.base, f.file_off
        ),
        (Some(f), Some(a)) => format!(
            "CORE-FAULT image={} base={:#x} file+{:#x} vm+{:#x} image_addr={:#x} symbol={}{}",
            f.host.display(),
            f.base,
            f.file_off,
            a.vm,
            a.vm,
            a.symbol.clone().unwrap_or_else(|| "<no symbol>".into()),
            if a.converted {
                ""
            } else {
                " (NOT converted: this image is not a Mach-O, so its file offset is not its symbolizer address)"
            }
        ),
        _ => format!(
            "CORE-FAULT unresolved: {rip:#x} is in no mapping this core's NT_FILE lists{}",
            if anon_hint {
                " -- it IS inside a PT_LOAD the dump carries, i.e. an ANONYMOUS mapping, which has no image name to give"
            } else {
                ""
            }
        ),
    };
    let insn_line = match (&insn_bytes, &fault) {
        (Some(_), Some(f)) => format!(
            "CORE-INSN {insn_hex}{} (read from {} at file offset {:#x}; the core itself does not carry that page)",
            if trap.is_empty() { String::new() } else { format!(" -- {trap}") },
            f.host.display(),
            f.file_off
        ),
        (Some(_), None) => format!("CORE-INSN {insn_hex}"),
        (None, Some(f) ) if f.exists => format!(
            "CORE-INSN <unreadable: cannot open {} at file offset {:#x}>",
            f.host.display(),
            f.file_off
        ),
        _ => "CORE-INSN <no address in an image to read>".to_string(),
    };
    let operands_lines: Vec<String> = match &operands {
        Some(o) => vec![
            "CORE-OPERANDS source=registers-at-trap (BEST-EFFORT: the guest image carries no debug info and a core \
             is one instruction, so the register file is the only place these can come from; the rule is that a \
             register POINTS AT a word whose low bits name an owner another register also holds -- re-read the \
             disassembly before trusting a value from here)"
                .to_string(),
            format!(
                "CORE-OPERANDS predicate_reg={} predicate={:#x} once_word={:#x} once_word_reg={} masked_owner={:#x} \
                 masked_owner_reg={} check={}",
                o.predicate_reg,
                o.predicate,
                o.word,
                o.word_reg.unwrap_or("<no register holds the word itself>"),
                o.owner,
                o.owner_reg,
                if o.word_reg.is_some() {
                    "consistent (the word a register holds equals the word at the pointer)"
                } else {
                    "PARTIAL (no register holds the word itself: only the dereference gave it)"
                }
            ),
        ],
        None => vec![format!("CORE-OPERANDS unavailable: {operand_why}")],
    };
    let tsd_line = match &tsd {
        Ok(0) => format!(
            "CORE-OPERANDS-TSD3 gs_base={gs_base:#x} slot={TSD_SELF_SLOT} value=0x0 (ZERO: this thread's identity \
             word names nobody, so it can exclude no other thread)"
        ),
        Ok(v) => format!(
            "CORE-OPERANDS-TSD3 gs_base={gs_base:#x} slot={TSD_SELF_SLOT} value={v:#x} (*(unsigned long*)($gs_base+{}) \
             = __TSD_MACH_THREAD_SELF)",
            TSD_SELF_SLOT * TSD_SLOT_BYTES
        ),
        Err(e) => format!("CORE-OPERANDS-TSD3 gs_base={gs_base:#x} slot={TSD_SELF_SLOT} value=UNREADABLE ({e})"),
    };
    let walk_lines: Vec<String> = walk
        .iter()
        .enumerate()
        .map(|(i, (f, a))| match (a, &f.image) {
            (Some(a), Some(im)) => format!(
                "  #{i} fp={:#x} {:#x} {} file+{:#x} vm+{:#x} {}",
                f.fp,
                f.ret,
                basename_of(&im.host),
                im.file_off,
                a.vm,
                a.symbol.clone().unwrap_or_else(|| "<no symbol>".into())
            ),
            _ => format!("  #{i} fp={:#x} {:#x} <no image>", f.fp, f.ret),
        })
        .collect();

    if args.json {
        let sig_obj = match sig {
            Some(s) => json_object(vec![
                ("signo", s.signo.to_string()),
                ("name", jstr(&sig_label(s.signo))),
                ("meaning", jstr(sig_meaning(&s.signo.to_string()).unwrap_or(""))),
                ("si_code", s.code.to_string()),
                ("si_code_meaning", jstr(sig_code_meaning(s.signo, s.code).unwrap_or(""))),
                ("si_errno", s.errno.to_string()),
                ("si_addr", format!("\"{:#x}\"", s.addr)),
            ]),
            None => "null".to_string(),
        };
        let fault_obj = match (&fault, &fault_addr) {
            (Some(f), Some(a)) => json_object(vec![
                ("path", jstr(&f.host.display().to_string())),
                ("path_as_the_core_names_it", jstr(&f.name)),
                ("exists", f.exists.to_string()),
                ("base", format!("\"{:#x}\"", f.base)),
                ("file_offset", format!("\"{:#x}\"", f.file_off)),
                ("image_addr", format!("\"{:#x}\"", a.vm)),
                ("image_addr_converted", a.converted.to_string()),
                ("symbol", a.symbol.clone().map(|s| jstr(&s)).unwrap_or_else(|| "null".into())),
            ]),
            _ => "null".to_string(),
        };
        let operands_obj = match &operands {
            Some(o) => json_object(vec![
                ("predicate_reg", jstr(o.predicate_reg)),
                ("predicate", format!("\"{:#x}\"", o.predicate)),
                ("once_word", format!("\"{:#x}\"", o.word)),
                ("once_word_reg", o.word_reg.map(jstr).unwrap_or_else(|| "null".into())),
                ("masked_owner", format!("\"{:#x}\"", o.owner)),
                ("masked_owner_reg", jstr(o.owner_reg)),
            ]),
            None => "null".to_string(),
        };
        let tsd_obj = match &tsd {
            Ok(v) => json_object(vec![
                ("address", format!("\"{:#x}\"", tsd_self_addr(gs_base))),
                ("slot", TSD_SELF_SLOT.to_string()),
                ("value", format!("\"{v:#x}\"")),
                ("zero", (*v == 0).to_string()),
            ]),
            Err(e) => json_object(vec![
                ("address", format!("\"{:#x}\"", tsd_self_addr(gs_base))),
                ("slot", TSD_SELF_SLOT.to_string()),
                ("value", "null".to_string()),
                ("read_error", jstr(e)),
            ]),
        };
        let callers: String = walk
            .iter()
            .map(|(f, a)| {
                let (img, off, vm, sym) = match (a, &f.image) {
                    (Some(a), Some(im)) => {
                        (Some(im.host.display().to_string()), Some(im.file_off), Some(a.vm), a.symbol.clone())
                    }
                    _ => (None, None, None, None),
                };
                json_object(vec![
                    ("fp", format!("\"{:#x}\"", f.fp)),
                    ("ret", format!("\"{:#x}\"", f.ret)),
                    ("image", img.map(|s| jstr(&s)).unwrap_or_else(|| "null".into())),
                    ("file_offset", off.map(|o| format!("\"{o:#x}\"")).unwrap_or_else(|| "null".into())),
                    ("image_addr", vm.map(|v| format!("\"{v:#x}\"")).unwrap_or_else(|| "null".into())),
                    ("symbol", sym.map(|s| jstr(&s)).unwrap_or_else(|| "null".into())),
                ])
            })
            .collect::<Vec<_>>()
            .join(",");
        let log_obj = match (&args.log, &mark) {
            (Some(p), Some(m)) => json_object(vec![
                ("path", jstr(&p.display().to_string())),
                ("mark_sig", m.sig.to_string()),
                ("mark_ip", format!("\"{:#x}\"", m.ip)),
                ("mark_ip_is_instruction_pointer_from_addr", m.ip_from_addr.to_string()),
                ("mark_tid", m.tid.map(|t| t.to_string()).unwrap_or_else(|| "null".into())),
                ("same_fault_as_the_core", (m.ip == rip).to_string()),
            ]),
            (Some(p), None) => json_object(vec![
                ("path", jstr(&p.display().to_string())),
                ("mark", "null".to_string()),
                ("note", jstr("the log carries no [sigexc-fatal mark this reader can attribute")),
            ]),
            (None, _) => "null".to_string(),
        };
        let traces = if args.traces { core_gdb_traces(&c.file) } else { Vec::new() };
        println!(
            "{}",
            json_object(vec![
                ("core", jstr(&core.display().to_string())),
                ("size", size.to_string()),
                ("signal", sig.map(|s| jstr(&sig_label(s.signo))).unwrap_or_else(|| "null".into())),
                ("siginfo", sig_obj),
                ("faulting_lwp", faulting_lwp.to_string()),
                ("faulting_thread_rule", jstr(&how_faulting)),
                ("threads", threads.to_string()),
                ("rip", format!("\"{rip:#x}\"")),
                ("rsp", format!("\"{rsp:#x}\"")),
                ("rbp", format!("\"{rbp:#x}\"")),
                ("gs_base", format!("\"{gs_base:#x}\"")),
                ("image", fault.as_ref().map(|f| jstr(&f.host.display().to_string())).unwrap_or_else(|| "null".into())),
                ("offset", format!("\"{:#x}\"", fault.as_ref().map(|f| f.file_off).unwrap_or(0))),
                ("symbol", fault_addr.as_ref().and_then(|a| a.symbol.clone()).map(|s| jstr(&s)).unwrap_or_else(|| "null".into())),
                ("fault", fault_obj),
                ("insn", jstr(&insn_hex)),
                ("trap", jstr(trap)),
                ("operands", operands_obj),
                ("operands_why", jstr(&operand_why)),
                ("tsd_self", tsd_obj),
                ("mappings", maps_count.to_string()),
                ("range_scale", jstr(match scale { MapScale::Pages => "pages", MapScale::Bytes => "bytes" })),
                ("file_offset_unit_declared_by_the_note", file_page.to_string()),
                ("range_scale_evidence", json_object(vec![
                    ("entries_inside_a_ptload_as_bytes", bytes_inside.to_string()),
                    ("entries_inside_a_ptload_as_pages", pages_inside.to_string()),
                ])),
                ("frames", format!("[{}]", walk.iter().map(|(f, _)| format!("\"{:#x}\"", f.ret)).collect::<Vec<_>>().join(","))),
                ("callers", format!("[{callers}]")),
                ("callers_stop", jstr(&walk_stop)),
                ("generated_by", jstr(&generated_by)),
                ("log", log_obj),
                ("gdb_traces", format!("[{}]", traces.iter().map(|l| jstr(l)).collect::<Vec<_>>().join(","))),
            ])
        );
        return Ok(ExitCode::SUCCESS);
    }
    crate::say(&format!("CORE file={} size={size}", core.display()));
    crate::say(&sig_line);
    if let Some(s) = sig {
        if let Some(m) = sig_code_meaning(s.signo, s.code) {
            crate::say(&format!("CORE-SIGNAL-CODE {m}"));
        }
    }
    crate::say(&format!("CORE-THREAD faulting=lwp {faulting_lwp} of {threads} thread(s) ({how_faulting})"));
    crate::say(&format!(
        "CORE-REGISTERS rip={rip:#x} rsp={rsp:#x} rbp={rbp:#x} rdi={:#x} gs_base={gs_base:#x}",
        regs.get("rdi").unwrap_or(0)
    ));
    if !generated_by.is_empty() {
        crate::say(&format!("CORE-GENERATED-BY {generated_by}"));
    }
    crate::say(&format!(
        "CORE-MAPPINGS source=NT_FILE count={maps_count} range-scale={} (decided from this core: {bytes_inside} of \
         {maps_count} entries fall inside a PT_LOAD as bytes, {pages_inside} as pages) file-offset-unit={}",
        match scale {
            MapScale::Pages => "pages",
            MapScale::Bytes => "bytes",
        },
        if file_page == 1 { "bytes (the note declares page_size=1)" } else { "the note's declared page size" }
    ));
    crate::say(&fault_line);
    crate::say(&insn_line);
    for l in &operands_lines {
        crate::say(l);
    }
    crate::say(&tsd_line);
    if let Some(log) = args.log.as_ref() {
        match &mark {
            Some(m) => crate::say(&format!(
                "CORE-LOG {} marks sig={} ip={:#x} tid={} -- this core's faulting thread is lwp {faulting_lwp} at \
                 rip {rip:#x}, so the two ip values {}",
                log.display(),
                m.sig,
                m.ip,
                m.tid.map(|t| t.to_string()).unwrap_or_else(|| "<none: this mark carries no tid=>".into()),
                if m.ip == rip {
                    "AGREE: both files describe the same fault"
                } else {
                    "DIFFER: the log and the core are not describing the same fault, so neither may be read as \
                     evidence for the other"
                }
            )),
            None => crate::say(&format!(
                "CORE-LOG {} carries no [sigexc-fatal mark this reader can attribute (a mark with no rip= needs a \
                 synchronous trap's addr=), so the faulting thread comes from the core's own note order",
                log.display()
            )),
        }
    }
    // EVERY caller symbolized, because that is the work this command exists to remove: doing it by hand took a
    // python script over NT_FILE and a gdb round, and getting the scale or the de-virtualization wrong resolves
    // nothing while looking like an answer.
    crate::say(&format!(
        "CORE-STACK frames={} (walked through the core's own frame pointers and mapped through the core's own NT_FILE \
         table, not through gdb)",
        walk.len()
    ));
    for l in &walk_lines {
        crate::say(l);
    }
    crate::say(&format!("CORE-STACK-STOP {walk_stop}"));
    if args.traces {
        crate::say("CORE-TRACES-GDB gdb's own view, printed verbatim: on a guest core its unwind is usually useless because it has no symbols or unwind information for the guest's Mach-O images, and seeing that is the point of the flag");
        for l in core_gdb_traces(&c.file) {
            crate::say(&format!("CORE-TRACES-GDB {l}"));
        }
    }
    Ok(ExitCode::SUCCESS)
}

// --------------------------------------------------------------------------------------------------------------------
// identity: the per-thread census, from a core or from a live prefix process
// --------------------------------------------------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct IdentityArgs {
    /// The core to census. Without it, the newest `core.*` under --dir is used.
    #[arg(long)]
    core: Option<PathBuf>,
    /// Directory holding cores when --core is not given.
    #[arg(long, default_value = "/tmp/t4cores")]
    dir: PathBuf,
    /// Census a LIVE process (host pid) instead of a core. This needs ptrace permission, because the thread's
    /// `gs_base` is a register and only a debugger can read it. TWO samples are taken with the target RUNNING in
    /// between: a stopped target cannot show a value changing, so a flag that could only ever be false would be a
    /// flag that measures nothing.
    #[arg(long)]
    pid: Option<u32>,
    /// Prefix whose images resolve each thread's instruction pointer. Defaults to DWDIAG_PREFIX.
    #[arg(long)]
    prefix: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

/// One thread's identity at one instant.
struct IdentitySample {
    lwp: u32,
    /// `__TSD_MACH_THREAD_SELF`, or a READ FAILURE with its reason. A failure is never replaced by a number: a
    /// plausible value where the read failed is exactly the defect this command exists to remove.
    slot3: Result<u64, String>,
    /// Whether the value CHANGED between two observations. `None` means unobservable (a core is one instant).
    unstable: Option<bool>,
    ip: u64,
    /// The image the instruction pointer is in, and the symbol there, where they resolve.
    ip_image: Option<Resolved>,
    ip_addr: Option<ImageAddr>,
    /// Set when this thread appeared in only one of the two live samples (thread churn, which is NOT instability).
    partial: bool,
}

/// The distinct identity values and the LWPs carrying each, most threads first.
///
/// A FAILED read is not a value: it has no identity to count, so it is carried as its own list rather than as a zero
/// (a zero is a real, meaningful value here -- "this thread's identity names nobody").
fn census_counts(samples: &[IdentitySample]) -> Vec<(u64, Vec<u32>)> {
    let mut out: Vec<(u64, Vec<u32>)> = Vec::new();
    for s in samples {
        let Ok(v) = s.slot3 else { continue };
        match out.iter_mut().find(|(x, _)| *x == v) {
            Some((_, lwps)) => lwps.push(s.lwp),
            None => out.push((v, vec![s.lwp])),
        }
    }
    out.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    out
}

/// Whether a value is shared by more than one thread. ZERO IS NOT A DUPLICATE and not a name either: an identity of 0
/// excludes nobody, so two threads at 0 are "not set", not "two threads claiming one name" -- the distinction the
/// existing core-lock census makes, kept here so the two commands cannot disagree about the same core.
fn value_is_duplicated(counts: &[(u64, Vec<u32>)], v: u64) -> bool {
    v != 0 && counts.iter().any(|(x, l)| *x == v && l.len() > 1)
}

/// Read a thread's `__TSD_MACH_THREAD_SELF` out of a core, or say exactly why it could not be read.
fn read_tsd_self(c: &mut CoreFile, gs_base: u64) -> Result<u64, String> {
    if gs_base == 0 {
        return Err("gs_base is 0 in this thread's register note, so there is no TSD block to read".to_string());
    }
    let addr = tsd_self_addr(gs_base);
    c.read_u64(addr).map_err(|e| format!("{e} (slot {TSD_SELF_SLOT} at {addr:#x})"))
}

/// The gdb script a LIVE census runs. `thread apply all` is what makes it a census, and every line carries the gdb
/// thread number so a dropped line is DETECTABLE against `info threads` instead of silently changing the count.
///
/// The `$gs_base == 0` branch is MEASURED and necessary: on Linux x86-64 a thread's thread-local storage lives in FS,
/// so GS is 0 for a HOST process and `*(unsigned long*)(0+24)` would make gdb abort the whole `thread apply all` at
/// the first thread -- turning a census into a one-line error. A Darling GUEST is what this command is usually
/// pointed at, and its GS base is real (0x763d6f130060 on /tmp/t4cores/core.127004); a host process instead gets a
/// stated per-thread read failure, which is the answer: its identity is not GS-based.
const IDENTITY_GDB_SCRIPT: &str = r#"set pagination off
set confirm off
define dvid
  if $gs_base == 0
    printf "@ident tid=%d gs=0x0 ip=%#lx slot3=UNREADABLE\n", $_thread, $pc
  else
    printf "@ident tid=%d gs=%#lx ip=%#lx slot3=%#lx\n", $_thread, $gs_base, $pc, *(unsigned long*)($gs_base+24)
  end
end
thread apply all dvid
"#;

/// One gdb attach's worth of a live census.
#[derive(Default)]
struct LiveSample {
    /// gdb thread number -> `(gs_base, ip, slot3)`.
    rows: BTreeMap<u32, (u64, u64, Result<u64, String>)>,
    /// gdb thread number -> LWP, from `info threads`.
    lwp: BTreeMap<u32, u32>,
    /// How many threads `info threads` listed, so a script that stopped early shows up as a gap.
    listed: usize,
    /// gdb's own stderr, kept because a failed memory read is the usual reason for that gap.
    error: Option<String>,
}

/// Parse one gdb attach. Kept separate from running gdb so the join and the gap detection are testable on captured
/// output -- the same reason the existing core-lock parser is separate from its gdb run.
fn parse_live_sample(text: &str, error: Option<String>) -> LiveSample {
    let mut s = LiveSample { error, ..Default::default() };
    let re_thread = Regex::new(r"^\s*\*?\s*(\d+)\s+.*\(LWP (\d+)\)").unwrap();
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("@ident ") {
            // `tid=` is the gdb thread NUMBER, which the script prints with `%d` (DECIMAL), while gs/ip/slot3 are
            // `%#lx` (hex). MEASURED defect this avoids: parsing the number as hex made thread 10 read as 16, so
            // from the tenth thread on, the row stopped matching its LWP and EVERY thread became a "no @ident line"
            // failure -- a census whose threads silently disappear, which is the failure this command exists to
            // remove. A target with ten or more threads is therefore what the contract starts.
            let field = |k: &str| -> Option<&str> { rest.split_whitespace().find_map(|w| w.strip_prefix(k)) };
            let hex = |k: &str| -> Option<u64> {
                field(k).and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            };
            let Some(tid) = field("tid=").and_then(|v| v.parse::<u32>().ok()) else { continue };
            let gs = hex("gs=").unwrap_or(0);
            let ip = hex("ip=").unwrap_or(0);
            // A zero here is `$gs_base` being 0, which is a thread with no TSD block, not a failed read: the script
            // only prints a value when the read SUCCEEDED, so a zero is the value that was actually read.
            let slot = match hex("slot3=") {
                Some(v) if gs != 0 => Ok(v),
                _ if gs == 0 => Err("$gs_base = 0: no GS-based TSD block to read".to_string()),
                _ => Err("gdb printed no slot3= value for this thread".to_string()),
            };
            s.rows.insert(tid, (gs, ip, slot));
            continue;
        }
        if let Some(c) = re_thread.captures(line) {
            if let (Ok(tid), Ok(lwp)) = (c[1].parse::<u32>(), c[2].parse::<u32>()) {
                s.lwp.insert(tid, lwp);
            }
        }
    }
    s.listed = s.lwp.len();
    s
}

/// One live sample: attach, read every thread, detach.
fn live_sample(pid: u32) -> Result<LiveSample, String> {
    // A UNIQUE script path per invocation. MEASURED: with a fixed name under /tmp, running the census as root failed
    // with "Permission denied" (it could not overwrite the file the invoking user already owned), and two concurrent
    // censuses would truncate each other's script. The file is removed once gdb has read it.
    let script = std::env::temp_dir().join(format!("dwdiag-identity-{}.gdb", std::process::id()));
    fs::write(&script, IDENTITY_GDB_SCRIPT).map_err(|e| format!("writing {}: {e}", script.display()))?;
    let out = Command::new("gdb")
        .args(["-nx", "-q", "-batch", "-iex", "set debuginfod enabled off"])
        .arg("-p")
        .arg(pid.to_string())
        // `info threads` runs BEFORE the script so the LWP map survives a script that stops part way.
        .arg("-ex")
        .arg("info threads")
        .arg("-x")
        .arg(&script)
        .output()
        .map_err(|e| format!("running gdb (ptrace permission is required to census a live process): {e}"))?;
    let _ = fs::remove_file(&script);
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.lines().filter(|l| !l.trim().is_empty()).take(4).collect::<Vec<_>>().join(" | ");
    Ok(parse_live_sample(&String::from_utf8_lossy(&out.stdout), if err.is_empty() { None } else { Some(err) }))
}

/// The live census: two samples, joined by LWP, with the target RUNNING in between.
///
/// A thread that gdb LISTED and never read is NOT dropped: it becomes a sample whose identity is a READ FAILURE with
/// the reason. Dropping it is the defect this command exists to remove -- a silently missing thread changes the count
/// of a shared identity, and the count is the answer.
fn live_identity(pid: u32) -> Result<Vec<IdentitySample>, String> {
    let first = live_sample(pid)?;
    std::thread::sleep(std::time::Duration::from_millis(250));
    let second = live_sample(pid)?;
    // AN EMPTY CENSUS IS NOT A MEASUREMENT. Every live process has at least one thread, so reading none means the
    // attach did not happen -- and a report of "0 threads" would read like a process with no threads. gdb's own
    // message is the answer to "why", and the usual one is a tracer permission this command cannot talk its way out
    // of: a non-root tracer may only attach to its OWN DESCENDANTS (kernel.yama.ptrace_scope).
    if first.rows.is_empty() && second.rows.is_empty() {
        return Err(format!(
            "gdb read no thread from pid {pid} ({} listed, none with an identity; gdb said: {}). ptrace_scope={}: a \
             non-root tracer may attach only to its own descendants, so run this census as the target's ancestor or \
             through sudo",
            first.listed.max(second.listed),
            first.error.clone().or(second.error).unwrap_or_else(|| "<no message>".to_string()),
            fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").unwrap_or_else(|_| "?".into()).trim(),
        ));
    }
    let lwps: std::collections::BTreeSet<u32> = first.lwp.values().chain(second.lwp.values()).copied().collect();
    let mut out = Vec::new();
    for lwp in lwps {
        let pick = |s: &LiveSample| -> Option<(u64, u64, Result<u64, String>)> {
            let tid = s.lwp.iter().find(|(_, l)| **l == lwp).map(|(t, _)| *t)?;
            s.rows.get(&tid).cloned()
        };
        let a = pick(&first);
        let b = pick(&second);
        let (slot3, unstable, partial, ip) = match (&a, &b) {
            // The value CHANGED between two attaches with the target running: that is what unstable means here, and
            // it is only observable because the target was resumed in between.
            (Some((_, _, x)), Some((_, ip, y))) => {
                (x.clone(), Some(x.as_ref().ok() != y.as_ref().ok()), false, *ip)
            }
            // Seen in only ONE sample: thread churn. Reporting that as instability would blame the value for the
            // thread pool's own lifecycle, so it is flagged separately.
            (Some((_, ip, x)), None) | (None, Some((_, ip, x))) => (x.clone(), None, true, *ip),
            (None, None) => {
                let why = format!(
                    "gdb listed this thread (LWP {lwp}) and printed no @ident line for it: the script's `thread apply \
                     all` stopped before reaching it, usually a memory read that failed{}",
                    first
                        .error
                        .as_ref()
                        .or(second.error.as_ref())
                        .map(|e| format!(" (gdb said: {e})"))
                        .unwrap_or_default()
                );
                (Err(why), None, true, 0)
            }
        };
        out.push(IdentitySample { lwp, slot3, unstable, ip, ip_image: None, ip_addr: None, partial });
    }
    out.sort_by_key(|s| s.lwp);
    // A census whose thread list came from `info threads` and whose values came from per-thread reads must SAY when
    // the two disagree by more than churn.
    let listed = first.listed.max(second.listed);
    let read = first.rows.len().max(second.rows.len());
    if listed > read {
        let n = out.iter().filter(|s| s.slot3.is_err()).count();
        if n == 0 {
            return Err(format!(
                "gdb listed {listed} thread(s) and read {read}: the difference is not accounted for per thread, so \
                 this census cannot be trusted"
            ));
        }
    }
    Ok(out)
}

/// Census the guest's per-thread identity: `__TSD_MACH_THREAD_SELF` (TSD slot 3) per thread, machine-readable flags
/// for zero, duplicate and unstable values, and a count per distinct value.
///
/// MEASURED why this is a command and not an incantation: the same census was taken by hand for the libdispatch
/// SIGILL, with `thread apply all p/x` piped through greps that silently dropped lines and produced a WRONG count
/// once -- and the number that mattered (most threads sharing one identity) is exactly the kind a truncated text
/// scrape gets wrong. A core is read through its own notes; a live process through two gdb attaches. Either way the
/// answer is per thread, with a stated failure where a read failed, and never a number where there was none.
fn run_identity(args: IdentityArgs) -> Result<ExitCode> {
    if args.pid.is_some() && args.core.is_some() {
        bail!("--pid censuses a LIVE process and --core reads a core file: give one, not both");
    }
    let prefix_owned = args.prefix.clone().or_else(|| {
        std::env::var("DWDIAG_PREFIX").ok().filter(|s| !s.is_empty()).map(PathBuf::from)
    });
    let prefix = prefix_owned.as_deref();
    let mut cache = SymCache::default();
    let mut samples: Vec<IdentitySample> = Vec::new();
    let source: String;
    let mut extra: Vec<(&str, String)> = Vec::new();
    let unstable_note;

    if let Some(pid) = args.pid {
        source = format!("live pid={pid}");
        samples = live_identity(pid).map_err(anyhow::Error::msg)?;
        let listed = samples.iter().filter(|s| !s.partial).count();
        extra.push(("live_samples", jstr("2 (the target ran between them)")));
        extra.push(("live_threads_seen_in_both_samples", listed.to_string()));
        extra.push((
            "live_threads_churned",
            samples.iter().filter(|s| s.partial).count().to_string(),
        ));
        unstable_note = "sampled by TWO attaches with the target running in between: a stopped target cannot show a \
                         value changing, so instability is only observable this way"
            .to_string();
        // The instruction pointers are resolved against the LIVE process's own maps.
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
            .map(|t| parse_maps_full(&t))
            .unwrap_or_default();
        for s in samples.iter_mut() {
            s.ip_image = live_resolve(&maps, s.ip, prefix);
            s.ip_addr = s.ip_image.as_ref().map(|r| image_addr_of(r, &mut cache));
        }
    } else {
        let core = match &args.core {
            Some(p) => p.clone(),
            None => newest_core(&args.dir, "core").with_context(|| {
                let pat = core_pattern();
                format!(
                    "nothing to census: no core under {} and no --pid. core_pattern is {} ({}{})",
                    args.dir.display(),
                    pat.pattern,
                    if pat.piped { "it PIPES the dump to a handler, so no file is kept" } else { "" },
                    if pat.piped { "" } else { "which writes into the directory part of the pattern" }
                )
            })?,
        };
        source = format!("core={}", core.display());
        let mut c = CoreFile::open(&core)?;
        let regs: Vec<(u32, u64, u64)> =
            c.threads.iter().map(|t| (t.lwp, t.regs.gs_base(), t.regs.rip())).collect();
        for (lwp, gs, ip) in regs {
            samples.push(IdentitySample {
                lwp,
                slot3: read_tsd_self(&mut c, gs),
                unstable: None,
                ip,
                ip_image: c.resolve(ip, prefix),
                ip_addr: None,
                partial: false,
            });
        }
        for s in samples.iter_mut() {
            s.ip_addr = s.ip_image.as_ref().map(|r| image_addr_of(r, &mut cache));
        }
        extra.push(("cores_check", jstr("read from the core's own notes (NT_PRSTATUS), not from gdb")));
        unstable_note = "unobservable in a core: a core is ONE instant, so no value can be seen to change. \
                         Re-read a live process with --pid to observe instability"
            .to_string();
    }
    samples.sort_by_key(|s| s.lwp);

    let counts = census_counts(&samples);
    let unreadable: Vec<&IdentitySample> = samples.iter().filter(|s| s.slot3.is_err()).collect();
    let zeros: Vec<u32> = samples.iter().filter(|s| s.slot3.as_ref().copied() == Ok(0)).map(|s| s.lwp).collect();
    let unstable: Vec<u32> = samples.iter().filter(|s| s.unstable == Some(true)).map(|s| s.lwp).collect();
    // MEASURED: a live HOST process has no GS-based TSD at all (Linux x86-64 keeps thread-locals in FS), so every
    // thread's read fails for the same reason. That is a fact about the TARGET, not about the reads, and it is said
    // once instead of leaving 28 identical read failures to be interpreted.
    let all_gs_zero = args.pid.is_some()
        && !samples.is_empty()
        && samples.iter().all(|s| {
            s.slot3.as_ref().err().map(|e| e.contains("$gs_base = 0") && !e.contains("no PT_LOAD")).unwrap_or(false)
        });

    if args.json {
        let threads_json: String = samples
            .iter()
            .map(|s| {
                json_object(vec![
                    ("lwp", s.lwp.to_string()),
                    ("slot3", s.slot3.as_ref().map(|v| format!("\"{v:#x}\"")).unwrap_or_else(|_| "null".into())),
                    ("read_error", s.slot3.as_ref().err().map(|e| jstr(e)).unwrap_or_else(|| "null".into())),
                    ("zero", (s.slot3.as_ref().copied() == Ok(0)).to_string()),
                    ("duplicate", s.slot3.as_ref().map(|v| value_is_duplicated(&counts, *v).to_string()).unwrap_or_else(|_| "null".into())),
                    ("unstable", s.unstable.map(|u| u.to_string()).unwrap_or_else(|| "null".into())),
                    ("seen_in_one_sample_only", s.partial.to_string()),
                    ("ip", format!("\"{:#x}\"", s.ip)),
                    ("image", s.ip_image.as_ref().map(|r| jstr(&r.host.display().to_string())).unwrap_or_else(|| "null".into())),
                    ("image_base", s.ip_image.as_ref().map(|r| format!("\"{:#x}\"", r.base)).unwrap_or_else(|| "null".into())),
                    ("image_addr", s.ip_addr.as_ref().map(|a| format!("\"{:#x}\"", a.vm)).unwrap_or_else(|| "null".into())),
                    ("image_addr_converted", s.ip_addr.as_ref().map(|a| a.converted.to_string()).unwrap_or_else(|| "null".into())),
                    ("symbol", s.ip_addr.as_ref().and_then(|a| a.symbol.clone()).map(|x| jstr(&x)).unwrap_or_else(|| "null".into())),
                ])
            })
            .collect::<Vec<_>>()
            .join(",");
        let groups = |f: fn(&(u64, Vec<u32>)) -> bool| -> String {
            counts
                .iter()
                .filter(|c| f(c))
                .map(|(v, l)| json_object(vec![
                    ("value", format!("\"{v:#x}\"")),
                    ("count", l.len().to_string()),
                    ("lwps", format!("[{}]", l.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","))),
                ]))
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut pairs: Vec<(&str, String)> = vec![
            ("source", jstr(&source)),
            ("slot", TSD_SELF_SLOT.to_string()),
            ("slot_address", jstr("*(unsigned long*)($gs_base+24)")),
            ("slot_name", jstr("__TSD_MACH_THREAD_SELF")),
            ("threads_total", samples.len().to_string()),
            ("distinct", counts.len().to_string()),
            ("threads", format!("[{threads_json}]")),
            ("summary", format!("[{}]", groups(|_| true))),
            ("duplicates", format!("[{}]", groups(|(v, l)| *v != 0 && l.len() > 1))),
            ("zero", format!("[{}]", zeros.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","))),
            ("unreadable", format!("[{}]", unreadable.iter().map(|s| s.lwp.to_string()).collect::<Vec<_>>().join(","))),
            ("unstable", if args.pid.is_some() { format!("[{}]", unstable.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")) } else { "null".to_string() }),
            ("unstable_note", jstr(&unstable_note)),
            ("not_a_guest_gs_based_tsd", all_gs_zero.to_string()),
            ("counts_note", jstr("a value of 0 is NOT counted as a duplicate: an identity of 0 names nobody, so two threads at 0 are unset rather than sharing a name")),
        ];
        for (k, v) in extra {
            pairs.push((k, v));
        }
        println!("{}", json_object(pairs));
        return Ok(ExitCode::SUCCESS);
    }

    crate::say(&format!("IDENTITY source={source} threads={}", samples.len()));
    crate::say(&format!(
        "IDENTITY-DEFINITION slot={TSD_SELF_SLOT} read=*(unsigned long*)($gs_base+24) name=__TSD_MACH_THREAD_SELF \
         -- the value libdispatch compares a lock's owner against; 0 means this thread's identity names nobody"
    ));
    for s in &samples {
        let (slot, dup) = match &s.slot3 {
            Ok(v) => (format!("{v:#x}"), Some(value_is_duplicated(&counts, *v))),
            Err(e) => (format!("UNREADABLE ({e})"), None),
        };
        let img = match (&s.ip_image, &s.ip_addr) {
            (Some(r), Some(a)) if a.converted => format!(
                " image={} image_base={:#x} image_addr={:#x} symbol={}",
                basename_of(&r.host),
                r.base,
                a.vm,
                a.symbol.clone().unwrap_or_else(|| "<no symbol>".into())
            ),
            // A non-Mach-O image (a host core's libc, where a guest thread's own pthread really is): the file offset
            // is printed as what it IS, because the symbol tables do not address by file offset and calling it an
            // image address would make a `no symbol` look like a finding about the image.
            (Some(r), Some(a)) => format!(
                " image={} image_base={:#x} file+{:#x} (NOT converted: not a Mach-O, so this is a file offset and the \
                 symbol lookup for it is meaningless) symbol={}",
                basename_of(&r.host),
                r.base,
                a.vm,
                a.symbol.clone().unwrap_or_else(|| "null".into())
            ),
            _ => " image=<none: the instruction pointer is in no file-backed mapping>".to_string(),
        };
        crate::say(&format!(
            "IDENTITY-THREAD lwp={} slot3={slot} zero={} duplicate={} unstable={} ip={:#x}{img}{}",
            s.lwp,
            matches!(s.slot3, Ok(0)),
            dup.map(|d| d.to_string()).unwrap_or_else(|| "null".into()),
            s.unstable.map(|u| u.to_string()).unwrap_or_else(|| "n/a".into()),
            s.ip,
            if s.partial { " seen_in_one_sample_only=true" } else { "" }
        ));
    }
    for (v, lwps) in &counts {
        if value_is_duplicated(&counts, *v) {
            crate::say(&format!(
                "IDENTITY-DUPLICATE value={v:#x} count={} lwps={} (these threads carry the SAME identity, so a lock \
                 held by one reads as held by the other)",
                lwps.len(),
                lwps.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
            ));
        }
    }
    for (v, lwps) in &counts {
        crate::say(&format!("IDENTITY-SUMMARY value={v:#x} count={}", lwps.len()));
    }
    crate::say(&format!(
        "IDENTITY-SUMMARY distinct={} threads={} unreadable={} zero={}",
        counts.len(),
        samples.len(),
        unreadable.len(),
        zeros.len()
    ));
    if !zeros.is_empty() {
        crate::say(&format!(
            "IDENTITY-ZERO lwps={} (an identity of 0 excludes nobody and clears whatever word its unlock writes; \
             decide whether these are guest pthreads before blaming them)",
            zeros.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
        ));
    }
    if !unreadable.is_empty() {
        // Grouped by REASON with the LWPs listed: thirty identical paragraphs hide the fact that it is one cause,
        // while a per-thread attribution is still what a reader needs. The JSON keeps the failure per thread.
        let mut groups: Vec<(String, Vec<u32>)> = Vec::new();
        for s in &unreadable {
            let why = s.slot3.as_ref().err().cloned().unwrap_or_default();
            match groups.iter_mut().find(|(r, _)| *r == why) {
                Some((_, l)) => l.push(s.lwp),
                None => groups.push((why, vec![s.lwp])),
            }
        }
        for (why, lwps) in groups {
            crate::say(&format!(
                "IDENTITY-READ-FAILURE reason={why} lwps={}",
                lwps.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
            ));
        }
    }
    crate::say(&format!("IDENTITY-UNSTABLE {unstable_note}"));
    if all_gs_zero {
        crate::say(
            "IDENTITY-NOT-A-GUEST every thread's $gs_base is 0, so this process keeps its thread-local storage in FS \
             and has no GS-based TSD: it is a HOST process, not a Darling guest, and the identity this command reads \
             does not exist in it -- which is why every thread is reported as a read FAILURE rather than as a zero",
        );
    }
    if args.pid.is_some() {
        crate::say(&format!(
            "IDENTITY-LIVE threads_seen_in_both_samples={} churned={} (a thread in one sample only is the thread \
             pool's lifecycle, not an unstable value)",
            samples.iter().filter(|s| !s.partial).count(),
            samples.iter().filter(|s| s.partial).count()
        ));
    }
    Ok(ExitCode::SUCCESS)
}

/// Resolve a live process's instruction pointer through its OWN `/proc/<pid>/maps`, which is the live counterpart of
/// the core's NT_FILE table: same question, same shape of answer.
fn live_resolve(maps: &[MapRegion], ip: u64, prefix: Option<&Path>) -> Option<Resolved> {
    let r = maps.iter().find(|m| m.lo <= ip && ip < m.hi)?;
    if r.file.is_empty() {
        return None;
    }
    let hit = guest_path_to_host(&r.file, prefix);
    let exists = hit.is_some();
    Some(Resolved {
        base: r.lo,
        name: r.file.clone(),
        host: hit.unwrap_or_else(|| PathBuf::from(&r.file)),
        exists,
        file_off: r.file_off + (ip - r.lo),
    })
}

/// The signature of a process that is not working any more: one pattern repeating near the END of the log with
/// almost nothing new between its repetitions.
///
/// MEASURED need, and it cost this session three wrong answers. "The log stopped growing" cannot tell a stuck
/// process from an EXITED one (two runs were read as a stall after the linker had already exited), and line
/// COUNTS only say what a process has done, never whether it is still doing anything. What actually identified
/// the failure was seeing `pc-entry -> pc-postplane st=#- -> pc-return-9+` repeat for pages with nothing new
/// between, found by hand. This is that observation as a command.
///
/// Both inputs are censused together on purpose: the spinning markers sit in the guest image's own log while the
/// run's progress lines sit in the harness log, and a report that reads only one of them sees half the story.
fn run_loops(args: LoopsArgs) -> Result<ExitCode> {
    let mut paths: Vec<PathBuf> = Vec::new();
    match &args.log {
        Some(p) => paths.push(p.clone()),
        None => {
            if let Some(p) = newest_verdict_log() { paths.push(p); }
        }
    }
    if let Some(p) = &args.guest_log { paths.push(p.clone()); }
    if paths.is_empty() {
        bail!("nothing to read: pass --log and/or --guest-log (no `dwdiag-verdict-*.log` in the temp directory)");
    }

    let mut lines: Vec<String> = Vec::new();
    for p in &paths {
        let text = read_log_lossy(p).with_context(|| format!("reading {}", p.display()))?;
        for l in text.lines() {
            let t = l.trim();
            if !t.is_empty() { lines.push(normalize_line(t)); }
        }
    }
    if lines.is_empty() { bail!("the logs were empty"); }

    let total = lines.len();
    let tail_start = ((total as f64) * (1.0 - args.tail_frac.clamp(0.0, 0.99))) as usize;
    // first, last, count per pattern
    let mut stat: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    for (i, l) in lines.iter().enumerate() {
        let e = stat.entry(l.as_str()).or_insert((i, i, 0));
        e.1 = i;
        e.2 += 1;
    }
    let mut rows: Vec<(usize, usize, usize, &str)> = stat
        .iter()
        .filter(|(_, (_, last, count))| *count >= args.min && *last >= tail_start)
        .map(|(l, (first, last, count))| (*count, last - first, *last, *l))
        .collect();
    rows.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    rows.truncate(10);

    let mut distinct_cache: Vec<(usize, usize, usize, &str, usize)> = Vec::new();
    for (count, _, last, line) in &rows {
        let (first, _, _) = stat.get(*line).copied().unwrap_or((0, 0, 0));
        let distinct = lines[first..=*last].iter().collect::<std::collections::HashSet<_>>().len();
        distinct_cache.push((*count, first, *last, line, distinct));
    }
    // THE DECIDING MEASUREMENT IS THE TAIL'S OWN VARIETY, not a ratio between repeats and span. MEASURED twice:
    // a repeat/span ratio flags any busy log (a working run repeats `pc-entry` thousands of times too), and the
    // first version of this file compared the count against the span in LINES, which is thousands either way.
    // What actually separated the two runs was this: the spinning log's last lines were the SAME FOUR markers
    // over and over, while a working log's tail keeps producing lines it has not produced before.
    let tail_len = args.tail_len.min(total);
    let tail_distinct = lines[total - tail_len..].iter().collect::<std::collections::HashSet<_>>().len();
    let kind = loop_tail_kind(rows.len(), tail_len, tail_distinct, args.spin_max_distinct);

    if args.json {
        println!("{{\"lines\":{total},\"tail_from\":{tail_start},\"tail_len\":{tail_len},\"tail_distinct\":{tail_distinct},\"kind\":\"{kind}\",\"patterns\":[{}]}}",
            distinct_cache.iter().map(|(c, f, l, t, d)| format!(
                "{{\"count\":{c},\"first\":{f},\"last\":{l},\"distinct_in_span\":{d},\"pattern\":{}}}", jstr(t))).collect::<Vec<_>>().join(","));
        return Ok(ExitCode::SUCCESS);
    }
    crate::say(&format!("LOOPS log={} lines={} tail_from={} min={} tail_frac={}",
        paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(","),
        total, tail_start, args.min, args.tail_frac));
    for (count, first, last, t, distinct) in &distinct_cache {
        crate::say(&format!("LOOP count={count} span_lines={} distinct_in_span={distinct} first={first} last={last} line={t}",
            last - first));
    }
    crate::say(&format!("LOOPS-VERDICT patterns={} tail_lines={} tail_distinct={} tail={kind}",
        rows.len(), tail_len, tail_distinct));
    if rows.is_empty() {
        crate::say("LOOPS-NOTE no pattern meets the repetition threshold near the tail; this is not a spin finding and does not establish the process's state");
    }
    if kind != "spin" {
        crate::say("LOOPS-NOTE the selected log tail does not establish a spin or forward progress: correlate with the process's identity, wait state and exit evidence");
    }
    Ok(ExitCode::SUCCESS)
}

fn loop_tail_kind(patterns: usize, tail_len: usize, tail_distinct: usize, max_distinct: usize) -> &'static str {
    if tail_len == 0 {
        "unmeasured"
    } else if tail_distinct == tail_len {
        "nonrepeating"
    } else if patterns == 0 {
        "insufficient-repetition"
    } else if tail_distinct <= max_distinct {
        "spin"
    } else {
        "varied"
    }
}

/// A line with its variable parts erased, so repetitions become the SAME string. Without this every line differs
/// by a pid, a tid, a stack word or an address, and a loop of a thousand identical events looks like a thousand
/// unique ones -- which is exactly how a spin is missed by eye and by grep.
fn normalize_line(l: &str) -> String {
    let mut out = String::with_capacity(l.len());
    let mut characters = l.chars().peekable();
    while let Some(c) = characters.next() {
        // Start at a digit, never a hex letter in a marker such as pc-entry.
        if c.is_ascii_digit() {
            out.push('#');
            if c == '0' {
                let mut prefix = characters.clone();
                if matches!(prefix.next(), Some('x' | 'X'))
                    && prefix.next().is_some_and(|next| next.is_ascii_hexdigit())
                {
                    characters.next();
                }
            }
            while characters.peek().is_some_and(|next| next.is_ascii_hexdigit()) {
                characters.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The kernel already answered "which instruction died", and this reads its answer instead of re-deriving
/// it. A guest fault is delivered by the host, so the host logs it:
///
///   traps: mldr[1747380] trap invalid opcode ip:778c2145e5fa sp:... error:0 in libsystem_kernel.dylib[778c21416000+9d000]
///
/// MEASURED, and it is why this command exists: in one session that single line named the faulting image,
/// its load base, the offset and -- after one symbolize -- the function, while three custom probes, a gdb
/// catch and a stack scanner had produced a story that was wrong twice. The line is written whether or not
/// a core is kept (`ulimit -c 0` here), which is exactly the case where the usual routes fail.
fn run_trap(args: TrapArgs) -> Result<ExitCode> {
    let text = match &args.kernel_log {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        None => {
            let sudo = sudo_prefix();
            let mut cmd = Command::new(sudo.first().copied().unwrap_or("dmesg"));
            if !sudo.is_empty() { cmd.arg(sudo[1]); }
            let mut out = cmd.arg("dmesg").output();
            if out.as_ref().map(|o| !o.status.success()).unwrap_or(true) {
                out = Command::new("journalctl").args(["-k", "--no-pager", "-n", "20000"]).output();
            }
            String::from_utf8_lossy(&out.context("running dmesg/journalctl")?.stdout).into_owned()
        }
    };

    let runtime = crate::installed_runtime_root().ok();
    if let Some(prefix) = &args.prefix { println!("TRAP guest-prefix={} (not an image root)", prefix.display()); }

    let mut rows: Vec<String> = Vec::new();
    for line in text.lines() {
        if !line.contains("trap ") && !line.contains("segfault at ") && !line.contains("general protection") {
            continue;
        }
        let Some((name, pid, reason, ip, image, base, size)) = parse_trap_line(line) else { continue };
        if let Some(want) = &args.process {
            if !name.contains(want.as_str()) { continue; }
        }
        let sym = match runtime {
            Some(root) => resolve_installed_image(root, &image)
                .and_then(|path| unwind_symbolize(ip.wrapping_sub(base), path.to_str().unwrap_or("")))
                .unwrap_or_else(|| "<image not found in selected installation>".to_string()),
            None => "<installed image identity unavailable; pass --runtime-root>".to_string(),
        };
        rows.push(format!(
            "TRAP pid={} name={} reason={} image={} base={:#x} size={:#x} off={:#x} -> {}",
            pid, name, reason, image, base, size, ip.wrapping_sub(base), sym
        ));
    }
    // Newest last, then cut to the requested number: the interesting one is the most recent.
    if rows.len() > args.limit { rows.drain(0..rows.len() - args.limit); }
    if args.json {
        println!("{{\"traps\":[{}]}}", rows.iter()
            .map(|r| format!("{{\"line\":{}}}", jesc(r)))
            .collect::<Vec<_>>().join(","));
        return Ok(ExitCode::SUCCESS);
    }
    crate::say(&format!("TRAP-CENSUS source={} reported={}",
        args.kernel_log.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "dmesg".into()),
        rows.len()));
    if !rows.is_empty() {
        // Stated because it bit this command on its first run: `symbolize` answers with the nearest symbol AT OR
        // BELOW the address, so when the containing function is absent from the table the answer is the PREVIOUS
        // function plus an offset larger than that function's own size (`__simple_atoi16 + 0xea`, whose function
        // is about 0x9a long). That offset is the tell, and the reader must not have to know the table to spot it.
        crate::say("TRAP-NOTE symbols come from `symbolize`, which reports the nearest symbol AT OR BELOW the address; an offset larger than that function's size means the containing function is missing from the table, so read `off` as the fact and the symbol as a hint");
    }
    for r in &rows { crate::say(r); }
    if rows.is_empty() {
        crate::say("TRAP-NOTE no trap line matched; the kernel reports a guest fault only when the signal is \
                    delivered by the host, and a masked signal may be logged as nothing at all");
    }
    Ok(ExitCode::SUCCESS)
}

/// `... traps: NAME[PID] trap REASON ip:IP sp:SP error:E in IMAGE[BASE+SIZE]`
/// `... NAME[PID]: segfault at IP ip SP sp error E in IMAGE[BASE+SIZE] ...`
fn parse_trap_line(line: &str) -> Option<(String, u64, String, u64, String, u64, u64)> {
    // Two shapes, and both matter:
    //   traps: NAME[PID] trap invalid opcode ip:HEX sp:... error:0 in IMG[BASE+SIZE]
    //   NAME[PID]: segfault at HEX ip HEX sp HEX error E in IMG[BASE+SIZE]
    // The second has no "traps: " prefix, its pid is followed by a colon, and its ip carries no '='.
    // A parser written for the first shape silently reports NOTHING for the second, which is worse than
    // reporting an error, so both are handled here and the contract carries one line of each shape.
    // Drop the kernel's timestamp first. MEASURED: the segfault shape starts "[  125.000000] NAME[PID]:", and
    // with the spaces inside those brackets intact the first whitespace token is "[" -- so the pid parse got an
    // empty string and the whole line was dropped. The contract carries that exact line.
    let stripped = line.split_once("] ").map(|(_, rest)| rest).unwrap_or(line);
    let after = line.split("traps: ").nth(1).unwrap_or(stripped);
    let mut it = after.split_whitespace();
    let head = it.next()?;
    let (name, pid_s) = head.split_once('[')?;
    // digits only: the pid is followed by ']' in one shape and by ']:' in the other
    let pid: u64 = pid_s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()?;
    let reason = it.next()?.trim_end_matches(':').to_string();
    let mut ip = None;
    let mut image = None;
    let mut base = None;
    let mut size = None;
    let mut prev_was_ip = false;
    for tok in it {
        if prev_was_ip {
            ip = u64::from_str_radix(tok, 16).ok();
            prev_was_ip = false;
            continue;
        }
        if tok == "ip" {
            prev_was_ip = true;
        } else if let Some(v) = tok.strip_prefix("ip:") {
            ip = u64::from_str_radix(v, 16).ok();
        } else if let Some(v) = tok.strip_prefix("ip=") {
            ip = u64::from_str_radix(v, 16).ok();
        } else if let Some(open) = tok.find('[') {
            let img = tok[..open].to_string();
            let rest = &tok[open + 1..];
            if let Some((b, sz)) = rest.trim_end_matches(']').split_once('+') {
                base = u64::from_str_radix(b, 16).ok();
                size = u64::from_str_radix(sz, 16).ok();
                image = Some(img);
            }
        }
    }
    Some((name.to_string(), pid, reason, ip?, image?, base?, size?))
}

/// Find an image only in the selected immutable installation, never guest system aliases.
fn resolve_installed_image(root: &Path, image: &str) -> Option<PathBuf> {
    const DIRS: [&str; 4] = [
        "bin", "libexec/darling/usr/lib/system", "libexec/darling/usr/lib",
        "libexec/darling/usr/libexec/darling",
    ];
    for d in DIRS {
        let p = root.join(d).join(image);
        if let Ok(resolved) = fs::canonicalize(&p) {
            if resolved.starts_with(root) && resolved.is_file() { return Some(resolved); }
        }
    }
    // Anything else: bounded walk, only for the file we were told to find.
    fn walk(dir: &std::path::Path, want: &str, depth: usize) -> Option<PathBuf> {
        if depth == 0 { return None; }
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            let p = e.path();
            let kind = e.file_type().ok()?;
            if kind.is_file() && p.file_name().map(|name| name == want).unwrap_or(false) { return Some(p); }
            if kind.is_dir() {
                if let Some(f) = walk(&p, want, depth - 1) { return Some(f); }
            }
        }
        None
    }
    walk(&root.join("libexec/darling"), image, 8)
}

/// The word gdb wants after `handle`: a bare signal NAME.
///
/// `--catch SIGSEGV` is what a reader writes, and the first version turned it into `SIGSIGSEGV`, which gdb
/// rejects with "Unrecognized or ambiguous flag word" -- a measurement that reports nothing about the guest.
/// Accept the name with or without its `SIG` prefix, and pass a signal NUMBER through unchanged, because gdb
/// understands both spellings but not a doubled one.
fn gdb_signal_word(name: &str) -> String {
    let t = name.trim();
    if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
        return t.to_string();
    }
    let upper = t.to_ascii_uppercase();
    // gdb's `handle` accepts a NUMBER or a name WITH the `SIG` prefix: a bare `SEGV` is rejected as
    // "Unrecognized or ambiguous flag word", measured. So the prefix is ensured, not stripped.
    if upper.starts_with("SIG") {
        upper
    } else {
        format!("SIG{upper}")
    }
}

fn run_catch(pid: u32, signal: &str, timeout_s: u64) -> Result<ExitCode> {
    let sudo = sudo_prefix();
    // The catch has to answer a guest question, and gdb cannot walk a guest frame. What gdb CAN do
    // is stop the target on the signal, and while it is stopped the stack is readable. So the gdb
    // session copies the maps and each thread's stack out, and the frames above are then resolved by
    // the same scanner the live unwinder uses -- no second attach, no second symbolizer.
    let dir = std::env::temp_dir().join(format!("dwdiag-catch-{pid}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let script = dir.join("catch.gdb");
    // ORDER IS THE MEASUREMENT. `info registers rip rsp` / `x/4i $pc` used to run AFTER the python
    // loop, and that loop switches to every thread and leaves the LAST one selected -- so the
    // registers printed under "Thread N received signal SIGSEGV" were the last-iterated thread's, not
    // the stopped one's. MEASURED 2026-10-15: that made a SIGSEGV delivered to a parked libdispatch
    // worker (stack: __linux_futex -> sem_down -> sys_workq_kernreturn -> _dispatch_worker_thread2)
    // read as a fault in a host Vulkan worker (glibc __futex_abstimed_wait_cancelable64), which sent
    // the investigation at the wrong process component. Capture them while the signal thread is still
    // the selected one; the per-thread stack images below are unaffected either way.
    let script_text = format!(
        "set pagination off\n\
         set confirm off\n\
         set follow-fork-mode parent\n\
         set detach-on-fork off\n\
         set schedule-multiple on\n\
         {handles}\n\
         handle SIGCONT nostop noprint pass\n\
         handle SIGSTOP nostop noprint pass\n\
         handle SIGCHLD nostop noprint pass\n\
         signal SIGCONT\n\
         info registers rip rsp\n\
         x/4i $pc\n\
         python\n\
         import gdb, os, traceback\n\
         try:\n\
         \x20   d = '{dir}'\n\
         \x20   thread = gdb.selected_thread()\n\
         \x20   inf = thread.inferior if thread is not None else gdb.selected_inferior()\n\
         \x20   ipid = inf.pid or {pid}\n\
         \x20   open(os.path.join(d, 'inferior-pid'), 'w').write(str(ipid))\n\
         \x20   open(os.path.join(d, 'maps'), 'w').write(open('/proc/%d/maps' % ipid).read())\n\
         \x20   for t in inf.threads():\n\
         \x20       t.switch()\n\
         \x20       rsp = int(gdb.parse_and_eval('$rsp'))\n\
         \x20       open(os.path.join(d, 'stack-0x%x.bin' % rsp), 'wb').write(bytes(inf.read_memory(rsp, 4096)))\n\
         except Exception:\n\
         \x20   open(os.path.join(d, 'python-error.txt'), 'w').write(traceback.format_exc())\n\
         end\n\
         thread apply all bt\n",
        // A comma-separated list, because the measured failure delivers two signals: the guest
        // takes SIGILL and then dies of SIGSEGV, and arming only the second one leaves the first to
        // gdb's default behaviour rather than to a decision we stated.
        handles = signal
            .split(',')
            .map(|s| format!("handle {} stop print nopass", gdb_signal_word(s)))
            .collect::<Vec<_>>()
            .join("\n         "),
        dir = dir.display(),
    );
    std::fs::write(&script, script_text)
        .with_context(|| format!("writing {}", script.display()))?;

    let mut cmd = Command::new(sudo.first().copied().unwrap_or("gdb"));
    if !sudo.is_empty() { cmd.arg(sudo[1]).arg("timeout").arg(timeout_s.to_string()).arg("gdb"); }
    let out = cmd
        .arg("-p").arg(pid.to_string())
        .args(["-batch", "-x"])
        .arg(&script)
        .output()
        .context("running gdb in catch mode")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let err = String::from_utf8_lossy(&out.stderr);
    // A failed session used to be silent: no frames, no reason. The transcript is kept beside the
    // stack images and its tail is printed, because "gdb_exit=Some(1)" and nothing else is exactly
    // the kind of silence that costs another full run to explain.
    let _ = std::fs::write(dir.join("gdb.out"), format!("{text}\n=== stderr ===\n{err}"));
    crate::say(&format!("CATCH pid={pid} signal={} gdb_exit={:?}", gdb_signal_word(signal), out.status.code()));
    for line in text.lines().chain(err.lines()) {
        let t = line.trim_end();
        if t.contains("Program received signal")
            || t.contains("si_code")
            || t.contains("si_addr")
            || t.contains("CATCH-STOPPED")
            || t.starts_with("Thread ")
            || t.starts_with('#')
            || t.contains(":\t")          // the x/4i disassembly lines
            || t.trim_start().starts_with("rip")
            || t.trim_start().starts_with("rsp")
        {
            crate::say(&format!("  {t}"));
        }
    }

    if out.status.code() != Some(0) {
        crate::say("CATCH-NOTE gdb did not exit 0; tail of its transcript:");
        let all: Vec<&str> = text.lines().chain(err.lines()).collect();
        for line in all.iter().rev().take(12).collect::<Vec<_>>().into_iter().rev() {
            crate::say(&format!("  {line}"));
        }
    }
    if let Ok(e) = std::fs::read_to_string(dir.join("python-error.txt")) {
        crate::say(&format!("CATCH-PYTHON-ERROR {}", e.trim()));
    }

    let mut captured_stack = false;
    // The stack images gdb left behind, resolved now. This is the part gdb cannot do itself.
    if let Ok(maps_text) = std::fs::read_to_string(dir.join("maps")) {
        let maps = parse_maps_text(&maps_text);
        let image_ok = |p: &str| !p.is_empty() && !p.starts_with('[') && !unwind_is_hostish(p);
        let mut dumps: Vec<(u64, std::path::PathBuf)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(h) = name.strip_prefix("stack-0x").and_then(|s| s.strip_suffix(".bin")) {
                    if let Ok(rsp) = u64::from_str_radix(h, 16) { dumps.push((rsp, e.path())); }
                }
            }
        }
        dumps.sort();
        let mut segments = MachoSegmentCache::default();
        for (rsp, path) in dumps {
            let mem = std::fs::read(&path)?;
            captured_stack |= !mem.is_empty();
            let frames = scan_stack(&mem, &maps, &image_ok, 12, &mut segments);
            crate::say(&format!("CATCH-STACK rsp={rsp:#x} frames={}", frames.len()));
            for (addr, img, sym) in &frames {
                crate::say(&format!("  FRAME {addr:#x} image={} {sym}",
                    img.rsplit('/').next().unwrap_or(img)));
            }
        }
    }
    Ok(if out.status.success() && !dir.join("python-error.txt").exists() && captured_stack {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn run_unwind(args: UnwindArgs) -> Result<ExitCode> {
    if let Some(sig) = args.catch.clone() {
        return run_catch(args.pid, &sig, args.catch_timeout);
    }
    if !std::path::Path::new(&format!("/proc/{}", args.pid)).exists() {
        bail!("no such pid {}", args.pid);
    }
    let sudo = sudo_prefix();
    let regs = unwind_registers(args.pid, &sudo)?;
    let maps = unwind_maps(args.pid)?;

    let image_ok = |path: &str| -> bool {
        if path.is_empty() || path.starts_with('[') { return false; }
        match &args.image {
            Some(pat) => path.contains(pat.as_str()),
            None => !unwind_is_hostish(path),
        }
    };
    // A dylib is mapped at a random address, so an absolute stack word is NOT an address inside
    // the image: it has to be rebased by (mapping_start - file_offset). Passing the absolute
    // address was the bug that made every shared-library frame resolve to a bogus symbol.
    let image_of = |addr: u64| -> Option<(u64, u64, u64, String)> {
        maps.iter()
            .find(|(lo, hi, x, _, _)| *x && *lo <= addr && addr < *hi)
            .map(|(lo, hi, _, foff, p)| (*lo, *hi, *foff, p.clone()))
    };
    // A mapping's `foff` is a FILE offset while a symbol table speaks IMAGE addresses, and for a UNIVERSAL
    // guest image those differ by the slice base. MachoSegments makes that conversion (see scan_stack);
    // the cache keeps one parse per image.
    let mut segments = MachoSegmentCache::default();

    let mut total_frames = 0usize;
    let mut rows: Vec<(u64, u64, u64, Option<(String, u64)>, Vec<(u64, String, String)>, &'static str)> = Vec::new();

    for (tid_ref, rsp_ref, rip_ref, rbp_ref) in &regs {
        let tid = *tid_ref;
        let rsp = *rsp_ref;
        let rip = *rip_ref;
        let mem = {
            let mut cmd = Command::new(sudo.first().copied().unwrap_or("dd"));
            if !sudo.is_empty() { cmd.arg(sudo[1]); }
            cmd.args(["dd", &format!("if=/proc/{}/task/{}/mem", args.pid, tid),
                      "bs=4096", "iflag=skip_bytes,count_bytes",
                      &format!("skip={rsp}"), &format!("count={}", args.window), "status=none"])
                .output()
                .ok()
                .map(|o| o.stdout)
                .unwrap_or_default()
        };
        // Frame-pointer chains can omit callers compiled without frame pointers.
        // An explicit scan reports candidates; it must never be presented as a backtrace.
        let fp_rets = if args.scan {
            Vec::new()
        } else {
            fp_chain(&mem, rsp, *rbp_ref, rsp, &maps, &image_ok, args.max)
        };
        let (frames, via) = if fp_rets.is_empty() {
            (scan_stack(&mem, &maps, &image_ok, args.max, &mut segments), "scan")
        } else {
            let decoded = fp_rets
                .into_iter()
                .filter_map(|v| {
                    let (lo, _, foff, path) = image_of(v)?;
                    let sym_addr = segments
                        .image_addr(&path, foff + (v - lo))
                        .unwrap_or(v - lo + foff);
                    let sym = unwind_symbolize(sym_addr, &path)?;
                    Some((v, path, sym))
                })
                .collect::<Vec<_>>();
            (decoded, "fp")
        };
        total_frames += frames.len();
        let rip_img = image_of(rip).map(|(lo, _, _, p)| (p, lo));
        rows.push((tid, rsp, rip, rip_img, frames, via));
    }

    if args.json {
        let mut out = String::from("{\"pid\":");
        out.push_str(&args.pid.to_string());
        out.push_str(",\"threads\":[");
        for (i, (tid, rsp, _rip_abs, rip_img, frames, via)) in rows.iter().enumerate() {
            if i > 0 { out.push(','); }
            out.push_str(&format!("{{\"tid\":{},\"rsp\":\"{:#x}\",\"frames_via\":\"{}\",\"rip_image\":\"{}\",\"frames\":[",
                tid, rsp, via, rip_img.as_ref().map(|(p, _lo)| p.clone()).unwrap_or_default()));
            for (j, (addr, path, sym)) in frames.iter().enumerate() {
                if j > 0 { out.push(','); }
                out.push_str(&format!("{{\"addr\":\"{:#x}\",\"image\":\"{}\",\"symbol\":\"{}\"}}",
                    addr, jesc(path), jesc(sym)));
            }
            out.push_str("]}");
        }
        out.push_str("]}");
        println!("{out}");
        return Ok(ExitCode::SUCCESS);
    }

    crate::say(&format!("UNWIND pid={} window={} threads={}", args.pid, args.window, rows.len()));
    for (tid, rsp, rip_abs, rip_img, frames, via) in &rows {
        // Where the thread is RIGHT NOW, resolved. Printing only the image name left the single
        // most useful register unread: a stalled thread sits in a syscall wrapper most of the time,
        // and knowing which wrapper is the difference between "it is in a wait" and "it is in the
        // wrong wait".
        let rip_s = match rip_img {
            Some((p, _lo)) => {
                let sym = image_of(*rip_abs)
                    .and_then(|(lo, _, foff, path)| {
                        let sym_addr = segments
                            .image_addr(&path, foff + (rip_abs - lo))
                            .unwrap_or(rip_abs - lo + foff);
                        unwind_symbolize(sym_addr, &path)
                    });
                match sym {
                    Some(sym) => format!("image={} rip={sym}", p.rsplit('/').next().unwrap_or(p)),
                    None => format!("image={}", p.rsplit('/').next().unwrap_or(p)),
                }
            }
            None => "image=<host or unmapped>".to_string(),
        };
        crate::say(&format!("THREAD tid={} rsp={:#x} rip_{} frames_via={} symbolized_frames={}", tid, rsp, rip_s, via, frames.len()));
        if frames.is_empty() {
            crate::say("  NOTE no frame on this thread resolved to a symbol: either nothing above rsp points into a guest image, or the image has no symbol table (stripped images are reported as such by `dwdiag symbolize`)");
        }
        for (addr, path, sym) in frames {
            crate::say(&format!("  FRAME {:#x} image={} {}", addr, path.rsplit('/').next().unwrap_or(path), sym));
        }
    }
    crate::say(&format!("UNWIND-VERDICT threads={} symbolized_frames={} note=frames are words above each thread rsp that fall in a guest image, sit past that image's first 16 KiB, and resolve to a symbol; a thread with none resolved either has nothing there or points at a stripped image", rows.len(), total_frames));
    Ok(ExitCode::SUCCESS)
}


fn run_witness(args: WitnessArgs) -> Result<ExitCode> {
    let log = match args.log {
        Some(p) => p,
        None => newest_verdict_log()
            .context("no `dwdiag-verdict-*.log` in the temp directory; pass --log")?,
    };
    let text = read_log_lossy(&log).with_context(|| format!("reading {}", log.display()))?;
    let census = witness_census(&text);
    let fired: Vec<_> = census.iter().filter(|(_, c, _)| *c > 0).collect();
    let silent: Vec<_> = census
        .iter()
        .filter(|(_, c, _)| *c == 0)
        .map(|(n, _, _)| n.clone())
        .collect();
    if args.json {
        let mut obj = String::from("{\"log\":\"");
        obj.push_str(&jesc(&log.display().to_string()));
        obj.push_str("\",\"instruments\":[");
        for (i, (name, count, sample)) in census.iter().enumerate() {
            if i > 0 {
                obj.push(',');
            }
            obj.push_str(&format!(
                "{{\"name\":\"{}\",\"count\":{},\"sample\":\"{}\"}}",
                jesc(name),
                count,
                jesc(sample)
            ));
        }
        obj.push_str("]}");
        println!("{obj}");
    } else {
        println!(
            "WITNESS log={} instruments={} fired={}",
            log.display(),
            census.len(),
            fired.len()
        );
        for (name, count, sample) in &census {
            if *count > 0 {
                println!("  {name:<14} {count:>7}  {sample}");
            }
        }
        println!(
            "WITNESS-SILENT {}",
            if silent.is_empty() {
                "<none>".to_string()
            } else {
                silent.join(",")
            }
        );
    }
    Ok(ExitCode::SUCCESS)
}

// Keep process identity and server-log discovery on the same run-owned prefix,
// never an ambient DWDIAG_PREFIX/DPREFIX or a parent inferred from --server-log.
fn progress_prefix_from_run(run: &str) -> Option<PathBuf> {
    let mut prefix = None;
    for line in run.lines() {
        let mut rest = line;
        while let Some(i) = rest.find("prefix=") {
            rest = &rest[i + "prefix=".len()..];
            let end = rest.find(|c: char| c.is_whitespace() || c == ']').unwrap_or(rest.len());
            if end > 0 {
                let candidate = PathBuf::from(&rest[..end]);
                if candidate.is_absolute() {
                    prefix = Some(candidate);
                }
            }
            rest = &rest[end..];
        }
    }
    prefix
}

fn progress_runtime_exe_matches(actual: &Path, expected: &Path) -> bool {
    let raw = actual.as_os_str().as_bytes();
    Path::new(std::ffi::OsStr::from_bytes(raw.strip_suffix(b" (deleted)").unwrap_or(raw))) == expected
}

fn progress_prefix_marker_matches(environment: &[u8], prefix: &Path) -> bool {
    environment.split(|byte| *byte == 0).any(|value| {
        value.strip_prefix(b"DPREFIX=").or_else(|| value.strip_prefix(b"DARLING_PREFIX="))
            .map(|raw| Path::new(std::ffi::OsStr::from_bytes(raw)) == prefix).unwrap_or(false)
    })
}

#[cfg(test)]
mod progress_scope_tests {
    use super::*;

    #[test]
    fn recorded_prefix_selection_keeps_the_server_log_contract() {
        assert_eq!(progress_prefix_from_run("wrapper started\nwrapper finished\n"), None);
        assert_eq!(progress_prefix_from_run("[dwdiag-env prefix=/owned/guest runtime-root=/image]\n"),
            Some(PathBuf::from("/owned/guest")));
        assert_eq!(progress_prefix_from_run("prefix=/earlier\nprefix=relative\nprefix=/current]\n"),
            Some(PathBuf::from("/current")));
    }

    #[test]
    fn runtime_identity_rejects_other_images_and_name_matches() {
        let server = Path::new("/image/bin/darlingserver");
        assert!(progress_runtime_exe_matches(server, server));
        assert!(progress_runtime_exe_matches(Path::new("/image/bin/darlingserver (deleted)"), server));
        assert!(!progress_runtime_exe_matches(Path::new("/other-image/bin/darlingserver"), server));
        assert!(!progress_runtime_exe_matches(Path::new("/image/bin/darlingserver-helper"), server));
    }

    #[test]
    fn prefix_candidates_require_an_exact_environment_marker() {
        let prefix = Path::new("/owned/guest");
        assert!(progress_prefix_marker_matches(b"OTHER=1\0DPREFIX=/owned/guest\0", prefix));
        assert!(progress_prefix_marker_matches(b"DARLING_PREFIX=/owned/guest\0", prefix));
        assert!(!progress_prefix_marker_matches(b"DPREFIX=/owned/guest-other\0", prefix));
        assert!(!progress_prefix_marker_matches(b"COMMAND=DPREFIX=/owned/guest\0", prefix));
        assert!(!progress_prefix_marker_matches(b"DWDIAG_PREFIX=/owned/guest\0", prefix));
    }

    #[test]
    fn a_short_nonrepeating_tail_is_not_a_spin_finding() {
        assert_eq!(loop_tail_kind(0, 2, 2, 8), "nonrepeating");
        assert_eq!(loop_tail_kind(2, 30, 4, 8), "spin");
        assert_eq!(loop_tail_kind(2, 30, 14, 8), "varied");
        assert_eq!(loop_tail_kind(0, 6, 2, 8), "insufficient-repetition");
        assert_eq!(loop_tail_kind(2, 0, 0, 8), "unmeasured");
    }

    #[test]
    fn progress_cli_requires_one_owned_evidence_selection() {
        let parse = |args: &[&str]| <crate::Cli as clap::Parser>::try_parse_from(args.iter().copied());
        assert!(parse(&["runner", "diag", "progress", "--log", "/run.log"]).is_ok());
        assert!(parse(&["runner", "diag", "progress", "--state-dir", "/job"]).is_ok());
        assert!(parse(&["runner", "diag", "progress"]).is_err());
        assert!(parse(&["runner", "diag", "progress", "--state-dir", "/job", "--log", "/other.log"]).is_err());
        assert!(parse(&["runner", "diag", "progress", "--state-dir", "/job", "--server-log", "/mutable.log"]).is_err());
    }
}

fn run_progress(args: ProgressArgs) -> Result<ExitCode> {
    // Name the log that was actually read (user directive: never withhold a fact that changes the reading). MEASURED
    // need: a `--log`-less invocation silently picked a different run's log and the wake census described THAT run --
    // a reader comparing two runs would have attributed the numbers to the wrong one.
    let selected = args.state_dir.as_deref().map(select_evidence);
    if let Some(report) = &selected {
        if !report.state.has_census() {
            if args.json { println!("{}", evidence_report_json(report)); } else { print_evidence_report(report); }
            return Ok(ExitCode::from(2));
        }
    }
    let log = selected.as_ref().map(|report| report.instruments_log.as_path()).or(args.log.as_deref())
        .context("progress needs --log or --state-dir")?;
    eprintln!("PROGRESS-LOG {}", log.display());
    let run = read_log_lossy(log).with_context(|| format!("reading {}", log.display()))?;
    let managed = args.state_dir.as_deref().and_then(evidence_manifest);
    let guest = args
        .guest_log
        .as_ref()
        .map(|p| read_log_lossy(p).unwrap_or_default())
        .unwrap_or_default();
    let p = summarize_progress(&run, &guest, &args.mode);
    // Proactive stop reason (user directive): a CRASHED run has no workload result line, so every summary field is
    // empty and the output used to read `workload=absent` -- which says nothing about WHY. MEASURED need: a
    // darlingserver abort in the plane pass produced exactly that, and the crash was only found by grepping the log
    // by hand. The crash line plus the first panic-backtrace frames are printed here, with the command that decodes
    // them, so the reason is never withheld from the next reader.
    let crash_line = run.lines().find(|l| l.contains("dserver-CRASH")).map(|l| {
        l.split("dserver-CRASH")
            .last()
            .unwrap_or(l)
            .trim()
            .to_string()
    });
    let mut crash_frames: Vec<String> = Vec::new();
    if crash_line.is_some() {
        for line in run.lines() {
            let l = line.trim();
            if l.starts_with("darlingserver(+0x") && crash_frames.len() < 4 {
                crash_frames.push(l.to_string());
            }
        }
    }
    // Wake-channel summary (user directive: the reading violation A turns on must be one command away). A plane
    // publish is either woken by the process doorbell or only found later by the server's bounded poll, and the
    // loader's instrument now names which. Counting OCCURRENCES, not lines, is deliberate: the older instrument ended
    // its record with a literal backslash-n, so several records shared one line and a line-based count undercounts
    // exactly the path this is meant to expose.
    let (mut wake_doorbell, mut wake_none, mut wake_unknown) = (0u64, 0u64, 0u64);
    {
        let mut idx = 0usize;
        while let Some(rel) = run[idx..].find("[plane-wake]") {
            let at = idx + rel;
            idx = at + 1;
            let seg = &run[at..(at + 160).min(run.len())];
            // TOKEN equality, never a substring test: the retired label was `via=doorbell-or-server-poll`, which
            // CONTAINS `via=doorbell`, so a substring classifier reported 38 doorbell wakes for a run whose channel
            // was in fact never recorded -- a verdict wrong in the most dangerous direction. Extracting the token
            // makes the old label land in `unknown`, which is the truth about it.
            let token = seg.find("via=").map(|v| {
                let rest = &seg[v + 4..];
                let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                &rest[..end]
            });
            match token {
                Some("doorbell") => wake_doorbell += 1,
                Some("none") => wake_none += 1,
                _ => wake_unknown += 1,
            }
        }
    }
    if args.json {
        println!(
            "{{\"workload\":\"{}\",\"result\":\"{}\",\"last_guest\":\"{}\",\"last_published_op\":\"{}\",\"last_served_op\":\"{}\",\"serviced\":{},\"denied\":{},\"created\":{},\"first_denial_call\":\"{}\"}}",
            jesc(&p.workload),
            jesc(&p.result),
            jesc(&p.last_guest),
            jesc(&p.last_published_op),
            jesc(&p.last_served_op),
            p.serviced,
            p.denied,
            p.created,
            jesc(&p.first_denial_call)
        );
        if let Some(cl) = &crash_line {
            println!(
                "{{\"crash\":\"{}\",\"frames\":[{}]}}",
                jesc(cl),
                crash_frames
                    .iter()
                    .map(|f| format!("\"{}\"", jesc(f)))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
    } else {
        println!(
            "PROGRESS workload={} last-guest={} last-published-op={} last-served-op={} serviced={} denied={} created={} first-denial={}",
            p.workload,
            if p.last_guest.is_empty() {
                "<none>"
            } else {
                &p.last_guest
            },
            if p.last_published_op.is_empty() {
                "<none>"
            } else {
                &p.last_published_op
            },
            if p.last_served_op.is_empty() {
                "<none>"
            } else {
                &p.last_served_op
            },
            p.serviced,
            p.denied,
            p.created,
            if p.first_denial_call.is_empty() {
                "<none>"
            } else {
                &p.first_denial_call
            }
        );
        if !p.result.is_empty() {
            println!("PROGRESS-RESULT {}", p.result);
        }
        if wake_doorbell + wake_none + wake_unknown > 0 {
            let total_publishes = wake_doorbell + wake_none + wake_unknown;
            println!(
                "WAKES plane-publishes={} doorbell={} none={} unknown={}",
                total_publishes, wake_doorbell, wake_none, wake_unknown
            );
            if args.min_plane_publishes > 0 && total_publishes < args.min_plane_publishes {
                println!(
                    "WAKES-REGRESSION only {total_publishes} plane publishes, at least {} expected: a boot that stops early looks exactly like this",
                    args.min_plane_publishes
                );
            }
            if wake_none > 0 {
                println!(
                    "WAKES-VERDICT the bounded poll is LOAD-BEARING: {wake_none} publish(es) had no doorbell to ring"
                );
            } else if wake_unknown == 0 {
                println!(
                    "WAKES-VERDICT every publish rang the doorbell: the poll is not what makes progress"
                );
            } else {
                println!(
                    "WAKES-VERDICT {wake_unknown} record(s) predate the channel-aware instrument; re-run to judge"
                );
            }
        }
        // A receive that missed its token means a bundle was consumed by ANOTHER consumer or never arrived -- the exact
        // mechanism that broke two boots in this session (a doorbell envelope adopted instead of stored, while the lane
        // attach still waited for it by token). The line existed in the log; nothing surfaced it.
        let misses: Vec<&str> = run
            .lines()
            .filter(|l| {
                l.contains("fd-courier-recv") && l.contains("MISS")
                    || l.contains("[fd-courier-miss]")
            })
            .collect();
        if !misses.is_empty() {
            println!(
                "COURIER-MISSES {} record(s); first: {}",
                misses.len(),
                misses[0].trim()
            );
        } else {
            println!(
                "COURIER-MISSES none visible in this log (the receive-side instrument is env-gated; absence here is not evidence that no bundle was lost)"
            );
        }
        let prefix_from_log = progress_prefix_from_run(&run);
        let selected_prefix = if args.state_dir.is_some() {
            managed.as_ref().and_then(EvidenceManifest::scoped_prefix)
                .filter(|recorded| args.prefix.as_deref().map(|explicit| explicit == *recorded).unwrap_or(true))
        } else {
            args.prefix.as_deref().or(prefix_from_log.as_deref())
        };
        // Compare only a positively scoped process with the selected runtime.
        // A shared installed executable cannot identify the guest prefix.
        'server_identity: {
            use std::os::unix::fs::MetadataExt;
            let Some(prefix) = selected_prefix else {
                println!("SERVER-IDENTITY unavailable scope=unavailable (no explicit or recorded run prefix; --server-log alone does not identify live processes)");
                break 'server_identity;
            };
            let source = if args.state_dir.is_some() { "managed-manifest" }
                else if args.prefix.is_some() { "explicit-prefix" } else { "recorded-run-prefix" };
            let selected_runtime = if args.state_dir.is_some() {
                managed.as_ref().and_then(EvidenceManifest::scoped_runtime)
            } else {
                crate::installed_runtime_root().ok()
            };
            let Some(root) = selected_runtime else {
                println!("SERVER-IDENTITY unavailable scope=unavailable prefix={} source={source} (ordinary runtime scope is absent or ambiguous)", prefix.display());
                break 'server_identity;
            };
            let prefix_handle = match fs::File::open(prefix) {
                Ok(handle) => handle,
                Err(error) => {
                    println!("SERVER-IDENTITY unavailable scope=unavailable prefix={} source={source} ({error})", prefix.display());
                    break 'server_identity;
                }
            };
            let expected = match prefix_handle.metadata() {
                Ok(metadata) if metadata.is_dir() => metadata,
                _ => {
                    println!("SERVER-IDENTITY unavailable scope=unavailable prefix={} source={source} (prefix directory identity unreadable)", prefix.display());
                    break 'server_identity;
                }
            };
            println!("SERVER-IDENTITY-SCOPE prefix={} source={source} runtime-root={} prefix_dev={} prefix_ino={} observation=current-point-in-time signal-authority=false",
                prefix.display(), root.display(), expected.dev(), expected.ino());
            let deployed_path = root.join("bin/darlingserver");
            let deployed_hash = match sha256_of(&deployed_path) {
                Ok(hash) => Some(hash),
                Err(error) => {
                    println!("SERVER-IDENTITY deployed={} UNMEASURED ({error})", deployed_path.display());
                    None
                }
            };
            let deployed_size = fs::metadata(&deployed_path).map(|metadata| metadata.len()).unwrap_or(0);
            if let Some(hash) = &deployed_hash {
                println!("SERVER-IDENTITY deployed={} sha256={hash} size={deployed_size}", deployed_path.display());
            }
            let mut found = 0usize;
            let mut candidates = 0usize;
            match fs::read_dir("/proc") {
                Ok(entries) => for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    let Ok(_pid) = name.parse::<u32>() else { continue };
                    // Retain and compare the prefix directory identity, as the
                    // lifecycle census does. Environment-only matches remain
                    // read-only candidates, never signal authority.
                    let retained = fs::read_dir(format!("/proc/{name}/fd")).map(|fds| fds.flatten().any(|fd|
                        fs::metadata(fd.path()).map(|actual| actual.is_dir()
                            && actual.dev() == expected.dev() && actual.ino() == expected.ino()).unwrap_or(false)
                    )).unwrap_or(false);
                    if !retained && !fs::read(format!("/proc/{name}/environ"))
                        .map(|environment| progress_prefix_marker_matches(&environment, prefix)).unwrap_or(false) {
                        continue;
                    }
                    let exe = match fs::read_link(format!("/proc/{name}/exe")) {
                        Ok(path) => path,
                        Err(_) => continue,
                    };
                    if !progress_runtime_exe_matches(&exe, &deployed_path) { continue; }
                    let exe_s = exe.to_string_lossy();
                    if retained { found += 1; } else { candidates += 1; }
                    let running_exe = PathBuf::from(format!("/proc/{name}/exe"));
                    let size = fs::metadata(&running_exe).map(|m| m.len()).unwrap_or(0);
                    // Start time: /proc/<pid>/stat field 22 (starttime in clock ticks) plus btime is more than this
                    // needs -- the uptime-relative value is enough to say WHICH incarnation is running.
                    let stat = std::fs::read_to_string(format!("/proc/{name}/stat")).unwrap_or_default();
                    let start_ticks = stat.rsplit(')').next().and_then(|rest| {
                        rest.split_whitespace()
                            .nth(19)
                            .and_then(|v| v.parse::<u64>().ok())
                    });
                    let uptime = std::fs::read_to_string("/proc/uptime").unwrap_or_default();
                    let up: f64 = uptime
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0.0);
                    let started_ago = start_ticks
                        .map(|ticks| up - (ticks as f64 / 100.0))
                        .unwrap_or(-1.0);
                    let running_hash = sha256_of(&running_exe).ok();
                    let sum: String = running_hash
                        .as_deref()
                        .map(|h| h.chars().take(16).collect())
                        .unwrap_or_default();
                    // Compare the two binaries' HASHES. A size comparison cannot establish that the running server
                    // is the deployed one -- the trap this project keeps recording is a stale server -- and a
                    // verdict of "hash not compared" is not a measurement at all.
                    let verdict = match (&deployed_hash, &running_hash) {
                        (Some(d), Some(r)) if d == r => {
                            "MATCH (the running server is the deployed binary)".to_string()
                        }
                        (Some(d), Some(r)) => format!(
                            "HASH-MISMATCH (deployed {}.. is {deployed_size} bytes, running {}.. is {size} bytes)",
                            &d[..16.min(d.len())],
                            &r[..16.min(r.len())]
                        ),
                        (Some(_), None) => {
                            format!("UNMEASURED (cannot read {exe_s} to hash the running server)")
                        }
                        (None, _) => {
                            "UNMEASURED (no deployed binary was resolved to compare against)".to_string()
                        }
                    };
                    let label = if retained { "SERVER-IDENTITY" } else { "SERVER-IDENTITY-CANDIDATE" };
                    let proof = if retained { "retained-prefix-directory" } else { "prefix-census-marker-only" };
                    println!(
                        "{label} pid={name} exe={exe_s} sha256={sum} started_ago={started_ago:.1}s proof={proof} signal-authority=false -- {verdict}"
                    );
                },
                Err(error) => {
                    println!("SERVER-IDENTITY unavailable scope=selected (cannot enumerate processes: {error})");
                    break 'server_identity;
                }
            }
            if found == 0 {
                println!(
                    "SERVER-IDENTITY observed=0 marker_candidates={candidates} scope=selected (no retained-prefix server identity observed; inaccessible processes and marker-only candidates do not establish absence)"
                );
            }
        }
        // SERVER SIDE, from its own log (see the option's comment). Counts only: the two files have different clocks,
        // so an interleaved ordering would be a fabricated one. Presence plus count is what decides the question.
        'server_evidence: {
            // Only an explicit log or this run's recorded prefix can supply
            // server facts. Ambient/default prefixes may belong to another run.
            // The same explicit/recorded scope selected for process identity.
            let (server_log_path, server_log_source): (Cow<'_, Path>, &str) = if args.state_dir.is_some() {
                match managed.as_ref().and_then(EvidenceManifest::captured_server_log) {
                    Some(path) => (Cow::Borrowed(path), "managed finite server capture"),
                    None => {
                        println!("SERVER-LOG unavailable: managed manifest has no finalized scoped server capture; mutable prefix history is NOT included");
                        break 'server_evidence;
                    }
                }
            } else {
                match args.server_log.as_deref() {
                    Some(path) => (Cow::Borrowed(path), "explicit --server-log"),
                    None => match args.prefix.as_ref().or(prefix_from_log.as_ref()) {
                        Some(prefix) => (
                            Cow::Owned(prefix.join("private/var/log/dserver.log")),
                            if args.prefix.is_some() { "explicit --prefix" } else { "the run's own prefix line" },
                        ),
                        None => {
                            println!("SERVER-LOG unavailable: pass --server-log/--prefix or a run log with prefix=; server-side facts are NOT included");
                            break 'server_evidence;
                        }
                    },
                }
            };
            eprintln!("SERVER-LOG-PATH {} (from {})", server_log_path.display(), server_log_source);
            let server_text = read_log_lossy(&server_log_path).unwrap_or_default();
            if server_text.is_empty() {
                println!(
                    "SERVER-LOG unreadable or empty ({}) -- server-side facts are NOT included in this report",
                    server_log_path.display()
                );
            } else {
                let sent = server_text
                    .lines()
                    .filter(|l| l.contains("plane-doorbell-sent"))
                    .count();
                let guest_timeouts = run
                    .lines()
                    .filter(|l| l.contains("drain attempts=") && l.contains("adopted=0"))
                    .count();
                println!(
                    "SERVER-SENT plane-doorbell-sent={sent} (from {})",
                    server_log_path.display()
                );
                if sent > 0 && guest_timeouts > 0 {
                    println!(
                        "SERVER-GUEST-SPLIT the server sent the doorbell {sent} time(s) while {guest_timeouts} guest drain window(s) expired empty: the descriptor is being SENT but not RECEIVED (look at the guest's receive path, not at the sender)"
                    );
                } else if sent == 0 {
                    println!(
                        "SERVER-GUEST-SPLIT the server did not send anything: the send path never ran"
                    );
                }
            }
        }
        // ORDERED TIMELINE of the three events that decide violation A's ordering. MEASURED need: a run showed 14
        // doorbell ADOPTIONS and 44 publishes that still reported `db=-1`, and no reading said WHICH came first --
        // counts cannot express an ordering, and the ordering is the whole remaining question. The events are
        // printed in log order with their position, so "the first N publishes precede the first adoption" is a
        // sentence the tool says instead of one the reader infers.
        {
            let mut events: Vec<(usize, String)> = Vec::new();
            for (n, line) in run.lines().enumerate() {
                // Only a REAL adoption is an ADOPT event. The drain-outcome line carries the same tag and says
                // `adopted=0`, and counting it as an adoption produced the false verdict "every publish followed the
                // first adoption" for a run whose own drain lines said the opposite. Same lesson as the earlier
                // substring classifier: match the VALUE.
                if line.contains("[plane-doorbell]")
                    && line.contains("adopted=1")
                    && !line.contains("drain")
                {
                    events.push((
                        n,
                        format!(
                            "ADOPT   {}",
                            line.trim().chars().take(90).collect::<String>()
                        ),
                    ));
                } else if line.contains("[plane-wake]") {
                    let seg = line;
                    let via = seg
                        .find("via=")
                        .map(|v| {
                            let r = &seg[v + 4..];
                            let e = r.find(|c: char| c.is_whitespace()).unwrap_or(r.len());
                            &r[..e]
                        })
                        .unwrap_or("?");
                    let db = seg
                        .find("db=")
                        .map(|v| {
                            let r = &seg[v + 3..];
                            let e = r.find(|c: char| c.is_whitespace()).unwrap_or(r.len());
                            &r[..e]
                        })
                        .unwrap_or("?");
                    events.push((n, format!("PUBLISH via={via} db={db}")));
                } else if line.contains("attach-rc") {
                    let wake = line
                        .find("wake=")
                        .map(|v| {
                            let r = &line[v + 5..];
                            let e = r.find(|c: char| c.is_whitespace()).unwrap_or(r.len());
                            &r[..e]
                        })
                        .unwrap_or("?");
                    events.push((n, format!("ATTACH  wake={wake}")));
                }
            }
            if !events.is_empty() {
                println!(
                    "TIMELINE first {} of {} event(s):",
                    events.len().min(12),
                    events.len()
                );
                for (n, e) in events.iter().take(12) {
                    println!("  line {n:>5}  {e}");
                }
                let first_adopt = events
                    .iter()
                    .find(|(_, e)| e.starts_with("ADOPT"))
                    .map(|(n, _)| *n);
                let publishes_before = match first_adopt {
                    Some(a) => events
                        .iter()
                        .filter(|(n, e)| *n < a && e.starts_with("PUBLISH"))
                        .count(),
                    None => events
                        .iter()
                        .filter(|(_, e)| e.starts_with("PUBLISH"))
                        .count(),
                };
                match first_adopt {
                    Some(_) if publishes_before == 0 => {
                        println!("TIMELINE-VERDICT every publish followed the first adoption")
                    }
                    Some(_) => println!(
                        "TIMELINE-VERDICT {publishes_before} publish(es) PRECEDED the first adoption: the ordering the doorbell needs is not yet in place"
                    ),
                    None => println!("TIMELINE-VERDICT no adoption in this log at all"),
                }
            }
        }
        if let Some(cl) = &crash_line {
            println!("STOP-REASON crash: {cl}");
            for f in &crash_frames {
                println!("  {f}");
            }
            println!(
                "  decode: dwdiag crash --binary <server binary> --log {}",
                log.display()
            );
        }
    }
    // The exit code is a QUESTION ("did the workload speak?"), not a judgement: absent means the caller must look at
    // `last-guest`/`last-served-op`, present means the run got far enough to be judged on the result line itself.
    Ok(if p.workload == "present" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

// ----------------------------------------------------------------------------------------------------------------

#[derive(clap::Args, Debug)]
pub struct DenialsArgs {
    #[arg(long)]
    log: PathBuf,
    /// Kernel image whose symbol `mach_driver_get_fd` is the base for every denial's `delta`.
    #[arg(long)]
    kernel: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

/// The denials of one run, as a table, with the caller resolved and the surrounding lifecycle context attached.
fn run_denials(args: DenialsArgs) -> Result<ExitCode> {
    let text = read_log_lossy(&args.log).with_context(|| format!("reading {}", args.log.display()))?;
    let syms = match &args.kernel {
        Some(k) if stored_evidence::resolve(k).is_file() => Some(load_symbols(k)?),
        Some(k) => {
            crate::say(&format!("DENIALS: kernel image {} does not exist; callers will not be symbolized", k.display()));
            None
        }
        None => None,
    };
    let base = syms
        .as_ref()
        .and_then(|s| s.iter().find(|s| symbol_name(&s.name) == "mach_driver_get_fd"))
        .map(|s| s.addr);
    // The context that has decided every question in this stage: was this process's transport rebound, and did the plane
    // or the urgent pool refuse it first?
    let mut rebinds: Vec<(u64, usize)> = Vec::new();
    let mut refusals: Vec<(usize, String)> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if let Some(rest) = line.split("postfork-child rebind pid=").nth(1) {
            if let Ok(pid) = rest.split_whitespace().next().unwrap_or("").parse::<u64>() {
                rebinds.push((pid, i));
            }
        }
        if line.contains("[plane-refuse]") || line.contains("[urgent-refuse]") {
            refusals.push((i, line.trim().to_string()));
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut rows = 0usize;
    crate::say(&format!("DENIALS log={} lines={}", args.log.display(), text.lines().count()));
    for (i, line) in text.lines().enumerate() {
        let Some(pos) = line.find("rpc-socket-DENIED") else { continue };
        let fields: Vec<&str> = line[pos..].split_whitespace().collect();
        let get = |k: &str| fields.iter().find_map(|f| f.strip_prefix(k)).map(|v| v.to_string());
        let pid: u64 = get("pid=").and_then(|v| v.parse().ok()).unwrap_or(0);
        let call = get("call=").unwrap_or_default();
        if !seen.insert((pid, call.clone())) {
            continue;
        }
        let delta = get("delta=").unwrap_or_default();
        let location = match (base, parse_hex(&delta)) {
            (Some(b), Ok(d)) => syms
                .as_ref()
                .and_then(|s| locate(s, b + d))
                .map(|(idx, off)| format!("{} + 0x{:x}", symbol_name(&syms.as_ref().unwrap()[idx].name), off))
                .unwrap_or_else(|| "NOT-IN-IMAGE".to_string()),
            _ => "UNRESOLVED (pass --kernel)".to_string(),
        };
        let rebound = rebinds.iter().find(|(p, _)| *p == pid).map(|(_, r)| if *r < i { "before" } else { "after" });
        let refusal = refusals.iter().rev().find(|(ri, _)| *ri < i).map(|(_, l)| l.clone()).unwrap_or_default();
        rows += 1;
        crate::say(&format!(
            "DENIAL pid={pid} call={call} image={} delta={delta} at={location} rebind={} refusal={}",
            get("image=").unwrap_or_default(),
            rebound.unwrap_or("none"),
            if refusal.is_empty() { "-".to_string() } else { refusal }
        ));
    }
    crate::say(&format!("DENIALS-DONE rows={rows} rebinds={}", rebinds.len()));
    Ok(if rows == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

#[derive(clap::Args, Debug)]
pub struct TraceArgs {
    #[arg(long)]
    log: PathBuf,
    /// The pid or tid to follow. Lines naming it, without needing a word-boundary guess by the caller.
    #[arg(long)]
    pid: u64,
    /// Also show lines that name no pid but carry these tokens (refusals, attach, courier, checkin...).
    #[arg(long = "also", num_args = 0.., default_values_t = Vec::<String>::new())]
    also: Vec<String>,
    /// Only the last N matching lines.
    #[arg(long)]
    tail: Option<usize>,
    /// Also search this other log (typically the prefix's private/var/log/dserver.log) for the same pid, so one command
    /// answers "what did the guest do" AND "what did the server do" without a second hand-written grep.
    #[arg(long)]
    server: Option<PathBuf>,
}

fn run_trace(args: TraceArgs) -> Result<ExitCode> {
    let text = read_log_lossy(&args.log).with_context(|| format!("reading {}", args.log.display()))?;
    let pid = args.pid.to_string();
    let pid_patterns = [format!("pid={pid}"), format!("tid={pid}"), format!("pid={pid} "), format!("tid={pid} ")];
    let defaults = ["plane-refuse", "urgent-refuse", "dring-attach", "courier-", "checkin", "release-drops-pending"];
    if let Some(server_path) = &args.server {
        match read_log_lossy(server_path) {
            Ok(server_text) => {
                let matches: Vec<&str> = server_text
                    .lines()
                    .filter(|l| l.contains(&format!("pid={pid}")) || l.contains(&format!("tid={pid}")))
                    .collect();
                crate::say(&format!(
                    "TRACE-SERVER {} lines={} matches={}",
                    server_path.display(),
                    server_text.lines().count(),
                    matches.len()
                ));
                for l in matches.iter().rev().take(12).rev() {
                    crate::say(&format!("  S {}", l.trim()));
                }
            }
            Err(_) => crate::say(&format!("TRACE-SERVER {} (unreadable)", server_path.display())),
        }
    }
    let mut hits: Vec<(usize, &str)> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let names_pid = pid_patterns.iter().any(|p| line.contains(p.as_str()));
        let carries_token = args.also.iter().any(|a| line.contains(a.as_str()))
            || (args.also.is_empty() && defaults.iter().any(|d| line.contains(d)));
        if names_pid || carries_token {
            hits.push((i, line));
        }
    }
    let total = hits.len();
    let shown: Vec<&(usize, &str)> = match args.tail {
        Some(n) if n < total => hits.iter().skip(total - n).collect(),
        _ => hits.iter().collect(),
    };
    crate::say(&format!("TRACE log={} pid={} matched={} shown={}", args.log.display(), args.pid, total, shown.len()));
    for (i, l) in shown {
        crate::say(&format!("{i}: {}", l.trim()));
    }
    crate::say(&format!("TRACE-DONE matched={total}"));
    Ok(if total == 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

/// Report the processes a PREFIX owns, matched by executable path AND command line, and refuse to call a prefix
/// clean on a name match alone.
///
/// MEASURED motivation: a stale-process check written as `pgrep -c shellspawn` reported zero while three guest
/// launchers from three earlier runs were still alive, because the launcher's process NAME is not `shellspawn` and a
/// name pattern that matches nothing is indistinguishable from a clean prefix. The count that told the truth came from
/// the cleanup tool's prefix-owned census -- five, not zero. That is the same class of false negative the verdict rule
/// exists to prevent (absence of a marker is not PASS), so the census belongs here, beside the other verdicts, and it
/// prints the executable and the command line it matched on rather than a bare number.
#[derive(Args, Debug)]
pub struct ProcessesArgs {
    /// Prefix to census.
    #[arg(long)]
    prefix: PathBuf,
    /// Print one line per matching process.
    #[arg(long)]
    list: bool,
    #[arg(long)]
    json: bool,
}

fn run_processes(args: ProcessesArgs) -> Result<ExitCode> {
    let wanted = args.prefix.to_string_lossy().to_string();
    let mut rows = Vec::new();
    for pid in prefix_processes(&args.prefix) {
        let exe = fs::read_link(format!("/proc/{pid}/exe")).map(|path| path.display().to_string()).unwrap_or_default();
        let command = fs::read(format!("/proc/{pid}/cmdline")).map(|bytes|
            String::from_utf8_lossy(&bytes).replace('\0', " ").trim_end().to_string()
        ).unwrap_or_default();
        rows.push((pid, exe, command));
    }
    rows.sort_by_key(|r| r.0);
    if args.json {
        let items: Vec<String> = rows
            .iter()
            .map(|(pid, exe, cmd)| {
                format!(
                    "{{\"pid\":{pid},\"exe\":\"{}\",\"cmdline\":\"{}\"}}",
                    jesc(exe),
                    jesc(cmd)
                )
            })
            .collect();
        crate::say(&format!(
            "{{\"prefix\":\"{}\",\"count\":{},\"clean\":{},\"processes\":[{}]}}",
            jesc(&wanted),
            rows.len(),
            rows.is_empty() as u8,
            items.join(",")
        ));
    } else {
        if args.list {
            for (pid, exe, cmd) in &rows {
                crate::say(&format!("PREFIX-PROCESS pid={pid} exe={exe} cmdline={cmd}"));
            }
        }
        crate::say(&format!(
            "PREFIX-PROCESSES prefix={} count={} clean={}",
            wanted,
            rows.len(),
            rows.is_empty() as u8
        ));
    }
    Ok(if rows.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

pub fn dispatch(cmd: DiagCommand) -> Result<ExitCode> {
    match cmd {
        DiagCommand::Source(a) => run_source_check(a),
        DiagCommand::Watch(a) => run_watch(a),
        DiagCommand::Build(a) => run_build(a),
        DiagCommand::Deploy(a) => run_deploy(a),
        DiagCommand::Cycle(a) => run_cycle(a),
        DiagCommand::Symbolize(a) => run_symbolize(a),
        DiagCommand::Waits(a) => run_waits(a),
        DiagCommand::Futex(a) => run_futex(a),
        DiagCommand::CoreLock(a) => run_core_lock(a),
        DiagCommand::Ring(a) => run_ring(a),
        DiagCommand::Unwind(a) => run_unwind(a),
        DiagCommand::Trap(a) => run_trap(a),
        DiagCommand::Loops(a) => run_loops(a),
        DiagCommand::Mappings(a) => run_mappings(a),
        DiagCommand::Env(a) => run_env(a),
        DiagCommand::Core(a) => run_core(a),
        DiagCommand::Identity(a) => run_identity(a),
        DiagCommand::Cores(a) => run_cores(a),
        DiagCommand::Crash(a) => run_crash(a),
        DiagCommand::Verdict(a) => run_verdict(a),
        DiagCommand::Suite(a) => run_suite(a),
        DiagCommand::Progress(a) => run_progress(a),
        DiagCommand::Job(a) => run_job(a),
        DiagCommand::Courier(a) => run_courier(a),
        DiagCommand::Witness(a) => run_witness(a),
        DiagCommand::Evidence(a) => run_evidence(a),
        DiagCommand::Prefix(a) => run_prefix(a),
        DiagCommand::Denials(a) => run_denials(a),
        DiagCommand::Trace(a) => run_trace(a),
        DiagCommand::Processes(a) => run_processes(a),
    }
}

/// The durable-artifact gate, as ONE supported command instead of a hand-rolled script per attempt.
///
/// Prepare isolated guest state with an ordinary installation and explicit test assets.
///
/// Every step prints a `PREFIX-STAGE` line BEFORE it runs. That is not decoration: a gate that was killed at a wait
/// boundary once produced no output at all, and the stage line is what turns "it went silent" into "it died at boot".
#[derive(clap::Args, Debug)]
pub struct PrefixArgs {
    #[arg(long)]
    prefix: PathBuf,
    /// Run ordinary darling-bootstrap before staging test inputs.
    #[arg(long)]
    bootstrap: bool,
    #[arg(long)]
    build: Option<PathBuf>,
    #[arg(long)]
    guest_toolchain: Option<String>,
    /// Bootstrap against an already installed image without building/installing.
    #[arg(long)]
    no_build: bool,
    /// `SOURCE=DESTINATION` pairs for TEST ASSETS, which are not part of the runtime install (the workload fixture is
    /// one, and its absence is what made an earlier run report workload=absent).
    #[arg(long = "asset", value_parser = parse_kv, num_args = 0..)]
    asset: Vec<(String, String)>,
    /// `KEY=VALUE` environment for the harness, and through it for the launcher, the server and the guest -- the same
    /// shape as `verdict --env`. MEASURED need: a gate that needs an environment must not be reachable only by exporting
    /// it in the caller's shell; one attempt at enabling the server-side plane log that way did not arrive at all.
    #[arg(long = "env", value_parser = parse_kv, num_args = 0..)]
    env: Vec<(String, String)>,
    /// Workload mode after guest-state and asset preparation; omitted stops after preparation.
    #[arg(long, default_value = "")]
    mode: String,
    #[arg(long, default_value = "")]
    args: String,
    /// The workload's path AS THE GUEST SEES IT. MEASURED: the guest's /usr/bin resolves through /Volumes/SystemRoot
    /// to the HOST's /usr/bin, so a fixture installed at <prefix>/usr/bin is invisible to it and the run dies with
    /// "/usr/bin/<fixture>: not found" (rc=127) -- which reads as a broken workload rather than a wrong location. The
    /// guest-visible, writable place is /private/var/tmp, so that is the default here.
    #[arg(long, default_value = "/private/var/tmp/ring_mach_msg_test")]
    guest_command: String,
    #[arg(long, default_value_t = 260)]
    wait: u64,
    #[arg(long)]
    json: bool,
}

/// Hash actual file bytes with the host sha256sum utility.
/// Runtime-image integrity belongs to the normal installation receipt; test assets are separate.
fn sha256_of(path: &Path) -> Result<String> {
    sha256_file(path).with_context(|| format!("hashing {}", path.display()))
}

fn stage_test_asset(source: &Path, destination: &Path, prefix: &Path) -> Result<()> {
    if !prefix.is_absolute() || prefix.components().any(|part| matches!(part, std::path::Component::ParentDir))
        || prefix.ancestors().any(Path::is_symlink) {
        bail!("guest state must be an absolute no-symlink path without '..': {}", prefix.display());
    }
    let relative = destination.strip_prefix(prefix).context("test asset must stay inside guest state")?;
    if !relative.starts_with("private/var/tmp")
        || relative.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        bail!("test assets belong under guest /private/var/tmp, not system-image paths");
    }
    let parent = destination.parent().context("test asset parent")?;
    let mut ancestor = destination;
    while ancestor != prefix {
        if ancestor.is_symlink() { bail!("test asset destination traverses a guest symlink: {}", ancestor.display()); }
        ancestor = ancestor.parent().context("test asset path ancestry")?;
    }
    fs::create_dir_all(parent)?;
    fs::copy(source, destination).with_context(|| format!("staging test asset {} -> {}", source.display(), destination.display()))?;
    let expected = sha256_of(source)?;
    let actual = sha256_of(destination)?;
    if expected != actual { bail!("staged test fixture digest differs: {}", destination.display()); }
    println!("ASSET-INSTALL MATCH sha256={actual} source={} destination={}", source.display(), destination.display());
    Ok(())
}

fn run_prefix(args: PrefixArgs) -> Result<ExitCode> {
    let prefix = &args.prefix;
    let root = crate::runtime_root()?;
    if args.bootstrap {
        let build = required_path("--build", args.build.clone(), "DWDIAG_BUILD")?;
        println!("PREFIX-STAGE bootstrap runtime-root={} prefix={}", root.display(), prefix.display());
        let mut command = Command::new("mise");
        command.args(["run", "west", "darling-bootstrap", "--build-dir"]).arg(build)
            .arg("--runtime-root").arg(root).arg("--prefix").arg(prefix);
        if let Some(toolchain) = &args.guest_toolchain { command.arg("--guest-toolchain").arg(toolchain); }
        if args.no_build { command.arg("--no-build"); }
        crate::inherit_owner_lease(&mut command);
        let status = command.status().context("ordinary installed-runtime bootstrap")?;
        if !status.success() { return Ok(ExitCode::from(3)); }
    } else if args.guest_toolchain.is_some() {
        bail!("--guest-toolchain requires explicit --bootstrap");
    }
    crate::installed_runtime_root()?;
    // Bootstrap and the workload harness are lifecycle owners themselves. Lease
    // only the intervening asset mutation; never nest an outer lock around them.
    let staging_scope = crate::PrefixScope::acquire(prefix, root, true)?;
    let mut explicit_workload = false;
    let host_view = prefix.join(args.guest_command.trim_start_matches('/'));
    for (source, destination) in &args.asset {
        let destination = Path::new(destination);
        let destination = if destination.is_absolute() { destination.to_path_buf() } else { prefix.join(destination) };
        println!("PREFIX-STAGE asset {} -> {}", source, destination.display());
        stage_test_asset(Path::new(source), &destination, prefix)?;
        explicit_workload |= destination == host_view;
    }
    if !explicit_workload {
        let name = Path::new(&args.guest_command).file_name().context("guest workload basename")?;
        let source = root.join("libexec/darling/usr/bin").join(name);
        if !source.is_file() {
            bail!("installed workload prerequisite missing: {}; provide an explicit --asset for a custom fixture", source.display());
        }
        stage_test_asset(&source, &host_view, prefix)?;
    }
    println!("PREFIX-STAGE assets={} runtime-root={} (no runtime files copied into guest state)", args.asset.len(), root.display());
    let host_view = prefix.join(args.guest_command.trim_start_matches('/'));
    println!(
        "ASSET-CHECK guest={} host={} host-present={} asset-installs={}",
        args.guest_command,
        host_view.display(),
        host_view.is_file(),
        args.asset.len()
    );
    drop(staging_scope);
    if args.mode.trim().is_empty() {
        println!("PREFIX-STAGE: no --mode given, stopping after installation");
        return Ok(ExitCode::SUCCESS);
    }
    // A server log that ACCUMULATES across runs cannot answer "what did the server do during THIS run", which is the
    // question every server-side probe comes down to. Record each log's line count before and after, so the slice is
    // named and any later query can be scoped to it.
    let server_logs = ["private/var/log/dserver.log", "private/var/log/dserver-diag.log"];
    let mut server_before: Vec<(String, u64)> = Vec::new();
    for rel in server_logs {
        let p = prefix.join(rel);
        let n = read_log_lossy(&p).map(|s| s.lines().count() as u64).unwrap_or(0);
        server_before.push((p.display().to_string(), n));
    }
    println!(
        "PREFIX-STAGE workload mode={} args={:?} wait={}",
        args.mode, args.args, args.wait
    );
    let va = VerdictArgs {
        prefix: Some(prefix.clone()),
        mode: args.mode.clone(),
        args: args.args.clone(),
        wait: args.wait,
        env: args.env.clone(),
        boot_runner: PathBuf::from("scripts/darling-boot-run.sh"),
        guest_command: args.guest_command.clone(),
        guest_symbols: None,
        repeat: 1,
        list_modes: false,
        json: args.json,
        freeze_on_fail: false,
        log: None,
    };
    let code = run_verdict(va);
    for (path, n) in server_before {
        let after = std::fs::read_to_string(&path).map(|s| s.lines().count() as u64).unwrap_or(0);
        crate::say(&format!("SERVER-LOG-SLICE {path} lines={n}:{after} (this run)"));
    }
    code
}

#[derive(clap::Subcommand, Debug)]
pub enum DiagCommand {
    /// Watch a running guest's kernel signal dispositions (SigCgt/SigBlk) against the run log's size.
    Watch(WatchArgs),
    /// Report whether a build tree actually compiles given source files, and refuse when it does not.
    Source(SourceArgs),
    /// Build the runtime pair the rule requires (libsystem_kernel and the dyld image TOGETHER) and check that the
    /// instrument strings a caller expects are present in the built artifact.
    Build(BuildArgs),
    /// Publish the complete normal CMake installation into the selected immutable runtime root.
    Deploy(DeployArgs),
    /// Publish or explicitly reuse an installed image, run a workload and report fired instruments.
    Cycle(CycleArgs),
    /// Resolve a reported offset to `symbol + offset` for any image (guest dylib or server binary).
    Symbolize(SymbolizeArgs),
    /// Turn a `dserver-CRASH` line into a location, a stack walk and the disassembly around the fault.
    Crash(CrashArgs),
    /// Run ONE guest workload and judge it by its own machine-readable line; absence of that line is FAIL/HANG.
    Verdict(VerdictArgs),
    /// Run a SET of guest workloads and print one table with the counters that decide acceptance.
    Suite(SuiteArgs),
    /// Say WHERE a finished run stopped: the workload's own line, the guest loader's last stage, and the last plane op
    /// the server actually serviced. Published-vs-serviced is the diagnosis; this prints both instead of grepping.
    Progress(ProgressArgs),
    /// Count the packets per TRANSPORT for a run log, and judge the AF_UNIX endpoint's purity. Rows with no
    /// instrument behind them are printed UNMEASURED, never as zero: a census that cannot see a transport must say so.
    Courier(CourierArgs),
    /// Resolve the futex waits a capture bundle holds through BOTH sides' memory maps and join them by
    /// shared-object identity (device, inode, file offset + displacement), naming the object and saying which
    /// side is missing. A waiter and its waker usually live in different processes, so comparing virtual
    /// addresses is meaningless; this is the join that a stall needs and that was done by hand every time.
    Futex(FutexArgs),
    /// Recover, from a core, the unfair lock a dying thread was aborting on: the lock address, its word, the
    /// self token the slow path compared against, and every live thread's self token. It exists because this exact
    /// step was done by hand three times, twice wrongly, and because the only honest answer it can give about
    /// acquisition history is "a core is one instant".
    CoreLock(CoreLockArgs),
    /// Decode the server's lock-free event ring: the fixed six-word records a dump prints, their schema, and what
    /// the dump CANNOT show. The ring exists so a diagnostic event never prints or syscalls on the path it observes
    /// (`dtape_test_ring_record` reserves one slot with a single atomic RMW and then stores, so a torn record is
    /// possible by design and overwritten records are simply absent). A reader that skips those two facts reports
    /// half-written events as measurements and silence as evidence, which is why this is a command and not a grep.
    Ring(RingArgs),
    /// Report which INSTRUMENTS fired in a run log, and which stayed SILENT. A registered instrument with zero hits is
    /// the failure this exists to catch: a guard that silently does nothing cannot be told from no guard at all, and a
    /// hand-written grep over one log finds a line but cannot tell you which of the other instruments never spoke.
    Witness(WitnessArgs),
    /// Say what a finished run's instrument evidence IS before anything censuses it: which registered windows belong
    /// to this run, what was truncated, rotated or unreadable, and which state the census below is in. It is the read
    /// half of the run manifest `west-job.sh` writes at start, and it exists so an unreadable log is reported as
    /// `unavailable`/`partial` rather than as an instrument that stayed silent.
    Evidence(EvidenceArgs),
    /// Diagnose a finished managed job using its persisted scope and finite captured logs: show actual failure
    /// bytes, instrument activity, progress, waits and repetition. A core requires an unambiguous registered
    /// capture; ambient cores and boot-wide kernel logs are never attributed. Current process observations
    /// are scoped separately to the selected prefix/runtime, not evidence of the past run.
    Job(JobArgs),
    /// Read a stopped guest's stacks: per-thread rsp from the debugger, then the words above it,
    /// filtered to guest images and symbolized. Host gdb cannot walk a Darwin-ABI frame, so this
    /// is how a stuck guest gets function names instead of a plausible story. With --catch SIGNAL
    /// it instead attaches, arms a stop on that signal, resumes the target and reports the trap.
    Unwind(UnwindArgs),
    /// Join the server's whole wait/wake vocabulary per ulock object: who waits, who owns, and
    /// whether a wake was ever issued for it. A stall is not diagnosed by the last log line, and
    /// this table was re-derived by hand in every investigation until it became a command.
    Waits(WaitsArgs),
    /// The chronologically ordered story of ONE process in a run log: every line that names its pid or tid, plus the
    /// plane/urgent refusals around it. This is the question of this whole stage -- "what happened to this child?" --
    /// and it was reconstructed by hand with grep/sed/python six times, each time risking the wrong slice of a
    /// two-million-line log.
    Trace(TraceArgs),
    /// One row per DISTINCT denial in a run log, with the caller SYMBOLIZED and the post-fork context next to it.
    ///
    /// This is the recurring question of this whole stage, assembled by hand five times: which call, which pid, which
    /// caller, and was that process's transport rebound before the denial? The `delta` on a denial line is measured from
    /// the symbol `mach_driver_get_fd` in the KERNEL image (not dyld, not the server binary), which is a trap that has
    /// already produced one wrong attribution; passing `--kernel` resolves it here instead of by hand.
    Denials(DenialsArgs),
    /// Prepare writable guest state and test assets for the selected installed runtime, then optionally run a workload.
    /// Runtime files are never copied into the guest prefix.
    Prefix(PrefixArgs),
    /// Report processes owning the guest prefix through directory descriptors or exact prefix environment.
    /// The count describes the observed census; normal product shutdown and lifecycle cleanup remain required.
    Processes(ProcessesArgs),
    /// Read the KERNEL's own report of where a guest died and symbolize the address inside a prefix.
    ///
    /// MEASURED need: a guest fault is delivered by the host, so the host log carries process, reason, image,
    /// load base and instruction pointer -- one line that names the faulting function once symbolized, kept even
    /// when no core is written (`ulimit -c 0`). Three custom probes, a gdb catch and a stack scanner produced a
    /// wrong story twice in the same session while that line sat in `dmesg` unread.
    Trap(TrapArgs),
    /// Turn crash dumps on, off or report them -- and say why an unreadable crash is unreadable.
    ///
    /// MEASURED: `ulimit -c` was 0 and core_pattern piped to apport, so every fatal fault in this environment left
    /// NOTHING to read while looking identical to a fault with no information. Both settings are one step away and
    /// a throwaway process proved a real core is produced once they are set.
    Cores(CoresArgs),
    /// Read a CORE and name the faulting function. A guest's ud2 runs NATIVELY, so Darling cannot report it as a
    /// syscall and four other routes measured blind on the same crash (silent dmesg, an armed-but-silent witness, a
    /// guest that masks SIGSEGV, and a catch waiting for a swallowed signal). The core is written by the kernel and
    /// read by gdb with no ptrace; it is also OFF by default here, which this command states rather than hides.
    Core(CoreArgs),
    /// Census the per-thread identity a core (or a live prefix process) holds: `__TSD_MACH_THREAD_SELF` per thread,
    /// with machine-readable zero/duplicate/unstable flags and a count per distinct value.
    ///
    /// MEASURED why: that census was taken by hand for the libdispatch SIGILL, out of `thread apply all p/x` piped
    /// through greps that silently dropped lines and produced a wrong count once. A shared identity is exactly what a
    /// truncated scrape gets wrong, and it is the number the whole question turns on.
    Identity(IdentityArgs),
    /// Report the pattern of a process that is NOT working any more: one line repeating near the end of the log
    /// with almost nothing new between its repetitions.
    ///
    /// MEASURED need: "the log stopped growing" cannot tell a stuck process from an EXITED one (two runs here
    /// were read as a stall after the process had already exited), and line counts say what a process has done,
    /// never whether it is still doing anything. The real signature -- `pc-entry -> pc-postplane st=#- ->
    /// pc-return-9+` repeating for pages with nothing new between -- had to be found by eye.
    Loops(LoopsArgs),
    /// Print a core's OWN mapping table (NT_FILE), one row per mapping, plus optionally the mapping that owns an
    /// address and the bytes the core carries there.
    ///
    /// MEASURED why this is a command and not a throwaway script: the host's `readelf -n` REFUSES this core's 64-bit
    /// note ("Cannot decode 64-bit note in 32-bit build"), and reading the mapping list (or the bytes of a mapping)
    /// by hand was written from scratch three times -- twice with the page/byte unit of the note's file offsets
    /// wrong. The reader below is the one `core`/`identity`/`unwind` already use; this command is its standalone
    /// face, so the mapping table can be read without naming a faulting function first.
    Mappings(MappingsArgs),
    /// Print the runtime root and compact fingerprint of key installed binaries, with guest state reported separately.
    /// Shares verdict/cycle's candidate set; this compact fingerprint does not replace the complete install receipt.
    Env(EnvArgs),
}

// A tiny helper used by the table so a caller can see the set in a stable order under --json too.
#[allow(dead_code)]
fn btree_from(pairs: Vec<(String, String)>) -> BTreeMap<String, String> {
    pairs.into_iter().collect()
}

#[derive(clap::Args, Debug)]
pub struct MappingsArgs {
    /// The core file to read. Without it, the newest `core.*` under --dir is used.
    #[arg(long)]
    core: Option<PathBuf>,
    /// Directory holding cores when --core is not given.
    #[arg(long, default_value = "/tmp/t4cores")]
    dir: PathBuf,
    /// Prefix whose guest paths are de-virtualized so a row also names the file on THIS host. Without it the rows
    /// carry the path as the core records it, which is the /private/... path the guest used.
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// Also report the ONE mapping that owns this address (hex with or without `0x`, or decimal) and the file offset
    /// inside it. An address in no mapping is reported as such, never as offset 0.
    #[arg(long, value_name = "ADDR")]
    addr: Option<String>,
    /// Also print the bytes the core carries at ADDR:LEN (hex addresses, length in bytes), read through the core's
    /// OWN PT_LOAD segments. This is the arithmetic a throwaway parser did by hand, and it refuses -- with the reason
    /// -- when the dump does not cover the range instead of printing zeros.
    #[arg(long, value_name = "ADDR:LEN")]
    read: Option<String>,
    /// One compact JSON line instead of the human rows.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct EnvArgs {
    /// Optional writable guest-state prefix, reported separately from installed image digests.
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// One compact JSON line instead of the RUN-ENV line.
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args, Debug)]
pub struct CourierArgs {
    /// Run log. Defaults to the newest `dwdiag-verdict-*.log`.
    #[arg(long)]
    log: Option<PathBuf>,
    #[arg(long)]
    json: bool,
    /// The DEPLOYED artifact whose instruments this census relies on (default: the live prefix's loader). A silent
    /// instrument and an instrument that sent nothing look identical in a log; the artifact decides which.
    /// Deployed artifacts whose instruments this census relies on; defaults to the live prefix's loader, kernel
    /// image and server when none is given.
    #[arg(long)]
    artifact: Vec<PathBuf>,
    /// The prefix whose deployed artifacts the defaults come from. Without it the prefix is read out of the run
    /// log (`prefix=...`) or DWDIAG_PREFIX; if none resolves, every instrument check is UNMEASURED rather than
    /// silently taken from another prefix.
    #[arg(long)]
    prefix: Option<PathBuf>,
}

// THE TRANSPORT CENSUS. One row per transport, with the log token that counts it and its source instrument. A row whose
// instrument does not exist in the tree yet is printed UNMEASURED with the reason -- the alternative (a zero) is a
// number nobody measured, which is the failure mode this project keeps recording.
struct TransportRow {
    name: &'static str,
    /// Log patterns whose matching lines count this transport.
    patterns: &'static [&'static str],
    /// None = no instrument exists for this row today.
    instrument: Option<&'static str>,
    /// A token whose presence in the DEPLOYED artifact makes this row's count evidence rather than silence.
    proof_token: &'static str,
    /// A row that MUST be zero for the courier-purity requirement.
    must_be_zero: bool,
    /// The row's instrument is OPT-IN (an env-gated trace): its silence then means the trace was off, not that no
    /// traffic flowed. The count is reported as UNMEASURED rather than 0 (directive section 12: no fabricated zeros).
    opt_in_instrument: bool,
}

const TRANSPORTS: &[TransportRow] = &[
    TransportRow {
        name: "SPSC Ring (per-thread lane, ordinary calls)",
        patterns: &[r"RING_TRACE gen ENTER callnum="],
        instrument: Some("RING_TRACE gen ENTER (only under DARLING_GUEST_RING_TRACE=1)"),
        proof_token: "RING_TRACE gen ENTER callnum=",
        must_be_zero: false,
        opt_in_instrument: true,
    },
    TransportRow {
        name: "duplex Ring/mailbox (caller-S2C, OOL)",
        patterns: &[r"RING_MACHMSG_PUBLISH", r"dtape\.msgq event="],
        instrument: Some("guest RING_MACHMSG_PUBLISH / server dtape.msgq"),
        proof_token: "RING_MACHMSG_PUBLISH",
        must_be_zero: false,
        opt_in_instrument: true,
    },
    TransportRow {
        name: "process management plane (shared page, slot)",
        patterns: &[r"\[plane-", r"\[release-drops-pending\]"],
        instrument: Some("plane-* lines (partial: only named paths print)"),
        proof_token: "[plane-",
        must_be_zero: false,
        opt_in_instrument: false,
    },
    TransportRow {
        name: "urgent shared plane (interrupt/sigprocess)",
        patterns: &[r"urgent-service"],
        instrument: Some("urgent-service (server: one line per serviced urgent slot)"),
        proof_token: "urgent-service",
        must_be_zero: false,
        opt_in_instrument: false,
    },
    TransportRow {
        name: "SCM_RIGHTS courier (fd-bearing packets)",
        patterns: &[r"\[afunix-send\] .*scm=1", r"\[courier-send\] .*scm=1"],
        instrument: Some("afunix-send + courier-send (scm=1)"),
        proof_token: "[courier-send]",
        must_be_zero: false,
        opt_in_instrument: false,
    },
    TransportRow {
        name: "legacy ordinary AF_UNIX (semantic, no fd)",
        patterns: &[r"\[afunix-send\] .*scm=0", r"\[courier-send\] .*scm=0"],
        instrument: Some("afunix-send + courier-send (scm=0)"),
        proof_token: "[afunix-send]",
        must_be_zero: true,
        opt_in_instrument: false,
    },
    TransportRow {
        name: "zero-fd control/wake packets on AF_UNIX",
        patterns: &[r"\[afunix-wake\]"],
        instrument: Some(
            "afunix-wake (gone: the plane wake is now a non-packet; [plane-wake] records it)",
        ),
        proof_token: "[plane-wake]",
        must_be_zero: true,
        opt_in_instrument: false,
    },
];

fn run_courier(args: CourierArgs) -> Result<ExitCode> {
    let log = match args.log {
        Some(p) => p,
        None => newest_verdict_log()
            .context("no `dwdiag-verdict-*.log` in the temp directory; pass --log")?,
    };
    let text = read_log_lossy(&log).with_context(|| format!("read {}", log.display()))?;
    println!(
        "COURIER log={} lines={}",
        log.display(),
        text.lines().count()
    );
    // The ARTIFACT decides whether a zero is evidence: a token that is not in the deployed binary means the row was
    // never measured, however quiet the log is. (A silent probe is not evidence -- this project's own rule.)
    // The artifacts must come from the prefix THIS RUN used: a default pointing at some other prefix decides the
    // census against the wrong binary, which is worse than not deciding it.
    let resolved_prefix = resolve_prefix(args.prefix.clone(), Some(&log));
    let selected_runtime = crate::installed_runtime_root().ok();
    let default_artifacts: Vec<PathBuf> = match selected_runtime {
        Some(p) => vec![
            p.join("libexec/darling/usr/libexec/darling/mldr"),
            p.join("libexec/darling/usr/lib/system/libsystem_kernel.dylib"),
            // The SERVER carries the plane's own instruments (plane-wake, courier-send, urgent-service), so a
            // census of those rows cannot be judged without it: a zero whose instrument is missing from this
            // binary is not evidence.
            p.join("bin/darlingserver"),
        ],
        None => {
            println!(
                "COURIER-WARN no ordinary installation selected: instrument checks are UNMEASURED; pass --runtime-root or explicit --artifact"
            );
            Vec::new()
        }
    };
    if let Some(p) = &resolved_prefix {
        println!("COURIER-PREFIX {}", p.display());
    }
    let artifacts = if args.artifact.is_empty() {
        &default_artifacts
    } else {
        &args.artifact
    };
    let mut artifact_blobs: Vec<Vec<u8>> = Vec::new();
    for a in artifacts {
        match stored_evidence::read(a) {
            Ok(b) => artifact_blobs.push(b),
            Err(_) => println!("COURIER-WARN cannot read artifact {}", a.display()),
        }
    }
    let has_token = |tok: &str| -> Option<bool> {
        if tok.is_empty() {
            return None;
        }
        if artifact_blobs.is_empty() {
            return None;
        }
        let t = tok.as_bytes();
        Some(
            artifact_blobs
                .iter()
                .any(|b| b.windows(t.len()).any(|w| w == t)),
        )
    };
    println!("{:<48} {:>8}  {}", "transport", "packets", "instrument");
    let mut violations: Vec<String> = Vec::new();
    for row in TRANSPORTS {
        let mut n = 0u64;
        for pat in row.patterns {
            let re = Regex::new(pat).expect("transport pattern is a literal of this file");
            n += text.lines().filter(|l| re.is_match(l)).count() as u64;
        }
        let (count, inst) = match row.instrument {
            Some(i) => match has_token(row.proof_token) {
                Some(false) => (
                    "UNMEASURED".to_string(),
                    "instrument ABSENT from the deployed artifact",
                ),
                // None means the token could not be looked for at all (nothing readable to look in, or no token
                // defined). `n` is then a count of log lines, not a measurement of this transport, and reporting it
                // as one is how an unmeasured zero became PASS.
                None => (
                    "UNMEASURED".to_string(),
                    "instrument could not be checked: no readable deployed artifact",
                ),
                Some(true) => (format!("{n}"), i),
            },
            None => ("UNMEASURED".to_string(), "no instrument in the tree yet"),
        };
        // OPT-IN INSTRUMENT (directive section 12): a zero from an env-gated trace measures the TRACE FLAG, not the
        // traffic. Report it as UNMEASURED, because a fabricated zero row is worse than an admitted gap.
        let (count, inst) = if row.opt_in_instrument && count == "0" && !inst.contains("ABSENT") {
            (
                "UNMEASURED".to_string(),
                format!("{inst} -- trace not enabled in this run"),
            )
        } else {
            (count, inst.to_string())
        };
        println!("{:<48} {:>8}  {}", row.name, count, inst);
        if row.must_be_zero {
            if count == "UNMEASURED" {
                violations.push(format!("{} UNMEASURED ({inst})", row.name));
            } else if n > 0 {
                violations.push(format!("{} = {n} (must be 0)", row.name));
            }
        }
    }
    // KIND-LEVEL DELIVERY ACCOUNTING (user directive: the question "who received the bundle" must not require
    // reading the server's source). The server already logs every courier bundle with its kind and whether the
    // target connection is the LOADER's (`[courier-send-image] bundle-to pid=.. kind=.. isLoader=..`). Aggregating
    // that answers, in one command, a question that cost a source dive: which kinds reach the loader and which
    // reach only the guest image. The generic verdict flags any kind delivered ONLY to isLoader=0, because for the
    // process doorbell that is exactly the defect the wake census exposed (36 of 38 publishes had no doorbell).
    {
        use std::collections::BTreeMap;
        let mut by_kind: BTreeMap<(String, String), u64> = BTreeMap::new();
        for line in text.lines() {
            let Some(pos) = line.find("bundle-to ") else {
                continue;
            };
            let seg = &line[pos..];
            let field = |name: &str| -> Option<String> {
                let at = seg.find(name)?;
                let rest = &seg[at + name.len()..];
                let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                Some(rest[..end].to_string())
            };
            if let (Some(kind), Some(loader)) = (field("kind="), field("isLoader=")) {
                *by_kind.entry((kind, loader)).or_insert(0) += 1;
            }
        }
        if by_kind.is_empty() {
            println!(
                "COURIER-KINDS none -- the server's per-bundle delivery record is env-gated; re-run the workload with DARLING_SERVER_COURIER_LOG=1 to account for delivery by kind"
            );
        }
        if !by_kind.is_empty() {
            println!("COURIER-KINDS kind loader count");
            for ((kind, loader), n) in &by_kind {
                println!("  {kind:<22} isLoader={loader}  {n}");
            }
            let kinds: Vec<&String> = by_kind.keys().map(|(k, _)| k).collect();
            let mut only_image: Vec<&String> = Vec::new();
            for k in kinds {
                let to_loader: u64 = by_kind
                    .iter()
                    .filter(|((kk, l), _)| kk == k && l == "1")
                    .map(|(_, n)| *n)
                    .sum();
                let to_image: u64 = by_kind
                    .iter()
                    .filter(|((kk, l), _)| kk == k && l == "0")
                    .map(|(_, n)| *n)
                    .sum();
                if to_loader == 0 && to_image > 0 {
                    only_image.push(k);
                }
            }
            if only_image.is_empty() {
                println!(
                    "COURIER-KINDS-VERDICT every delivered kind reached the loader connection at least once"
                );
            } else {
                println!(
                    "COURIER-KINDS-VERDICT kind(s) delivered ONLY to the guest image (isLoader=0): {}",
                    only_image
                        .iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }
    if violations.is_empty() {
        println!("COURIER-VERDICT PASS legacy-ordinary-afunix=0 zero-fd-control=0");
        Ok(ExitCode::SUCCESS)
    } else {
        for v in &violations {
            println!("COURIER-VIOLATION {v}");
        }
        println!("COURIER-VERDICT FAIL violations={}", violations.len());
        Ok(ExitCode::from(1))
    }
}


#[cfg(test)]
mod witness_tests {
    use super::*;

    // ONE SAMPLE LINE PER INSTRUMENT, and the assertion that the registered pattern matches it. Why this exists: the
    // registry is what makes the census a census, and it rots the moment an instrument's FORMAT changes -- which
    // happened for real, twice in one session: `SEM-SITE` gained a `tcb=` field so `^SEM-SITE op=` stopped matching,
    // and the ring dump was rewritten from `trace-record` to `dtape.ering seq=`. In both cases the instrument was on
    // and the census called it silent. A format change now fails here instead of silently emptying a report.
    const SAMPLES: &[(&str, &str)] = &[
        (
            "sem-site",
            "SEM-SITE tcb=0x7d3d03e9e8c0 op=timedwait a=0x903 b=0x1E ra=0x71DA7C883893 sym0=semaphore_timedwait_trap_impl",
        ),
        ("iter-marks", "ITER 1 tid=1282542 port=2307 create"),
        (
            // Format copied from its emitter, `darling/src/startup/mldr/elfcalls/threads.c`
            // (`mldr_thread_diagf("[dthread-mask q=%d segv_blocked=%d tid=%d]\n", ...)`): a sample
            // invented here would pass this check while the real line stayed unmatched.
            "dthread-mask",
            "[dthread-mask q=0 segv_blocked=0 tid=1282542]",
        ),
        (
            "stall-dump",
            "[1790512650.010866](stall-dump, Error) stall-dump idle_ms=5136 serviced=571 processes=4 threads=8",
        ),
        // The eleven samples below were read out of their EMITTERS in the pinned product source, not built from
        // the registry pattern: a sample derived from the pattern it checks is a tautology that passes after the
        // emitter's format has already changed, which is the rot this table exists to catch.
        //   src/external/xnu/.../linux_premigration/signal/sigexc.c,
        //   .../linux_premigration/resources/dserver-ring.c,
        //   .../emulation/src/conversion/signal/sigaction.c,
        //   .../xnu_syscall/bsd/impl/signal/{sigaction,sigprocmask}.c,
        //   .../xnu_syscall/bsd/impl/process/wait4.c,
        //   .../xnu_syscall/mach/impl/mach_traps.c,
        //   .../linux_premigration/elfcalls_wrapper.c,
        //   src/external/darlingserver/src/server.cpp
        ("sigexc-deliver", "[sigexc-deliver linux_sig=11 si_code=1]"),
        ("sigexc-setup", "[sigexc-setup pid=1 tid=1282542 seq=3 libpage=0x7f0000000000]"),
        ("setrestart", "[setrestart sig=11 ret=0 host_tid=1282542 libpage=0x7f0000000000]"),
        ("native-exit", "[native-exit status=0 ra=0x71da7c883893]"),
        ("plane-claim-iter", "[plane-claim-iter n=3 t=0 obs=7 expect=7 page=0x7f2c00000000 op=1 tid=1282542]"),
        ("plane-reclaim", "[plane-reclaim] op=1 t=0 gen=9 tid=1282542"),
        ("fault", "[fault sig=11 addr=0x0 sicode=1]"),
        ("sigact", "[sigact pid=1 tid=1282542 bsd=11 linux=11 req=0x7fff0000 flags=0x0 ra=0x71da7c883893]"),
        ("guest-handler", "[guest-handler linux_sig=11 segv_masked=0]"),
        ("sigsegv-mask", "[sigsegv-mask how=0 ra=0x71da7c883893]"),
        ("wait4", "[wait4 pid=1282542 raw=0x0]"),
        ("segvdisp", "[segvdisp q=1 handler=0x71da7c883893 is_wrapper=0 is_bsd=1 is_sigexc=0 segv_masked=0 seq=4]"),
        (
            "completion-discarded",
            "[1790512650.010866](process-control-stale-completion, Error) completion-discarded pid=42 op=7 seq=5 slot_seq=4",
        ),
        (
            "ring-dump",
            "dtape.ering seq=453 tag=timer_arm a=0x62f094848e213 b=0x0 c=0x62f024c254e7f d=0x0",
        ),
        (
            "plane-refuse",
            "[plane-refuse] why=no-slot op=24 a=1 b=103079215108 tid=1274647",
        ),
        (
            "dtape-msgq",
            "dtape.msgq event=post_wake thread=0x653875af3de8 mqueue=0x653875aef3e8 arg=0x0 bits=0x300000000 result=1",
        ),
        (
            "dtape-timer",
            "dtape.wait_timer event=thread_unblock thread=0x60604ca39ee8 wait_result=0 had_timer=0 active=0",
        ),
        (
            "rpc-begin",
            "rpc.semaphore.begin operation=semaphore_timedwait pid=1 tid=1250752 wait_name=2307 signal_name=none sec=30 nsec=0",
        ),
        (
            "rpc-reply",
            "rpc.semaphore.reply operation=semaphore_timedwait pid=1 tid=1250752 wait_name=2307 signal_name=none code=49 outcome=timeout terminal=reply-enqueued",
        ),
        (
            "crash",
            "[dserver-CRASH sig=b addr=0x0,self=61d5aa4f9060,ret=0x0,sp=0x7de2c8112bf0,pc=0x61d5aa61229b",
        ),
        ("workload-stall", "RING_MACH_TEST_STALL age=31.9"),
        ("execpath-after", "seq=4 after-execpath status=0"),
        (
            "sigexc",
            "[sigexc-fatal sig=11 code=1 addr=0x0 pid=2678054 tid=2678054]",
        ),
        (
            "plane-slow",
            "[plane-slow op=24 state=1 rseq=7 rs=-1 rq=0 tid=1274647]",
        ),
        (
            "modrefs",
            "[modrefs-entry target=1 name=2 right=3 delta=-1]",
        ),
        ("allocprobe", "[allocprobe]"),
        (
            "ring-trace-gen",
            "RING_TRACE gen ENTER callnum=9 tid=1250752",
        ),
        ("iter-drop", "ITER 3 tid=1282542 drop_enter"),
        (
            "rpc-socket-denied",
            "[rpc-socket-DENIED] pid=1 tid=2 call=pthread_kill image=kernel delta=0x1a denied=1",
        ),
        (
            "checkout-path",
            "[checkout-path] pid=1 tid=2 page=0x7f ready=0 main=1",
        ),
        (
            "checkin-path",
            "[checkin-path] pid=1 tid=2 page=0x7f ready=0 -> no-transport (declined)",
        ),
        (
            "release-drops-pending",
            "[release-drops-pending] site=dserver-ring.c:2752",
        ),
        (
            "ulock-wait-park",
            "[ulock-wait-park] pid=1064369 op=0x1050002 addr=0x71f0683a3e00 word=0x102 owner_tid=1064369 owner_ptr=0x61a7a4f02b20 waiter_tid=1064413 nwaiters=1",
        ),
        (
            "ulock-wait-cleanup",
            "[ulock-wait-cleanup] pid=1064369 addr=0x71f0683a3e00 waiter_tid=1064413 depth=3 nwaiters=1",
        ),
        (
            "ulock-wake-entry",
            "[ulock-wake-entry] pid=1064369 addr=0x71f0683a3e00 owner_ptr=0x61a7a4f02b20 self=0x61a7a4f02b20 nwaiters=1 op=0x1050002",
        ),
        (
            "ulock-wake",
            "[ulock-wake] pid=1064369 addr=0x71f0683a3e00 op=0x1050002 nwaiters=1 woke=1 set_owner=0",
        ),
        (
            "ulock-wake-nobody",
            "[ulock-wake-nobody] pid=1064369 addr=0x71f0683a3e00 nwaiters=0 set_owner=0",
        ),
        (
            "ulock-wake-enoent",
            "[ulock-wake-enoent] pid=1064369 addr=0x71f0683a3e00 op=0x1050002",
        ),
        (
            "ulock-wake-late",
            "[ulock-wake-late] pid=1064369 addr=0x71f0683a3e00 owner=0x61a7a4f02b20 self=0x61a7a4f02b20",
        ),
    ];

    #[test]
    fn every_registered_instrument_matches_its_sample() {
        for (name, sample) in SAMPLES {
            let (_, pattern, _) = INSTRUMENTS
                .iter()
                .find(|(n, _, _)| n == name)
                .unwrap_or_else(|| panic!("instrument {name} is registered nowhere"));
            let re = Regex::new(pattern).unwrap();
            assert!(
                re.is_match(sample),
                "instrument {name} does not match its own sample line"
            );
        }
    }

    #[test]
    fn every_instrument_has_a_sample() {
        // EVERY missing name, not the first one: the one-at-a-time panic turns a registry gap into as many
        // edit-rebuild cycles as there are gaps, which is how one missing sample stayed unnoticed.
        let missing: Vec<&str> = INSTRUMENTS
            .iter()
            .filter(|(name, _, _)| !SAMPLES.iter().any(|(n, _)| n == name))
            .map(|(name, _, _)| *name)
            .collect();
        assert!(
            missing.is_empty(),
            "instruments with no sample line (their patterns are unchecked): {missing:?}"
        );
    }
}

#[cfg(test)]
mod workload_tests {
    use super::*;

    #[test]
    fn a_missing_workload_is_not_a_workload_failure() {
        let text = "mode=basic\n/usr/bin/ring_mach_msg_test: not found\n__DWDIAG_RC=127\n";
        let (line, verdict, rc) = judge_run_log(text, "basic");
        assert!(line.is_empty(), "{line}");
        assert!(verdict.starts_with("NO-RUN"), "{verdict}");
        assert_eq!(rc, Some(127));
    }

    #[test]
    fn a_pass_is_still_a_pass() {
        let text = "mode=basic\nRING_MACH_TEST mode=basic pass=1\n__DWDIAG_RC=0\n";
        let (line, verdict, rc) = judge_run_log(text, "basic");
        assert!(line.contains("pass=1"), "{line}");
        assert_eq!(verdict, "PASS");
        assert_eq!(rc, Some(0));
    }
}

#[cfg(test)]
mod stack_words_tests {
    use super::*;

    fn mem_of(words: &[u64]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn one_exec_map(lo: u64, hi: u64) -> Vec<(u64, u64, bool, u64, String)> {
        vec![(lo, hi, true, 0, "/fake/img".to_string())]
    }

    /// The order of `stack_words` is DEPTH, not address. This is the regression the callers depend
    /// on: the words it returns were sorted by address before, which turns a call chain into a set,
    /// so an unrelated function could read as the caller of any other. The innermost word is the
    /// SMALLEST here, so a sort would reorder all three and this test would fail.
    #[test]
    fn stack_words_keep_depth_order_not_address_order() {
        let maps = one_exec_map(0x1000, 0x10_0000);
        let words = [0x9_0000, 0x5_0000, 0x2_0000];
        assert_eq!(stack_words(&mem_of(&words), &maps), vec![0x9_0000, 0x5_0000, 0x2_0000]);
    }

    /// A repeated return address stays where its deepest frame is, and a word that is in no
    /// executable mapping is not a frame at all.
    #[test]
    fn stack_words_dedup_keeps_the_innermost_occurrence_and_drops_non_code() {
        let maps = one_exec_map(0x1000, 0x10_0000);
        let words = [0x9_0000, 0xdead_beef, 0x9_0000, 0x2_0000, 0x0];
        assert_eq!(stack_words(&mem_of(&words), &maps), vec![0x9_0000, 0x2_0000]);
    }
}

#[cfg(test)]
mod core_map_tests {
    use super::*;

    // `resolve_in_core` only ever sees BYTE offsets: the normalization (the kernel's page-scaled file offsets, and
    // gdb's byte-scaled ones) happens once in `CoreFile::open`, against the unit the note declares. MEASURED on the
    // real core: ranges are bytes while file_offset is a page number, so a raw offset of 1 cannot mean one byte.
    #[test]
    fn a_resolved_address_carries_its_mapping_base_and_a_byte_file_offset() {
        let maps = vec![(0x7dc012b27000u64, 0x7dc012b30000u64, 0x1000u64, "/tmp/nope".to_string())];
        let (base, off, name) = resolve_in_core(&maps, 0x7dc012b27396).unwrap();
        assert_eq!(base, 0x7dc012b27000);
        assert_eq!(off, 0x1000 + 0x396);
        assert_eq!(name, "/tmp/nope");
    }

    #[test]
    fn an_address_outside_every_mapping_resolves_to_nothing() {
        let maps = vec![(0x1000u64, 0x2000u64, 0u64, "/tmp/nope".to_string())];
        assert!(resolve_in_core(&maps, 0x2000).is_none());
        assert!(resolve_in_core(&maps, 0xfff).is_none());
    }

    // De-virtualization is what makes a guest path openable, and a path that names neither a guest view nor a real
    // file must resolve to NOTHING so the caller can say "unresolved" instead of symbolizing the wrong file.
    #[test]
    fn guest_paths_are_de_virtualized_and_missing_paths_are_not() {
        assert_eq!(guest_path_to_host("/Volumes/SystemRoot/tmp", None),
            Some(PathBuf::from("/tmp")));
        assert!(guest_path_to_host("/nonexistent/darling/path/xyz", None).is_none());
    }
}

#[cfg(test)]
mod mappings_cmd_tests {
    use super::*;

    // The address argument is typed by a human reading a hex dump, so both spellings must land on the same value,
    // and junk must be REFUSED rather than silently read as 0 -- 0 is a real address in a core, so a parse that
    // defaults to zero answers about the wrong mapping.
    #[test]
    fn an_address_argument_accepts_both_spellings_and_refuses_junk() {
        assert_eq!(parse_addr_arg("0x7dc012b27000").unwrap(), 0x7dc012b27000);
        assert_eq!(parse_addr_arg("7dc012b27000").unwrap(), 0x7dc012b27000);
        assert_eq!(parse_addr_arg("4096").unwrap(), 4096);
        assert!(parse_addr_arg("0xzz").is_err());
        assert!(parse_addr_arg("not-an-address").is_err());
    }

    // A `--read` argument is the arithmetic the throwaway parser did by hand: an address and a length, with a
    // missing separator or a non-numeric length REFUSED rather than read as zero -- zero bytes of the wrong range
    // is exactly the silent wrong answer this replaces.
    #[test]
    fn a_read_argument_needs_both_halves_and_a_numeric_length() {
        assert_eq!(parse_read_arg("0x5ee28f52c000:16").unwrap(), (0x5ee28f52c000, 16));
        assert_eq!(parse_read_arg("4096:4").unwrap(), (4096, 4));
        assert!(parse_read_arg("0x5ee28f52c000").is_err());
        assert!(parse_read_arg("0x5ee28f52c000:0x10").is_err());
        assert!(parse_read_arg("nope:4").is_err());
    }
}

#[cfg(test)]
mod runtime_fingerprint_tests {
    use super::*;

    // The identity line is the answer to "which build actually ran", so it must digest the DEPLOYED copy and it
    // must be empty (stating a reason) when there is nothing deployed -- an empty list can never read as "the same
    // build as the other run".
    #[test]
    fn the_fingerprint_names_a_deployed_copy_and_is_empty_without_one() {
        let root = std::env::temp_dir().join(format!("dwdiag-env-{}-{}", std::process::id(), line!()));
        let deployed = root.join("libexec/darling/usr/libexec/darling");
        fs::create_dir_all(&deployed).unwrap();
        fs::write(deployed.join("mldr"), b"not-really-a-loader\n").unwrap();
        let parts = runtime_fingerprint_parts(&root);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].0, "mldr");
        assert_eq!(parts[0].1.len(), 12);
        assert!(runtime_fingerprint(&root).starts_with(&format!("runtime-root={} mldr=", root.display())));
        let empty = std::env::temp_dir().join(format!("dwdiag-envempty-{}", std::process::id()));
        fs::create_dir_all(&empty).unwrap();
        assert!(runtime_fingerprint_parts(&empty).is_empty());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn capabilities_distinguish_guest_prefixes_with_shared_executables() {
        let root = std::env::temp_dir().join(format!("dwdiag-ownership-{}", std::process::id()));
        let first = root.join("first");
        let second = root.join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let retained = fs::File::open(&first).unwrap();
        assert!(process_owns_prefix(std::process::id(), &first));
        assert!(!process_owns_prefix(std::process::id(), &second));
        drop(retained);
        assert!(!process_owns_prefix(std::process::id(), &first));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn workload_recording_never_rewrites_install_receipts_or_existing_evidence() {
        let root = std::env::temp_dir().join(format!("dwdiag-evidence-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let receipt = root.join(".darling-deploy-receipt.json");
        fs::write(&receipt, "immutable install provenance").unwrap();
        let evidence = root.join("run.json");
        record_workload_evidence(&evidence, &root, "{\"verdict\":\"PASS\"}").unwrap();
        assert_eq!(fs::read_to_string(&receipt).unwrap(), "immutable install provenance");
        let recorded = fs::read(&evidence).unwrap();
        assert!(record_workload_evidence(&evidence, &root, "{\"verdict\":\"FAIL\"}").is_err());
        assert_eq!(fs::read(&evidence).unwrap(), recorded);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod core_identity_tests {
    use super::*;

    fn regs(pairs: &[(&str, u64)]) -> Regs {
        let mut v = [0u64; GPR_COUNT];
        for (n, val) in pairs {
            v[GPR.iter().position(|x| x == n).expect("a name in GPR")] = *val;
        }
        Regs { v }
    }

    fn put_u16(buf: &mut [u8], at: usize, v: u16) { buf[at..at + 2].copy_from_slice(&v.to_le_bytes()); }
    fn put_u32(buf: &mut [u8], at: usize, v: u32) { buf[at..at + 4].copy_from_slice(&v.to_le_bytes()); }
    fn put_u64(buf: &mut [u8], at: usize, v: u64) { buf[at..at + 8].copy_from_slice(&v.to_le_bytes()); }

    /// One ELF note, with the name NUL-terminated and both fields padded to 4 bytes exactly as the kernel writes
    /// them.
    fn note(ntype: u32, name: &str, desc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(name.len() as u32 + 1).to_le_bytes());
        out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        out.extend_from_slice(&ntype.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 { out.push(0); }
        out.extend_from_slice(desc);
        while out.len() % 4 != 0 { out.push(0); }
        out
    }

    /// A complete but TINY core, built byte by byte: one PT_LOAD the dump carries (a "stack" page), one it does not
    /// (a clean file-backed page, which is the normal case for the page a thread died on), and one PT_NOTE with an
    /// NT_PRSTATUS, an NT_SIGINFO, an NT_FILE and an NT_PRPSINFO.
    ///
    /// This is what makes the note LAYOUT testable: if a field offset or a register index drifts, this test fails,
    /// instead of a 670 MB core quietly reporting somebody else's register. The shell contract runs the same code
    /// against a core the KERNEL writes; this one pins the offsets against hand-placed bytes.
    ///
    /// `note_page` and `raw_file_ofs` are the NT_FILE convention under test: the kernel writes page_size=0x1000 with
    /// the file offset in PAGES, gdb's `gcore` writes page_size=1 with it in BYTES, and both are covered.
    fn synthetic_core(dir: &Path, tag: &str, note_page: u64, raw_file_ofs: u64) -> (PathBuf, PathBuf) {
        const NS: &str = "CORE";
        const IMAGE_AT: u64 = 0x20000;
        let image = dir.join(format!("libfake-{tag}.dylib"));
        fs::write(&image, b"not really a Mach-O").unwrap();

        let mut prstatus = vec![0u8; 336];
        put_u32(&mut prstatus, 0, 4); // pr_info.si_signo
        put_u32(&mut prstatus, 8, 2); // pr_info.si_code
        put_u32(&mut prstatus, PRSTATUS_PID_AT, 42);
        let mut set = |name: &str, v: u64| {
            let i = GPR.iter().position(|x| *x == name).unwrap();
            put_u64(&mut prstatus, PRSTATUS_REGS_AT + i * 8, v);
        };
        set("rip", IMAGE_AT + 0x200);
        set("rbp", 0x10800);
        set("rsp", 0x107f0);
        set("rdi", 0x10f00); // points at the once word in the carried page
        set("rcx", 0x100);
        set("rdx", 0x101);
        set("gs_base", 0x10f80); // slot 3 is at +24 = 0x10f98

        let mut siginfo = vec![0u8; 128];
        put_u32(&mut siginfo, 0, 4); // SIGILL
        put_u32(&mut siginfo, 8, 2); // ILL_ILLOPN
        put_u64(&mut siginfo, 16, IMAGE_AT + 0x200);

        let mut file_note = Vec::new();
        file_note.extend_from_slice(&1u64.to_le_bytes()); // count
        file_note.extend_from_slice(&note_page.to_le_bytes()); // the unit the file offset below is in
        file_note.extend_from_slice(&IMAGE_AT.to_le_bytes()); // start
        file_note.extend_from_slice(&(IMAGE_AT + 0x1000).to_le_bytes()); // end
        file_note.extend_from_slice(&raw_file_ofs.to_le_bytes());
        file_note.extend_from_slice(image.display().to_string().as_bytes());
        file_note.push(0);

        let mut psargs = vec![0u8; 136];
        psargs[PRPSINFO_PSARGS_AT..PRPSINFO_PSARGS_AT + 16].copy_from_slice(b"core-test-binary");

        let mut notes = Vec::new();
        notes.extend_from_slice(&note(NT_PRSTATUS, NS, &prstatus));
        notes.extend_from_slice(&note(NT_SIGINFO, NS, &siginfo));
        notes.extend_from_slice(&note(NT_FILE, NS, &file_note));
        notes.extend_from_slice(&note(NT_PRPSINFO, NS, &psargs));

        // The carried page: a two-frame chain, the once word rdi points at, and the thread's TSD slot 3.
        let mut page = vec![0u8; 0x1000];
        let at = |v: u64| (v - 0x10000) as usize;
        put_u64(&mut page, at(0x10800), 0x10820); // [rbp]    -> next frame pointer
        put_u64(&mut page, at(0x10808), IMAGE_AT + 0x250); // [rbp+8] -> a return address in the image
        put_u64(&mut page, at(0x10820), 0x10830);
        put_u64(&mut page, at(0x10828), 0x9); // a return address in NO image: the walk must stop here
        put_u64(&mut page, at(0x10f00), 0x101); // the once word
        put_u64(&mut page, at(0x10f98), 0x103); // TSD slot 3

        let phnum = 3u16;
        let mut buf = vec![0u8; 0x1000];
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // 64-bit
        buf[5] = 1; // little-endian
        put_u16(&mut buf, 16, 4); // ET_CORE
        put_u64(&mut buf, 0x20, 0x40); // e_phoff
        put_u16(&mut buf, 0x36, 56); // e_phentsize
        put_u16(&mut buf, 0x38, phnum);
        let phdr = |buf: &mut [u8], i: usize, ptype: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64| {
            let p = 0x40 + i * 56;
            put_u32(buf, p, ptype);
            put_u32(buf, p + 4, 6); // rw
            put_u64(buf, p + 8, off);
            put_u64(buf, p + 16, vaddr);
            put_u64(buf, p + 32, filesz);
            put_u64(buf, p + 40, memsz);
            put_u64(buf, p + 48, 0x1000);
        };
        let notes_off = 0x2000u64;
        phdr(&mut buf, 0, 1, 0x1000, 0x10000, 0x1000, 0x1000); // the page the dump carries
        phdr(&mut buf, 1, 1, 0x2000, IMAGE_AT, 0, 0x1000); // a clean page the dump does NOT carry
        phdr(&mut buf, 2, 4, notes_off, 0, notes.len() as u64, 0); // PT_NOTE
        buf.extend_from_slice(&page);
        assert_eq!(buf.len() as u64, 0x2000, "the note area must start where the header says");
        buf.extend_from_slice(&notes);

        let core = dir.join(format!("core.synthetic-{tag}"));
        fs::write(&core, &buf).unwrap();
        (core, image)
    }

    /// The two NT_FILE conventions, both read the same way: the note's file offset is multiplied by the unit the note
    /// DECLARES. MEASURED: the kernel writes page_size=0x1000 with a page-numbered file offset, gdb's `gcore` writes
    /// page_size=1 with a byte one -- and assuming 4096 for the latter made every file offset 4096x too large, so the
    /// instruction at the fault came back empty from a core that had it.
    #[test]
    fn both_nt_file_conventions_normalize_to_the_same_byte_offset() {
        let dir = std::env::temp_dir().join(format!("dwdiag-core-unit-fmt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // The kernel: raw 1, page_size 0x1000 -> 0x1000 bytes.
        let (kernel_core, _) = synthetic_core(&dir, "kernel", 0x1000, 1);
        let k = CoreFile::open(&kernel_core).unwrap();
        assert_eq!(k.file_page, 0x1000);
        assert_eq!(k.resolve(0x20200, None).unwrap().file_off, 0x1000 + 0x200);
        // gdb's gcore: raw 0x2800, page_size 1 -> 0x2800 bytes.
        let (gdb_core, _) = synthetic_core(&dir, "gdb", 1, 0x2800);
        let g = CoreFile::open(&gdb_core).unwrap();
        assert_eq!(g.file_page, 1);
        assert_eq!(g.resolve(0x20200, None).unwrap().file_off, 0x2800 + 0x200);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn archived_core_preserves_registers_and_seekable_memory() {
        let dir = std::env::temp_dir().join(format!("dwdiag-core-zstd-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let (core, _) = synthetic_core(&dir, "archived", 0x1000, 1);
        let mut raw = CoreFile::open(&core).unwrap();
        let expected_memory = raw.read_mem(0x10800, 16).unwrap();
        let compressed = core.with_file_name(format!("{}.zst", core.file_name().unwrap().to_string_lossy()));
        let output = Command::new("zstd").args(["-q", "-c", "--"]).arg(&core)
            .stdout(fs::File::create(&compressed).unwrap()).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        fs::remove_file(&core).unwrap();
        let mut archived = CoreFile::open(&core).unwrap();
        assert_eq!(archived.threads[0].lwp, raw.threads[0].lwp);
        assert_eq!(archived.threads[0].regs.rip(), raw.threads[0].regs.rip());
        assert_eq!(archived.maps, raw.maps);
        assert_eq!(archived.read_mem(0x10800, 16).unwrap(), expected_memory);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_synthetic_core_is_read_field_by_field() {
        let dir = std::env::temp_dir().join(format!("dwdiag-core-unit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (core, image) = synthetic_core(&dir, "kernel", 0x1000, 1);

        let mut c = CoreFile::open(&core).unwrap();
        // The LAYOUT, asserted rather than assumed: the register indices, the prstatus field offsets and the note
        // sizes all come from the same constants the reader uses.
        assert_eq!(GPR.len(), GPR_COUNT);
        assert_eq!((GPR[GPR_RIP], GPR[GPR_RBP], GPR[GPR_RSP], GPR[GPR_GS_BASE]), ("rip", "rbp", "rsp", "gs_base"));
        assert_eq!(PRSTATUS_BYTES, 328);
        assert_eq!(c.threads.len(), 1);
        assert_eq!(c.threads[0].lwp, 42);
        assert_eq!(c.threads[0].regs.rip(), 0x20200);
        assert_eq!(c.threads[0].regs.gs_base(), 0x10f80);
        assert_eq!(c.sig.map(|s| (s.signo, s.code)), Some((4, 2)));
        assert_eq!(c.args, "core-test-binary");
        // The scale is decided from the core's own program headers: one entry fits a PT_LOAD as bytes, none as pages.
        assert_eq!(c.scale, MapScale::Bytes);
        assert_eq!(c.inside, (1, 0));

        // The mapping table names the image, the base and the FILE offset (page-scaled).
        let r = c.resolve(0x20200, None).unwrap();
        assert_eq!((r.base, r.file_off), (0x20000, 0x1000 + 0x200));
        assert_eq!(r.name, image.display().to_string());
        assert!(r.exists, "the synthetic image file does exist");

        // Memory: the carried page reads, the page the dump skipped does not, and it says WHY.
        assert_eq!(c.read_u64(0x10f98).unwrap(), 0x103);
        let err = c.read_mem(0x20000, 8).unwrap_err();
        assert!(err.contains("did not carry"), "{err}");
        assert!(c.carried(0x20000) && !c.carried(0x50000));

        // The operands, through the same rule the real core answers with.
        let regs = c.threads[0].regs;
        let o = once_operands(&regs, |a| c.read_u64(a).ok()).unwrap();
        assert_eq!((o.predicate_reg, o.predicate), ("rdi", 0x10f00));
        assert_eq!((o.word, o.word_reg), (0x101, Some("rdx")));
        assert_eq!((o.owner, o.owner_reg), (0x100, "rcx"));

        // The walk: two frames, every return address mapped through the core's own table, and a STATED stop.
        let (frames, stop) = core_fp_chain(&mut c, regs.rbp(), regs.rsp(), None, 16);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].ret, 0x20250);
        assert_eq!(frames[0].image.as_ref().map(|i| i.file_off), Some(0x1000 + 0x250));
        assert_eq!(frames[1].ret, 0x9);
        assert!(frames[1].image.is_none());
        assert!(stop.contains("no mapped image"), "{stop}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_not_a_core_is_refused_by_name() {
        let dir = std::env::temp_dir().join(format!("dwdiag-core-unit-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("not-a-core");
        fs::write(&p, b"hello").unwrap();
        let Err(err) = CoreFile::open(&p) else { panic!("a text file must be refused") };
        let err = format!("{err:#}");
        assert!(err.contains("shorter than an ELF header"), "{err}");
        // A file with an ELF header's worth of bytes that is still not an ELF.
        let p2 = dir.join("still-not-a-core");
        fs::write(&p2, vec![b'x'; 100]).unwrap();
        let Err(err) = CoreFile::open(&p2) else { panic!("junk must be refused") };
        let err = format!("{err:#}");
        assert!(err.contains("not an ELF file"), "{err}");
        // And an ELF that is not a core: the tool's own binary is one, and the refusal has to name why.
        if let Ok(exe) = std::env::current_exe() {
            let Err(err) = CoreFile::open(&exe) else { panic!("a test binary must be refused") };
            let err = format!("{err:#}");
            assert!(err.contains("not ET_CORE"), "{err}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// The live parser, on captured output: the gdb thread NUMBER is decimal while the registers are hex, and
    /// `info threads` is what turns that number into the host LWP.
    ///
    /// THREAD 10+ IS THE CASE THAT MATTERS. Parsing the number as hex makes 10 read as 16, the row stops matching its
    /// LWP, and every thread silently becomes a "listed but never read" failure -- the dropped-thread defect this
    /// command exists to remove, reintroduced by one radix. The blob also has a thread gdb listed and never read, so
    /// the gap is testable too.
    #[test]
    fn a_live_sample_joins_decimal_thread_numbers_to_lwps_and_sees_a_short_read() {
        let text = "\
  Id   Target Id         Frame\n\
* 1    Thread 0x7f (LWP 5001) \"t\" 0x0 in f ()\n\
  10   Thread 0x7f (LWP 5010) \"t\" 0x0 in f ()\n\
  11   Thread 0x7f (LWP 5011) \"t\" 0x0 in f ()\n\
@ident tid=1 gs=0x1000 ip=0x2000 slot3=0x103\n\
@ident tid=10 gs=0x1100 ip=0x2100 slot3=0x903\n";
        let s = parse_live_sample(text, None);
        assert_eq!(s.listed, 3, "three threads were listed");
        assert_eq!(s.lwp.get(&1), Some(&5001));
        assert_eq!(s.lwp.get(&10), Some(&5010), "thread 10 is ten, not sixteen");
        assert_eq!(s.rows.get(&10).map(|r| r.2.clone()), Some(Ok(0x903)));
        assert_eq!(s.rows.get(&10).map(|r| r.1), Some(0x2100));
        // Listed and never read: the census has to be able to see this as a gap, which is why the count is carried.
        assert!(s.rows.get(&11).is_none());
        assert_eq!(s.rows.len(), 2);
        // A zero $gs_base is a READ FAILURE with its reason, not a value of zero.
        let s2 = parse_live_sample("@ident tid=1 gs=0x0 ip=0x2000 slot3=UNREADABLE\n", None);
        assert_eq!(s2.rows.get(&1).map(|r| r.2.clone()), Some(Err("$gs_base = 0: no GS-based TSD block to read".to_string())));
    }

    fn sample(lwp: u32, slot: Result<u64, String>) -> IdentitySample {
        IdentitySample { lwp, slot3: slot, unstable: None, ip: 0, ip_image: None, ip_addr: None, partial: false }
    }

    #[test]
    fn the_census_counts_values_flags_duplicates_and_keeps_failures_out_of_the_values() {
        let s = vec![
            sample(1, Ok(0x103)),
            sample(2, Ok(0x103)),
            sample(3, Ok(0x103)),
            sample(4, Ok(0x903)),
            sample(5, Ok(0)),
            sample(6, Ok(0)),
            sample(7, Err("gs_base is 0 in this thread's register note".to_string())),
        ];
        let c = census_counts(&s);
        assert_eq!(c[0], (0x103, vec![1, 2, 3]));
        assert!(value_is_duplicated(&c, 0x103));
        assert!(!value_is_duplicated(&c, 0x903));
        // MEASURED rule kept from the core-lock census: an identity of 0 names nobody, so two threads at 0 are
        // unset rather than sharing a name.
        assert!(!value_is_duplicated(&c, 0));
        // A failed read is not a value and not a zero: the census has 6 values over 7 threads.
        assert_eq!(c.iter().map(|(_, l)| l.len()).sum::<usize>(), 6);
        assert_eq!(c.iter().filter(|(v, _)| *v == 0).count(), 1);
    }

    #[test]
    fn the_once_operands_are_located_from_the_pointer_register_and_its_masked_owner() {
        // MEASURED, on /tmp/t4cores/core.127004: rdi points at 0x101, rcx holds 0x100 = 0x101 & !3, rdx holds the
        // word -- the three values the hand diagnosis recorded.
        let r = regs(&[("rdi", 0x763d_5799_d988), ("rcx", 0x100), ("rdx", 0x101)]);
        let o = once_operands(&r, |a| (a == 0x763d_5799_d988).then_some(0x101)).unwrap();
        assert_eq!((o.predicate_reg, o.predicate), ("rdi", 0x763d_5799_d988));
        assert_eq!(o.word, 0x101);
        assert_eq!(o.word_reg, Some("rdx"));
        assert_eq!((o.owner, o.owner_reg), (0x100, "rcx"));
    }

    #[test]
    fn operands_are_never_invented_when_the_register_file_does_not_match() {
        // Nothing readable at all.
        let r = regs(&[("rdi", 0x1000), ("rsi", 0x2000)]);
        assert!(once_operands(&r, |_| None).is_none());
        // A word whose masked form appears in NO other register: exactly the coincidence the rule must reject.
        assert!(once_operands(&r, |a| (a == 0x1000).then_some(0xab)).is_none());
        // A 64-bit value that is a pointer, not a once word.
        let r = regs(&[("rdi", 0x1000), ("rcx", 0x100)]);
        assert!(once_operands(&r, |a| (a == 0x1000).then_some(1 << 40)).is_none());
    }

    /// `--catch SIGSEGV` is the spelling a reader writes; it must not become `SIGSIGSEGV`.
    #[test]
    fn the_armed_signal_word_keeps_one_sig_prefix() {
        assert_eq!(gdb_signal_word("SIGSEGV"), "SIGSEGV");
        assert_eq!(gdb_signal_word("segv"), "SIGSEGV");
        assert_eq!(gdb_signal_word(" SIGILL "), "SIGILL");
        assert_eq!(gdb_signal_word("11"), "11");
    }

    #[test]
    fn the_signal_label_is_a_name_a_reader_recognises() {
        assert_eq!(sig_label(4), "SIGILL");
        assert_eq!(sig_label(11), "SIGSEGV");
        // A signal this tool has no name for is its NUMBER, never a made-up `SIGSIG`.
        assert_eq!(sig_label(33), "33");
        assert!(sig_code_meaning(4, -6).unwrap().contains("SI_TKILL"));
        assert!(sig_code_meaning(4, 2).unwrap().contains("ud2"));
        assert!(sig_code_meaning(4, 9999).is_none());
    }

    /// The discovery that replaced a hardcoded directory: the pattern decides the directory and the name prefix, and
    /// a pattern line for a LIVE Process is not turned into a path at all.
    #[test]
    fn core_pattern_is_split_into_a_directory_and_a_name_prefix() {
        let p = core_pattern();
        if p.pattern.starts_with('|') {
            assert!(p.piped);
        } else {
            assert!(!p.piped);
            assert!(p.pattern.starts_with(&p.dir.display().to_string()) || p.dir == Path::new("."));
        }
    }
}

#[cfg(test)]
mod macho_vmaddr_tests {
    use super::*;

    #[test]
    fn segment_file_offsets_map_to_vm_addresses_in_thin_and_fat_images() {
        let dir = std::env::temp_dir().join(format!("dwdiag-vmaddr-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let mut thin = vec![0u8; 0x3000];
        thin[0..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        thin[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        thin[8..12].copy_from_slice(&3u32.to_le_bytes());
        thin[12..16].copy_from_slice(&6u32.to_le_bytes());
        thin[16..20].copy_from_slice(&1u32.to_le_bytes());
        thin[20..24].copy_from_slice(&72u32.to_le_bytes());
        thin[32..36].copy_from_slice(&0x19u32.to_le_bytes());
        thin[36..40].copy_from_slice(&72u32.to_le_bytes());
        thin[56..64].copy_from_slice(&0x12000u64.to_le_bytes());
        thin[64..72].copy_from_slice(&0x2000u64.to_le_bytes());
        thin[72..80].copy_from_slice(&0x2000u64.to_le_bytes());
        thin[80..88].copy_from_slice(&0x1000u64.to_le_bytes());
        let mut fat = vec![0u8; 0x4000];
        fat[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        fat[4..8].copy_from_slice(&1u32.to_be_bytes());
        fat[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
        fat[12..16].copy_from_slice(&3u32.to_be_bytes());
        fat[16..20].copy_from_slice(&0x1000u32.to_be_bytes());
        fat[20..24].copy_from_slice(&0x3000u32.to_be_bytes());
        fat[24..28].copy_from_slice(&12u32.to_be_bytes());
        fat[0x1000..].copy_from_slice(&thin);
        for (name, bytes, slice_base) in [("thin", thin, 0), ("fat", fat, 0x1000)] {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            let image = path.to_str().unwrap();
            assert_eq!(macho_vmaddr_for_fileoff(image, slice_base + 0x2000), Some(0x12000));
            assert_eq!(macho_vmaddr_for_fileoff(image, slice_base + 0x2a9e), Some(0x12a9e));
            assert_eq!(macho_vmaddr_for_fileoff(image, slice_base + 0x2fff), Some(0x12fff));
            assert_eq!(macho_vmaddr_for_fileoff(image, slice_base + 0x1fff), None);
            assert_eq!(macho_vmaddr_for_fileoff(image, slice_base + 0x3000), None);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_non_macho_or_missing_image_is_not_converted() {
        assert_eq!(macho_vmaddr_for_fileoff("/nonexistent/image", 0x10), None);
    }
}


// ----------------------------------------------------------------------------------------------------------------
// job: one finished run explains itself
// ----------------------------------------------------------------------------------------------------------------

/// A job's own diagnosis, as one command.
///
/// Uses the finalized manifest's scope and finite captured sources. Missing ownership or capture boundaries
/// remain unavailable; neither ambient logs nor a boot-wide kernel row can fill them in. Current scoped
/// process observations are explicitly distinct from the completed run's captured evidence.
///
/// It DELEGATES: each step is the existing subcommand, invoked with arguments this code builds. Nothing here parses a
/// log itself, so there is still exactly one implementation of every question.
#[derive(clap::Args, Debug)]
pub struct JobArgs {
    /// State directory of a finished west job (`west-job.sh start|status|follow` print it).
    #[arg(long)]
    pub state_dir: PathBuf,
    /// Require this prefix to match the managed run's persisted unambiguous scope; never infer scope from observer environment.
    #[arg(long)]
    pub prefix: Option<PathBuf>,
    /// One JSON object instead of the human block.
    #[arg(long)]
    pub json: bool,
    /// Lines kept per step.
    #[arg(long, default_value_t = 24)]
    pub lines: usize,
    /// Seconds allowed per step.
    #[arg(long, default_value_t = 60)]
    pub step_timeout_seconds: u64,
    /// Dump thread state for these pids instead of the prefix census (comma separated).
    #[arg(long, value_delimiter = ',')]
    pub pids: Vec<u32>,
}

#[derive(Default)]
struct JobStep {
    label: String,
    command: String,
    status: Option<i32>,
    output: Vec<String>,
    note: Option<String>,
}

fn job_step(
    exe: &Path,
    root: Option<&Path>,
    label: &str,
    argv: &[String],
    lines: usize,
    timeout_seconds: u64,
) -> JobStep {
    let command = match root {
        Some(root) => format!("{} --runtime-root {} {}", exe.display(), root.display(), argv.join(" ")),
        None => format!("{} {}", exe.display(), argv.join(" ")),
    };
    let mut child = Command::new("timeout");
    child.arg(timeout_seconds.to_string()).arg(exe);
    if let Some(root) = root { child.arg("--runtime-root").arg(root); }
    child.env_remove("DWDIAG_PREFIX").env_remove("DPREFIX").env_remove("DARLING_PREFIX")
        .env_remove("DARLING_RUNTIME_ROOT").env_remove("DARLING_LAUNCHER");
    let out = child.args(argv).output();
    let mut step = JobStep {
        label: label.to_string(),
        command,
        ..Default::default()
    };
    match out {
        Ok(o) => {
            step.status = o.status.code();
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            step.output = text
                .lines()
                .take(lines)
                .map(|l| l.to_string())
                .collect();
            if o.status.code().is_none() {
                step.note = Some(format!(
                    "{} was killed by a signal (its reason is in the lines above)",
                    label
                ));
            } else if o.status.code() != Some(0) && step.output.is_empty() {
                step.note = Some(format!(
                    "{} exited {:?} with no output; that is the tool saying it could not read, not that nothing happened",
                    label,
                    o.status.code()
                ));
            }
        }
        Err(e) => {
            step.note = Some(format!("{} could not be started: {e}", label));
        }
    }
    step
}

fn read_small(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn read_kernel(path: &Path, lines: usize, sudo: bool) -> Option<String> {
    if let Ok(text) = fs::read_to_string(path) {
        let joined: Vec<&str> = text.lines().take(lines).collect();
        if !joined.is_empty() {
            return Some(joined.join("|"));
        }
    }
    if !sudo {
        return None;
    }
    let out = Command::new("sudo")
        .arg("-n")
        .arg("head")
        .arg("-n")
        .arg(lines.to_string())
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let joined: Vec<&str> = text.lines().take(lines).collect();
    if joined.is_empty() {
        None
    } else {
        Some(format!("via-sudo {}", joined.join("|")))
    }
}

fn sudo_available() -> bool {
    // One probe that is true for root and for a passwordless sudoer alike; when it is false the
    // caller is told the stack needs root rather than being handed a silent gap.
    Command::new("sudo")
        .arg("-n")
        .arg("true")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn job_prefix(args: &JobArgs, state_dir: &Path) -> Option<PathBuf> {
    let manifest = evidence_manifest(state_dir)?;
    let prefix = manifest.scoped_prefix()?;
    if args.prefix.as_deref().is_some_and(|explicit| explicit != prefix) {
        return None;
    }
    Some(prefix.to_path_buf())
}

/// Say what a finished run's instrument evidence IS, before any census reads it.
///
/// WHY THIS IS A COMMAND. Every census in this file answers a question about a run; this one answers the question
/// UNDER them -- "do I actually hold this run's bytes?" -- and it was previously answered implicitly, by whichever
/// file a discovery heuristic happened to pick. A silent instrument and an unreadable log both end in an empty
/// census, and a census of zero reads as "the instrument was silent": this prints `unavailable`, `partial`,
/// `no-evidence` or `unscoped` so the two can never be confused again.
#[derive(clap::Args, Debug)]
pub struct EvidenceArgs {
    /// State directory of a run (`west-job.sh start|status|follow` print it).
    #[arg(long)]
    pub state_dir: PathBuf,
    /// One JSON object instead of the human lines.
    #[arg(long)]
    pub json: bool,
}

fn run_evidence(args: EvidenceArgs) -> Result<ExitCode> {
    if !args.state_dir.is_dir() {
        bail!("no state directory: {}", args.state_dir.display());
    }
    let report = select_evidence(&args.state_dir);
    if args.json {
        println!("{}", evidence_report_json(&report));
    } else {
        print_evidence_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

/// The run manifest `west-job.sh` writes at job start: the prefix, the run's start time, and every log that existed
/// with the size it had.
///
/// Finalization publishes `end=` only after registered source boundaries have
/// become finite captured copies. A live/legacy manifest is not permission to
/// read mutable originals or discover logs by timestamps.
#[derive(Debug, Default)]
struct EvidenceManifest {
    scope: Option<String>,
    runtime_root: Option<PathBuf>,
    prefix_source: Option<String>,
    runtime_source: Option<String>,
    prefix_unavailable: Option<String>,
    runtime_unavailable: Option<String>,
    unavailable: Vec<String>,
    /// Finite captured copy -> original source path, never discovery authority.
    sources: Vec<(PathBuf, PathBuf)>,
    prefix: Option<PathBuf>,
    /// Unix seconds when the job started, as the launcher recorded it.
    start: Option<u64>,
    /// Unix seconds when the job finished, when the writer recorded one.
    end: Option<u64>,
    /// (path, size at start): reading a file from that offset is what makes a slice belong to this run.
    files: Vec<(PathBuf, u64)>,
}

impl EvidenceManifest {
    fn scoped_prefix(&self) -> Option<&Path> {
        (self.scope.as_deref() == Some("explicit") && self.prefix_unavailable.is_none())
            .then_some(self.prefix.as_deref()).flatten().filter(|path| path.is_absolute())
    }

    fn scoped_runtime(&self) -> Option<&Path> {
        (self.scope.as_deref() == Some("explicit") && self.runtime_unavailable.is_none())
            .then_some(self.runtime_root.as_deref()).flatten().filter(|path| path.is_absolute())
    }

    fn captured_server_log(&self) -> Option<&Path> {
        let prefix = self.scoped_prefix()?;
        self.end?;
        let expected = prefix.join("private/var/log/dserver.log");
        let mut matches = self.sources.iter().filter(|(copy, original)| original == &expected
            && self.files.iter().any(|(path, offset)| path == copy && *offset == 0));
        let (copy, _) = matches.next()?;
        if matches.next().is_some() { return None; }
        Some(copy)
    }

    fn captured_core(&self) -> Option<&Path> {
        self.scoped_runtime()?;
        self.end?;
        let mut matches = self.sources.iter().filter(|(copy, original)| original.file_name()
            .is_some_and(|name| name.as_bytes().starts_with(b"core."))
            && self.files.iter().any(|(path, offset)| path == copy && *offset == 0));
        let (copy, _) = matches.next()?;
        if matches.next().is_some() { return None; }
        Some(copy)
    }
}

fn parse_evidence_manifest(text: &str) -> EvidenceManifest {
    let mut out = EvidenceManifest::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("scope=") {
            if out.scope.as_deref().is_some_and(|previous| previous != v) {
                out.scope = Some("ambiguous".to_string());
            } else {
                out.scope = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("prefix-source=") {
            out.prefix_source = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("runtime-root-source=") {
            out.runtime_source = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("prefix-unavailable=") {
            out.prefix_unavailable = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("runtime-root-unavailable=") {
            out.runtime_unavailable = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("unavailable=") {
            out.unavailable.push(v.to_string());
        } else if let Some(v) = line.strip_prefix("source=") {
            if let Some((copy, original)) = v.split_once('\t') {
                out.sources.push((PathBuf::from(copy), PathBuf::from(original)));
            } else {
                out.unavailable.push(format!("invalid captured-source mapping: {v}"));
            }
        } else if let Some(v) = line.strip_prefix("runtime-root=") {
            let path = PathBuf::from(v);
            if out.runtime_root.as_ref().is_some_and(|previous| previous != &path) || !path.is_absolute() {
                out.runtime_unavailable = Some("invalid or ambiguous recorded runtime root".to_string());
            }
            out.runtime_root = Some(path);
        } else if let Some(v) = line.strip_prefix("prefix=") {
            let path = PathBuf::from(v);
            if out.prefix.as_ref().is_some_and(|previous| previous != &path) || !path.is_absolute() {
                out.prefix_unavailable = Some("invalid or ambiguous recorded prefix".to_string());
            }
            out.prefix = Some(path);
        } else if let Some(v) = line.strip_prefix("start=") {
            out.start = v.trim().parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("end=") {
            out.end = v.trim().parse::<u64>().ok();
        } else if let Some(rest) = line.strip_prefix("file=") {
            let mut it = rest.rsplitn(2, ' ');
            let size = it.next().and_then(|s| s.parse::<u64>().ok());
            let path = it.next();
            if let (Some(p), Some(sz)) = (path, size) {
                out.files.push((PathBuf::from(p), sz));
            } else {
                out.unavailable.push(format!("invalid registered window: {rest}"));
            }
        }
    }
    out
}

fn evidence_manifest(state_dir: &Path) -> Option<EvidenceManifest> {
    let text = fs::read_to_string(state_dir.join("evidence-manifest")).ok()?;
    Some(parse_evidence_manifest(&text))
}

/// The five states a run's instrument evidence can be in, exactly one of which the selection reports. They exist
/// because "the instrument was silent" and "I could not read the log" are different facts, and an in-path instrument
/// writes to the SAME fd as the measured output, so a census over an unreadable log prints zeros that cannot be told
/// from a measurement. Only `Measured` may print a zero, and only because every window it read was whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceState {
    /// Every registered window was readable and complete -- the ONLY state in which an empty census is a measurement.
    Measured,
    /// A registered log was rotated or truncated: its recorded pre-run offset is beyond its current size, so none of
    /// its bytes can be attributed to this run and the census is incomplete even when rows survive elsewhere.
    Partial,
    /// A registered log is missing or unreadable, so its window cannot be read at all.
    Unavailable,
    /// No finalized runtime log was registered; the job wrapper alone is not runtime instrument evidence.
    NoEvidence,
    /// No run manifest: the evidence cannot be attributed to any run, so nothing is guessed and no row is produced.
    Unscoped,
}

impl EvidenceState {
    fn as_str(self) -> &'static str {
        match self {
            EvidenceState::Measured => "measured",
            EvidenceState::Partial => "partial",
            EvidenceState::Unavailable => "unavailable",
            EvidenceState::NoEvidence => "no-evidence",
            EvidenceState::Unscoped => "unscoped",
        }
    }

    /// The name the human block prints, in the tool's `UNMEASURED`/`NO-EVIDENCE` style. `--json` carries `as_str`.
    fn label(self) -> &'static str {
        match self {
            EvidenceState::Measured => "MEASURED",
            EvidenceState::Partial => "PARTIAL",
            EvidenceState::Unavailable => "UNAVAILABLE",
            EvidenceState::NoEvidence => "NO-EVIDENCE",
            EvidenceState::Unscoped => "UNSCOPED",
        }
    }

    /// Whether a census over this run's slice may be printed at all. `partial` may be printed, but never read as
    /// complete; nothing else has rows to census.
    fn has_census(self) -> bool {
        matches!(self, EvidenceState::Measured | EvidenceState::Partial)
    }

    /// Whether an empty census in this state is a measurement rather than a gap.
    fn zero_is_measured(self) -> bool {
        matches!(self, EvidenceState::Measured)
    }
}

#[derive(Debug, Clone, Default)]
struct FailureExcerpt {
    /// One-based line numbers within this selected finite window, not a mutable original.
    rows: Vec<(usize, String)>,
    source_lines: usize,
    matches: usize,
    omitted: bool,
}

fn is_failure_record(line: &str) -> bool {
    let line = line.trim_start();
    // CTest may prefix captured producer output with its numeric test index.
    let line = line.split_once(": ").filter(|(index, _)| !index.is_empty()
        && index.bytes().all(|byte| byte.is_ascii_digit())).map(|(_, rest)| rest).unwrap_or(line);
    if line.starts_with("Assertion failed:") || line.starts_with("assertion failed:")
        || (line.contains(": Assertion ") && line.ends_with(" failed."))
        || (line.starts_with("thread '") && line.contains(" panicked at "))
        || line.starts_with("panic: ") || line.starts_with("PANIC: ") || line.starts_with("panic(cpu ")
        || line.starts_with("dserver-CRASH") || line.starts_with("[dserver-CRASH")
        || line.starts_with("fatal error:")
        || line.starts_with("Binding the unix socket:")
        || line.starts_with("Cannot remove prefix state entry ")
        || (line.contains(" mismatch: expected ") && line.contains(", actual ")) {
        return true;
    }
    let dyld = line.strip_prefix("dyld: ").or_else(|| line.strip_prefix("dyld[")
        .and_then(|rest| rest.split_once("]: ").map(|(_, message)| message)));
    if dyld.is_some_and(|message| ["Library not loaded:", "Symbol not found:", "lazy symbol binding failed:"]
        .iter().any(|prefix| message.starts_with(prefix))) {
        return true;
    }
    // Compiler/linker diagnostics and the shell's terminal signal report have
    // concrete grammars. An Error-level server trace alone is not a failure.
    static FAILURE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(concat!(
        r"^(?:.+:[0-9]+(?::[0-9]+)?:[ \t]+(?:fatal )?error:",
        r"|(?:clang(?:\+\+)?(?:-[0-9.]+)?|gcc|g\+\+|cc|c\+\+|ld):[ \t]+(?:fatal )?error:",
        r"|ld: (?:library not found|framework not found|symbol\(s\) not found)",
        r"|Undefined symbols for architecture ",
        r"|(?:/[^: ]+/)?(?:bash|sh): line [0-9]+: [0-9]+ (?:Illegal instruction|Abort trap|Aborted|Segmentation fault|Bus error)(?::|[ \t]))"
    )).expect("fixed failure-record grammar"));
    FAILURE.is_match(line)
}

fn failure_excerpt(text: &str) -> FailureExcerpt {
    let mut rows: Vec<(usize, String)> = Vec::new();
    let (mut bytes, mut omitted) = (0usize, false);
    let (mut source_lines, mut matches, mut after) = (0usize, 0usize, 0usize);
    let mut previous = [(0usize, ""); 2];
    {
        let mut add = |number: usize, line: &str| {
            if number == 0 || rows.last().is_some_and(|(last, _)| *last >= number) { return; }
            let available = (16 * 1024usize).saturating_sub(bytes).min(2048);
            if rows.len() == 24 || available == 0 { omitted = true; return; }
            let rendered = if line.len() <= available {
                line.to_string()
            } else {
                const MARKER: &str = "... [excerpt line truncated]";
                omitted = true;
                if available < MARKER.len() { return; }
                let mut end = available - MARKER.len();
                while !line.is_char_boundary(end) { end -= 1; }
                format!("{}{MARKER}", &line[..end])
            };
            bytes += rendered.len();
            rows.push((number, rendered));
        };
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            source_lines = number;
            if is_failure_record(line) {
                matches += 1;
                for (number, line) in previous { add(number, line); }
                add(number, line);
                after = 2;
            } else if after > 0 {
                add(number, line);
                after -= 1;
            }
            previous[0] = previous[1];
            previous[1] = (number, line);
        }
    }
    FailureExcerpt { rows, source_lines, matches, omitted }
}

fn failure_excerpt_output(excerpt: &FailureExcerpt, tail_lines: usize, limit: usize) -> Vec<String> {
    let tail_first = excerpt.source_lines.saturating_sub(tail_lines) + 1;
    excerpt.rows.iter().filter(|(number, _)| *number < tail_first).take(limit)
        .map(|(number, line)| format!("line={number} {line}")).collect()
}

/// One file the selection considered, and what happened to it.
#[derive(Debug, Clone)]
struct EvidenceSource {
    path: PathBuf,
    /// `registered` finite capture or this job's own wrapper log.
    kind: &'static str,
    offset: u64,
    /// Size now, when the file could be stated at all.
    size: Option<u64>,
    read: u64,
    /// `ok`, `truncated`, `missing` or `unreadable`.
    status: &'static str,
    reason: Option<String>,
    /// Last at most 64 decoded lines, retained during the already-required read.
    tail: Vec<String>,
    failure: FailureExcerpt,
}

/// What a run's instrument evidence IS, decided before anything censuses it.
#[derive(Debug)]
struct EvidenceReport {
    state: EvidenceState,
    state_dir: PathBuf,
    instruments_log: PathBuf,
    rows_bytes: u64,
    sources: Vec<EvidenceSource>,
    reasons: Vec<String>,
}

/// Read only explicitly registered finite windows and the job's owned wrapper log.
/// Activity registration and timestamps are observation hints, not authority to
/// discover additional logs or attribute another run's bytes.
fn select_evidence(state_dir: &Path) -> EvidenceReport {
    let out_path = state_dir.join("instruments-sliced.log");
    let mut report = EvidenceReport {
        state: EvidenceState::Measured,
        state_dir: state_dir.to_path_buf(),
        instruments_log: out_path.clone(),
        rows_bytes: 0,
        sources: Vec::new(),
        reasons: Vec::new(),
    };
    let Some(manifest) = evidence_manifest(state_dir) else {
        report.state = EvidenceState::Unscoped;
        report.reasons.push(format!(
            "no evidence-manifest in {}: a run's instrument evidence cannot be attributed by guessing, so no log is read and no row is produced",
            state_dir.display()
        ));
        fs::write(&out_path, "").ok();
        return report;
    };
    if manifest.scope.as_deref() != Some("explicit") || manifest.end.is_none() {
        report.state = EvidenceState::Unavailable;
        report.reasons.push("managed manifest scope is absent/ambiguous or its finite capture is not finalized; no discovery or legacy fallback is permitted".to_string());
        if let Err(error) = fs::write(&out_path, "") {
            report.reasons.push(format!("cannot clear selected evidence {}: {error}", out_path.display()));
        }
        return report;
    }
    let mut entries: Vec<(PathBuf, u64, &'static str)> =
        vec![(state_dir.join("log"), 0, "job-owned")];
    entries.extend(manifest.files.iter().filter(|(path, _)| !manifest.sources.iter().any(|(copy, original)|
        copy == path && original.file_name().is_some_and(|name| name.as_bytes().starts_with(b"core."))))
        .map(|(p, o)| (p.clone(), *o, "registered")));
    report.reasons.extend(manifest.unavailable.iter().map(|reason| format!("registered evidence unavailable: {reason}")));
    let (mut missing, mut unreadable, mut truncated) = (false, false, false);
    let mut out = String::new();
    for (path, offset, kind) in &entries {
        let (path, offset) = (path, *offset);
        if *kind == "registered" && manifest.sources.iter().filter(|(copy, _)| copy == path).count() != 1 {
            unreadable = true;
            report.reasons.push(format!("registered source {} has no unambiguous finite capture mapping; no original or discovery fallback is read", path.display()));
            report.sources.push(EvidenceSource {
                path: path.clone(), kind, offset, size: None, read: 0, status: "unscoped",
                reason: Some("missing or ambiguous finite capture mapping".to_string()), tail: Vec::new(),
                failure: FailureExcerpt::default(),
            });
            continue;
        }
        match stored_evidence::read(path) {
            Ok(bytes) => {
                if *kind == "registered" && offset as usize > bytes.len() {
                    truncated = true;
                    report.reasons.push(format!(
                        "registered log {} is truncated or rotated: its recorded pre-run offset {offset} is beyond its current size {}",
                        path.display(),
                        bytes.len()
                    ));
                    report.sources.push(EvidenceSource {
                        path: path.clone(),
                        kind,
                        offset,
                        size: Some(bytes.len() as u64),
                        read: 0,
                        status: "truncated",
                        reason: Some(format!("recorded pre-run offset {offset} > current size {}", bytes.len())),
                        tail: Vec::new(),
                        failure: FailureExcerpt::default(),
                    });
                    continue;
                }
                let from = (offset as usize).min(bytes.len());
                if !out.is_empty() && !out.ends_with('\n') { out.push('\n'); }
                let slice = &bytes[from..];
                let decoded = String::from_utf8_lossy(slice).replace('\u{0}', "\n");
                let mut tail: Vec<String> = decoded.lines().rev().take(64).map(str::to_string).collect();
                tail.reverse();
                let failure = failure_excerpt(&decoded);
                out.push_str(&decoded);
                report.rows_bytes += slice.len() as u64;
                report.sources.push(EvidenceSource {
                    path: path.clone(),
                    kind,
                    offset,
                    size: Some(bytes.len() as u64),
                    read: slice.len() as u64,
                    status: "ok",
                    reason: None,
                    tail,
                    failure,
                });
            }
            Err(e) => {
                let status = if e.kind() == std::io::ErrorKind::NotFound {
                    missing = true;
                    "missing"
                } else {
                    unreadable = true;
                    "unreadable"
                };
                report.reasons.push(format!("{kind} log {} cannot be read: {e}", path.display()));
                report.sources.push(EvidenceSource {
                    path: path.clone(),
                    kind,
                    offset,
                    size: None,
                    read: 0,
                    status,
                    reason: Some(e.to_string()),
                    tail: Vec::new(),
                    failure: FailureExcerpt::default(),
                });
            }
        }
    }
    report.state = if missing || unreadable || !manifest.unavailable.is_empty() {
        EvidenceState::Unavailable
    } else if truncated {
        EvidenceState::Partial
    } else if !entries.iter().any(|(_, _, kind)| *kind == "registered") {
        report.reasons.push("no finalized runtime log was registered; the wrapper log alone is not runtime instrument evidence".to_string());
        EvidenceState::NoEvidence
    } else {
        EvidenceState::Measured
    };
    if let Err(error) = fs::write(&out_path, out) {
        report.state = EvidenceState::Unavailable;
        report.reasons.push(format!("cannot publish selected evidence {}: {error}", out_path.display()));
    }
    report
}

/// The human block for one evidence selection: the state first, then one line per source with its reason.
fn print_evidence_report(r: &EvidenceReport) {
    let zero = if r.rows_bytes == 0 {
        if r.state.zero_is_measured() {
            " rows=0 measured-zero (the only state where an empty census is a measurement)"
        } else {
            " rows=0 NOT-A-MEASUREMENT (the census below must not be read as an instrument standing silent)"
        }
    } else {
        ""
    };
    println!(
        "EVIDENCE-STATE {} state_dir={} instruments_log={}{}",
        r.state.label(),
        r.state_dir.display(),
        r.instruments_log.display(),
        zero
    );
    for s in &r.sources {
        println!(
            "EVIDENCE-SOURCE {} kind={} offset={} size={} read={} status={}{}",
            s.path.display(),
            s.kind,
            s.offset,
            s.size.map(|v| v.to_string()).unwrap_or_else(|| "absent".to_string()),
            s.read,
            s.status,
            s.reason.as_ref().map(|x| format!(" reason={x}")).unwrap_or_default()
        );
    }
    for reason in &r.reasons {
        println!("EVIDENCE-REASON {reason}");
    }
}

fn evidence_report_json(r: &EvidenceReport) -> String {
    let mut obj = String::from("{");
    obj.push_str(&format!("\"state\":\"{}\",", r.state.as_str()));
    obj.push_str(&format!("\"state_dir\":\"{}\",", jesc(&r.state_dir.display().to_string())));
    obj.push_str(&format!("\"instruments_log\":\"{}\",", jesc(&r.instruments_log.display().to_string())));
    obj.push_str(&format!("\"rows_bytes\":{},", r.rows_bytes));
    obj.push_str(&format!("\"zero_is_measured\":{},", r.state.zero_is_measured()));
    obj.push_str("\"sources\":[");
    for (i, s) in r.sources.iter().enumerate() {
        if i > 0 {
            obj.push(',');
        }
        obj.push_str(&format!(
            "{{\"path\":\"{}\",\"kind\":\"{}\",\"offset\":{},\"size\":{},\"read\":{},\"status\":\"{}\",\"reason\":{}}}",
            jesc(&s.path.display().to_string()),
            s.kind,
            s.offset,
            s.size.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
            s.read,
            s.status,
            s.reason.as_ref().map(|x| format!("\"{}\"", jesc(x))).unwrap_or_else(|| "null".to_string())
        ));
    }
    obj.push_str("],\"reasons\":[");
    for (i, reason) in r.reasons.iter().enumerate() {
        if i > 0 {
            obj.push(',');
        }
        obj.push_str(&format!("\"{}\"", jesc(reason)));
    }
    obj.push_str("]}");
    obj
}

fn run_job(args: JobArgs) -> Result<ExitCode> {
    let state_dir = args.state_dir.clone();
    if !state_dir.is_dir() {
        bail!("no state directory: {}", state_dir.display());
    }
    let job_log = state_dir.join("log");
    if !stored_evidence::resolve(&job_log).is_file() {
        bail!("no run log: {}", job_log.display());
    }
    let exe = std::env::current_exe().context("resolving this binary")?;
    let rc = fs::read_to_string(state_dir.join("rc")).ok().map(|s| s.trim().to_string());
    let prefix = job_prefix(&args, &state_dir);
    let evidence = select_evidence(&state_dir);
    let instr_log = evidence.instruments_log.clone();
    let manifest = evidence_manifest(&state_dir);
    let runtime = manifest.as_ref().and_then(EvidenceManifest::scoped_runtime);
    let mut scope_reasons = Vec::new();
    match &manifest {
        Some(manifest) => {
            if manifest.scope.as_deref() != Some("explicit") {
                scope_reasons.push("managed scope is absent or ambiguous".to_string());
            }
            if let Some(reason) = &manifest.prefix_unavailable {
                scope_reasons.push(format!("prefix unavailable: {reason}"));
            } else if manifest.scoped_prefix().is_none() {
                scope_reasons.push("prefix unavailable: no unambiguous absolute persisted prefix".to_string());
            }
            if let Some(reason) = &manifest.runtime_unavailable {
                scope_reasons.push(format!("runtime unavailable: {reason}"));
            } else if runtime.is_none() {
                scope_reasons.push("runtime unavailable: no unambiguous absolute persisted installation".to_string());
            }
            if args.prefix.as_deref().is_some_and(|explicit| Some(explicit) != manifest.scoped_prefix()) {
                scope_reasons.push("--prefix conflicts with persisted run scope".to_string());
            }
        }
        None => scope_reasons.push("managed evidence manifest unavailable; no observer or command-text fallback".to_string()),
    }
    let core_window_note = Some("managed core evidence requires a finalized registered capture; timestamps, ambient core directories and boot-wide kernel logs are not ownership proof".to_string());

    let mut steps: Vec<JobStep> = Vec::new();
    let step = |label: &str, argv: Vec<String>| {
        job_step(&exe, runtime, label, &argv, args.lines, args.step_timeout_seconds)
    };

    // A census over a log this run does not own prints zeros, and a zero cannot be told from an instrument standing
    // silent. So the census runs only when the selection says the run's own window was readable: `partial` gets one
    // that is labelled incomplete, and `unavailable`/`no-evidence`/`unscoped` get no census at all.
    let mut evidence_note: Option<String> = None;
    if evidence.state.has_census() {
        steps.push(step("witness", vec!["diag".into(), "witness".into(), "--log".into(), instr_log.display().to_string()]));
        steps.push(step("waits", vec!["diag".into(), "waits".into(), "--log".into(), instr_log.display().to_string()]));
        if evidence.state == EvidenceState::Partial {
            evidence_note = Some(format!(
                "instrument census is PARTIAL and must not be read as complete: {}",
                evidence.reasons.first().map(|s| s.as_str()).unwrap_or("a registered window is incomplete")
            ));
        }
    } else {
        evidence_note = Some(format!(
            "instrument census NOT RUN: evidence state is {} -- {} (a census would print zeros that cannot be told from a measurement)",
            evidence.state.as_str(),
            evidence.reasons.first().map(|s| s.as_str()).unwrap_or("no reason recorded")
        ));
    }
    if evidence.state.has_census() {
        let mut progress = vec!["diag".into(), "progress".into(), "--state-dir".into(), state_dir.display().to_string()];
        if let Some(prefix) = args.prefix.as_ref().or(prefix.as_ref()) {
            progress.extend(["--prefix".into(), prefix.display().to_string()]);
        }
        steps.push(step("progress", progress));
        steps.push(step("loops", vec!["diag".into(), "loops".into(), "--log".into(), instr_log.display().to_string()]));
    }
    // Preserve actual failure bytes (compiler/loader errors included), rather
    // than reporting only instrument counters over the wrapper's two lines.
    for source in &evidence.sources {
        if source.tail.is_empty() { continue; }
        let original = manifest.as_ref().and_then(|manifest| manifest.sources.iter()
            .find(|(copy, _)| copy == &source.path).map(|(_, original)| original.as_path()))
            .unwrap_or(&source.path);
        let keep = args.lines.min(source.tail.len());
        let excerpt = failure_excerpt_output(&source.failure, keep, args.lines);
        if !excerpt.is_empty() {
            let earlier = source.failure.rows.iter().filter(|(number, _)|
                *number <= source.failure.source_lines.saturating_sub(keep)).count();
            let limited = source.failure.omitted || earlier > excerpt.len();
            steps.push(JobStep {
                label: "log-failure".to_string(),
                command: format!("selected finite failure excerpt {}", source.path.display()),
                note: Some(format!("source={} captured={} offset={} status={}; one-based selected-window lines; recognized_records={} selection_limited={limited}; at most 24 lines/16KiB, two context lines either side; overlapping windows and tail lines are not repeated; a recognized record is not a workload verdict",
                    original.display(), source.path.display(), source.offset, source.status, source.failure.matches)),
                output: excerpt,
                ..Default::default()
            });
        }
        steps.push(JobStep {
            label: "log-tail".to_string(),
            command: format!("selected finite evidence {}", source.path.display()),
            output: source.tail[source.tail.len() - keep..].to_vec(),
            note: Some(format!("source={} captured={} offset={} status={}; selected-window lines {}-{} (last at most {}); recognized_failure_records={}{}; not mutable source history",
                original.display(), source.path.display(), source.offset, source.status,
                source.failure.source_lines.saturating_sub(keep) + 1, source.failure.source_lines, args.lines.min(64),
                source.failure.matches, if source.failure.matches == 0 { " (cause unrecognized; tail retained without inferring success)" } else { "" })),
            ..Default::default()
        });
    }

    let core_note = if runtime.is_none() {
        Some("core diagnosis unavailable: managed runtime scope is absent or ambiguous; no observer runtime fallback".to_string())
    } else if let Some(core) = manifest.as_ref().and_then(EvidenceManifest::captured_core) {
        let mut argv = vec!["diag".into(), "core".into(), "--core".into(), core.display().to_string(), "--traces".into()];
        if let Some(prefix) = &prefix { argv.extend(["--prefix".into(), prefix.display().to_string()]); }
        steps.push(step("core", argv));
        None
    } else {
        Some("core/kernel evidence unavailable: no unambiguous finite registered core; unrelated ambient cores and boot-wide kernel rows are NOT attributed to this job".to_string())
    };

    // Process state: what the processes are DOING, not what they wrote.
    let mut process_lines: Vec<String> = Vec::new();
    let mut process_note: Option<String> = None;
    if let (Some(p), Some(runtime)) = (&prefix, runtime) {
        let mut pids = args.pids.clone();
        let census = job_step(
            &exe,
            Some(runtime),
            "processes",
            &["diag".into(), "processes".into(), "--prefix".into(), p.display().to_string(), "--list".into()],
            args.lines,
            args.step_timeout_seconds,
        );
        let census_text = census.output.join("\n");
        if pids.is_empty() {
            for line in census_text.lines() {
                if let Some(rest) = line.strip_prefix("PREFIX-PROCESS ") {
                    if let Some(pid) = rest.split_whitespace().find_map(|word| word.strip_prefix("pid="))
                        .and_then(|value| value.parse::<u32>().ok()) {
                        pids.push(pid);
                    }
                }
            }
        }
        pids.retain(|pid| process_owns_prefix(*pid, p) && fs::read_link(format!("/proc/{pid}/exe"))
            .map(|exe| exe.starts_with(runtime)).unwrap_or(false));
        if args.pids.is_empty() { pids.truncate(4); }
        process_lines.push(format!("DIAG-CURRENT-PROCESSES prefix={} runtime-root={} observed={} observation=current-point-in-time signal-authority=false",
            p.display(), runtime.display(), pids.len()));
        if pids.is_empty() {
            process_note = Some(format!(
                "no selected-prefix/runtime process was observed for {}; exit or inaccessible process evidence cannot establish a globally empty process set",
                p.display()
            ));
        } else {
            let sudo = sudo_available();
            for pid in pids {
                let base = PathBuf::from(format!("/proc/{pid}"));
                let wchan = read_small(&base.join("wchan")).unwrap_or_else(|| "unreadable".into());
                let syscall = fs::read_to_string(base.join("syscall"))
                    .ok()
                    .and_then(|s| s.split_whitespace().next().map(|v| v.to_string()))
                    .unwrap_or_else(|| "unreadable".into());
                let cmd = fs::read_to_string(base.join("cmdline"))
                    .map(|s| s.replace('\u{0}', " ").trim().to_string())
                    .unwrap_or_else(|_| "unreadable".into());
                process_lines.push(format!("DIAG[threads] pid={pid} wchan={wchan} syscall={syscall} cmd={}", &cmd[..cmd.len().min(60)]));
                let mut tids: Vec<u32> = Vec::new();
                if let Ok(entries) = fs::read_dir(base.join("task")) {
                    for e in entries.flatten() {
                        if let Ok(t) = e.file_name().to_string_lossy().parse::<u32>() {
                            tids.push(t);
                        }
                    }
                }
                tids.sort_unstable();
                for tid in tids.into_iter().take(8) {
                    let tbase = base.join("task").join(tid.to_string());
                    let twchan = read_small(&tbase.join("wchan")).unwrap_or_else(|| "?".into());
                    match read_kernel(&tbase.join("stack"), 3, sudo) {
                        Some(stack) => process_lines.push(format!("      tid={tid} wchan={twchan} stack={stack}")),
                        None => process_lines.push(format!(
                            "      tid={tid} wchan={twchan} kernel-stack-unreadable (needs root, and sudo -n is unavailable)"
                        )),
                    }
                }
                process_lines.push(format!(
                    "DIAG-HINT for a guest that dies by signal: {} unwind --pid {pid} --catch SIGSEGV",
                    exe.display()
                ));
            }
        }
    } else {
        process_note = Some(
            "managed prefix/runtime scope is absent, ambiguous or conflicts with --prefix; observer environment and opaque command text are not scope authority".to_string(),
        );
    }

    if args.json {
        let mut obj = String::from("{");
        obj.push_str(&format!("\"state_dir\":\"{}\",", jesc(&state_dir.display().to_string())));
        obj.push_str(&format!("\"rc\":{},", rc.as_deref().unwrap_or("null")));
        obj.push_str(&format!("\"job_log\":\"{}\",", jesc(&job_log.display().to_string())));
        obj.push_str(&format!("\"instrument_log\":\"{}\",", jesc(&instr_log.display().to_string())));
        obj.push_str(&format!("\"evidence_state\":\"{}\",", evidence.state.as_str()));
        obj.push_str(&format!("\"evidence_note\":{},", evidence_note.as_ref().map(|n| format!("\"{}\"", jesc(n))).unwrap_or_else(|| "null".into())));
        obj.push_str(&format!("\"evidence_report\":{},", evidence_report_json(&evidence)));
        obj.push_str(&format!("\"core_window_note\":{},", core_window_note.as_ref().map(|n| format!("\"{}\"", jesc(n))).unwrap_or_else(|| "null".into())));
        obj.push_str(&format!("\"runtime_root\":{},\"scope_source\":\"managed-manifest\",\"scope_reasons\":[{}],",
            runtime.map(|path| jstr(&path.display().to_string())).unwrap_or_else(|| "null".to_string()),
            scope_reasons.iter().map(|reason| jstr(reason)).collect::<Vec<_>>().join(",")));
        obj.push_str(&format!("\"prefix_source\":{},\"runtime_root_source\":{},",
            manifest.as_ref().and_then(|manifest| manifest.prefix_source.as_deref()).map(jstr).unwrap_or_else(|| "null".to_string()),
            manifest.as_ref().and_then(|manifest| manifest.runtime_source.as_deref()).map(jstr).unwrap_or_else(|| "null".to_string())));
        obj.push_str(&format!("\"core_note\":{},\"process_note\":{},",
            core_note.as_ref().map(|note| jstr(note)).unwrap_or_else(|| "null".to_string()),
            process_note.as_ref().map(|note| jstr(note)).unwrap_or_else(|| "null".to_string())));
        match &prefix {
            Some(p) => obj.push_str(&format!("\"prefix\":\"{}\",", jesc(&p.display().to_string()))),
            None => obj.push_str("\"prefix\":null,"),
        }
        obj.push_str("\"steps\":[");
        for (i, s) in steps.iter().enumerate() {
            if i > 0 {
                obj.push(',');
            }
            obj.push_str(&format!(
                "{{\"label\":\"{}\",\"command\":\"{}\",\"status\":{},\"output\":[",
                jesc(&s.label),
                jesc(&s.command),
                s.status.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
            ));
            for (j, line) in s.output.iter().enumerate() {
                if j > 0 {
                    obj.push(',');
                }
                obj.push_str(&format!("\"{}\"", jesc(line)));
            }
            obj.push_str(&format!("],\"note\":{}}}", s.note.as_ref().map(|note| jstr(note)).unwrap_or_else(|| "null".to_string())));
        }
        obj.push_str("],\"process_state\":[");
        for (i, line) in process_lines.iter().enumerate() {
            if i > 0 {
                obj.push(',');
            }
            obj.push_str(&format!("\"{}\"", jesc(line)));
        }
        obj.push_str("]}");
        println!("{obj}");
        return Ok(ExitCode::SUCCESS);
    }

    println!("DIAG-BEGIN state={}", state_dir.display());
    if let Some(rc) = &rc {
        println!("DIAG-RC rc={rc}");
    }
    println!("DIAG-LOGS job={} instruments={}", job_log.display(), instr_log.display());
    println!("DIAG-SCOPE source=managed-manifest prefix={} runtime-root={} prefix-source={} runtime-root-source={}",
        prefix.as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| "UNAVAILABLE".to_string()),
        runtime.map(|path| path.display().to_string()).unwrap_or_else(|| "UNAVAILABLE".to_string()),
        manifest.as_ref().and_then(|manifest| manifest.prefix_source.as_deref()).unwrap_or("UNAVAILABLE"),
        manifest.as_ref().and_then(|manifest| manifest.runtime_source.as_deref()).unwrap_or("UNAVAILABLE"));
    for reason in &scope_reasons { println!("DIAG-SCOPE-UNAVAILABLE {reason}"); }
    print_evidence_report(&evidence);
    if let Some(note) = &evidence_note {
        println!("DIAG-NOTE {note}");
    }
    if let Some(note) = &core_window_note {
        println!("DIAG-NOTE {note}");
    }
    if let Some(note) = core_note {
        println!("DIAG-NOTE {note}");
    }
    for s in &steps {
        println!("\nDIAG[{}] {}", s.label, s.command);
        for line in &s.output {
            println!("{line}");
        }
        if let Some(note) = &s.note {
            println!("DIAG-NOTE {note}");
        }
    }
    if let Some(note) = &process_note {
        println!("\nDIAG-NOTE {note}");
    }
    for line in &process_lines {
        println!("{line}");
    }
    println!("DIAG-END state={}", state_dir.display());
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------------------------
// FUTEX PAIRING (`dwdiag futex`)
//
// WHY THIS EXISTS: a stall in this project keeps arriving as "two threads are in futex_wait_queue",
// which is true and useless. The waiting thread and whoever must wake it are normally DIFFERENT
// processes (the loader waits on a ring the server publishes), so comparing virtual addresses says
// nothing -- equal addresses are neither necessary nor sufficient. What does identify the byte is the
// kernel's own naming of it in both processes: the device and inode of the file, the file offset of
// the mapping plus the displacement of the address inside it. This command does that join from a
// capture bundle, so the question stops being answered by hand.
// ---------------------------------------------------------------------------------------------

/// One memory region with the fields a shared-object identity needs.
#[derive(Clone, Debug)]
struct MapRegion {
    lo: u64,
    hi: u64,
    shared: bool,
    file_off: u64,
    dev: String,
    ino: u64,
    file: String,
}

fn parse_maps_full(text: &str) -> Vec<MapRegion> {
    let mut v = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(perm), Some(off), Some(dev), Some(ino)) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let (Some(a), Some(b)) = (range.split('-').next(), range.split('-').nth(1)) else {
            continue;
        };
        let (Ok(lo), Ok(hi), Ok(file_off)) = (
            u64::from_str_radix(a, 16),
            u64::from_str_radix(b, 16),
            u64::from_str_radix(off, 16),
        ) else {
            continue;
        };
        let Ok(ino) = ino.parse::<u64>() else { continue };
        let file = line.splitn(6, ' ').nth(5).unwrap_or("").trim().to_string();
        v.push(MapRegion {
            lo,
            hi,
            shared: perm.contains('s'),
            file_off,
            dev: dev.to_string(),
            ino,
            file,
        });
    }
    v
}

/// The byte two processes share: same device, same inode, same file offset. Virtual addresses are not part of it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ObjectKey {
    dev: String,
    ino: u64,
    file_off: u64,
    file: String,
}

#[derive(Clone, Debug)]
struct FutexWait {
    tree: &'static str,
    pid: u32,
    label: String,
    tid: u32,
    addr: u64,
    op: u64,
    val: u64,
    wchan: String,
    shared: Option<ObjectKey>,
    /// How the address was resolved, in words: `shared`, `private-anon`, `private-file` or `unmapped`. An
    /// unresolved wait is reported with its reason instead of being dropped.
    resolution: &'static str,
}

#[derive(Debug, Default)]
struct FutexReport {
    processes: usize,
    waits: Vec<FutexWait>,
    /// (pid, tid, address, snapshot file) of every wait already recorded, so a process kept in two trees or a
    /// thread captured in several generations is not reported as several waits.
    seen: std::collections::BTreeSet<(u32, u32, u64, String)>,
    /// For each shared object, every OTHER mapping of it (pid, address): the other half of the join.
    peers: BTreeMap<ObjectKey, Vec<(String, u64)>>,
    /// Waits taken from the OUT-OF-BAND trace, with the wake that followed each one. Empty when no trace was given,
    /// which is a named absence in the output rather than a silent zero.
    trace_waits: Vec<FutexTraceWait>,
    /// Whether an out-of-band trace was supplied and accepted.
    trace_present: bool,
    /// Events in that trace that belong to OTHER processes: a kernel probe is system-wide, so this is normally
    /// large, and reporting it is what keeps the selection visible instead of silent.
    trace_foreign_events: u64,
    /// True when the run manifest recorded no end, so the window could only be checked from its start.
    trace_window_open_ended: bool,
}

/// One WAIT from the out-of-band trace, joined to the first wake that followed it on the same object.
#[derive(Clone, Debug)]
struct FutexTraceWait {
    pid: u32,
    tid: u32,
    addr: u64,
    /// `shared`, `private-anon`, `private-file` or `unmapped`, in words, like the snapshot waits.
    resolution: &'static str,
    object: Option<ObjectKey>,
    /// (pid, tid, woke) of the first wake on the same object after this wait, when there was one.
    waker: Option<(u32, u32, u64)>,
    /// How many wakes followed on the object: 0 is the finding this whole trace exists to state.
    wakes_after: usize,
}

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x") {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn first_line_of(path: &Path) -> String {
    fs::read_to_string(path)
        .ok()
        .and_then(|t| t.lines().next().map(|l| l.to_string()))
        .unwrap_or_default()
}

fn resolve_futex_addr(maps: &[MapRegion], addr: u64) -> (&'static str, Option<ObjectKey>) {
    for r in maps {
        if r.lo <= addr && addr < r.hi {
            if r.shared && !r.file.is_empty() {
                return (
                    "shared",
                    Some(ObjectKey {
                        dev: r.dev.clone(),
                        ino: r.ino,
                        file_off: r.file_off + (addr - r.lo),
                        file: r.file.clone(),
                    }),
                );
            }
            return (
                if r.file.is_empty() {
                    "private-anon"
                } else {
                    "private-file"
                },
                None,
            );
        }
    }
    ("unmapped", None)
}

// ---------------------------------------------------------------------------------------------------------------
// The out-of-band futex trace: the wake half, plus the discipline that keeps an answer about THIS run.
// ---------------------------------------------------------------------------------------------------------------

/// One event of an out-of-band futex trace (`--futex-trace`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum FutexTraceKind {
    Wait,
    Wake,
}

#[derive(Clone, Debug)]
struct FutexTraceEvent {
    kind: FutexTraceKind,
    pid: u32,
    tid: u32,
    addr: u64,
    /// `woke=`, present on wake events only.
    woke: Option<u64>,
    ts_ns: u128,
}

fn parse_futex_trace(text: &str) -> Result<Vec<FutexTraceEvent>, String> {
    let mut out = Vec::new();
    // A trace from a kernel probe carries MONOTONIC timestamps (`nsecs`), while a run window is recorded as wall
    // clock. The probe therefore prints one base line with both clocks, and every event is converted here. Without
    // it the reader would have to guess, and a guess is what the window check exists to prevent -- it would refuse
    // the honest probe's own trace.
    let mut base: Option<(u128, u128)> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.trim_start_matches('#').trim().strip_prefix("BASE ") {
            let mut wall_s = None;
            let mut mono_ns = None;
            for field in rest.split_whitespace() {
                match field.split_once('=') {
                    Some(("wall_s", v)) => wall_s = v.parse::<u128>().ok(),
                    Some(("mono_ns", v)) => mono_ns = v.parse::<u128>().ok(),
                    _ => {}
                }
            }
            match (wall_s, mono_ns) {
                (Some(w), Some(m)) => base = Some((w * 1_000_000_000, m)),
                _ => {
                    return Err(format!(
                        "futex trace line {}: BASE needs wall_s= and mono_ns=",
                        n + 1
                    ))
                }
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let kind = match it.next().unwrap_or("") {
            "WAIT" | "FUTEX_WAIT" => FutexTraceKind::Wait,
            "WAKE" | "FUTEX_WAKE" => FutexTraceKind::Wake,
            other => {
                return Err(format!(
                    "futex trace line {}: unknown event {other:?} (expected WAIT or WAKE)",
                    n + 1
                ))
            }
        };
        let (mut pid, mut tid, mut addr, mut woke, mut ts_ns) = (None, None, None, None, None);
        for field in it {
            let Some((k, v)) = field.split_once('=') else {
                return Err(format!("futex trace line {}: {field:?} is not key=value", n + 1));
            };
            match k {
                "pid" => pid = v.parse::<u32>().ok(),
                "tid" => tid = v.parse::<u32>().ok(),
                "uaddr" => addr = parse_hex_or_dec(v),
                "woke" => woke = v.parse::<u64>().ok(),
                "ts_ns" => ts_ns = v.parse::<u128>().ok(),
                other => {
                    return Err(format!("futex trace line {}: unknown field {other:?}", n + 1))
                }
            }
        }
        let (Some(pid), Some(tid), Some(addr)) = (pid, tid, addr) else {
            return Err(format!("futex trace line {}: needs pid=, tid= and uaddr=", n + 1));
        };
        // Without a timestamp an event can only be placed in a run by guessing, and that guess is exactly the
        // failure this check exists to prevent, so it is refused instead of defaulted.
        let Some(ts_ns) = ts_ns else {
            return Err(format!(
                "futex trace line {}: needs ts_ns= -- a trace without timestamps cannot be attributed to a run",
                n + 1
            ));
        };
        let ts_ns = match base {
            Some((wall_base, mono_base)) => wall_base + ts_ns.saturating_sub(mono_base),
            None => ts_ns,
        };
        out.push(FutexTraceEvent { kind, pid, tid, addr, woke, ts_ns });
    }
    if out.is_empty() {
        return Err("the futex trace carries no event".to_string());
    }
    Ok(out)
}

/// The run window from the bundle's evidence manifest: the launcher records `start`, and `end` when a writer
/// recorded one (the job's `rc` file is the other half this reader does not own).
fn bundle_run_window(bundle: &Path) -> Option<(u64, Option<u64>)> {
    let mut candidates = vec![
        bundle.join("evidence-manifest"),
        bundle.join("state").join("evidence-manifest"),
    ];
    if let Ok(entries) = fs::read_dir(bundle) {
        for e in entries.flatten() {
            candidates.push(e.path().join("evidence-manifest"));
        }
    }
    for path in candidates {
        let Ok(text) = fs::read_to_string(&path) else { continue };
        let m = parse_evidence_manifest(&text);
        if let Some(start) = m.start {
            return Some((start, m.end));
        }
    }
    None
}

/// Keep the events that belong to this bundle's run, and refuse a trace that is about another run entirely.
///
/// MEASURED, and the reason this selects rather than refuses: a kernel probe is SYSTEM-WIDE. The first real trace
/// taken with `probes/futex.bt` carried 29198 events, including processes that have nothing to do with the run
/// (`date`, other shells). Refusing on the first foreign pid would therefore reject every honest trace, so the
/// events are selected by the pids the bundle captured and the rest are COUNTED; what is refused is a trace with
/// no event of this run at all, which is a trace of some other run. The window is then checked on the selected
/// events only, because a system-wide trace legitimately contains events from outside it.
fn select_futex_trace(
    events: Vec<FutexTraceEvent>,
    bundle_pids: &std::collections::BTreeSet<u32>,
    window: Option<(u64, Option<u64>)>,
) -> Result<(Vec<FutexTraceEvent>, u64), String> {
    let total = events.len() as u64;
    let selected: Vec<FutexTraceEvent> = events
        .into_iter()
        .filter(|e| bundle_pids.contains(&e.pid))
        .collect();
    let foreign = total - selected.len() as u64;
    if selected.is_empty() {
        return Err(format!(
            "futex trace has no event from any of the {} pids this bundle captured ({total} events, all foreign): the trace is about another run",
            bundle_pids.len()
        ));
    }
    let Some((start, end)) = window else {
        return Err(
            "the bundle declares no run window (no readable evidence-manifest with start=), so a trace cannot be \
             attributed to this run; a trace from another run reads exactly like this one"
                .to_string(),
        );
    };
    let lo = start as u128 * 1_000_000_000;
    if let Some(e) = selected.iter().find(|e| e.ts_ns < lo) {
        return Err(format!(
            "futex trace event ts_ns={} precedes the run start ({}) : the trace is from another run",
            e.ts_ns, start
        ));
    }
    match end {
        Some(end) => {
            let hi = end as u128 * 1_000_000_000;
            if let Some(e) = selected.iter().find(|e| e.ts_ns > hi) {
                return Err(format!(
                    "futex trace event ts_ns={} follows the run end ({end}): the trace is from another run",
                    e.ts_ns
                ));
            }
            Ok((selected, foreign))
        }
        // The window's end is not this reader's to invent, so an open-ended window is reported as such rather
        // than presented as a full check.
        None => Ok((selected, foreign)),
    }
}

/// Resolve one traced event's address through the maps the bundle captured for its pid.
fn resolve_traced_addr(
    maps_by_pid: &[(String, Vec<MapRegion>)],
    pid: u32,
    addr: u64,
) -> (&'static str, Option<ObjectKey>) {
    for (p, maps) in maps_by_pid {
        if p.parse::<u32>() == Ok(pid) {
            return resolve_futex_addr(maps, addr);
        }
    }
    ("unmapped-pid", None)
}

/// Join each traced WAIT to the FIRST wake on the same object after it, and keep the ones with no wake at all.
///
/// The object is what makes the join possible across processes: the two sides of a shared futex sit at different
/// addresses in different address spaces, and only (dev, inode, file offset) is the same on both.
fn pair_futex_trace(
    events: &[FutexTraceEvent],
    maps_by_pid: &[(String, Vec<MapRegion>)],
) -> Vec<FutexTraceWait> {
    let mut waits = Vec::new();
    for e in events {
        if e.kind != FutexTraceKind::Wait {
            continue;
        }
        let (resolution, object) = resolve_traced_addr(maps_by_pid, e.pid, e.addr);
        let mut waker = None;
        let mut wakes_after = 0usize;
        for w in events {
            if w.kind != FutexTraceKind::Wake || w.ts_ns <= e.ts_ns {
                continue;
            }
            let (_, woke_object) = resolve_traced_addr(maps_by_pid, w.pid, w.addr);
            // Two ways for a wake to be the one that released this wait, and both are needed. A SHARED object is
            // joined by identity, because the two sides sit at different addresses in different address spaces. A
            // PRIVATE futex (the common case: a mutex in a heap allocation) has no shared object at all, so it is
            // joined by the same process and the same address -- and requiring an object there would report every
            // private wait as never woken.
            let same_object = object.is_some() && woke_object.as_ref() == object.as_ref();
            let same_private_site = object.is_none() && w.pid == e.pid && w.addr == e.addr;
            if !same_object && !same_private_site {
                continue;
            }
            wakes_after += 1;
            if waker.is_none() {
                waker = Some((w.pid, w.tid, w.woke.unwrap_or(0)));
            }
        }
        waits.push(FutexTraceWait {
            pid: e.pid,
            tid: e.tid,
            addr: e.addr,
            resolution,
            object,
            waker,
            wakes_after,
        });
    }
    waits
}

fn pair_futex(bundle: &Path, futex_trace: Option<&Path>) -> Result<FutexReport> {
    // Both trees: the workload's and the daemonized server's. The server is not a descendant of the workload, so
    // reading only one tree is exactly how the other half of a shared futex goes missing.
    let trees = [
        ("capture-tree", bundle.join("capture-tree")),
        ("guarded-tree", bundle.join("guarded-tree")),
    ];
    let mut report = FutexReport::default();
    let mut maps_by_pid: Vec<(String, Vec<MapRegion>)> = Vec::new();
    for (tree, dir) in &trees {
        let Ok(entries) = fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(rest) = name.strip_prefix("pid-") else { continue };
            let Ok(pid) = rest.parse::<u32>() else { continue };
            let pdir = e.path();
            report.processes += 1;
            let maps = fs::read_to_string(pdir.join("proc-maps.txt"))
                .map(|t| parse_maps_full(&t))
                .unwrap_or_default();
            maps_by_pid.push((pid.to_string(), maps.clone()));
            let label = first_line_of(&pdir.join("proc-cmdline.txt"));
            let Ok(files) = fs::read_dir(&pdir) else { continue };
            for f in files.flatten() {
                let n = f.file_name().to_string_lossy().to_string();
                // A syscall snapshot is a MOMENT, not a trace: it says who is waiting now, never who woke whom.
                let (tid, wchan_name) = if n == "proc-syscall.txt" {
                    (pid, "proc-wchan.txt".to_string())
                } else if n.ends_with("-syscall.txt") {
                    let Some(t) = n
                        .split("-tid-")
                        .nth(1)
                        .and_then(|r| r.split('-').next())
                        .and_then(|t| t.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    (t, n.replace("-syscall.txt", "-wchan.txt"))
                } else {
                    continue;
                };
                let Ok(text) = fs::read_to_string(f.path()) else { continue };
                let f: Vec<&str> = text.split_whitespace().collect();
                if f.len() < 4 {
                    continue;
                }
                // The raw number is LINUX-numbered in a guest: futex is 202 on x86_64, 98 on i386, 422 for
                // futex_time64. Accept all three rather than reading a wait as "not a futex".
                let Some(nr) = f[0].parse::<i64>().ok() else { continue };
                if !matches!(nr, 202 | 98 | 422) {
                    continue;
                }
                let (Some(addr), Some(op)) = (parse_hex_or_dec(f[1]), parse_hex_or_dec(f[2])) else {
                    continue;
                };
                let val = parse_hex_or_dec(f[3]).unwrap_or(0);
                let (resolution, shared) = resolve_futex_addr(&maps, addr);
                // The SAME process appears in both trees (the guarded tree keeps the ancestors of the target, and
                // the same thread is snapshotted once per capture generation). Recording the snapshot's own name
                // lets the report collapse those repeats instead of listing one wait six times.
                let wait_key = (pid, tid, addr, n.clone());
                if !report.seen.insert(wait_key) {
                    continue;
                }
                report.waits.push(FutexWait {
                    tree,
                    pid,
                    label: label.chars().take(60).collect(),
                    tid,
                    addr,
                    op,
                    val,
                    wchan: first_line_of(&pdir.join(wchan_name)),
                    shared,
                    resolution,
                });
            }
        }
    }
    // The join: for every shared object a wait resolved to, find the OTHER processes that map the same object and
    // the address it has there. This is what makes "the peer is mapped but not waiting" a statement instead of a
    // guess, and it is also what exposes an object mapped by nobody else.
    let mut peer_keys: Vec<ObjectKey> = report.waits.iter().filter_map(|w| w.shared.clone()).collect();
    peer_keys.sort();
    peer_keys.dedup();
    for key in &peer_keys {
        for (pid, maps) in &maps_by_pid {
            // A process that is itself waiting on this byte is not the missing waker -- it is the other half of a
            // mutual wait, which is a different diagnosis and gets its own line (MUTUAL-WAIT below). The possible
            // wakers are therefore the mappings held by processes that are NOT waiting.
            for r in maps {
                if !r.shared || r.dev != key.dev || r.ino != key.ino {
                    continue;
                }
                if key.file_off < r.file_off {
                    continue;
                }
                let addr = r.lo + (key.file_off - r.file_off);
                let this_pid_waits = report
                    .waits
                    .iter()
                    .any(|w| w.shared.as_ref() == Some(key) && w.pid.to_string() == *pid);
                if addr < r.hi && !this_pid_waits {
                    let e = report.peers.entry(key.clone()).or_default();
                    let pair = (pid.clone(), addr);
                    if !e.contains(&pair) {
                        e.push(pair);
                    }
                }
            }
        }
    }

    // The wake half, and only from the out-of-band trace: a syscall snapshot is a moment and cannot show who woke
    // whom, so this is not an alternative source for the same fact.
    if let Some(path) = futex_trace {
        let text = fs::read_to_string(path)
            .with_context(|| format!("cannot read the futex trace {}", path.display()))?;
        let events = match parse_futex_trace(&text) {
            Ok(events) => events,
            Err(e) => bail!("{e}"),
        };
        let bundle_pids: std::collections::BTreeSet<u32> = maps_by_pid
            .iter()
            .filter_map(|(p, _)| p.parse::<u32>().ok())
            .collect();
        let window = bundle_run_window(bundle);
        let open_ended = window.map(|(_, end)| end.is_none()).unwrap_or(false);
        let (selected, foreign) = match select_futex_trace(events, &bundle_pids, window) {
            Ok(v) => v,
            Err(e) => bail!("{e}"),
        };
        report.trace_window_open_ended = open_ended;
        report.trace_foreign_events = foreign;
        report.trace_waits = pair_futex_trace(&selected, &maps_by_pid);
        report.trace_present = true;
    }
    Ok(report)
}

// ---------------------------------------------------------------------------------------------------------------
// The server's event ring: the fixed record schema, and the two things a dump cannot say by itself.
// ---------------------------------------------------------------------------------------------------------------

/// One decoded ring record.
///
/// The four payload words are printed and NOT interpreted: their meaning is per tag and belongs to the producer's
/// own switch, so naming them here would be a second schema that silently drifts from the first one.
#[derive(Clone, Debug)]
struct RingRecord {
    seq: u64,
    tag: String,
    fields: [u64; 4],
}

#[derive(Debug, Default)]
struct RingDump {
    records: Vec<RingRecord>,
    /// ONE ENTRY PER DUMP in the log, because a log holds several: every guest process dumps its own ring at
    /// exit, and a reader that applied one header's counts to all the records would report a number that belongs
    /// to no ring at all. MEASURED: the first real guest log carried 8 dumps and 342 records.
    per_dump: Vec<RingDumpPart>,
    /// A record LINE that does not satisfy the schema: the producer printed the slot, so the event happened, but
    /// the fields cannot be trusted. This is a TORN record, not a missing one.
    malformed_records: Vec<String>,
    /// Anything else that carried the prefix without being a header or a record.
    malformed_other: Vec<String>,
}

/// One dump's own header, and what was read back inside its section.
#[derive(Debug, Default, Clone)]
struct RingDumpPart {
    /// `events=`: how many slots were RESERVED, which is not how many the dump shows.
    events: Option<u64>,
    /// `shown=`: how many the producer TRIED to print. It skips a slot whose `seq` no longer matches the index it
    /// is reading, so the printed count can be smaller, and that difference is the measurement of overwriting --
    /// the producer's own comment says a record "overwritten or partly written while we read" is "reported by
    /// omission, never guessed".
    shown: Option<u64>,
    /// `guest=`: whether this dump came from a GUEST ring rather than the server's.
    guest: Option<bool>,
    records: u64,
    torn: u64,
}

fn parse_ring_dump(text: &str) -> RingDump {
    let mut out = RingDump::default();
    let mut current: Option<usize> = None;
    for raw in text.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("dtape.ering ") else {
            continue;
        };
        if let Some(header) = rest.strip_prefix("dump ") {
            let mut events = None;
            let mut shown = None;
            let mut guest = None;
            for f in header.split_whitespace() {
                let Some((k, v)) = f.split_once('=') else {
                    out.malformed_other
                        .push(format!("dump header field {f:?} is not key=value"));
                    continue;
                };
                match k {
                    "events" => events = v.parse::<u64>().ok(),
                    "shown" => shown = v.parse::<u64>().ok(),
                    // A GUEST dump says so, because the two rings have different owners: the server's lives in
                    // the server process, the guest's in the guest's own address space. Same schema, same
                    // reader -- but a reader must be able to say which one it read.
                    "guest" => guest = v.parse::<u64>().ok().map(|n| n != 0),
                    other => out
                        .malformed_other
                        .push(format!("dump header has unknown field {other:?}")),
                }
            }
            current = Some(out.per_dump.len());
            out.per_dump.push(RingDumpPart {
                events,
                shown,
                guest,
                records: 0,
                torn: 0,
            });
            continue;
        }
        // A record. EVERY field is required and only these fields are accepted, because a missing one means the
        // slot was read while it was being written: accepting the line anyway is exactly how a half-written
        // record becomes a measurement.
        let (mut seq, mut tag, mut fields) = (None, None, [None; 4]);
        for f in rest.split_whitespace() {
            let Some((k, v)) = f.split_once('=') else {
                out.malformed_records
                    .push(format!("record field {f:?} is not key=value"));
                continue;
            };
            match k {
                "seq" => seq = v.parse::<u64>().ok(),
                "tag" => tag = Some(v.to_string()),
                "a" | "b" | "c" | "d" => {
                    let i = (k.as_bytes()[0] - b'a') as usize;
                    fields[i] = parse_hex_or_dec(v);
                }
                other => out
                    .malformed_records
                    .push(format!("record has unknown field {other:?}")),
            }
        }
        let (Some(seq), Some(tag), [Some(a), Some(b), Some(c), Some(d)]) = (seq, tag, fields) else {
            out.malformed_records.push(format!(
                "{line} is incomplete (a slot read while being written, or a field that is not a number)"
            ));
            if let Some(section) = current {
                if let Some(part) = out.per_dump.get_mut(section) {
                    part.torn += 1;
                }
            }
            continue;
        };
        out.records.push(RingRecord {
            seq,
            tag,
            fields: [a, b, c, d],
        });
        if let Some(section) = current {
            if let Some(part) = out.per_dump.get_mut(section) {
                part.records += 1;
            }
        }
    }
    out
}

fn run_ring(args: RingArgs) -> Result<ExitCode> {
    let text = fs::read_to_string(&args.log)
        .with_context(|| format!("cannot read {}", args.log.display()))?;
    let dump = parse_ring_dump(&text);
    if dump.records.is_empty() && dump.per_dump.is_empty() {
        if args.json {
            println!(
                "{{\"present\":false,\"log\":\"{}\"}}",
                jesc(&args.log.display().to_string())
            );
            return Ok(ExitCode::SUCCESS);
        }
        println!(
            "RING-NO-DUMP {} carries no `dtape.ering` line: the ring is off (DSERVER_TRACE_RING) or its dump never ran -- a silent ring is not a ring with no event",
            args.log.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let parsed = dump.records.len() as u64;
    let torn = dump.malformed_records.len() as u64;
    // Every count below is per DUMP, because a log holds several: one per guest process. Summing them is honest as
    // a total, and applying ONE header's counts to all the records -- which is what a single-header reader did --
    // is not: it reports a number that belongs to no ring at all. MEASURED: the first real guest log carried 8
    // dumps and 342 records.
    let dumps = dump.per_dump.len() as u64;
    let sum_events: u64 = dump.per_dump.iter().filter_map(|p| p.events).sum();
    let sum_shown: u64 = dump.per_dump.iter().filter_map(|p| p.shown).sum();
    let any_events = dump.per_dump.iter().any(|p| p.events.is_some());
    let any_shown = dump.per_dump.iter().any(|p| p.shown.is_some());
    let guest_dumps = dump
        .per_dump
        .iter()
        .filter(|p| p.guest == Some(true))
        .count();
    // Two different facts, counted apart. A slot the producer PRINTED that came back incomplete is TORN: the event
    // happened and its fields cannot be trusted. A slot it never printed was already overwritten when the dump ran,
    // which the producer's own comment calls "reported by omission, never guessed". Collapsing them would make a
    // torn record indistinguishable from a missing one.
    let skipped = if any_shown {
        Some(sum_shown.saturating_sub(parsed + torn))
    } else {
        None
    };
    let first = dump.records.iter().map(|r| r.seq).min();
    let last = dump.records.iter().map(|r| r.seq).max();
    // The producer prints a slot only when its seq still matches the index it reads, so within ONE dump the printed
    // sequences are contiguous except where a slot was overwritten or read torn. Across several dumps they are not,
    // so a gap is only computed when the log holds exactly one.
    let gaps = match (first, last) {
        (Some(f), Some(l)) if dumps <= 1 => (l - f + 1).saturating_sub(parsed),
        _ => 0,
    };
    let mut tallies: BTreeMap<&str, u64> = BTreeMap::new();
    for r in &dump.records {
        *tallies.entry(r.tag.as_str()).or_insert(0) += 1;
    }
    let unknown = tallies.get("?").copied().unwrap_or(0);

    if args.json {
        let mut out = String::from("{\"present\":true");
        out.push_str(&format!(",\"log\":\"{}\"", jesc(&args.log.display().to_string())));
        out.push_str(&format!(",\"dumps\":{dumps},\"guest_dumps\":{guest_dumps}"));
        out.push_str(&format!(
            ",\"events\":{},\"shown\":{},\"parsed\":{parsed}",
            if any_events { sum_events.to_string() } else { "null".into() },
            if any_shown { sum_shown.to_string() } else { "null".into() },
        ));
        out.push_str(&format!(
            ",\"torn\":{torn},\"skipped\":{},\"seq_gaps\":{gaps},\"unknown_tag\":{unknown}",
            skipped.map(|v| v.to_string()).unwrap_or("null".into()),
        ));
        out.push_str(",\"tags\":{");
        for (i, (tag, n)) in tallies.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{}\":{n}", jesc(tag)));
        }
        out.push_str("},\"malformed_records\":[");
        for (i, m) in dump.malformed_records.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{}\"", jesc(m)));
        }
        out.push_str("],\"malformed_other\":[");
        for (i, m) in dump.malformed_other.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{}\"", jesc(m)));
        }
        out.push_str("],\"records\":[");
        // A cap, stated rather than silent: a dump can hold thousands of records, and a machine-readable answer of
        // 40 MB is not composable. `records_truncated` says whether anything was left out.
        const RECORD_CAP: usize = 64;
        for (i, r) in dump.records.iter().take(RECORD_CAP).enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"seq\":{},\"tag\":\"{}\",\"a\":{},\"b\":{},\"c\":{},\"d\":{}}}",
                r.seq,
                jesc(&r.tag),
                r.fields[0],
                r.fields[1],
                r.fields[2],
                r.fields[3]
            ));
        }
        out.push_str(&format!(
            "],\"records_truncated\":{}}}",
            dump.records.len() > RECORD_CAP
        ));
        println!("RING-JSON {out}");
        return Ok(ExitCode::SUCCESS);
    }

    println!(
        "RING {} dumps={} guest_dumps={} parsed={parsed} seq={:?}..{:?}",
        args.log.display(),
        dumps,
        guest_dumps,
        first,
        last
    );
    // One line per dump, because a log holds one per guest process: the counts BELONG to a ring, and a total that
    // is not attached to any of them is how a reader reports a number no ring ever had.
    for (i, part) in dump.per_dump.iter().enumerate() {
        let skipped_here = part.shown.map(|s| s.saturating_sub(part.records + part.torn));
        println!(
            "  DUMP {i} guest={} events={} shown={} parsed={} torn={} skipped={}",
            match part.guest {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unspecified",
            },
            part.events.map(|v| v.to_string()).unwrap_or("-".into()),
            part.shown.map(|v| v.to_string()).unwrap_or("-".into()),
            part.records,
            part.torn,
            skipped_here.map(|v| v.to_string()).unwrap_or("-".into())
        );
    }
    for (tag, n) in &tallies {
        // One sample per tag, with its payload: a count alone would decode the schema and then say nothing with it.
        let sample = dump.records.iter().find(|r| r.tag == *tag);
        let sample_text = match sample {
            Some(r) => format!(
                " sample: seq={} a={:#x} b={:#x} c={:#x} d={:#x}",
                r.seq, r.fields[0], r.fields[1], r.fields[2], r.fields[3]
            ),
            None => String::new(),
        };
        if *tag == "?" {
            println!(
                "  TAG ? n={n} UNKNOWN-TAG (the producer prints `?` for a tag its switch does not know, so the numeric tag is NOT recoverable from the dump){sample_text}"
            );
        } else {
            println!("  TAG {tag} n={n}{sample_text}");
        }
    }
    if torn == 0 && skipped == Some(0) {
        println!(
            "RING-COMPLETE every slot the producer printed was read back intact (shown={sum_shown}, seq_gaps={gaps})"
        );
    } else {
        if torn > 0 {
            println!(
                "RING-TORN {torn} slot(s) were printed but are incomplete: the events happened and their fields cannot be trusted (seq_gaps={gaps})"
            );
        }
        match skipped {
            Some(n) if n > 0 => println!(
                "RING-SKIPPED {n} slot(s) were already overwritten when the dump ran: those events happened and are NOT in this dump at all (seq_gaps={gaps})"
            ),
            Some(_) => {}
            None => println!(
                "RING-UNKNOWN-COMPLETENESS the dump header carries no shown=, so how many slots were attempted cannot be known (seq_gaps={gaps})"
            ),
        }
    }
    if !dump.malformed_other.is_empty() {
        println!("RING-MALFORMED-DUMP {} header line(s) did not parse:", dump.malformed_other.len());
        for m in dump.malformed_other.iter().take(3) {
            println!("  {m}");
        }
    }
    if !dump.malformed_records.is_empty() {
        println!("RING-MALFORMED {} record line(s):", dump.malformed_records.len());
        for m in dump.malformed_records.iter().take(5) {
            println!("  {m}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_futex(args: FutexArgs) -> Result<ExitCode> {
    let report = pair_futex(&args.bundle, args.futex_trace.as_deref())?;
    if args.json {
        // Hand-written JSON, like every other output of this tool: it must be readable by a machine without
        // pulling in a serializer whose presence would be the only reason the type is shaped this way.
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let mut out = String::from("{\"processes\":");
        out.push_str(&report.processes.to_string());
        out.push_str(",\"waits\":[");
        for (i, w) in report.waits.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"tree\":\"{}\",\"pid\":{},\"tid\":{},\"addr\":{},\"op\":{},\"val\":{},\"wchan\":\"{}\",\"resolution\":\"{}\",\"label\":\"{}\"",
                w.tree,
                w.pid,
                w.tid,
                w.addr,
                w.op,
                w.val,
                esc(&w.wchan),
                w.resolution,
                esc(&w.label)
            ));
            match &w.shared {
                Some(k) => out.push_str(&format!(
                    ",\"object\":{{\"dev\":\"{}\",\"ino\":{},\"file_off\":{},\"file\":\"{}\"}}}}",
                    esc(&k.dev),
                    k.ino,
                    k.file_off,
                    esc(&k.file)
                )),
                None => out.push_str(",\"object\":null}"),
            }
        }
        out.push_str("],\"peers\":{");
        for (n, (k, list)) in report.peers.iter().enumerate() {
            if n > 0 {
                out.push(',');
            }
            let key = format!("{}:{}:{}", k.dev, k.ino, k.file_off);
            let addrs: Vec<String> = list
                .iter()
                .map(|(pid, a)| format!("{{\"pid\":\"{pid}\",\"addr\":{a}}}"))
                .collect();
            out.push_str(&format!("\"{key}\":[{}]", addrs.join(",")));
        }
        out.push_str(",\"trace\":{");
        out.push_str(&format!("\"present\":{},", report.trace_present));
        out.push_str(&format!(
            "\"window_open_ended\":{},",
            report.trace_window_open_ended
        ));
        out.push_str(&format!(
            "\"foreign_events\":{},",
            report.trace_foreign_events
        ));
        out.push_str("\"waits\":[");
        for (i, w) in report.trace_waits.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let object = w
                .object
                .as_ref()
                .map(|k| format!("{}:{}:{}", k.dev, k.ino, k.file_off))
                .unwrap_or_default();
            let (waker_pid, waker_tid, waker_woke) = match w.waker {
                Some((p, t, n)) => (p.to_string(), t.to_string(), n.to_string()),
                None => ("null".to_string(), "null".to_string(), "null".to_string()),
            };
            out.push_str(&format!(
                "{{\"pid\":{},\"tid\":{},\"addr\":{},\"resolution\":\"{}\",\"object\":\"{}\",\"waker_pid\":{},\"waker_tid\":{},\"waker_woke\":{},\"wakes_after\":{}}}",
                w.pid, w.tid, w.addr, w.resolution, object, waker_pid, waker_tid, waker_woke, w.wakes_after
            ));
        }
        out.push_str("]}");
        out.push_str("}}");
        println!("FUTEX-JSON {out}");
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "FUTEX bundle={} processes={} waits={}",
        args.bundle.display(),
        report.processes,
        report.waits.len()
    );
    if !report.trace_present {
        println!(
            "FUTEX-TRACE-ABSENT no --futex-trace was given: the wake half cannot come from a syscall snapshot, so nothing below says who woke whom"
        );
    } else {
        println!(
            "FUTEX-TRACE waits={} window_open_ended={} foreign_events={} (a kernel probe is system-wide, so events from pids this bundle did not capture are counted and dropped)",
            report.trace_waits.len(),
            report.trace_window_open_ended,
            report.trace_foreign_events
        );
        for w in &report.trace_waits {
            match &w.waker {
                Some((pid, tid, woke)) => println!(
                    "  WAIT pid={} tid={} addr={:#x} resolution={} WAKER pid={pid} tid={tid} woke={woke} wakes_after={}",
                    w.pid, w.tid, w.addr, w.resolution, w.wakes_after
                ),
                None => println!(
                    "  WAIT pid={} tid={} addr={:#x} resolution={} NO-WAKE (nothing woke this object after the wait: the finding this trace exists to state)",
                    w.pid, w.tid, w.addr, w.resolution
                ),
            }
        }
    }
    if report.waits.is_empty() {
        println!(
            "FUTEX-NONE no futex syscall snapshot resolved in this bundle: either nothing was waiting when it was taken, or the capture kept no per-thread syscall file (name them with --capture-snapshots and --capture-tree)"
        );
    }
    // One row per distinct wait STATE, not per snapshot: the same thread is captured in several generations, and
    // repeating its line once per generation turned a four-wait stall into a thirty-line report. The count is kept,
    // because "it was still waiting when the last capture was taken" is a fact worth keeping.
    let mut by_object: BTreeMap<String, BTreeMap<(u32, u32, u64, u64, u64, String), usize>> = BTreeMap::new();
    for w in &report.waits {
        let id = match &w.shared {
            Some(k) => format!("OBJECT shared dev={} ino={} off={:#x} name={}", k.dev, k.ino, k.file_off, k.file),
            None => format!("OBJECT {} pid={} addr={:#x}", w.resolution, w.pid, w.addr),
        };
        *by_object
            .entry(id)
            .or_default()
            .entry((w.pid, w.tid, w.addr, w.op, w.val, w.wchan.clone()))
            .or_insert(0) += 1;
    }
    for (id, waits) in &by_object {
        println!("{id}");
        for ((pid, tid, addr, op, val, wchan), n) in waits {
            println!(
                "  WAIT pid={pid} tid={tid} addr={addr:#x} op={op:#x} val={val:#x} wchan={wchan} snapshots={n}"
            );
        }
        // Peers belong to the OBJECT, so they are printed once for it: repeating them per waiting thread is how a
        // four-wait report looked like forty lines.
        let mut any_peer = false;
        let keys: Vec<ObjectKey> = report
            .peers
            .keys()
            .filter(|k| id.contains(&format!("ino={} off={:#x}", k.ino, k.file_off)))
            .cloned()
            .collect();
        for k in &keys {
            if let Some(peers) = report.peers.get(k) {
                for (pid, addr) in peers {
                    println!(
                        "  PEER-MAPS pid={pid} addr={addr:#x} (mapped by a process that is NOT waiting on it: this side could be the waker that never came)"
                    );
                    any_peer = true;
                }
            }
        }
        // More than one PROCESS waiting on one byte is a deadlock-shaped fact and must not be left implicit.
        let key_here = report
            .waits
            .iter()
            .filter(|w| w.shared.is_some() && id.contains(&format!("ino={}", w.shared.as_ref().unwrap().ino)))
            .filter_map(|w| w.shared.clone())
            .next();
        if let Some(k) = key_here {
            let mut pids: Vec<u32> = report
                .waits
                .iter()
                .filter(|w| w.shared.as_ref() == Some(&k))
                .map(|w| w.pid)
                .collect();
            pids.sort();
            pids.dedup();
            if pids.len() > 1 {
                println!(
                    "  MUTUAL-WAIT pids={pids:?} (more than one process waits on this byte: each is the other's missing waker)"
                );
            }
        }
        let shared_here = report.waits.iter().any(|w| {
            w.shared.is_some() && id.contains(&format!("ino={}", w.shared.as_ref().unwrap().ino))
        });
        if shared_here && !any_peer {
            println!(
                "  PEER-MAPS none (no other process in this bundle maps this byte, so nothing outside this process can complete the wait)"
            );
        }
        if id.contains("OBJECT private") {
            println!(
                "  NOTE this wait is on memory only its own process has: no peer can be the missing waker, and the answer must be inside that process"
            );
        }
    }
    println!(
        "WAKE-EVIDENCE none-in-bundle (a syscall snapshot records who is waiting at one instant; wakes need a host futex trace taken during the SAME run)"
    );
    let shared = report.waits.iter().filter(|w| w.shared.is_some()).count();
    let private = report.waits
        .iter()
        .filter(|w| w.resolution.starts_with("private"))
        .count();
    let unmapped = report.waits.iter().filter(|w| w.resolution == "unmapped").count();
    println!(
        "FUTEX-VERDICT waits={} shared={shared} private={private} unmapped={unmapped}",
        report.waits.len()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod futex_tests {
    use super::*;

    fn bundle_fixture(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dwdiag-futex-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("capture-tree/pid-100")).unwrap();
        fs::create_dir_all(dir.join("guarded-tree/pid-200")).unwrap();
        // The same memfd seen at two different base addresses, which is the normal case and the reason virtual
        // addresses cannot be compared.
        fs::write(
            dir.join("capture-tree/pid-100/proc-maps.txt"),
            "1000-2000 rw-s 00000000 00:01 42 /memfd:dring (deleted)\n3000-4000 rw-p 00000000 00:00 0 \n",
        )
        .unwrap();
        fs::write(dir.join("capture-tree/pid-100/proc-cmdline.txt"), "/usr/bin/ld -demangle\n").unwrap();
        fs::write(
            dir.join("capture-tree/pid-100/snapshot-1-tid-101-syscall.txt"),
            "202 0x1080 0x0 0x1d 0x0 0x0 0x0 0x0 0x0\n",
        )
        .unwrap();
        fs::write(dir.join("capture-tree/pid-100/snapshot-1-tid-101-wchan.txt"), "futex_wait_queue\n").unwrap();
        fs::write(
            dir.join("guarded-tree/pid-200/proc-maps.txt"),
            "5000-6000 rw-s 00000000 00:01 42 /memfd:dring (deleted)\n7000-8000 rw-p 00000000 00:00 0 \n",
        )
        .unwrap();
        fs::write(dir.join("guarded-tree/pid-200/proc-cmdline.txt"), "darlingserver 4 3 prefix\n").unwrap();
        // One wait on the shared object from the OTHER side, and one on unmapped memory: the second must be
        // reported as unresolved rather than dropped or attributed to the shared object.
        fs::write(
            dir.join("guarded-tree/pid-200/snapshot-1-tid-201-syscall.txt"),
            "202 0x5080 0x0 0x1 0x0 0x0 0x0 0x0 0x0\n",
        )
        .unwrap();
        fs::write(
            dir.join("guarded-tree/pid-200/snapshot-1-tid-202-syscall.txt"),
            "202 0xdeadbeef 0x0 0x1 0x0 0x0 0x0 0x0 0x0\n",
        )
        .unwrap();
        // A THIRD process that maps the same object and is NOT waiting: this is the only process that could be the
        // waker, and a report that cannot name it cannot answer the question the command exists for.
        fs::create_dir_all(dir.join("guarded-tree/pid-300")).unwrap();
        fs::write(
            dir.join("guarded-tree/pid-300/proc-maps.txt"),
            "9000-9100 rw-s 00000000 00:01 42 /memfd:dring (deleted)\n",
        )
        .unwrap();
        fs::write(dir.join("guarded-tree/pid-300/proc-cmdline.txt"), "darlingserver helper\n").unwrap();
        dir
    }

    #[test]
    fn joins_a_waiter_with_the_peer_mapping_by_shared_object_identity() {
        let dir = bundle_fixture("join");
        let r = pair_futex(&dir, None).unwrap();
        assert_eq!(r.waits.len(), 3);
        let ld = r.waits.iter().find(|w| w.pid == 100).unwrap();
        let key = ld.shared.as_ref().expect("the loader wait resolves to a shared object");
        assert_eq!(key.ino, 42);
        assert_eq!(key.file_off, 0x80, "identity carries the file offset, not the virtual address");
        assert_eq!(ld.val, 0x1d);
        // The server's own wait on the SAME object at a different address must be joined to the loader's key.
        let srv = r.waits.iter().find(|w| w.pid == 200 && w.resolution == "shared").unwrap();
        assert_eq!(srv.shared.as_ref().unwrap().file_off, 0x80);
        // And the peers of that key are the two mappings (each side sees the other).
        let peers = r.peers.get(key).expect("a process maps the same object without waiting");
        assert_eq!(
            peers,
            &vec![("300".to_string(), 0x9080)],
            "only a process that is NOT waiting can be the waker: {peers:?}"
        );
        // Both waiting processes are joined to the same key, which is what makes the mutual wait visible.
        assert_eq!(
            r.waits.iter().filter(|w| w.shared.as_ref() == Some(key)).count(),
            2
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_an_unmapped_wait_with_its_reason_instead_of_dropping_it() {
        let dir = bundle_fixture("unmapped");
        let r = pair_futex(&dir, None).unwrap();
        let u = r.waits.iter().find(|w| w.tid == 202).unwrap();
        assert_eq!(u.resolution, "unmapped");
        assert!(u.shared.is_none());
        assert!(!r.trace_present, "no trace was given, so the absence must be reported as one");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The fixture's run window sits in the year 2000, so a trace written "now" cannot fall inside it by accident.
    const WINDOW_START: u64 = 946684800;
    const WINDOW_END: u64 = 946771200;

    fn write_manifest(dir: &Path) {
        fs::write(
            dir.join("evidence-manifest"),
            format!("version=1\nstart={WINDOW_START}\nend={WINDOW_END}\n"),
        )
        .unwrap();
    }

    fn trace_fixture(tag: &str, lines: &[String]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "dwdiag-futex-trace-{tag}-{}.txt",
            std::process::id()
        ));
        fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    fn at(seconds_into_run: u128) -> u128 {
        WINDOW_START as u128 * 1_000_000_000 + seconds_into_run
    }

    #[test]
    fn pairs_a_wait_with_the_wake_on_the_same_object_in_another_address_space() {
        let dir = bundle_fixture("trace-pair");
        write_manifest(&dir);
        // 0x1080 in pid-100 and 0x9080 in pid-300 are the SAME byte of the shared memfd (file offset 0x80). The
        // waker lives in a different address space, so only (dev, ino, offset) can join them -- which is exactly
        // what a snapshot cannot do, because a snapshot has no wake in it at all.
        let trace = trace_fixture(
            "pair",
            &[
                format!("WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}", at(10)),
                format!("WAKE pid=300 tid=301 uaddr=0x9080 woke=1 ts_ns={}", at(20)),
            ],
        );
        let r = pair_futex(&dir, Some(&trace)).unwrap();
        assert!(r.trace_present);
        assert!(!r.trace_window_open_ended, "the manifest records both ends here");
        let w = r.trace_waits.iter().find(|w| w.tid == 101).unwrap();
        assert_eq!(w.waker, Some((300, 301, 1)));
        assert_eq!(w.wakes_after, 1);
        assert!(w.object.is_some(), "the wait resolved to the shared object");
        let _ = fs::remove_file(&trace);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wait_whose_object_is_never_woken_is_reported_as_the_finding() {
        let dir = bundle_fixture("trace-nowake");
        write_manifest(&dir);
        let trace = trace_fixture(
            "nowake",
            &[
                format!("WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}", at(10)),
                // A wake on a DIFFERENT object (offset 0x90 in pid-300's mapping of the same memfd) must not be
                // counted as this wait's waker: "some wake happened" is not "this wait was woken".
                format!("WAKE pid=300 tid=301 uaddr=0x9090 woke=1 ts_ns={}", at(20)),
            ],
        );
        let r = pair_futex(&dir, Some(&trace)).unwrap();
        let w = r.trace_waits.iter().find(|w| w.tid == 101).unwrap();
        assert_eq!(w.waker, None);
        assert_eq!(w.wakes_after, 0);
        let _ = fs::remove_file(&trace);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_trace_naming_a_pid_the_bundle_never_saw_is_refused() {
        let dir = bundle_fixture("trace-otherpid");
        write_manifest(&dir);
        let trace = trace_fixture(
            "otherpid",
            &[format!("WAIT pid=999 tid=999 uaddr=0x1080 ts_ns={}", at(10))],
        );
        let err = pair_futex(&dir, Some(&trace)).unwrap_err().to_string();
        assert!(err.contains("all foreign"), "{err}");
        let _ = fs::remove_file(&trace);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_private_futex_is_paired_by_process_and_address() {
        // The common case: a mutex inside a heap allocation. There is no shared object to join on, so requiring one
        // would report every private wait as never woken -- a wrong answer about the most ordinary lock there is.
        let dir = bundle_fixture("trace-private");
        write_manifest(&dir);
        // 0x3080 lies in pid-100's PRIVATE mapping (3000-4000 rw-p), not in the shared memfd.
        let trace = trace_fixture(
            "private",
            &[
                format!("WAIT pid=100 tid=101 uaddr=0x3080 ts_ns={}", at(10)),
                format!("WAKE pid=100 tid=102 uaddr=0x3080 woke=1 ts_ns={}", at(20)),
            ],
        );
        let r = pair_futex(&dir, Some(&trace)).unwrap();
        let w = r.trace_waits.iter().find(|w| w.tid == 101).unwrap();
        assert!(w.resolution.starts_with("private"), "{}", w.resolution);
        assert!(w.object.is_none());
        assert_eq!(w.waker, Some((100, 102, 1)));
        let _ = fs::remove_file(&trace);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_system_wide_trace_is_selected_by_pid_and_the_dropped_events_are_counted() {
        // MEASURED on this host: `probes/futex.bt` produced 29198 events across the whole system, including
        // processes with nothing to do with the run. A reader that refused on the first foreign pid would reject
        // every honest trace, so the events are selected and the rest reported.
        let dir = bundle_fixture("trace-systemwide");
        write_manifest(&dir);
        let trace = trace_fixture(
            "systemwide",
            &[
                format!("WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}", at(10)),
                format!("WAKE pid=999 tid=999 uaddr=0x1080 ts_ns={}", at(15)),
                format!("WAKE pid=300 tid=301 uaddr=0x9080 woke=1 ts_ns={}", at(20)),
            ],
        );
        let r = pair_futex(&dir, Some(&trace)).unwrap();
        assert_eq!(r.trace_foreign_events, 1, "the foreign event must be counted, not silently dropped");
        // The pairing must not be confused by the foreign event: the only wake on this object after the wait is
        // the one from pid 300.
        let w = r.trace_waits.iter().find(|w| w.tid == 101).unwrap();
        assert_eq!(w.waker, Some((300, 301, 1)));
        let _ = fs::remove_file(&trace);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_probe_base_line_converts_monotonic_timestamps_into_the_run_window() {
        // A kernel probe reports MONOTONIC time; a run window is wall clock. The probe prints both once, and the
        // reader converts -- otherwise it would have to guess, and a guess is what the window check exists to stop.
        let dir = bundle_fixture("trace-base");
        write_manifest(&dir);
        let mono_base = 1_000_000_000u128;
        let trace = trace_fixture(
            "base",
            &[
                format!("# BASE wall_s={} mono_ns={mono_base}", WINDOW_START),
                format!("WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}", mono_base + 10),
            ],
        );
        let r = pair_futex(&dir, Some(&trace)).unwrap();
        assert_eq!(r.trace_waits.len(), 1);
        // Converted, the event lands inside the window (it would be refused if the raw monotonic value were used,
        // because a monotonic nanosecond count is far below the wall-clock window).
        let _ = fs::remove_file(&trace);

        // A base line whose wall clock is before the run window proves the conversion is applied to the EVENTS and
        // not only parsed: the same monotonic offsets now land outside it.
        let old = trace_fixture(
            "base-old",
            &[
                format!("# BASE wall_s={} mono_ns={mono_base}", WINDOW_START - 100_000),
                format!("WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}", mono_base + 10),
            ],
        );
        let err = pair_futex(&dir, Some(&old)).unwrap_err().to_string();
        assert!(err.contains("precedes the run start"), "{err}");
        let _ = fs::remove_file(&old);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_trace_from_outside_the_run_window_is_refused() {
        let dir = bundle_fixture("trace-window");
        write_manifest(&dir);
        // The pids are right and the window says otherwise: an earlier run whose pids were recycled reads exactly
        // like this run's trace, so the window is the check that separates them. Both ends are exercised.
        let after = trace_fixture(
            "window-after",
            &[format!(
                "WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}",
                (WINDOW_END as u128 + 10) * 1_000_000_000
            )],
        );
        let err = pair_futex(&dir, Some(&after)).unwrap_err().to_string();
        assert!(err.contains("run end"), "{err}");
        let _ = fs::remove_file(&after);

        let before = trace_fixture(
            "window-before",
            &[format!(
                "WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}",
                (WINDOW_START as u128 - 10) * 1_000_000_000
            )],
        );
        let err = pair_futex(&dir, Some(&before)).unwrap_err().to_string();
        assert!(err.contains("precedes the run start"), "{err}");
        let _ = fs::remove_file(&before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_trace_without_timestamps_or_a_window_is_refused() {
        let dir = bundle_fixture("trace-nots");
        write_manifest(&dir);
        let trace = trace_fixture("nots", &["WAIT pid=100 tid=101 uaddr=0x1080".to_string()]);
        let err = pair_futex(&dir, Some(&trace)).unwrap_err().to_string();
        assert!(err.contains("ts_ns"), "{err}");
        let _ = fs::remove_file(&trace);

        // And a bundle that declares no window at all: the trace is refused rather than attributed by guesswork.
        let bare = bundle_fixture("trace-nowindow");
        let good = trace_fixture("nowindow", &[format!("WAIT pid=100 tid=101 uaddr=0x1080 ts_ns={}", at(10))]);
        let err = pair_futex(&bare, Some(&good)).unwrap_err().to_string();
        assert!(err.contains("no run window"), "{err}");
        let _ = fs::remove_file(&good);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&bare);
    }
}

#[cfg(test)]
mod ring_tests {
    use super::*;

    const HEADER: &str = "dtape.ering dump events=4 shown=4";

    fn record(seq: u64, tag: &str) -> String {
        format!("dtape.ering seq={seq} tag={tag} a=0x1 b=0x2 c=0x3 d=0x4")
    }

    #[test]
    fn parses_the_schema_and_counts_by_tag() {
        let text = format!(
            "{HEADER}\n{}\n{}\n{}\n",
            record(0, "recv_park"),
            record(1, "recv_done"),
            record(2, "recv_park"),
        );
        let d = parse_ring_dump(&text);
        assert_eq!(d.records.len(), 3);
        assert_eq!(d.per_dump.len(), 1);
        assert_eq!(d.per_dump[0].events, Some(4));
        assert_eq!(d.per_dump[0].shown, Some(4));
        assert_eq!(d.per_dump[0].records, 3);
        assert!(d.malformed_records.is_empty() && d.malformed_other.is_empty());
        let r = &d.records[0];
        assert_eq!((r.seq, r.tag.as_str(), r.fields), (0, "recv_park", [1, 2, 3, 4]));
    }

    #[test]
    fn a_record_missing_a_field_is_malformed_and_never_a_measurement() {
        // Exactly what a slot read while being written looks like: the producer stores the fields with PLAIN
        // stores after one atomic reservation, so a reader can see seq without d.
        let text = format!(
            "{HEADER}\ndtape.ering seq=0 tag=recv_park a=0x1 b=0x2 c=0x3\n{}",
            record(1, "recv_done")
        );
        let d = parse_ring_dump(&text);
        assert_eq!(d.records.len(), 1, "only the intact record may be measured");
        assert_eq!(d.malformed_records.len(), 1);
        assert!(
            d.malformed_records[0].contains("incomplete"),
            "{:?}",
            d.malformed_records
        );
    }

    #[test]
    fn an_unknown_tag_is_counted_and_its_number_is_not_invented() {
        // The producer prints `?` for a tag its switch does not know, so the numeric tag is not in the dump at all.
        // Counting it as anything else would be inventing a value the dump does not carry.
        let d = parse_ring_dump(&format!("{HEADER}\n{}\n", record(0, "?")));
        assert_eq!(d.records.len(), 1);
        assert_eq!(d.records[0].tag, "?");
    }

    #[test]
    fn overwritten_slots_are_measured_as_omissions_and_as_sequence_gaps() {
        // shown=10 while only 8 records came back: two slots no longer matched their index, which is the producer's
        // own "reported by omission". The gap between seq 0..7 and the missing 8..9 is the same fact, seen from the
        // sequence side.
        let mut text = String::from("dtape.ering dump events=3000 shown=10\n");
        for seq in 0..8 {
            text.push_str(&record(seq, "recv_park"));
            text.push('\n');
        }
        let d = parse_ring_dump(&text);
        let parsed = d.records.len() as u64;
        let torn = d.malformed_records.len() as u64;
        // A slot the producer printed but that came back incomplete is TORN; a slot it never printed was already
        // overwritten. This dump has no torn line, so every unprinted slot is a skip.
        let skipped = d.per_dump[0].shown.unwrap() - (parsed + torn);
        let first = d.records.iter().map(|r| r.seq).min().unwrap();
        let last = d.records.iter().map(|r| r.seq).max().unwrap();
        assert_eq!(parsed, 8);
        assert_eq!(torn, 0);
        assert_eq!(skipped, 2);
        assert_eq!((first, last), (0, 7));
        assert_eq!((last - first + 1) - parsed, 0, "the printed range is contiguous here");
    }

    #[test]
    fn a_guest_dump_is_the_same_schema_and_says_it_came_from_the_guest() {
        // The guest ring is the guest's own memory (the shared transport's ABI block is separately versioned and
        // validated, so extending it is not something to slip in beside this), but the SLOT SCHEMA is the server's
        // word for word -- which is what lets one reader and one set of arithmetic cover both dumps.
        let text = "dtape.ering dump events=2 shown=2 guest=1\n\
                    dtape.ering seq=0 tag=[pc-entry a=0xffffffff b=0x55d0 c=0x0 d=0x0\n";
        let d = parse_ring_dump(text);
        assert_eq!(d.per_dump.len(), 1);
        assert_eq!(d.per_dump[0].guest, Some(true));
        assert_eq!(d.records.len(), 1);
        assert_eq!(d.records[0].tag, "[pc-entry");
        assert_eq!(d.records[0].fields[0], 0xffffffff, "the digit is a FIELD, not a formatted string");
        assert!(d.malformed_records.is_empty() && d.malformed_other.is_empty());
    }

    #[test]
    fn several_dumps_in_one_log_are_counted_per_dump_not_by_the_last_header() {
        // MEASURED on the first real guest log: one dump per guest process, 8 of them and 342 records. A reader
        // that kept the last header's counts and applied them to every record reported a number belonging to no
        // ring at all, which is worse than no number.
        let text = "dtape.ering dump events=2 shown=2 guest=1\n\
                    dtape.ering seq=0 tag=[pc-entry a=0x1 b=0x2 c=0x0 d=0x0\n\
                    dtape.ering seq=1 tag=[pc-entry a=0x3 b=0x4 c=0x0 d=0x0\n\
                    dtape.ering dump events=5 shown=5 guest=1\n\
                    dtape.ering seq=0 tag=[pc-postplane a=0x5 b=0x6 c=0x0 d=0x0\n";
        let d = parse_ring_dump(text);
        assert_eq!(d.per_dump.len(), 2);
        assert_eq!((d.per_dump[0].records, d.per_dump[0].shown), (2, Some(2)));
        assert_eq!((d.per_dump[1].records, d.per_dump[1].shown), (1, Some(5)));
        assert_eq!(d.records.len(), 3, "the records of both dumps are all read");
    }

    #[test]
    fn a_log_with_no_dump_is_not_a_zero_census() {
        let d = parse_ring_dump("some run log\nwith no ring dump in it\n");
        assert!(d.records.is_empty());
        assert!(d.per_dump.is_empty());
        assert!(d.malformed_records.is_empty() && d.malformed_other.is_empty());
    }
}

// --------------------------------------------------------------- core-lock recovery

/// What the core says about one aborting thread's unfair lock. Every field is read from the core; none is inferred
/// from a symbol and none is a claim about what happened before the snapshot.
#[derive(Debug, Default, Clone)]
struct CoreLock {
    trap_tid: String,
    trap_pc: u64,
    /// The abort's argument as it stood at the trap. The trap instructions do not write it, which is what makes it
    /// trustworthy -- and that is verified by reading the instructions, not assumed.
    trap_arg: u64,
    gs_base: u64,
    slot3: u64,
    slow_rbp: u64,
    slow_ret_pc: u64,
    lock: u64,
    self_token: u64,
    current: u64,
    word: u64,
    /// (tid, self token) for every thread the core held.
    tokens: Vec<(String, u64)>,
}

const CORE_LOCK_SCRIPT: &str = r#"set pagination off
set confirm off
printf "@trap tid=%d pc=%#lx rdi=%#lx rbp=%#lx gs=%#lx\n", $_thread, $pc, $rdi, $rbp, $gs_base
printf "@tok tid=%d slot3=%#lx\n", $_thread, *(unsigned long*)($gs_base+24)
set $slow = *(unsigned long*)$rbp
printf "@slow tid=%d rbp=%#lx retpc=%#lx\n", $_thread, $slow, *(unsigned long*)($slow+8)
printf "@slowargs lock=%#lx self=%#lx current=%#lx\n", *(unsigned long*)($slow-8), *(unsigned int*)($slow-16), *(unsigned int*)($slow-24)
printf "@word lock=%#lx word=%#lx\n", *(unsigned long*)($slow-8), *(unsigned int*)(*(unsigned long*)($slow-8))
thread apply all printf "@alltid tid=%d slot3=%#lx\n", $_thread, *(unsigned long*)($gs_base+24)
"#;

fn hex_field(line: &str, name: &str) -> Option<u64> {
    let at = line.find(&format!("{name}="))?;
    let rest = &line[at + name.len() + 1..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    parse_hex_or_dec(&rest[..end])
}

/// Parse the gdb script's `@`-lines. Kept separate from running gdb so the interpretation is testable on captured
/// output -- the alternative is a command whose only test is a multi-gigabyte core.
fn parse_core_lock(text: &str) -> CoreLock {
    let mut out = CoreLock::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("@trap ") {
            out.trap_tid = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_start_matches("tid=")
                .to_string();
            out.trap_pc = hex_field(rest, "pc").unwrap_or(0);
            out.trap_arg = hex_field(rest, "rdi").unwrap_or(0);
            out.gs_base = hex_field(rest, "gs").unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("@tok ") {
            out.slot3 = hex_field(rest, "slot3").unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("@slow ") {
            out.slow_rbp = hex_field(rest, "rbp").unwrap_or(0);
            out.slow_ret_pc = hex_field(rest, "retpc").unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("@slowargs ") {
            out.lock = hex_field(rest, "lock").unwrap_or(0);
            out.self_token = hex_field(rest, "self").unwrap_or(0);
            out.current = hex_field(rest, "current").unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("@word ") {
            out.word = hex_field(rest, "word").unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("@alltid ") {
            let tid = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_start_matches("tid=")
                .to_string();
            if let Some(t) = hex_field(rest, "slot3") {
                out.tokens.push((tid, t));
            }
        }
    }
    out
}

/// The self tokens held by more than one live thread. An empty result is the measurement that RULES OUT a duplicate
/// live name at this instant; it cannot rule out a name recycled from a thread that has already died.
fn duplicate_tokens(tokens: &[(String, u64)]) -> Vec<u64> {
    let mut dups: Vec<u64> = Vec::new();
    for (i, (_, t)) in tokens.iter().enumerate() {
        if *t == 0 {
            continue;
        }
        if tokens
            .iter()
            .enumerate()
            .any(|(j, (_, o))| j != i && o == t)
            && !dups.contains(t)
        {
            dups.push(*t);
        }
    }
    dups
}

fn run_core_lock(args: CoreLockArgs) -> Result<ExitCode> {
    let core = match &args.core {
        Some(c) => c.clone(),
        None => {
            let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
            if let Ok(entries) = fs::read_dir(&args.dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if !name.starts_with("core.") {
                        continue;
                    }
                    let Ok(md) = e.metadata() else { continue };
                    let Ok(t) = md.modified() else { continue };
                    if newest.as_ref().map(|(nt, _)| t > *nt).unwrap_or(true) {
                        newest = Some((t, e.path()));
                    }
                }
            }
            newest
                .map(|(_, p)| p)
                .with_context(|| format!("no core.* under {}", args.dir.display()))?
        }
    };
    let script = std::env::temp_dir().join("dwdiag-core-lock.gdb");
    fs::write(&script, CORE_LOCK_SCRIPT)?;
    let mut cmd = Command::new("gdb");
    cmd.arg("-nx").arg("-q").arg("-batch").arg("-c").arg(&core).arg("-x").arg(&script);
    if args.no_tokens {
        // Keep the trap and slow-frame reads; drop the per-thread census that costs one reader each.
        let trimmed = CORE_LOCK_SCRIPT.replace(
            "thread apply all printf \"@alltid tid=%d slot3=%#lx\\n\", $_thread, *(unsigned long*)($gs_base+24)\n",
            "",
        );
        fs::write(&script, trimmed)?;
    }
    let out = cmd.output().context("gdb is required to read a core")?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.stderr.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr);
        for line in err.lines().filter(|l| !l.trim().is_empty()).take(4) {
            println!("CORE-LOCK-GDB {line}");
        }
    }
    let lock = parse_core_lock(&text);
    println!(
        "CORE-LOCK core={} trap_tid={} trap_pc={:#x} abort_arg={:#x}",
        core.display(),
        lock.trap_tid,
        lock.trap_pc,
        lock.trap_arg
    );
    println!(
        "CORE-LOCK-THREAD gs_base={:#x} slot3(self token)={:#x}",
        lock.gs_base, lock.slot3
    );
    println!(
        "CORE-LOCK-SLOW frame_rbp={:#x} return_pc={:#x} lock={:#x} saved_self={:#x} saved_current={:#x}",
        lock.slow_rbp, lock.slow_ret_pc, lock.lock, lock.self_token, lock.current
    );
    // The word's owner encoding is (word | 1) -- but only when the word names an owner at all. Printing
    // "owner_in_word=0x1" for a zero word invented an owner out of the unlocked value, which is the opposite
    // of what a reader needs when the whole question is whether the word was owned.
    if lock.word == 0 {
        println!(
            "CORE-LOCK-WORD lock={:#x} word=0x0 (UNLOCKED: no owner is named, so nothing excluded another thread)",
            lock.lock
        );
    } else {
        println!(
            "CORE-LOCK-WORD lock={:#x} word={:#x} owner_in_word={:#x}",
            lock.lock,
            lock.word,
            lock.word | 1
        );
    }
    println!(
        "CORE-LOCK-LAYOUT note: the lock/self/current values are read from the slow caller's frame at the offsets this build's prologue stores them to; verify with x/i around return_pc if the frame is suspect"
    );
    if !lock.tokens.is_empty() {
        let mut sorted = lock.tokens.clone();
        sorted.sort();
        for (tid, t) in &sorted {
            println!("CORE-LOCK-TOKEN tid={tid} slot3={t:#x}");
        }
        let zeros: Vec<&String> = lock
            .tokens
            .iter()
            .filter(|(_, t)| *t == 0)
            .map(|(tid, _)| tid)
            .collect();
        if !zeros.is_empty() {
            println!(
                "CORE-LOCK-TOKEN-ZERO tids={zeros:?} (a thread whose self token is 0 cannot exclude anyone on an unowned unfair lock and clears whatever word its unlock writes; decide whether these are guest pthreads before blaming them)"
            );
        }
        let dups = duplicate_tokens(&lock.tokens);
        if dups.is_empty() {
            println!(
                "CORE-LOCK-TOKENS-UNIQUE ({} live threads, no shared non-zero self token at this instant)",
                lock.tokens.len()
            );
        } else {
            println!(
                "CORE-LOCK-TOKENS-DUPLICATE tokens={dups:?} (two live threads share a self token: an unfair lock held by one reads as held by the other)"
            );
        }
    }
    if lock.slow_ret_pc != 0 {
        println!(
            "CORE-LOCK-NEXT the return PC on this frame is the caller of the slow path; symbolize it against the image with: dwdiag symbolize --binary <image> --addr {:#x}",
            lock.slow_ret_pc
        );
    }
    println!(
        "CORE-LOCK-HISTORY unavailable: a core is one instant, so this command does not say whether the owner re-entered or the word was left by an earlier holder, and it will not guess"
    );
    if args.json {
        let toks: Vec<String> = lock
            .tokens
            .iter()
            .map(|(tid, t)| format!("{{\"tid\":\"{tid}\",\"slot3\":\"{:#x}\"}}", t))
            .collect();
        println!(
            "CORE-LOCK-JSON {{\"core\":\"{}\",\"trap_tid\":\"{}\",\"trap_pc\":\"{:#x}\",\"abort_arg\":\"{:#x}\",\"lock\":\"{:#x}\",\"word\":\"{:#x}\",\"saved_self\":\"{:#x}\",\"saved_current\":\"{:#x}\",\"slow_ret_pc\":\"{:#x}\",\"tokens\":[{}]}}",
            core.display(),
            lock.trap_tid,
            lock.trap_pc,
            lock.trap_arg,
            lock.lock,
            lock.word,
            lock.self_token,
            lock.current,
            lock.slow_ret_pc,
            toks.join(",")
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod core_lock_tests {
    use super::*;

    // Captured from a real core (the T4 linker's SIGILL), so the parser is tested against what gdb actually prints.
    const CAPTURED: &str = "@trap tid=1 pc=0x7b6fe7af5237 rdi=0xa03 rbp=0x7b6fe4df8d30 gs=0x7b6fe4dfa0e0\n@tok tid=1 slot3=0xa03\n@slow tid=1 rbp=0x7b6fe4df8dd0 retpc=0x7b6fe7aef804\n@slowargs lock=0x7b6fd80a8e00 self=0xa03 current=0xa03\n@word lock=0x7b6fd80a8e00 word=0xa03\n@alltid tid=5 slot3=0x903\n@alltid tid=4 slot3=0x1303\n@alltid tid=3 slot3=0x0\n@alltid tid=2 slot3=0x103\n@alltid tid=1 slot3=0xa03\n";

    #[test]
    fn parses_the_lock_the_self_and_the_word_from_captured_output() {
        let l = parse_core_lock(CAPTURED);
        assert_eq!(l.lock, 0x7b6fd80a8e00);
        assert_eq!(l.self_token, 0xa03);
        assert_eq!(l.current, 0xa03);
        assert_eq!(l.word, 0xa03);
        assert_eq!(l.trap_arg, 0xa03);
        assert_eq!(l.tokens.len(), 5);
        assert_eq!(l.slow_ret_pc, 0x7b6fe7aef804);
    }

    #[test]
    fn a_zero_token_is_not_a_duplicate_and_no_live_token_is_shared_here() {
        let l = parse_core_lock(CAPTURED);
        assert!(duplicate_tokens(&l.tokens).is_empty());
        let with_duplicate = vec![("1".to_string(), 0xa03), ("2".to_string(), 0xa03)];
        assert_eq!(duplicate_tokens(&with_duplicate), vec![0xa03]);
        let with_zeros = vec![("1".to_string(), 0), ("2".to_string(), 0)];
        assert!(duplicate_tokens(&with_zeros).is_empty());
    }
}

#[cfg(test)]
mod evidence_manifest_tests {
    use super::*;

    /// A line the first registered instrument matches, so "evidence exists" is decided by the census's own registry
    /// and not by a second hand-written tag list.
    const INSTRUMENT_LINE: &str = "[ulock-wait-park] obj=0x1000 op=wait owner_tid=2 waiter_tid=3\n";

    /// Registered capture fixtures; ambient files must never enter their slices,
    /// regardless of a coinciding timestamp.
    fn fixture(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("dwdiag-evidence-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let state = root.join("state");
        let prefix = root.join("prefix");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(prefix.join("private/var/tmp")).unwrap();
        (state, prefix)
    }

    #[test]
    fn early_failure_data_survives_summary_noise_without_overlap_or_foreign_sources() {
        let (state, prefix) = fixture("early-failure-excerpt");
        let capture = state.join("producer.log");
        let mismatch = "arbitrary producer mismatch: expected <α: q|beta>, actual <δ: dynamic-value>";
        let assertion = "Assertion failed: (payload == arbitrary_token), function check, file /input.c, line 19.";
        let bind_error = "Binding the unix socket: File name too long";
        let prefix_state_error = "Cannot remove prefix state entry old.sock: No such device or address";
        let mut text = format!("setup one\nsetup two\n{mismatch}\n{assertion}\n{bind_error}\n{prefix_state_error}\nabort detail\n");
        for index in 0..120 { text.push_str(&format!("CTest summary row {index}\n")); }
        fs::write(&capture, text).unwrap();
        manifest(&state, &prefix, &[(&capture, 0)]);
        job_log(&state, "wrapper completed\n");
        let foreign = prefix.join("private/var/tmp/unowned.log");
        fs::write(&foreign, "foreign.c:1: error: unrelated failure\n").unwrap();

        let report = select_evidence(&state);
        let source = report.sources.iter().find(|source| source.path == capture).unwrap();
        assert!(!source.tail.iter().any(|line|
            [mismatch, assertion, bind_error, prefix_state_error].contains(&line.as_str())));
        assert_eq!(source.failure.matches, 4);
        assert!(source.failure.rows.contains(&(3, mismatch.to_string())));
        assert!(source.failure.rows.contains(&(4, assertion.to_string())));
        assert!(source.failure.rows.contains(&(5, bind_error.to_string())));
        assert!(source.failure.rows.contains(&(6, prefix_state_error.to_string())));
        assert!(source.failure.rows.windows(2).all(|pair| pair[0].0 < pair[1].0));
        let output = failure_excerpt_output(&source.failure, 24, 24);
        assert_eq!(output.iter().filter(|line| line.contains(mismatch)).count(), 1);
        assert_eq!(output.iter().filter(|line| line.contains(assertion)).count(), 1);
        assert_eq!(output.iter().filter(|line| line.contains(bind_error)).count(), 1);
        assert_eq!(output.iter().filter(|line| line.contains(prefix_state_error)).count(), 1);
        assert!(report.sources.iter().all(|source| source.failure.rows.iter()
            .all(|(_, line)| !line.contains("unrelated failure"))));
    }

    #[test]
    fn failure_excerpt_does_not_repeat_lines_already_shown_in_the_tail() {
        let excerpt = failure_excerpt("before\ndyld: Library not loaded: /arbitrary/image\n  Referenced from: /arbitrary/program\n  Reason: image not found\nafter\n");
        assert_eq!(excerpt.matches, 1);
        assert!(failure_excerpt_output(&excerpt, 5, 24).is_empty());
        let earlier = failure_excerpt_output(&excerpt, 2, 24);
        assert_eq!(earlier.len(), 3);
        assert!(earlier.iter().any(|line| line.contains("/arbitrary/image")));
        assert!(!earlier.iter().any(|line| line.contains("Reason: image not found")));
    }

    #[test]
    fn failure_excerpt_is_bounded_and_keeps_unknown_error_level_traces_unclassified() {
        let traces = "[1793085587.252126](ring, Error) [NOTICE] shared-memory transport ACTIVE\n\
            [1793085587.254192](process-control-complete, Error) status=0\n\
            an unfamiliar producer stopped without a known diagnostic\n";
        let unknown = failure_excerpt(traces);
        assert_eq!(unknown.matches, 0);
        assert!(unknown.rows.is_empty());

        let mut errors = String::new();
        for index in 0..100 {
            errors.push_str(&format!("input.c:{index}: error: {}\n", "α".repeat(3000)));
        }
        let bounded = failure_excerpt(&errors);
        assert_eq!(bounded.matches, 100);
        assert!(bounded.omitted);
        assert!(bounded.rows.len() <= 24);
        assert!(bounded.rows.iter().map(|(_, line)| line.len()).sum::<usize>() <= 16 * 1024);
    }

    fn manifest(state: &Path, prefix: &Path, entries: &[(&Path, u64)]) {
        let mut text = String::from("version=1\nscope=explicit\nruntime-root=/image\nstart=946684800\nend=946771200\n");
        text.push_str(&format!("prefix={}\n", prefix.display()));
        for (p, off) in entries {
            text.push_str(&format!("file={} {off}\n", p.display()));
            text.push_str(&format!("source={}\t{}\n", p.display(),
                prefix.join("registered").join(p.file_name().unwrap()).display()));
        }
        fs::write(state.join("evidence-manifest"), text).unwrap();
    }

    fn job_log(state: &Path, text: &str) {
        fs::write(state.join("log"), text).unwrap();
    }

    #[test]
    fn parses_the_prefix_start_end_and_every_registered_file_with_its_offset() {
        let m = parse_evidence_manifest(
            "version=1\nstart=1791645300\nend=1791649999\nprefix=/p/prefix\nfile=/tmp/darling-boot-032645-2125225.log 192767\nfile=/p/prefix/private/var/log/dserver.log 0\n",
        );
        assert_eq!(m.prefix, Some(PathBuf::from("/p/prefix")));
        assert_eq!(m.start, Some(1791645300));
        assert_eq!(m.end, Some(1791649999));
        assert_eq!(m.files.len(), 2);
        assert_eq!(m.files[0].1, 192767);
        assert_eq!(m.files[0].0, PathBuf::from("/tmp/darling-boot-032645-2125225.log"));
        assert_eq!(m.files[1].1, 0, "a file that did not exist yet is registered at offset 0");
    }

    #[test]
    fn a_path_with_spaces_survives_because_the_offset_is_the_last_field() {
        let m = parse_evidence_manifest("file=/tmp/a b/c.log 12\n");
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].0, PathBuf::from("/tmp/a b/c.log"));
        assert_eq!(m.files[0].1, 12);
    }

    #[test]
    fn a_missing_manifest_is_none_rather_than_an_empty_one() {
        let dir = std::env::temp_dir().join(format!("dwdiag-manifest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(evidence_manifest(&dir).is_none());
        fs::write(dir.join("evidence-manifest"), "version=1\n").unwrap();
        assert!(evidence_manifest(&dir).is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn measured_is_the_only_state_where_an_empty_window_is_a_measurement() {
        let (state, prefix) = fixture("measured-zero");
        let reg = state.join("reg.log");
        fs::write(&reg, "").unwrap();
        manifest(&state, &prefix, &[(&reg, 0)]);
        job_log(&state, "");
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Measured);
        assert!(r.reasons.is_empty(), "a complete window needs no excuse: {:?}", r.reasons);
        assert_eq!(r.rows_bytes, 0, "an empty window that WAS read is the only zero that may be printed");
        assert!(r.state.zero_is_measured());
    }

    #[test]
    fn a_window_with_rows_is_measured_and_contributes_them() {
        let (state, prefix) = fixture("measured-rows");
        let reg = state.join("reg.log");
        fs::write(&reg, format!("old\n{INSTRUMENT_LINE}")).unwrap();
        manifest(&state, &prefix, &[(&reg, 0)]);
        job_log(&state, "");
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Measured);
        assert!(r.rows_bytes > 0);
        assert_eq!(r.state.as_str(), "measured");
    }

    #[test]
    fn only_the_bytes_after_the_recorded_offset_are_this_runs() {
        let (state, prefix) = fixture("offset-slice");
        let reg = state.join("reg.log");
        fs::write(&reg, format!("another run's line\n{INSTRUMENT_LINE}")).unwrap();
        let offset = "another run's line\n".len() as u64;
        manifest(&state, &prefix, &[(&reg, offset)]);
        job_log(&state, "");
        let slice = fs::read_to_string(select_evidence(&state).instruments_log).unwrap();
        assert_eq!(slice, INSTRUMENT_LINE, "the pre-run bytes must not reach the census");
    }

    #[test]
    fn a_truncated_registered_log_is_partial_and_contributes_nothing() {
        let (state, prefix) = fixture("truncated");
        let reg = state.join("reg.log");
        fs::write(&reg, "short\n").unwrap();
        manifest(&state, &prefix, &[(&reg, 500)]);
        job_log(&state, "");
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Partial, "a rotation must not read from zero");
        assert_eq!(r.rows_bytes, 0);
        assert!(!r.state.zero_is_measured(), "a truncated window must never be a measured zero");
        assert!(r.reasons.iter().any(|x| x.contains("truncated or rotated")), "{:?}", r.reasons);
    }

    #[test]
    fn a_missing_registered_log_is_unavailable() {
        let (state, prefix) = fixture("missing");
        let gone = state.join("gone.log");
        manifest(&state, &prefix, &[(&gone, 0)]);
        job_log(&state, "");
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Unavailable);
        assert_eq!(r.rows_bytes, 0);
        assert!(!r.state.zero_is_measured());
    }

    #[test]
    fn an_unreadable_registered_log_is_unavailable() {
        let (state, prefix) = fixture("unreadable");
        let dir = state.join("not-a-file.log");
        fs::create_dir(&dir).unwrap();
        manifest(&state, &prefix, &[(&dir, 0)]);
        job_log(&state, "");
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Unavailable, "an unreadable log is not an empty one");
        assert!(!r.state.zero_is_measured());
    }

    #[test]
    fn unregistered_foreign_logs_do_not_change_the_registered_measurement() {
        let (state, prefix) = fixture("foreign");
        let reg = state.join("reg.log");
        fs::write(&reg, "").unwrap();
        manifest(&state, &prefix, &[(&reg, 0)]);
        job_log(&state, "");
        // Another source is not authority merely because it is under this prefix.
        let foreign = prefix.join("private/var/tmp/other-run.log");
        fs::write(&foreign, INSTRUMENT_LINE).unwrap();
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Measured);
        assert_eq!(r.rows_bytes, 0, "the other run's rows must not contribute");
        assert!(r.state.zero_is_measured());
        assert!(!r.sources.iter().any(|source| source.path == foreign));
    }

    #[test]
    fn even_an_in_window_unregistered_log_cannot_contribute() {
        let (state, prefix) = fixture("in-window");
        let reg = state.join("reg.log");
        fs::write(&reg, "").unwrap();
        manifest(&state, &prefix, &[(&reg, 0)]);
        job_log(&state, "");
        let fresh = prefix.join("private/var/tmp/fresh.log");
        fs::write(&fresh, INSTRUMENT_LINE).unwrap();
        let inside = std::time::UNIX_EPOCH + std::time::Duration::from_secs(946684800 + 60);
        fs::File::options()
            .write(true)
            .open(&fresh)
            .unwrap()
            .set_modified(inside)
            .unwrap();
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Measured);
        assert_eq!(r.rows_bytes, 0);
        assert!(!r.sources.iter().any(|source| source.path == fresh));
    }

    #[test]
    fn no_manifest_is_unscoped_and_reads_nothing() {
        let (state, _prefix) = fixture("unscoped");
        job_log(&state, INSTRUMENT_LINE);
        let r = select_evidence(&state);
        assert_eq!(r.state, EvidenceState::Unscoped);
        assert_eq!(r.rows_bytes, 0, "without a manifest nothing is guessed");
        assert_eq!(fs::read_to_string(&r.instruments_log).unwrap(), "");
    }

    #[test]
    fn a_missing_final_boundary_cannot_admit_a_live_original_log() {
        let (state, prefix) = fixture("unfinalized");
        let live = state.join("compile.log");
        fs::write(&live, "clang: error: this is not finalized\n").unwrap();
        fs::write(state.join("evidence-manifest"), format!(
            "scope=explicit\nprefix={}\nruntime-root=/image\nfile={} 0\n", prefix.display(), live.display())).unwrap();
        job_log(&state, "wrapper\n");
        let report = select_evidence(&state);
        assert_eq!(report.state, EvidenceState::Unavailable);
        assert_eq!(report.rows_bytes, 0);
        assert!(report.sources.is_empty());
    }

    #[test]
    fn unavailable_registration_is_not_hidden_by_other_readable_logs() {
        let (state, prefix) = fixture("boundary-gap");
        let captured = state.join("compile.log");
        fs::write(&captured, "clang: error: missing declaration\n").unwrap();
        manifest(&state, &prefix, &[(&captured, 0)]);
        let path = state.join("evidence-manifest");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str("unavailable=/owned/guest/compile.harness missing source boundary\n");
        fs::write(path, text).unwrap();
        job_log(&state, "wrapper\n");
        let report = select_evidence(&state);
        assert_eq!(report.state, EvidenceState::Unavailable);
        assert!(!report.state.zero_is_measured());
        assert!(report.sources.iter().any(|source| source.tail.iter()
            .any(|line| line == "clang: error: missing declaration")));
    }

    #[test]
    fn persisted_scope_and_unavailable_status_beat_command_text() {
        let (state, prefix) = fixture("scope");
        manifest(&state, &prefix, &[]);
        fs::write(state.join("command"), "DPREFIX=/unrelated/runtime --prefix /another").unwrap();
        let args = JobArgs { state_dir: state.clone(), prefix: None, json: false, lines: 24,
            step_timeout_seconds: 60, pids: Vec::new() };
        assert_eq!(job_prefix(&args, &state), Some(prefix));
        let path = state.join("evidence-manifest");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str("prefix-unavailable=ambiguous argv\nruntime-root-unavailable=ambiguous argv\n");
        fs::write(path, text).unwrap();
        assert_eq!(job_prefix(&args, &state), None);
        assert_eq!(evidence_manifest(&state).unwrap().scoped_runtime(), None);
    }

    #[test]
    fn only_a_finalized_registered_server_copy_supplies_server_history() {
        let mut manifest = parse_evidence_manifest(
            "scope=explicit\nprefix=/owned/guest\nruntime-root=/image\nend=1\nfile=/job/server-copy.log 0\nsource=/job/server-copy.log\t/owned/guest/private/var/log/dserver.log\n");
        assert_eq!(manifest.captured_server_log(), Some(Path::new("/job/server-copy.log")));
        manifest.end = None;
        assert_eq!(manifest.captured_server_log(), None);
        manifest.end = Some(1);
        manifest.prefix_unavailable = Some("ambiguous argv".to_string());
        assert_eq!(manifest.captured_server_log(), None);
    }

    #[test]
    fn a_finalized_manifest_without_a_capture_mapping_cannot_read_the_original() {
        let (state, prefix) = fixture("missing-copy-proof");
        let original = prefix.join("compile.log");
        fs::write(&original, "foreign compiler error\n").unwrap();
        fs::write(state.join("evidence-manifest"), format!(
            "scope=explicit\nend=1\nprefix={}\nruntime-root=/image\nfile={} 0\n",
            prefix.display(), original.display())).unwrap();
        job_log(&state, "");
        let report = select_evidence(&state);
        assert_eq!(report.state, EvidenceState::Unavailable);
        assert_eq!(report.rows_bytes, 0);
        assert!(report.sources.iter().all(|source| source.tail.is_empty()));
    }

    #[test]
    fn captured_core_selection_requires_a_registered_finite_copy_and_rejects_ambiguity() {
        let mut manifest = parse_evidence_manifest(
            "scope=explicit\nruntime-root=/image\nend=1\nfile=/job/core-copy 0\nsource=/job/core-copy\t/owned/core.123\n");
        assert_eq!(manifest.captured_core(), Some(Path::new("/job/core-copy")));
        manifest.sources.push((PathBuf::from("/job/second-core"), PathBuf::from("/owned/core.456")));
        manifest.files.push((PathBuf::from("/job/second-core"), 0));
        assert_eq!(manifest.captured_core(), None);
    }

    #[test]
    fn the_five_states_are_pairwise_distinct() {
        let all = [
            EvidenceState::Measured,
            EvidenceState::Partial,
            EvidenceState::Unavailable,
            EvidenceState::NoEvidence,
            EvidenceState::Unscoped,
        ];
        let mut names: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 5, "each evidence state must print its own name");
        assert_ne!(EvidenceState::Partial.as_str(), EvidenceState::Unavailable.as_str());
        assert_ne!(EvidenceState::Unavailable.as_str(), EvidenceState::NoEvidence.as_str());
        assert!(EvidenceState::Partial.has_census(), "partial keeps a labelled census");
        assert!(!EvidenceState::Unavailable.has_census());
    }
}

#[cfg(test)]
mod guest_fault_tests {
    use super::*;

    // The exact shape the deployed handler writes, copied from a real run log (the padding before the path is the
    // kernel's, not a typo): `[sigexc-fault-map <one /proc/self/maps line>]` immediately above `[sigexc-fatal ...]`.
    const FAULT_MAP: &str = "[sigexc-fault-map 76d22cce4000-76d22cddf000 r-xp 00001000 fc:00 5509130                    /opt/darling/usr/lib/system/libsystem_c.dylib]";
    const FATAL_DEPLOYED: &str = "[sigexc-fatal sig=4 code=2 addr=0x76D22CDD547F pid=794192 tid=794192]";
    const FATAL_RIP: &str = "[sigexc-fatal sig=11 code=1 addr=0x0 rip=0x100003a20 rsp=0x7ffee000 rbp=0x7ffee010 pid=1 tid=1]";

    fn log(fatal: &str) -> String {
        format!("[openat-entry sp=1]\n{FAULT_MAP}\n{fatal}\n[sigexc-default sig=4 tid=794192]\n")
    }

    #[test]
    fn fault_map_line_parses_into_a_mapping() {
        let line = FAULT_MAP.trim_start_matches("[sigexc-fault-map ").trim_end_matches(']');
        let (lo, hi, off, path) = parse_maps_line(line).expect("a real maps line must parse");
        assert_eq!(lo, 0x76d22cce4000);
        assert_eq!(hi, 0x76d22cddf000);
        assert_eq!(off, 0x1000);
        assert!(path.ends_with("libsystem_c.dylib"), "path kept whole: {path}");
    }

    #[test]
    fn an_anonymous_mapping_is_reported_not_dropped() {
        let (lo, hi, off, path) = parse_maps_line("7f0000000000-7f0000001000 rw-p 00000000 00:00 0").unwrap();
        assert_eq!((lo, hi, off), (0x7f0000000000, 0x7f0000001000, 0));
        assert_eq!(path, "", "no path is an empty path, not a parse failure");
        assert!(!mapping_is_file(&path));
    }

    #[test]
    fn a_kernel_pseudo_entry_is_a_name_and_not_a_path() {
        // The inode is NOT the path, and `[stack]` is not a file: both were reported as the image by the old
        // last-field parse, which then sent llvm-nm after a file that cannot exist.
        let (_, _, _, path) = parse_maps_line("7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]").unwrap();
        assert_eq!(path, "[stack]");
        assert!(!mapping_is_file(&path), "a pseudo-entry has no symbols to load");
        assert!(mapping_is_file("/usr/lib/libsystem_c.dylib"));
    }

    #[test]
    fn a_path_with_spaces_stays_one_path() {
        let (_, _, _, path) = parse_maps_line("1000-2000 r-xp 00000000 00:00 9 /tmp/a dir/lib x.dylib").unwrap();
        assert_eq!(path, "/tmp/a dir/lib x.dylib");
    }

    #[test]
    fn the_newest_attributable_fault_wins_over_a_later_teardown_signal() {
        // The shape of a real log: the client dies of SIGILL, then the harness's teardown raises SIGTERM (whose
        // si_addr is the sender's pid). Selecting the last fatal line blindly picked the teardown and reported "no
        // symbolizable fault" on a log that names the image two lines above.
        let text = format!(
            "{FAULT_MAP}\n{FATAL_DEPLOYED}\n[sigexc-default sig=4 tid=1]\n[sigexc-fatal sig=15 code=0 addr=0x3E8000C1E6E pid=2 tid=2]\n"
        );
        let mark = last_fault_mark(&text).expect("the SIGILL is still attributable");
        assert_eq!(mark.sig, 4);
        assert_eq!(mark.ip, 0x76D22CDD547F);
        assert!(log_has_symbolizable_fault(&text));
    }

    #[test]
    fn deployed_mark_uses_the_fault_address_as_the_instruction_pointer() {
        let mark = last_fault_mark(&log(FATAL_DEPLOYED)).expect("SIGILL addr= is an instruction pointer");
        assert_eq!(mark.sig, 4);
        assert_eq!(mark.ip, 0x76D22CDD547F);
        assert!(mark.ip_from_addr, "the provenance must be visible, not assumed");
    }

    #[test]
    fn rip_mark_still_wins_when_the_handler_prints_registers() {
        let mark = last_fault_mark(&log(FATAL_RIP)).unwrap();
        assert_eq!(mark.ip, 0x100003a20);
        assert!(!mark.ip_from_addr);
    }

    #[test]
    fn an_async_signal_address_is_not_dressed_up_as_an_instruction_pointer() {
        // SIGABRT raised by tkill: si_addr is the SENDER's pid (measured: 0x3E8000B173F), so there is no instruction
        // to symbolize and saying otherwise would invent a symbol.
        let text = log("[sigexc-fatal sig=6 code=-6 addr=0x3E8000B173F pid=726847 tid=726847]");
        assert!(last_fault_mark(&text).is_none());
        assert!(!log_has_symbolizable_fault(&text));
    }

    #[test]
    fn mappings_come_from_the_fault_map_mark_when_there_is_no_dump() {
        let maps = fault_mappings(&log(FATAL_DEPLOYED));
        assert_eq!(maps.len(), 1);
        let (lo, file_off, path) = find_mapping(&maps, 0x76D22CDD547F).expect("the fault is inside the named mapping");
        assert_eq!(lo, 0x76d22cce4000);
        assert_eq!(file_off, 0x1000);
        // The offset the symbolizer reads at: what the deployed handler's one line is worth.
        assert_eq!(file_off + (0x76D22CDD547F - lo), 0xF247F);
        assert!(path.ends_with("libsystem_c.dylib"));
    }

    #[test]
    fn a_maps_dump_is_preferred_and_does_not_swallow_the_fault_map_line() {
        let text = format!(
            "[sigexc-maps-begin]\n1000-2000 r-xp 00000000 00:00 0 /tmp/one\n3000-4000 rw-p 00001000 00:00 0 /tmp/two\n[sigexc-maps-end]\n{FAULT_MAP}\n{FATAL_DEPLOYED}\n"
        );
        let maps = fault_mappings(&text);
        assert_eq!(maps.len(), 3, "dump lines plus the fault-map line: {maps:?}");
        assert_eq!(find_mapping(&maps, 0x1800).unwrap().2, "/tmp/one");
        assert_eq!(find_mapping(&maps, 0x3800).unwrap().2, "/tmp/two");
        assert_eq!(find_mapping(&maps, 0x76D22CDD547F).unwrap().2.ends_with("libsystem_c.dylib"), true);
    }

    /// A minimal Mach-O written to a temp file: enough for the segment walk, which is all the conversion needs.
    fn write_macho(path: &std::path::Path, fat_slice_base: Option<u64>, vmaddr: u64, fileoff: u64, filesize: u64) {
        let mut b: Vec<u8> = Vec::new();
        if let Some(base) = fat_slice_base {
            b.extend_from_slice(&0xcafebabeu32.to_be_bytes()); // fat, big-endian
            b.extend_from_slice(&1u32.to_be_bytes()); // one arch
            b.extend_from_slice(&0x01000007u32.to_be_bytes()); // CPU_TYPE_X86_64
            b.extend_from_slice(&3u32.to_be_bytes()); // cpusubtype
            b.extend_from_slice(&(base as u32).to_be_bytes()); // offset
            b.extend_from_slice(&0x1000u32.to_be_bytes()); // size
            b.extend_from_slice(&12u32.to_be_bytes()); // align
        }
        if let Some(base) = fat_slice_base {
            while (b.len() as u64) < base {
                b.push(0);
            }
        }
        b.extend_from_slice(&0xfeedfacfu32.to_le_bytes()); // MH_MAGIC_64
        b.extend_from_slice(&0x01000007u32.to_le_bytes()); // cputype
        b.extend_from_slice(&3u32.to_le_bytes()); // cpusubtype
        b.extend_from_slice(&6u32.to_le_bytes()); // filetype MH_DYLIB -- the header has EIGHT fields; omitting this
                                                  // one shifted ncmds into the wrong slot and the walk found no
                                                  // segments at all (MEASURED: both fixture tests read None)
        b.extend_from_slice(&2u32.to_le_bytes()); // ncmds: LC_SEGMENT_64 + LC_END
        b.extend_from_slice(&0u32.to_le_bytes()); // sizeofcmds (walked by cmdsize, not this)
        b.extend_from_slice(&0u32.to_le_bytes()); // flags
        b.extend_from_slice(&0u32.to_le_bytes()); // reserved
        // LC_SEGMENT_64: cmd, cmdsize, segname[16], vmaddr, vmsize, fileoff, filesize
        b.extend_from_slice(&0x19u32.to_le_bytes());
        b.extend_from_slice(&72u32.to_le_bytes());
        let mut name = [0u8; 16];
        name[..6].copy_from_slice(b"__TEXT");
        b.extend_from_slice(&name);
        b.extend_from_slice(&vmaddr.to_le_bytes());
        b.extend_from_slice(&filesize.to_le_bytes());
        b.extend_from_slice(&fileoff.to_le_bytes());
        b.extend_from_slice(&filesize.to_le_bytes());
        b.extend_from_slice(&[0u8; 16]); // maxprot/initprot/nsects/flags
        while b.len() < 0x4000 {
            b.push(0x90);
        }
        fs::write(path, &b).unwrap();
    }

    #[test]
    fn a_thin_image_has_one_address_for_both() {
        let p = std::env::temp_dir().join(format!("dwdiag-thin-{}.macho", std::process::id()));
        write_macho(&p, None, 0, 0, 0x2000);
        assert_eq!(MachoSegments::load(p.to_str().unwrap()).unwrap().image_addr( 0x1800), Some(0x1800));
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn a_universal_image_reports_the_image_address_not_the_file_offset() {
        // MEASURED on the deployed libsystem_c.dylib: fat, x86_64 slice at file 0x1000, __TEXT vmaddr 0 at slice file
        // 0. A fault at file offset 0xf247f is image address 0xf147f, and resolving with the file offset named a
        // symbol 0x1000 bytes too high.
        let p = std::env::temp_dir().join(format!("dwdiag-fat-{}.macho", std::process::id()));
        write_macho(&p, Some(0x1000), 0, 0, 0x2000);
        assert_eq!(MachoSegments::load(p.to_str().unwrap()).unwrap().image_addr( 0x247f), Some(0x147f));
        assert_eq!(MachoSegments::load(p.to_str().unwrap()).unwrap().image_addr( 0x1800), Some(0x800));
        // Below the slice base there is no segment: None, so the caller falls back and says so.
        assert_eq!(MachoSegments::load(p.to_str().unwrap()).unwrap().image_addr( 0x400), None);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn a_non_macho_is_not_guessed_at() {
        let p = std::env::temp_dir().join(format!("dwdiag-notmacho-{}.bin", std::process::id()));
        fs::write(&p, b"#!/bin/sh\necho hello\n").unwrap();
        assert!(MachoSegments::load(p.to_str().unwrap()).is_none(), "a non-Mach-O must not be guessed at");
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn a_deliberate_trap_is_named_as_one() {
        assert!(decode_trap(&[0x0f, 0x0b, 0x66, 0x66]).unwrap().contains("ud2"));
        assert!(decode_trap(&[0xcc]).unwrap().contains("int3"));
        assert!(decode_trap(&[0xf4]).unwrap().contains("hlt"));
        // A real instruction is not a trap: a load must not be reported as an abort path.
        assert!(decode_trap(&[0x48, 0x8b, 0x00]).is_none());
    }

    #[test]
    fn fault_bytes_reads_at_the_offset_the_mapping_names() {
        let path = std::env::temp_dir().join(format!("dwdiag-insn-{}.bin", std::process::id()));
        let mut body = vec![0u8; 0x40];
        body[0x2f] = 0x0f;
        body[0x30] = 0x0b;
        fs::write(&path, &body).unwrap();
        let got = fault_bytes(path.to_str().unwrap(), 0x2f).expect("readable");
        assert_eq!(&got[..2], &[0x0f, 0x0b]);
        assert_eq!(decode_trap(&got).unwrap().contains("ud2"), true);
        // Out of range is None, not a silent empty buffer.
        assert!(fault_bytes(path.to_str().unwrap(), 0x1000).map(|b| b.is_empty()).unwrap_or(true));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_log_is_selectable_exactly_when_it_can_be_attributed() {
        assert!(log_has_symbolizable_fault(&log(FATAL_DEPLOYED)));
        assert!(log_has_symbolizable_fault(&format!("{FAULT_MAP}\n{FATAL_RIP}\n")));
        // A fatal mark with no mapping source at all: nothing to name, so not selectable.
        assert!(!log_has_symbolizable_fault(&format!("{FATAL_RIP}\n")));
        assert!(!log_has_symbolizable_fault("no fault here\n"));
    }
}

#[cfg(test)]
mod installed_runtime_contract_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn workload_completion_cannot_override_harness_or_shutdown_failure() {
        let mut output = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"VERDICT: PASS\n".to_vec(), stderr: Vec::new(),
        };
        assert!(completed_harness(&output));
        output.status = std::process::ExitStatus::from_raw(1 << 8);
        assert!(!completed_harness(&output));
        output.status = std::process::ExitStatus::from_raw(0);
        output.stdout = b"RING_MACH_TEST mode=basic pass=1\n".to_vec();
        assert!(!completed_harness(&output));
        output.stdout = b"VERDICT: PASS\nVERDICT: FAIL\n".to_vec();
        assert!(!completed_harness(&output));
    }

    #[test]
    fn test_asset_staging_cannot_install_system_files_or_follow_guest_symlinks() {
        let root = std::env::temp_dir().join(format!("dwdiag-assets-{}", std::process::id()));
        let prefix = root.join("guest");
        let source = root.join("fixture");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, b"fixture input").unwrap();
        let asset = prefix.join("private/var/tmp/fixture");
        stage_test_asset(&source, &asset, &prefix).unwrap();
        assert_eq!(fs::read(&asset).unwrap(), b"fixture input");
        assert!(stage_test_asset(&source, &prefix.join("usr/lib/dyld"), &prefix).is_err());
        let external = root.join("external");
        fs::create_dir(&external).unwrap();
        std::os::unix::fs::symlink(&external, prefix.join("private/var/tmp/redirect")).unwrap();
        assert!(stage_test_asset(&source, &prefix.join("private/var/tmp/redirect/fixture"), &prefix).is_err());
        assert!(!external.join("fixture").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
