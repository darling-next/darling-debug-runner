#![cfg(target_os = "linux")]

use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::prctl::set_child_subreaper;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use std::fs::{self, File};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Experiment {
    runner: Child,
    target: Option<(i32, File)>,
    directory: PathBuf,
}

impl Drop for Experiment {
    fn drop(&mut self) {
        let _ = self.runner.kill();
        let _ = self.runner.wait();
        if let Some((pid, fd)) = self.target.take() {
            // SAFETY: the owned pidfd names this fixture even after PID reuse.
            unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    nix::libc::SIGKILL,
                    std::ptr::null::<nix::libc::siginfo_t>(),
                    0,
                );
            }
            let _ = waitpid(Pid::from_raw(pid), None);
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn cancellation_waits_for_owner_cleanup_even_with_long_poll_interval() {
    set_child_subreaper(true).unwrap();
    let directory =
        std::env::temp_dir().join(format!("darling-cancel-test-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let ready = directory.join("ready");
    let binary = std::env::var_os("DARLING_DEBUG_RUNNER_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_darling-debug-runner").into());
    let runner = Command::new(binary)
        .args(["run", "--name", "cancel", "--poll-seconds", "60", "--timeout-seconds", "120"])
        .arg("--bundle-root")
        .arg(&directory)
        .args(["--terminate-command", "kill -TERM \"$TARGET_PID\"", "--", "python3", "-c"])
        .arg("import os,signal,sys,time\ndef stop(signum,frame):\n time.sleep(0.25)\n sys.exit(23)\nsignal.signal(signal.SIGTERM,stop)\nopen(sys.argv[1],'w').write(str(os.getpid()))\ntime.sleep(120)\n")
        .arg(&ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut experiment = Experiment {
        runner,
        target: None,
        directory,
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Ok(text) = fs::read_to_string(&ready)
            && let Ok(pid) = text.parse::<i32>()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "target did not become ready");
        assert!(
            experiment.runner.try_wait().unwrap().is_none(),
            "runner exited before readiness"
        );
        thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: pid comes from the live child fixture; pidfd_open returns an owned fd.
    let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) as i32 };
    assert!(fd >= 0);
    experiment.target = Some((pid, unsafe { File::from_raw_fd(fd) }));
    nix::sys::signal::kill(
        Pid::from_raw(experiment.runner.id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = experiment.runner.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "cancellation waited for the 60-second polling interval"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        status.code(),
        Some(1),
        "runner must report cancellation, not die from SIGINT"
    );
    let mut target = [PollFd::new(
        experiment.target.as_ref().unwrap().1.as_fd(),
        PollFlags::POLLIN,
    )];
    assert_eq!(
        poll(&mut target, 0u8).unwrap(),
        1,
        "runner returned before owner cleanup terminated its child"
    );
    assert!(target[0].revents().unwrap().contains(PollFlags::POLLIN));
}
