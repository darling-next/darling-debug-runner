//! Read finalized diagnostic payloads without requiring callers to restore archives.
use std::borrow::Cow;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

pub(super) fn resolve(path: &Path) -> Cow<'_, Path> {
    if path.extension().is_some_and(|ext| ext == "zst") || path.exists() {
        return Cow::Borrowed(path);
    }
    let mut compressed = path.as_os_str().to_os_string();
    compressed.push(".zst");
    let compressed = PathBuf::from(compressed);
    if compressed.is_file() { Cow::Owned(compressed) } else { Cow::Borrowed(path) }
}

fn decoder(path: &Path) -> Command {
    let mut command = Command::new("zstd");
    command.args(["-q", "-d", "-c", "--"]).arg(path).stdin(Stdio::null());
    command
}

fn decode_error(path: &Path, stderr: &[u8]) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!(
        "cannot decompress {}: {}", path.display(), String::from_utf8_lossy(stderr).trim()
    ))
}

pub(super) fn read(path: &Path) -> io::Result<Vec<u8>> {
    let path = resolve(path);
    if !path.extension().is_some_and(|ext| ext == "zst") {
        return fs::read(path);
    }
    let output = decoder(&path).output()?;
    if !output.status.success() {
        return Err(decode_error(&path, &output.stderr));
    }
    Ok(output.stdout)
}

/// Cores need seekable storage, not an allocation the size of their address space.
/// The temporary file is unlinked immediately and disappears on every exit path.
pub(super) fn open(path: &Path) -> io::Result<File> {
    let path = resolve(path);
    if !path.extension().is_some_and(|ext| ext == "zst") {
        return File::open(path);
    }
    let mut file = None;
    for _ in 0..64 {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary = std::env::temp_dir().join(format!("dwdiag-evidence-{}-{id}", std::process::id()));
        match OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&temporary) {
            Ok(candidate) => {
                fs::remove_file(&temporary)?;
                file = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let mut file = file.ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "cannot allocate evidence scratch"))?;
    let output = decoder(&path).stdout(Stdio::from(file.try_clone()?)).output()?;
    if !output.status.success() {
        return Err(decode_error(&path, &output.stderr));
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// External readers open the parent's descriptor while its File owner stays alive.
pub(super) fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd()))
}

pub(super) fn for_tool(path: &Path) -> io::Result<(Cow<'_, Path>, Option<File>)> {
    let path = resolve(path);
    if !path.extension().is_some_and(|ext| ext == "zst") {
        return Ok((path, None));
    }
    let file = open(&path)?;
    Ok((Cow::Owned(descriptor_path(&file)), Some(file)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("dwdiag-zstd-test-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn compressed(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let raw = self.0.join(name);
            fs::write(&raw, bytes).unwrap();
            let compressed = self.0.join(format!("{name}.zst"));
            let output = Command::new("zstd").args(["-q", "-c", "--"]).arg(&raw)
                .stdout(File::create(&compressed).unwrap()).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            fs::remove_file(&raw).unwrap();
            raw
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn compressed_log_resolves_logical_and_physical_paths_without_losing_bytes() {
        let fixture = Fixture::new();
        let bytes = b"before\0raw\xff\nRING_MACH_TEST mode=basic pass=1\n";
        let raw = fixture.compressed("run.log", bytes);
        assert_eq!(read(&raw).unwrap(), bytes);
        assert_eq!(read(&resolve(&raw)).unwrap(), bytes);
        fs::write(&raw, b"new live output").unwrap();
        assert_eq!(read(&raw).unwrap(), b"new live output");
    }

    #[test]
    fn compressed_core_remains_seekable_and_external_readers_share_its_lifetime() {
        let fixture = Fixture::new();
        let raw = fixture.compressed("core.1", b"0123456789abcdef");
        let mut core = open(&raw).unwrap();
        core.seek(SeekFrom::Start(10)).unwrap();
        let mut tail = String::new();
        core.read_to_string(&mut tail).unwrap();
        assert_eq!(tail, "abcdef");
        let output = Command::new("cat").arg(descriptor_path(&core)).output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"0123456789abcdef");
    }

    #[test]
    fn corrupt_archives_are_errors_not_empty_evidence() {
        let fixture = Fixture::new();
        let path = fixture.0.join("broken.log.zst");
        fs::write(&path, b"not a zstd frame").unwrap();
        assert_eq!(read(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(open(&path).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
