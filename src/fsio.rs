//! File helpers: atomic, private writes and vault path conventions.
//!
//! - Outputs go to a temporary sibling with mode 0600, then are renamed
//!   over the destination on `commit`, so a crash never leaves a
//!   half-written vault or plaintext, and nothing is replaced unless the
//!   caller says `force`.
//! - `lock` appends `.vault` (so `a.tar.gz` -> `a.tar.gz.vault`);
//!   `unlock` strips it and falls back to `.open` when the plaintext still
//!   sits next to the vault.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub const VAULT_EXT: &str = ".vault";

pub fn vault_path(src: &Path) -> PathBuf {
    let mut s = src.as_os_str().to_owned();
    s.push(VAULT_EXT);
    PathBuf::from(s)
}

pub fn open_path(vault: &Path) -> PathBuf {
    let name = vault.as_os_str().to_string_lossy();
    let stripped = name.strip_suffix(VAULT_EXT).map(PathBuf::from);
    match stripped {
        Some(p) if !p.exists() => p,
        Some(p) => {
            let mut s = p.into_os_string();
            s.push(".open");
            PathBuf::from(s)
        }
        None => {
            let mut s = vault.as_os_str().to_owned();
            s.push(".open");
            PathBuf::from(s)
        }
    }
}

/// Streams into a private temp file; `commit` renames it over `dest`.
/// Dropped without commit, the temp file is removed.
pub struct AtomicWriter {
    file: Option<File>,
    tmp: PathBuf,
    dest: PathBuf,
}

impl AtomicWriter {
    pub fn create(dest: &Path, force: bool) -> io::Result<AtomicWriter> {
        if dest.exists() && !force {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists (use --force or --out)", dest.display()),
            ));
        }
        let dir = dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let base = dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let tmp = dir.join(format!(".{base}.uniseal-{}.tmp", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let file = opts.open(&tmp)?;
        Ok(AtomicWriter { file: Some(file), tmp, dest: dest.to_path_buf() })
    }

    pub fn commit(mut self) -> io::Result<()> {
        let file = self.file.take().expect("open writer");
        file.sync_all()?;
        drop(file);
        let r = std::fs::rename(&self.tmp, &self.dest);
        if r.is_err() {
            let _ = std::fs::remove_file(&self.tmp);
        }
        r
    }
}

impl Write for AtomicWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.as_mut().expect("open writer").write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().expect("open writer").flush()
    }
}

impl Drop for AtomicWriter {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Atomically write `data` to `dest` (mode 0600), refusing to replace an
/// existing file unless `force`.
#[cfg(test)]
pub fn write_new(dest: &Path, data: &[u8], force: bool) -> io::Result<()> {
    let mut w = AtomicWriter::create(dest, force)?;
    w.write_all(data)?;
    w.commit()
}

/// Read-through SHA-256, to fingerprint a plaintext while it is encrypted.
pub struct HashReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> HashReader<R> {
    pub fn new(inner: R) -> Self {
        HashReader { inner, hasher: Sha256::new() }
    }
    pub fn digest(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Write sink that only keeps a SHA-256, to verify a vault without
/// materialising the plaintext.
#[derive(Default)]
pub struct HashSink {
    hasher: Sha256,
}

impl HashSink {
    pub fn digest(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl Write for HashSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(vault_path(Path::new("a.tar.gz")), PathBuf::from("a.tar.gz.vault"));
        assert_eq!(open_path(Path::new("/nonexistent/dir/a.tar.gz.vault")), PathBuf::from("/nonexistent/dir/a.tar.gz"));
        assert_eq!(open_path(Path::new("/nonexistent/dir/blob")), PathBuf::from("/nonexistent/dir/blob.open"));
    }

    #[test]
    fn no_overwrite_and_atomic() {
        let dir = std::env::temp_dir().join(format!("uniseal-fsio-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x");
        write_new(&p, b"one", false).unwrap();
        assert!(write_new(&p, b"two", false).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        {
            let mut w = AtomicWriter::create(&p, true).unwrap();
            w.write_all(b"abandoned").unwrap();
            // dropped without commit
        }
        assert_eq!(std::fs::read(&p).unwrap(), b"one", "uncommitted writer must not replace");
        write_new(&p, b"two", true).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(open_path(&vault_path(&p)), dir.join("x.open"), "plaintext present: fall back to .open");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(std::fs::read_dir(&dir).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hashing() {
        let mut r = HashReader::new(&b"hello"[..]);
        let mut sink = HashSink::default();
        io::copy(&mut r, &mut sink).unwrap();
        assert_eq!(r.digest(), sink.digest());
    }
}
