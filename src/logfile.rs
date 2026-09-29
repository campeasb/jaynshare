//! Size-rotated NDJSON files shared by the operational, crash and audit logs
//! On rotation, `.1` is newest, `.<retained>` oldest.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::state::open_private_append;

#[derive(Debug)]
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    retained_files: u64,
    file: File,
    size: u64,
}

impl RotatingFile {
    pub fn open(path: &Path, max_bytes: u64, retained_files: u64) -> io::Result<Self> {
        let file = open_private_append(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            retained_files,
            file,
            size,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Rotated files present beside the active one.
    pub fn retained_count(&self) -> u64 {
        (1..=self.retained_files)
            .take_while(|n| self.rotated(*n).exists())
            .count() as u64
    }

    /// Appends one line (LF added), rotating first when the line would overflow the file.
    pub fn append_line(&mut self, line: &[u8]) -> io::Result<()> {
        let needed = line.len() as u64 + 1;
        if self.size > 0 && self.size + needed > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(line)?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.size += needed;
        Ok(())
    }

    fn rotated(&self, n: u64) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(".{n}"));
        PathBuf::from(name)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let _ = fs::remove_file(self.rotated(self.retained_files));
        for n in (1..self.retained_files).rev() {
            let from = self.rotated(n);
            if from.exists() {
                fs::rename(&from, self.rotated(n + 1))?;
            }
        }
        fs::rename(&self.path, self.rotated(1))?;
        self.file = open_private_append(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_before_overflow_and_keeps_the_retained_count() {
        let dir = std::env::temp_dir().join(format!("jaynshare-log-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.ndjson");
        let mut f = RotatingFile::open(&path, 20, 2).unwrap();
        for i in 0..6 {
            f.append_line(format!("{{\"n\":{i}}}").as_bytes()).unwrap();
        }
        // 8 bytes per line: two lines per file, so the last file holds lines 4-5.
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"n\":4}\n{\"n\":5}\n");
        assert_eq!(
            fs::read_to_string(dir.join("server.ndjson.1")).unwrap(),
            "{\"n\":2}\n{\"n\":3}\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("server.ndjson.2")).unwrap(),
            "{\"n\":0}\n{\"n\":1}\n"
        );
        assert!(!dir.join("server.ndjson.3").exists());
        assert_eq!(f.retained_count(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }
}
