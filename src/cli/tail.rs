//! `log tail` and `audit tail`: file-backed readers of the
//! operational, crash and audit logs of the selected configuration. They
//! work on a stopped server, print the last `-n` matching objects one per
//! line, and with `--follow` keep printing, reopening the active file when
//! log rotation renames it away. `--json` writes each raw object
//! as the file holds it; the files carry no body or credential.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::audit::AUDIT_LOG;
use crate::config::{self, LogLevel};
use crate::logging::{CRASH_LOG, SERVER_LOG};
use crate::pool::fold;

use super::Failure;
use super::args::{AuditTailArgs, Cli, LogTailArgs};

/// The follow poll interval.
const POLL: Duration = Duration::from_millis(250);

/// One filter over parsed objects, and the rendering of a match.
struct Tail {
    path: PathBuf,
    count: usize,
    follow: bool,
    json: bool,
    matches: Box<dyn Fn(&Value) -> bool>,
    render: fn(&Value) -> String,
}

pub(super) fn log_tail(cli: &Cli, args: &LogTailArgs) -> Result<(), Failure> {
    let directory = log_directory(cli)?;
    let level = args.level.as_deref().map(parse_level).transpose()?;
    let since = args.since.as_deref().map(parse_since).transpose()?;
    let events = args.events.clone();
    let file = if args.crash { CRASH_LOG } else { SERVER_LOG };
    Tail {
        path: directory.join(file),
        count: args.count,
        follow: args.follow,
        json: cli.json,
        matches: Box::new(move |object| {
            level.is_none_or(|floor| level_of(object).is_some_and(|l| l <= floor))
                && (events.is_empty()
                    || events
                        .iter()
                        .any(|e| object["event"].as_str() == Some(e.as_str())))
                && since.is_none_or(|s| timestamp_of(object).is_some_and(|t| t >= s))
        }),
        render: render_log,
    }
    .run()
}

pub(super) fn audit_tail(cli: &Cli, args: &AuditTailArgs) -> Result<(), Failure> {
    let directory = log_directory(cli)?;
    let since = args.since.as_deref().map(parse_since).transpose()?;
    let account = args.account.as_deref().map(fold);
    let client = args.client.clone();
    let session = args.session.clone();
    let status = args.status;
    let failed_over = args.failed_over;
    Tail {
        path: directory.join(AUDIT_LOG),
        count: args.count,
        follow: args.follow,
        json: cli.json,
        matches: Box::new(move |record| {
            account.as_ref().is_none_or(|wanted| {
                record["serving_account"]["display_name"]
                    .as_str()
                    .is_some_and(|name| fold(name) == *wanted)
            }) && client.as_ref().is_none_or(|id| {
                record["principal"]["kind"] == "client" && record["principal"]["id"] == *id
            }) && session
                .as_ref()
                .is_none_or(|id| record["session_id"] == *id)
                && status.is_none_or(|code| record["status"] == code)
                && (!failed_over || record["failed_over"] == true)
                && since.is_none_or(|s| timestamp_of(record).is_some_and(|t| t >= s))
        }),
        render: render_audit,
    }
    .run()
}

/// The log directory of the selected configuration; exit 3 when the file
/// cannot be read or parsed, as for any operator verb.
fn log_directory(cli: &Cli) -> Result<PathBuf, Failure> {
    let path = config::config_path(cli.config.as_deref());
    let loaded = config::load(&path).map_err(|e| {
        Failure::local(
            3,
            "cli_configuration_invalid",
            format!("{}: {e}", path.display()),
        )
    })?;
    Ok(loaded.config.logging.directory)
}

fn parse_level(text: &str) -> Result<LogLevel, Failure> {
    match text {
        "error" => Ok(LogLevel::Error),
        "warn" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        other => Err(Failure::local(
            2,
            "cli_usage",
            format!("--level takes error, warn, info or debug, not {other:?}"),
        )),
    }
}

fn parse_since(text: &str) -> Result<OffsetDateTime, Failure> {
    OffsetDateTime::parse(text, &Rfc3339).map_err(|_| {
        Failure::local(
            2,
            "cli_usage",
            format!("--since takes an RFC 3339 timestamp, not {text:?}"),
        )
    })
}

fn level_of(object: &Value) -> Option<LogLevel> {
    match object["level"].as_str()? {
        "error" => Some(LogLevel::Error),
        "warn" => Some(LogLevel::Warn),
        "info" => Some(LogLevel::Info),
        "debug" => Some(LogLevel::Debug),
        _ => None,
    }
}

fn timestamp_of(object: &Value) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(object["timestamp"].as_str()?, &Rfc3339).ok()
}

fn text(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Timestamp, level, event, message, then `fields` as `key=value`.
fn render_log(object: &Value) -> String {
    let mut line = format!(
        "{} {:<5} {} {}",
        text(&object["timestamp"]),
        text(&object["level"]),
        text(&object["event"]),
        text(&object["message"])
    );
    if let Some(fields) = object["fields"].as_object() {
        for (key, value) in fields {
            line.push_str(&format!(" {key}={}", text(value)));
        }
    }
    line
}

/// Timestamp, principal, source, method and path, model, serving
/// account or reason, status, attempts, cause, error class.
fn render_audit(record: &Value) -> String {
    let principal = format!(
        "{}[{}]",
        text(&record["principal"]["kind"]),
        text(&record["principal"]["id"])
    );
    let served = if record["serving_account"].is_null() {
        format!("no-service={}", text(&record["no_service_reason"]))
    } else {
        text(&record["serving_account"]["display_name"])
    };
    format!(
        "{} {principal} {} {} {} model={} {served} status={} attempts={} cause={} error={}",
        text(&record["timestamp"]),
        text(&record["source_address"]),
        text(&record["method"]),
        text(&record["path"]),
        text(&record["model"]),
        text(&record["status"]),
        text(&record["attempts"]),
        text(&record["selection_cause"]),
        text(&record["error_class"]),
    )
}

impl Tail {
    fn run(self) -> Result<(), Failure> {
        let mut stdout = std::io::stdout().lock();
        let mut reader = Reader::open(&self.path)?;
        for line in self.last_matches(reader.drain()) {
            writeln!(stdout, "{line}").map_err(write_failed)?;
        }
        stdout.flush().map_err(write_failed)?;
        if !self.follow {
            return Ok(());
        }
        loop {
            std::thread::sleep(POLL);
            for line in reader.drain() {
                if let Some(rendered) = self.consider(&line) {
                    writeln!(stdout, "{rendered}").map_err(write_failed)?;
                }
            }
            stdout.flush().map_err(write_failed)?;
            reader.reopen_after_rotation()?;
        }
    }

    /// The last `count` matches of what the file holds now, rendered; `-n 0`
    /// keeps none, so a follow starts at the present.
    fn last_matches(&self, lines: Vec<String>) -> std::collections::VecDeque<String> {
        let mut matched = std::collections::VecDeque::with_capacity(self.count.min(4096));
        if self.count == 0 {
            return matched;
        }
        for rendered in lines.iter().filter_map(|line| self.consider(line)) {
            if matched.len() == self.count {
                matched.pop_front();
            }
            matched.push_back(rendered);
        }
        matched
    }

    /// One raw line to its rendering when it is a matching object; a line
    /// that is not JSON (a torn write) is skipped.
    fn consider(&self, line: &str) -> Option<String> {
        let object: Value = serde_json::from_str(line).ok()?;
        if !(self.matches)(&object) {
            return None;
        }
        Some(if self.json {
            line.trim_end().to_string()
        } else {
            (self.render)(&object)
        })
    }
}

/// A closed pipe ends the tail quietly (exit 1, no envelope).
fn write_failed(e: std::io::Error) -> Failure {
    Failure::local(1, "cli_internal", format!("standard output: {e}"))
}

/// The active file and the position read so far; identity by inode so a
/// rotation (rename away, new active file) is seen as such. A file that
/// does not exist yet (no crash has happened) reads as empty and is picked
/// up when it appears.
struct Reader {
    path: PathBuf,
    file: Option<BufReader<File>>,
    identity: Option<(u64, u64)>,
    partial: String,
}

impl Reader {
    fn open(path: &Path) -> Result<Self, Failure> {
        let file = match File::open(path) {
            Ok(file) => Some(file),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(Failure::local(
                    3,
                    "cli_configuration_invalid",
                    format!("{}: cannot read: {e}", path.display()),
                ));
            }
        };
        let identity = file.as_ref().and_then(identity);
        Ok(Self {
            path: path.to_path_buf(),
            file: file.map(BufReader::new),
            identity,
            partial: String::new(),
        })
    }

    /// Every complete line appended since the last call.
    fn drain(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        let Some(file) = &mut self.file else {
            return out;
        };
        let mut chunk = String::new();
        loop {
            chunk.clear();
            match file.read_line(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if chunk.ends_with('\n') {
                        let line = std::mem::take(&mut self.partial) + &chunk;
                        out.push(line);
                    } else {
                        // A line still being written: kept until its LF arrives.
                        self.partial.push_str(&chunk);
                    }
                }
            }
        }
        out
    }

    /// When the path now names another file, the old one has been
    /// rotated away and drained; continue from the start of the new one.
    fn reopen_after_rotation(&mut self) -> Result<(), Failure> {
        let Ok(current) = File::open(&self.path) else {
            return Ok(());
        };
        let current_identity = identity(&current);
        if current_identity != self.identity || self.shrank(&current) {
            let mut file = BufReader::new(current);
            let _ = file.seek(SeekFrom::Start(0));
            self.file = Some(file);
            self.identity = current_identity;
            self.partial.clear();
        }
        Ok(())
    }

    /// A truncated active file (same inode, fewer bytes than read) is read again.
    fn shrank(&mut self, current: &File) -> bool {
        let read_so_far = self
            .file
            .as_mut()
            .and_then(|f| f.stream_position().ok())
            .unwrap_or(0);
        current.metadata().is_ok_and(|m| m.len() < read_so_far)
    }
}

#[cfg(unix)]
fn identity(file: &File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    file.metadata().ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
fn identity(file: &File) -> Option<(u64, u64)> {
    file.metadata().ok().map(|m| (0, m.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tail(count: usize) -> Tail {
        Tail {
            path: PathBuf::new(),
            count,
            follow: false,
            json: true,
            matches: Box::new(|object| object["event"] == "kept"),
            render: render_log,
        }
    }

    fn lines(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                format!(
                    "{{\"event\":\"{}\",\"n\":{i}}}\n",
                    if i % 2 == 0 { "kept" } else { "dropped" }
                )
            })
            .collect()
    }

    #[test]
    fn the_history_is_the_last_count_matches_and_none_for_zero() {
        assert_eq!(tail(2).last_matches(lines(10)).len(), 2);
        assert!(tail(2).last_matches(lines(10))[1].contains("\"n\":8"));
        assert_eq!(tail(50).last_matches(lines(10)).len(), 5);
        assert!(tail(0).last_matches(lines(10)).is_empty());
    }

    #[test]
    fn a_log_line_renders_the_five_members_and_fields() {
        let object = json!({
            "timestamp": "2026-09-18T10:00:00Z", "level": "warn", "event": "reload",
            "message": "rejected", "fields": { "digest": "ab", "count": 2 }
        });
        assert_eq!(
            render_log(&object),
            "2026-09-18T10:00:00Z warn  reload rejected digest=ab count=2"
        );
    }

    #[test]
    fn an_audit_line_names_the_served_account_or_the_reason() {
        let served = json!({
            "timestamp": "t", "principal": { "kind": "loopback", "id": null }, "source_address": "127.0.0.1:5",
            "method": "POST", "path": "/v1/messages", "model": "m", "serving_account": { "display_name": "FSUB" },
            "no_service_reason": null, "status": 200, "attempts": 1, "selection_cause": "default", "error_class": null
        });
        assert_eq!(
            render_audit(&served),
            "t loopback[-] 127.0.0.1:5 POST /v1/messages model=m FSUB status=200 attempts=1 cause=default error=-"
        );
        let mut unserved = served.clone();
        unserved["serving_account"] = Value::Null;
        unserved["no_service_reason"] = json!("no_eligible_account");
        assert!(render_audit(&unserved).contains("no-service=no_eligible_account"));
    }
}
