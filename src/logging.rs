//! Operational and crash logs: NDJSON objects with
//! `timestamp`, `level`, `event`, `message`, `fields`. `warn` and `error` are
//! mirrored to standard error as text. A URL's user
//! information is replaced in every string before it is written, so a
//! message that quotes a proxy URL cannot carry its password.

use std::borrow::Cow;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{FilterExt, LevelFilter, Targets};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry, reload};

use crate::config::{LogLevel, LoggingSettings};
use crate::logfile::RotatingFile;
use crate::timestamp::rfc3339;

pub const SERVER_LOG: &str = "server.ndjson";
pub const CRASH_LOG: &str = "crash.ndjson";

pub struct NdjsonLayer {
    file: Mutex<RotatingFile>,
}

impl NdjsonLayer {
    pub fn open(path: &Path, settings: &LoggingSettings) -> std::io::Result<Self> {
        Ok(Self {
            file: Mutex::new(RotatingFile::open(
                path,
                settings.max_bytes,
                settings.retained_files,
            )?),
        })
    }
}

#[derive(Default)]
struct Fields {
    event: Option<String>,
    message: Option<String>,
    rest: Map<String, Value>,
}

impl Fields {
    fn put(&mut self, field: &Field, value: Value) {
        let value = match value {
            Value::String(text) => Value::String(redact_user_info(&text).into_owned()),
            other => other,
        };
        match field.name() {
            "event" => self.event = value.as_str().map(String::from),
            "message" => {
                self.message = Some(
                    value
                        .as_str()
                        .map_or_else(|| value.to_string(), String::from),
                )
            }
            name => {
                self.rest.insert(name.to_string(), value);
            }
        }
    }
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, json!(format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, json!(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, json!(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, json!(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, json!(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, json!(value));
    }
}

/// `scheme://user:password@host` becomes `scheme://[redacted]@host`
/// wherever it appears in a string; a URL without user information is
/// returned as it was.
pub fn redact_user_info(text: &str) -> Cow<'_, str> {
    let mut out = String::new();
    let mut rest = text;
    let mut changed = false;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let authority_end = tail
            .find(|c: char| {
                matches!(
                    c,
                    '/' | '?' | '#' | '"' | '\'' | ' ' | '\n' | '\t' | ')' | ']' | ',' | ';'
                )
            })
            .unwrap_or(tail.len());
        match tail[..authority_end].rfind('@') {
            Some(user_end) => {
                out.push_str("[redacted]");
                rest = &tail[user_end..];
                changed = true;
            }
            None => {
                out.push_str(&tail[..authority_end]);
                rest = &tail[authority_end..];
            }
        }
    }
    if changed {
        out.push_str(rest);
        Cow::Owned(out)
    } else {
        Cow::Borrowed(text)
    }
}

fn level_name(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        _ => "debug",
    }
}

impl<S: Subscriber> Layer<S> for NdjsonLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let level = level_name(event.metadata().level());
        let name = fields
            .event
            .unwrap_or_else(|| event.metadata().name().to_lowercase());
        let message = fields.message.unwrap_or_default();
        let object = json!({
            "timestamp": rfc3339(OffsetDateTime::now_utc()),
            "level": level,
            "event": name,
            "message": message,
            "fields": fields.rest,
        });
        if matches!(*event.metadata().level(), Level::ERROR | Level::WARN) {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{level}: {name}: {message}");
        }
        if let Ok(mut file) = self.file.lock() {
            let _ = file.append_line(object.to_string().as_bytes());
        }
    }
}

pub fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
    }
}

/// `logging.level` is a live key: the filter installed at start, reloadable.
static LEVEL: OnceLock<reload::Handle<LevelFilter, Registry>> = OnceLock::new();

/// Where crash objects go and how the file rotates.
static CRASH: OnceLock<(PathBuf, u64, u64)> = OnceLock::new();

/// Installs the server log and the crash hook. Returns an error naming the path.
pub fn init(settings: &LoggingSettings) -> Result<(), String> {
    let server_path = settings.directory.join(SERVER_LOG);
    let layer = NdjsonLayer::open(&server_path, settings)
        .map_err(|e| format!("cannot open {}: {e}", server_path.display()))?;
    let (filter, handle) = reload::Layer::new(level_filter(settings.level));
    // Only this crate's own safe events reach the operational log; a
    // dependency's tracing output (hyper, rustls) never lands there, whatever
    // the level. The reloadable level filter still gates their level.
    let product = Targets::new().with_target(env!("CARGO_PKG_NAME"), LevelFilter::TRACE);
    tracing_subscriber::registry()
        .with(layer.with_filter(filter.and(product)))
        .try_init()
        .map_err(|e| e.to_string())?;
    let _ = LEVEL.set(handle);
    install_crash_hook(settings);
    Ok(())
}

/// A reloaded `logging.level` applies to the next event.
pub fn set_level(level: LogLevel) {
    if let Some(handle) = LEVEL.get() {
        let _ = handle.reload(level_filter(level));
    }
}

/// One appended crash object — timestamp, failure class, safe
/// message and the backtrace when one is available; later crashes append.
pub fn crash(class: &str, message: &str, backtrace: Option<String>) {
    let Some((path, max_bytes, retained)) = CRASH.get() else {
        return;
    };
    let object = json!({
        "timestamp": rfc3339(OffsetDateTime::now_utc()),
        "class": class,
        "message": redact_user_info(message),
        "backtrace": backtrace,
    });
    if let Ok(mut file) = RotatingFile::open(path, *max_bytes, *retained) {
        let _ = file.append_line(object.to_string().as_bytes());
    }
}

fn install_crash_hook(settings: &LoggingSettings) {
    let _ = CRASH.set((
        settings.directory.join(CRASH_LOG),
        settings.max_bytes,
        settings.retained_files,
    ));
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        crash(
            "panic",
            &info.to_string(),
            Some(std::backtrace::Backtrace::force_capture().to_string()),
        );
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::redact_user_info;

    #[test]
    fn user_information_is_replaced_and_plain_urls_are_untouched() {
        assert_eq!(
            redact_user_info("proxy http://alice:s3cret@proxy.example:3128/ refused"),
            "proxy http://[redacted]@proxy.example:3128/ refused"
        );
        assert_eq!(
            redact_user_info("\"https://u:p@h\" and http://x@y"),
            "\"https://[redacted]@h\" and http://[redacted]@y"
        );
        assert_eq!(
            redact_user_info("https://api.anthropic.com/v1 a@b.example"),
            "https://api.anthropic.com/v1 a@b.example"
        );
        assert_eq!(redact_user_info("no url here"), "no url here");
    }
}
