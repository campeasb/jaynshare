//! The credential Claude Code holds for this host — its Keychain item
//! on macOS, else `~/.claude/.credentials.json` —
//! copied into the pool and never modified.

use std::fmt;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::time::Duration;

use serde_json::{Map, Value};
use time::OffsetDateTime;

use super::{OAuthCredential, Secret};

/// The `platform_hint`: which store to read instead of choosing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    Keychain,
    File,
}

impl Hint {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "keychain" => Some(Hint::Keychain),
            "file" => Some(Hint::File),
            _ => None,
        }
    }
}

/// The source class an error names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Keychain,
    CredentialsFile,
}

/// The cause, never the contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Missing,
    Unreadable,
    WrongShape,
    /// A family is all three of access token, refresh token and expiry.
    IncompleteFamily,
    /// The class is not readable on this platform (the Keychain off macOS).
    /// Claude Code only has the file and keychain family; the keychain class is
    /// unsupported off macOS.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportFailed {
    pub class: Class,
    pub cause: Cause,
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Class::Keychain => "keychain",
            Class::CredentialsFile => "credentials file",
        })
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Cause::Missing => "missing",
            Cause::Unreadable => "unreadable",
            Cause::WrongShape => "wrong shape",
            Cause::IncompleteFamily => "incomplete family",
            Cause::Unsupported => "unsupported",
        })
    }
}

impl fmt::Display for ImportFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.class, self.cause)
    }
}

/// The family Claude Code holds for this host, copied, never
/// modified. A hint forces one source; without one, macOS prefers
/// the Keychain when reading it works and falls back to the file.
pub async fn read(hint: Option<Hint>, home: &Path) -> Result<OAuthCredential, ImportFailed> {
    // cfg! runs both branches at compile time, but read_keychain only exists
    // on macOS; the branches below must be cfg-gated the same way.
    #[cfg(target_os = "macos")]
    {
        match hint {
            Some(Hint::File) => read_file(home),
            Some(Hint::Keychain) => read_keychain().await,
            // The Keychain wins whenever the item exists, so only its
            // absence reaches the file; a present but unreadable or malformed
            // item is reported as the Keychain failure it is.
            None => match read_keychain().await {
                Err(ImportFailed {
                    cause: Cause::Missing,
                    ..
                }) => read_file(home),
                outcome => outcome,
            },
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        match hint {
            Some(Hint::Keychain) => Err(ImportFailed {
                class: Class::Keychain,
                cause: Cause::Unsupported,
            }),
            _ => read_file(home),
        }
    }
}

/// `<home>/.claude/.credentials.json`, read once, never modified.
fn read_file(home: &Path) -> Result<OAuthCredential, ImportFailed> {
    let failed = |cause: Cause| ImportFailed {
        class: Class::CredentialsFile,
        cause,
    };
    let path = home.join(".claude").join(".credentials.json");
    let meta = std::fs::metadata(&path).map_err(|e| {
        failed(match e.kind() {
            std::io::ErrorKind::NotFound => Cause::Missing,
            _ => Cause::Unreadable,
        })
    })?;
    // The store is a regular file; a directory or device is unreadable.
    if !meta.is_file() {
        return Err(failed(Cause::Unreadable));
    }
    let bytes = std::fs::read(&path).map_err(|_| failed(Cause::Unreadable))?;
    parse_credentials_document(&bytes).map_err(failed)
}

/// The `Claude Code-credentials` generic password, whose payload is
/// the credentials-file document. Reached through `/usr/bin/security` exactly as the
/// keychain item is read by hand; the stderr is never echoed.
#[cfg(target_os = "macos")]
async fn read_keychain() -> Result<OAuthCredential, ImportFailed> {
    use tokio::process::Command;

    let failed = |cause: Cause| ImportFailed {
        class: Class::Keychain,
        cause,
    };
    let child = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            "Claude Code-credentials",
            "-w",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // The 5 s deadline: a timed-out read is killed with its child.
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| failed(Cause::Unreadable))?;
    let output = match tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await
    {
        Ok(Ok(output)) => output,
        Ok(Err(_)) | Err(_) => return Err(failed(Cause::Unreadable)),
    };
    if !output.status.success() {
        // security's exit 44 is the item-not-found report; anything else is
        // a read that did not happen.
        let cause = match output.status.code() {
            Some(44) => Cause::Missing,
            _ => Cause::Unreadable,
        };
        return Err(failed(cause));
    }
    parse_credentials_document(&output.stdout).map_err(failed)
}

/// The credentials-file document in either key placement — under `claudeAiOauth` or at
/// top level — with `expiresAt` in unix milliseconds. Only the three family
/// keys are read; the rest of the document is ignored.
pub fn parse_credentials_document(bytes: &[u8]) -> Result<OAuthCredential, Cause> {
    let document: Value = serde_json::from_slice(bytes).map_err(|_| Cause::WrongShape)?;
    let object = document.as_object().ok_or(Cause::WrongShape)?;
    let family = match object.get("claudeAiOauth") {
        Some(Value::Object(nested)) => nested,
        Some(_) => return Err(Cause::WrongShape),
        None => object,
    };
    let access_token = token(family, "accessToken")?;
    let refresh_token = token(family, "refreshToken")?;
    let expires_at = match family.get("expiresAt") {
        None => return Err(Cause::IncompleteFamily),
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|ms| {
                OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()
            })
            .ok_or(Cause::WrongShape)?,
        Some(_) => return Err(Cause::WrongShape),
    };
    Ok(OAuthCredential {
        access_token,
        refresh_token: Some(refresh_token),
        expires_at,
        last_refresh_attempt_at: None,
        last_refresh_success_at: None,
        refresh_not_before: None,
    })
}

fn token(family: &Map<String, Value>, key: &str) -> Result<Secret, Cause> {
    match family.get(key) {
        None => Err(Cause::IncompleteFamily),
        Some(Value::String(s)) if s.trim().is_empty() => Err(Cause::IncompleteFamily),
        Some(Value::String(s)) => Ok(Secret::new(s.trim().to_string())),
        Some(_) => Err(Cause::WrongShape),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::macros::datetime;

    use super::*;

    fn parse(document: Value) -> Result<OAuthCredential, Cause> {
        parse_credentials_document(document.to_string().as_bytes())
    }

    #[test]
    fn both_placements_parse_with_milliseconds_and_extra_keys_ignored() {
        let family = json!({
            "accessToken": "sk-ant-oat-a",
            "refreshToken": "sk-ant-ort-r",
            "expiresAt": 1_767_225_600_500i64,
            "subscriptionType": "max",
            "rateLimitTier": "default",
        });
        let expected = OAuthCredential {
            access_token: Secret::new("sk-ant-oat-a".into()),
            refresh_token: Some(Secret::new("sk-ant-ort-r".into())),
            expires_at: datetime!(2026-01-01 00:00:00.5 UTC),
            last_refresh_attempt_at: None,
            last_refresh_success_at: None,
            refresh_not_before: None,
        };
        assert_eq!(
            parse(json!({ "claudeAiOauth": family, "other": 1 })),
            Ok(expected.clone())
        );
        assert_eq!(parse(family), Ok(expected));
    }

    #[test]
    fn a_missing_or_empty_key_is_an_incomplete_family() {
        for key in ["accessToken", "refreshToken", "expiresAt"] {
            let mut family = json!({
                "accessToken": "a",
                "refreshToken": "r",
                "expiresAt": 1_767_225_600_000i64,
            });
            family.as_object_mut().unwrap().remove(key);
            assert_eq!(
                parse(json!({ "claudeAiOauth": family })),
                Err(Cause::IncompleteFamily),
                "without {key}"
            );
        }
        assert_eq!(
            parse(json!({ "accessToken": " ", "refreshToken": "r", "expiresAt": 1 })),
            Err(Cause::IncompleteFamily)
        );
    }

    #[test]
    fn a_wrong_type_or_non_object_is_the_wrong_shape() {
        assert_eq!(
            parse(json!({ "accessToken": 7, "refreshToken": "r", "expiresAt": 1 })),
            Err(Cause::WrongShape)
        );
        assert_eq!(
            parse(json!({ "accessToken": "a", "refreshToken": "r", "expiresAt": "soon" })),
            Err(Cause::WrongShape)
        );
        assert_eq!(
            parse(json!({ "claudeAiOauth": "a" })),
            Err(Cause::WrongShape)
        );
        assert_eq!(parse(json!([])), Err(Cause::WrongShape));
        assert_eq!(
            parse_credentials_document(b"not json"),
            Err(Cause::WrongShape)
        );
    }

    #[test]
    fn the_file_half_reports_each_cause_and_never_the_contents() {
        // Same pattern as `state.rs`'s temp fixture: a per-run directory.
        let home = std::env::temp_dir().join(format!("jaynshare-managed-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(home.join(".claude")).expect("temp .claude");
        let path = home.join(".claude/.credentials.json");
        let failed = |cause| ImportFailed {
            class: Class::CredentialsFile,
            cause,
        };

        // An absent file is missing.
        assert_eq!(read_file(&home), Err(failed(Cause::Missing)));

        // A directory is not the regular credentials file.
        std::fs::create_dir(&path).expect("plant a directory");
        assert_eq!(read_file(&home), Err(failed(Cause::Unreadable)));
        std::fs::remove_dir(&path).expect("remove the directory");

        // A parse failure is the wrong shape.
        std::fs::write(&path, b"not json").expect("plant bytes");
        assert_eq!(read_file(&home), Err(failed(Cause::WrongShape)));

        // A family missing a member is incomplete.
        std::fs::write(
            &path,
            json!({ "accessToken": "a", "expiresAt": 1_767_225_600_000i64 })
                .to_string()
                .as_bytes(),
        )
        .expect("plant an incomplete family");
        assert_eq!(read_file(&home), Err(failed(Cause::IncompleteFamily)));

        // A complete family parses, in both key placements.
        let family = json!({
            "accessToken": "sk-ant-oat-a",
            "refreshToken": "sk-ant-ort-r",
            "expiresAt": 1_767_225_600_000i64,
        });
        let expected = Ok(OAuthCredential {
            access_token: Secret::new("sk-ant-oat-a".into()),
            refresh_token: Some(Secret::new("sk-ant-ort-r".into())),
            expires_at: datetime!(2026-01-01 00:00 UTC),
            last_refresh_attempt_at: None,
            last_refresh_success_at: None,
            refresh_not_before: None,
        });
        std::fs::write(&path, family.to_string()).expect("plant the family");
        assert_eq!(read_file(&home), expected);
        std::fs::write(&path, json!({ "claudeAiOauth": family }).to_string())
            .expect("plant the nested family");
        assert_eq!(read_file(&home), expected);

        std::fs::remove_dir_all(&home).expect("clean the temp dir");
    }

    // The dispatch on a non-macOS host: no hint reads the file, the
    // Keychain hint is unsupported. (macOS would touch the real store,
    // so these arms stay untested here.)
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn the_dispatch_serves_the_file_and_names_the_keychain_unsupported() {
        let failed = read(None, Path::new("/nonexistent")).await.unwrap_err();
        assert_eq!(failed.to_string(), "credentials file: missing");
        let failed = read(Some(Hint::Keychain), Path::new("/nonexistent"))
            .await
            .unwrap_err();
        assert_eq!(failed.to_string(), "keychain: unsupported");
    }

    #[test]
    fn classes_and_hints_name_themselves() {
        assert_eq!(Hint::parse("keychain"), Some(Hint::Keychain));
        assert_eq!(Hint::parse("file"), Some(Hint::File));
        assert_eq!(Hint::parse("File"), None);
        assert_eq!(Class::Keychain.to_string(), "keychain");
        assert_eq!(Class::CredentialsFile.to_string(), "credentials file");
        for (cause, name) in [
            (Cause::Missing, "missing"),
            (Cause::Unreadable, "unreadable"),
            (Cause::WrongShape, "wrong shape"),
            (Cause::IncompleteFamily, "incomplete family"),
            (Cause::Unsupported, "unsupported"),
        ] {
            assert_eq!(cause.to_string(), name);
        }
        assert_eq!(
            ImportFailed {
                class: Class::Keychain,
                cause: Cause::IncompleteFamily
            }
            .to_string(),
            "keychain: incomplete family"
        );
    }
}
