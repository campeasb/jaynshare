//! Secret generation and verifiers: three
//! shapes, domain-separated SHA-256 digests, constant-time comparison. The
//! plaintext of a secret exists only between generation and disclosure; the
//! type that carries it prints nothing but its prefix.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The prefix and the hashing domain of each secret role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    EnrollmentCode,
    ClientSecret,
    OperatorSecret,
}

impl Role {
    pub fn prefix(self) -> &'static str {
        match self {
            Role::EnrollmentCode => "jse2_",
            Role::ClientSecret => "jsc2_",
            Role::OperatorSecret => "jso2_",
        }
    }

    /// The ASCII domain the digest is taken over.
    pub fn domain(self) -> &'static str {
        match self {
            Role::EnrollmentCode => "jaynshare/enrollment",
            Role::ClientSecret => "jaynshare/client",
            Role::OperatorSecret => "jaynshare/operator",
        }
    }
}

/// A freshly generated plaintext secret. No `Debug`/`Display` output ever
/// carries the value; it is dropped the moment it is disclosed.
pub struct Secret(String);

impl Secret {
    /// 32 random bytes as unpadded base64url behind the role's prefix.
    pub fn generate(role: Role) -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("OS randomness is always available");
        Self(format!(
            "{}{}",
            role.prefix(),
            URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// The durable form of a secret: algorithm, domain and lower-case hex digest
/// over the ASCII domain, one zero byte and the complete secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verifier {
    pub algorithm: String,
    pub domain: String,
    pub digest: String,
}

impl Verifier {
    pub fn new(role: Role, secret: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(role.domain().as_bytes());
        hasher.update([0u8]);
        hasher.update(secret.as_bytes());
        let digest = format!("{:x}", hasher.finalize());
        Self {
            algorithm: "sha256".to_string(),
            domain: role.domain().to_string(),
            digest,
        }
    }

    /// Digests are compared in constant time.
    pub fn matches(&self, role: Role, secret: &str) -> bool {
        self.domain == role.domain()
            && constant_time_eq(
                self.digest.as_bytes(),
                Self::new(role, secret).digest.as_bytes(),
            )
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_carry_their_role_prefix() {
        for (role, prefix) in [
            (Role::EnrollmentCode, "jse2_"),
            (Role::ClientSecret, "jsc2_"),
            (Role::OperatorSecret, "jso2_"),
        ] {
            let secret = Secret::generate(role);
            assert!(secret.as_str().starts_with(prefix));
            // 43 base64url characters of 32 bytes, unpadded.
            assert_eq!(secret.as_str().len(), prefix.len() + 43);
            assert!(
                secret.as_str()[prefix.len()..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            );
        }
    }

    #[test]
    fn generation_is_random() {
        let a = Secret::generate(Role::ClientSecret).into_string();
        let b = Secret::generate(Role::ClientSecret).into_string();
        assert_ne!(a, b);
        // The no-output property is structural: Secret implements neither Debug
        // nor Display, which is why the test above can format nothing.
        let _ = &a;
    }

    #[test]
    fn a_verifier_matches_only_its_own_domain_and_secret() {
        let secret = Secret::generate(Role::ClientSecret);
        let verifier = Verifier::new(Role::ClientSecret, secret.as_str());
        assert!(verifier.matches(Role::ClientSecret, secret.as_str()));
        // A client secret never passes the operator slot: the domain differs,
        // and neither does a copied digest.
        assert!(!verifier.matches(Role::OperatorSecret, secret.as_str()));
        assert!(!verifier.matches(Role::EnrollmentCode, secret.as_str()));
        assert!(!verifier.matches(Role::ClientSecret, "jsc2_other"));
    }

    #[test]
    fn the_digest_is_sha256_over_domain_zero_and_secret() {
        use sha2::Digest as _;
        let secret = Secret::generate(Role::EnrollmentCode);
        let verifier = Verifier::new(Role::EnrollmentCode, secret.as_str());
        let mut hasher = Sha256::new();
        hasher.update(b"jaynshare/enrollment\x00");
        hasher.update(secret.as_str().as_bytes());
        assert_eq!(verifier.digest, format!("{:x}", hasher.finalize()));
        assert_eq!(verifier.algorithm, "sha256");
        assert_eq!(verifier.domain, "jaynshare/enrollment");
    }
}
