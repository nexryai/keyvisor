//! Domain types shared by Keyvisor processes.
//!
//! This crate deliberately has no TPM or command-line dependencies. In particular, it
//! must not grow a type capable of containing plaintext private key material.

/// Stable identifier assigned to a TPM-backed key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(String);

impl KeyId {
    /// Creates an identifier after metadata validation.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the serialized identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Signing algorithms exposed by the first Keyvisor protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAlgorithm {
    /// ECDSA over the TPM-supported NIST P-256 curve.
    EcdsaNistP256,
    /// ECDSA over the TPM-supported NIST P-384 curve.
    EcdsaNistP384,
}

impl KeyAlgorithm {
    /// Returns the OpenSSH key type.
    #[must_use]
    pub const fn ssh_key_type(self) -> &'static str {
        match self {
            Self::EcdsaNistP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaNistP384 => "ecdsa-sha2-nistp384",
        }
    }

    /// Returns the SSH curve identifier.
    #[must_use]
    pub const fn ssh_curve_name(self) -> &'static str {
        match self {
            Self::EcdsaNistP256 => "nistp256",
            Self::EcdsaNistP384 => "nistp384",
        }
    }

    /// Returns the required signing digest length in bytes.
    #[must_use]
    pub const fn digest_size(self) -> usize {
        match self {
            Self::EcdsaNistP256 => 32,
            Self::EcdsaNistP384 => 48,
        }
    }

    /// Returns the fixed width of an ECDSA scalar or public coordinate.
    #[must_use]
    pub const fn ecdsa_component_size(self) -> usize {
        match self {
            Self::EcdsaNistP256 => 32,
            Self::EcdsaNistP384 => 48,
        }
    }
}

/// Authorization mode selected when a TPM signing object is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyUsePolicy {
    /// The TPM accepts signing operations without an authorization value.
    NoPin,
    /// Every signing operation requires the key's TPM-protected PIN.
    TpmPin,
}

/// Public, display-safe information about a signing key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySummary {
    pub id: KeyId,
    pub name: String,
    pub algorithm: KeyAlgorithm,
    pub use_policy: KeyUsePolicy,
    /// SSH wire-format public key blob. This never contains private material.
    pub public_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::{KeyId, KeyUsePolicy};

    #[test]
    fn key_id_round_trips() {
        let id = KeyId::new("example");
        assert_eq!(id.as_str(), "example");
    }

    #[test]
    fn use_policies_are_explicit() {
        assert_ne!(KeyUsePolicy::NoPin, KeyUsePolicy::TpmPin);
    }
}
