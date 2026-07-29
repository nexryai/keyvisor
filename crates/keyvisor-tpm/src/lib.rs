//! TPM boundary for Keyvisor.
//!
//! This interface is intentionally shaped so callers can request generation
//! and signing without ever receiving plaintext private parameters. The ESAPI
//! module is the only implementation allowed to cross that trust boundary.

use keyvisor_core::{KeyAlgorithm, KeySummary};
use std::fmt;

mod esapi;

pub use esapi::EsapiTpm;

/// Authorization supplied to one TPM command.
///
/// The PIN is borrowed so this boundary cannot retain or clone it. Callers must
/// keep its backing buffer short-lived and clear owned storage after use.
#[derive(Clone, Copy)]
pub enum TpmAuthorization<'a> {
    /// Authorize a key created with an empty authorization value.
    None,
    /// Authorize a DA-protected key without persisting the PIN.
    Pin(&'a [u8]),
}

/// A serialized reference to a TPM object.
///
/// `wrapped_private` is the encrypted and integrity-protected `TPM2B_PRIVATE`
/// object returned by the TPM. It is not a plaintext private key.
#[derive(Clone, Eq, PartialEq)]
pub struct TpmObject {
    pub public: Vec<u8>,
    pub wrapped_private: Vec<u8>,
    pub parent_name: Vec<u8>,
    pub use_policy: keyvisor_core::KeyUsePolicy,
}

impl fmt::Debug for TpmObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TpmObject")
            .field("public_len", &self.public.len())
            .field("wrapped_private", &"[redacted]")
            .field("parent_name", &self.parent_name)
            .field("use_policy", &self.use_policy)
            .finish()
    }
}

/// Read-only snapshot of the TPM-wide dictionary-attack state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DictionaryAttackState {
    pub failed_tries: u32,
    pub max_tries: u32,
    pub recovery_time_seconds: u32,
    pub lockout_recovery_seconds: u32,
}

/// Errors surfaced at the TPM trust boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TpmError {
    Unavailable,
    UnsupportedAlgorithm,
    InvalidAuthorization,
    AuthorizationFailed,
    DictionaryAttackLockout,
    PolicyFailed,
    InvalidObject,
    Transport,
}

impl fmt::Display for TpmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "TPM is unavailable",
            Self::UnsupportedAlgorithm => "TPM algorithm is unsupported",
            Self::InvalidAuthorization => "TPM authorization is invalid",
            Self::AuthorizationFailed => "TPM authorization failed",
            Self::DictionaryAttackLockout => "TPM dictionary-attack lockout is active",
            Self::PolicyFailed => "TPM policy check failed",
            Self::InvalidObject => "TPM object metadata is invalid",
            Self::Transport => "TPM transport failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TpmError {}

/// Operations the SSH agent is allowed to perform on the TPM.
pub trait TpmSigner {
    /// Generates a non-migratable signing object inside the TPM.
    ///
    /// # Errors
    ///
    /// Returns a [`TpmError`] if the TPM is unavailable, rejects the requested
    /// policy, or cannot create the object without weakening its attributes.
    fn generate(
        &mut self,
        name: &str,
        algorithm: KeyAlgorithm,
        authorization: TpmAuthorization<'_>,
    ) -> Result<(KeySummary, TpmObject), TpmError>;

    /// Signs a bounded digest using `TPM2_Sign`.
    ///
    /// # Errors
    ///
    /// Returns a [`TpmError`] if the object cannot be loaded, its authorization
    /// or policy fails, or the TPM transport is unavailable.
    fn sign(
        &mut self,
        key: &TpmObject,
        digest: &[u8],
        authorization: TpmAuthorization<'_>,
    ) -> Result<Vec<u8>, TpmError>;

    /// Reads the TPM-wide dictionary-attack counters without modifying them.
    ///
    /// # Errors
    ///
    /// Returns a [`TpmError`] when the properties cannot be read.
    fn dictionary_attack_state(&mut self) -> Result<DictionaryAttackState, TpmError>;
}
