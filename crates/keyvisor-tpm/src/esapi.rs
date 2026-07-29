use std::str::FromStr;

use keyvisor_core::{KeyAlgorithm, KeyId, KeySummary, KeyUsePolicy};
use tss_esapi::{
    Context, Error,
    abstraction::cipher::Cipher,
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{
        PropertyTag, SessionType, Tss2ResponseCodeKind,
        tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    },
    handles::{KeyHandle, ObjectHandle, SessionHandle},
    interface_types::{
        algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Private, Public,
        PublicBuilder, PublicEccParametersBuilder, RsaExponent, Signature, SignatureScheme,
        SymmetricDefinition,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
    tss2_esys::{TPM2B_DIGEST, TPMT_TK_HASHCHECK},
    utils,
};

use crate::{DictionaryAttackState, TpmAuthorization, TpmError, TpmObject, TpmSigner};

/// TPM2-TSS ESAPI-backed signer.
///
/// The storage parent is a deterministic primary object recreated for each
/// process. Creating it does not take ownership or persist a TPM handle.
pub struct EsapiTpm {
    context: Context,
    parent: KeyHandle,
    parent_name: Vec<u8>,
}

impl EsapiTpm {
    /// Connects using an explicit TCTI string such as `device` or
    /// `swtpm:host=127.0.0.1,port=2321`.
    ///
    /// # Errors
    ///
    /// Returns a [`TpmError`] if the TCTI is invalid, the TPM is unavailable,
    /// or the deterministic storage parent cannot be created.
    pub fn connect(tcti: &str) -> Result<Self, TpmError> {
        let tcti = TctiNameConf::from_str(tcti).map_err(|_| TpmError::Unavailable)?;
        let mut context = Context::new(tcti).map_err(map_tss_error)?;
        let parent_public = utils::create_restricted_decryption_rsa_public(
            Cipher::aes_128_cfb().try_into().map_err(map_tss_error)?,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .map_err(map_tss_error)?;

        // The owner hierarchy and the Keyvisor parent intentionally have empty
        // authorization values. No user PIN is present in this command.
        let parent = context
            .execute_with_nullauth_session(|context| {
                context.create_primary(Hierarchy::Owner, parent_public, None, None, None, None)
            })
            .map_err(map_tss_error)?
            .key_handle;
        let parent_name = context
            .tr_get_name(parent.into())
            .map_err(map_tss_error)?
            .value()
            .to_vec();

        Ok(Self {
            context,
            parent,
            parent_name,
        })
    }

    /// Connects using `TPM2TOOLS_TCTI`, `TCTI`, or `TEST_TCTI`; otherwise uses
    /// the default TPM resource-manager device.
    ///
    /// # Errors
    ///
    /// Returns a [`TpmError`] if the TPM cannot be opened.
    pub fn connect_default() -> Result<Self, TpmError> {
        let tcti = std::env::var("TPM2TOOLS_TCTI")
            .or_else(|_| std::env::var("TCTI"))
            .or_else(|_| std::env::var("TEST_TCTI"))
            .unwrap_or_else(|_| String::from("device"));
        Self::connect(&tcti)
    }

    fn create_public(use_policy: KeyUsePolicy) -> Result<Public, TpmError> {
        // These attributes are the extraction boundary: the TPM creates the
        // sensitive value and binds it to this TPM and this parent. `noDA` is
        // deliberately policy-dependent so only PIN keys consume DA attempts.
        let attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(use_policy == KeyUsePolicy::NoPin)
            .with_restricted(false)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .build()
            .map_err(map_tss_error)?;
        let scheme = EccScheme::create(
            EccSchemeAlgorithm::EcDsa,
            Some(HashingAlgorithm::Sha256),
            None,
        )
        .map_err(map_tss_error)?;
        let parameters =
            PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, EccCurve::NistP256)
                .build()
                .map_err(map_tss_error)?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_ecc_parameters(parameters)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(map_tss_error)
    }

    fn validate_public(public: &Public, use_policy: KeyUsePolicy) -> Result<(), TpmError> {
        // Persisted TPM2B_PUBLIC bytes are host-controlled input. Re-check the
        // complete security-relevant template before loading the paired blob.
        let attributes = public.object_attributes();
        if !attributes.fixed_tpm()
            || !attributes.fixed_parent()
            || !attributes.sensitive_data_origin()
            || !attributes.user_with_auth()
            || !attributes.sign_encrypt()
            || attributes.decrypt()
            || attributes.restricted()
            || attributes.no_da() != (use_policy == KeyUsePolicy::NoPin)
        {
            return Err(TpmError::InvalidObject);
        }

        match public {
            Public::Ecc { parameters, .. }
                if parameters.ecc_curve() == EccCurve::NistP256
                    && parameters.ecc_scheme()
                        == EccScheme::create(
                            EccSchemeAlgorithm::EcDsa,
                            Some(HashingAlgorithm::Sha256),
                            None,
                        )
                        .map_err(map_tss_error)? =>
            {
                Ok(())
            }
            _ => Err(TpmError::InvalidObject),
        }
    }

    fn load(&mut self, object: &TpmObject) -> Result<KeyHandle, TpmError> {
        // Reject blobs created under another parent before asking the TPM to
        // process them; this also gives corrupted records a stable error path.
        if object.parent_name != self.parent_name {
            return Err(TpmError::InvalidObject);
        }
        let public = Public::unmarshall(&object.public).map_err(|_| TpmError::InvalidObject)?;
        Self::validate_public(&public, object.use_policy)?;
        let private = Private::try_from(object.wrapped_private.clone())
            .map_err(|_| TpmError::InvalidObject)?;
        with_encrypted_session(&mut self.context, self.parent, None, |context| {
            context.load(self.parent, private, public)
        })
        .map_err(map_tss_error)
    }
}

impl TpmSigner for EsapiTpm {
    fn generate(
        &mut self,
        name: &str,
        algorithm: KeyAlgorithm,
        authorization: TpmAuthorization<'_>,
    ) -> Result<(KeySummary, TpmObject), TpmError> {
        if algorithm != KeyAlgorithm::EcdsaNistP256 {
            return Err(TpmError::UnsupportedAlgorithm);
        }
        let (auth, use_policy) = authorization_value(authorization)?;
        let requested_public = Self::create_public(use_policy)?;
        // TPM2_Create generates the private scalar internally. `out_private`
        // is a TPM-wrapped blob and never contains an exportable private key.
        let result = with_encrypted_session(&mut self.context, self.parent, None, |context| {
            context.create(self.parent, requested_public, Some(auth), None, None, None)
        })
        .map_err(map_tss_error)?;

        Self::validate_public(&result.out_public, use_policy)?;
        let ssh_public_key = ssh_public_key(&result.out_public)?;
        let child = with_encrypted_session(&mut self.context, self.parent, None, |context| {
            context.load(
                self.parent,
                result.out_private.clone(),
                result.out_public.clone(),
            )
        })
        .map_err(map_tss_error)?;
        let child_name = self
            .context
            .tr_get_name(child.into())
            .map_err(map_tss_error)?
            .value()
            .to_vec();
        self.context
            .flush_context(child.into())
            .map_err(map_tss_error)?;

        let object = TpmObject {
            public: result.out_public.marshall().map_err(map_tss_error)?,
            wrapped_private: result.out_private.value().to_vec(),
            parent_name: self.parent_name.clone(),
            use_policy,
        };
        let summary = KeySummary {
            id: KeyId::new(hex(&child_name)),
            name: name.to_owned(),
            algorithm,
            use_policy,
            public_key: ssh_public_key,
        };

        Ok((summary, object))
    }

    fn sign(
        &mut self,
        key: &TpmObject,
        digest: &[u8],
        authorization: TpmAuthorization<'_>,
    ) -> Result<Vec<u8>, TpmError> {
        if digest.len() != 32 {
            return Err(TpmError::InvalidObject);
        }
        let (auth, use_policy) = authorization_value(authorization)?;
        if use_policy != key.use_policy {
            return Err(TpmError::InvalidAuthorization);
        }

        let child = self.load(key)?;
        self.context
            .tr_set_auth(child.into(), auth)
            .map_err(map_tss_error)?;
        let digest = Digest::try_from(digest).map_err(map_tss_error)?;
        let validation = HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: TPM2B_DIGEST::default(),
        })
        .map_err(map_tss_error)?;
        let signature = with_encrypted_session(
            &mut self.context,
            self.parent,
            Some(child.into()),
            |context| {
                context.sign(
                    child,
                    digest,
                    SignatureScheme::EcDsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    validation,
                )
            },
        )
        .map_err(map_tss_error);

        // Always release the transient object, including after failed PIN
        // authorization. Preserve the command error when both operations fail.
        let flush = self
            .context
            .flush_context(child.into())
            .map_err(map_tss_error);
        let signature = match (signature, flush) {
            (Err(error), _) | (Ok(_), Err(error)) => return Err(error),
            (Ok(signature), Ok(())) => signature,
        };

        match signature {
            Signature::EcDsa(signature) => {
                let mut raw = Vec::with_capacity(64);
                append_padded_32(&mut raw, signature.signature_r().value())?;
                append_padded_32(&mut raw, signature.signature_s().value())?;
                Ok(raw)
            }
            _ => Err(TpmError::InvalidObject),
        }
    }

    fn dictionary_attack_state(&mut self) -> Result<DictionaryAttackState, TpmError> {
        Ok(DictionaryAttackState {
            failed_tries: required_property(&mut self.context, PropertyTag::LockoutCounter)?,
            max_tries: required_property(&mut self.context, PropertyTag::MaxAuthFail)?,
            recovery_time_seconds: required_property(
                &mut self.context,
                PropertyTag::LockoutInterval,
            )?,
            lockout_recovery_seconds: required_property(
                &mut self.context,
                PropertyTag::LockoutRecovery,
            )?,
        })
    }
}

fn authorization_value(
    authorization: TpmAuthorization<'_>,
) -> Result<(Auth, KeyUsePolicy), TpmError> {
    // An empty PIN must not silently downgrade to the no-PIN object policy.
    // Policy is derived from the typed authorization rather than caller flags.
    match authorization {
        TpmAuthorization::None => Ok((Auth::default(), KeyUsePolicy::NoPin)),
        TpmAuthorization::Pin([]) => Err(TpmError::InvalidAuthorization),
        TpmAuthorization::Pin(pin) => Auth::try_from(pin)
            .map(|auth| (auth, KeyUsePolicy::TpmPin))
            .map_err(|_| TpmError::InvalidAuthorization),
    }
}

fn with_encrypted_session<T>(
    context: &mut Context,
    salt_key: KeyHandle,
    bind: Option<ObjectHandle>,
    operation: impl FnOnce(&mut Context) -> Result<T, Error>,
) -> Result<T, Error> {
    // Salt the HMAC session with the TPM parent and enable parameter
    // encryption. PIN-bearing command and response parameters must never use
    // an unencrypted password session.
    let session = context
        .start_auth_session(
            Some(salt_key),
            bind,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(tss_esapi::WrapperErrorKind::WrongValueFromTpm)
        .map_err(Error::WrapperError)?;
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(session, attributes, mask)?;
    let result = context.execute_with_session(Some(session), operation);
    let flush = context.flush_context(SessionHandle::from(session).into());
    match (result, flush) {
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn required_property(context: &mut Context, property: PropertyTag) -> Result<u32, TpmError> {
    context
        .get_tpm_property(property)
        .map_err(map_tss_error)?
        .ok_or(TpmError::Transport)
}

fn ssh_public_key(public: &Public) -> Result<Vec<u8>, TpmError> {
    let Public::Ecc { unique, .. } = public else {
        return Err(TpmError::InvalidObject);
    };
    let mut point = Vec::with_capacity(65);
    point.push(4);
    append_padded_32(&mut point, unique.x().value())?;
    append_padded_32(&mut point, unique.y().value())?;

    let mut blob = Vec::with_capacity(104);
    append_ssh_string(&mut blob, b"ecdsa-sha2-nistp256");
    append_ssh_string(&mut blob, b"nistp256");
    append_ssh_string(&mut blob, &point);
    Ok(blob)
}

fn append_ssh_string(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("SSH field is bounded by TPM structure sizes");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn append_padded_32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TpmError> {
    if value.len() > 32 {
        return Err(TpmError::InvalidObject);
    }
    output.resize(output.len() + (32 - value.len()), 0);
    output.extend_from_slice(value);
    Ok(())
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn map_tss_error(error: Error) -> TpmError {
    // Keep low-level TPM response details inside this crate. Callers need
    // actionable authorization/lockout classes, not raw transport internals.
    match error {
        Error::Tss2Error(code) => match code.kind() {
            Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
                TpmError::AuthorizationFailed
            }
            Some(Tss2ResponseCodeKind::Lockout) => TpmError::DictionaryAttackLockout,
            Some(Tss2ResponseCodeKind::Policy | Tss2ResponseCodeKind::PolicyFail) => {
                TpmError::PolicyFailed
            }
            _ => TpmError::Transport,
        },
        Error::WrapperError(_) => TpmError::Transport,
    }
}
