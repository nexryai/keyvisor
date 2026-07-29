//! Bounded OpenSSH agent protocol parsing and serialization.

use std::fmt;

use keyvisor_core::KeySummary;

pub const MAX_PACKET_LENGTH: usize = 256 * 1024;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const ECDSA_SHA2_NISTP256: &[u8] = b"ecdsa-sha2-nistp256";

/// Supported, fully validated agent requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRequest<'a> {
    RequestIdentities,
    Sign {
        public_key: &'a [u8],
        data: &'a [u8],
        flags: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    EmptyPacket,
    PacketTooLarge,
    Truncated,
    TrailingData,
    UnsupportedRequest,
    InvalidSignature,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPacket => "SSH agent packet is empty",
            Self::PacketTooLarge => "SSH agent packet exceeds its limit",
            Self::Truncated => "SSH agent packet is truncated",
            Self::TrailingData => "SSH agent packet has trailing data",
            Self::UnsupportedRequest => "SSH agent request is unsupported",
            Self::InvalidSignature => "TPM ECDSA signature is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProtocolError {}

/// Parses one payload after its outer four-byte packet length.
///
/// # Errors
///
/// Returns [`ProtocolError`] for empty, oversized, truncated, trailing, or
/// unsupported input.
pub fn parse_request(packet: &[u8]) -> Result<AgentRequest<'_>, ProtocolError> {
    if packet.is_empty() {
        return Err(ProtocolError::EmptyPacket);
    }
    if packet.len() > MAX_PACKET_LENGTH {
        return Err(ProtocolError::PacketTooLarge);
    }

    let Some((message_type, mut input)) = packet.split_first() else {
        return Err(ProtocolError::EmptyPacket);
    };
    match *message_type {
        SSH2_AGENTC_REQUEST_IDENTITIES => {
            ensure_empty(input)?;
            Ok(AgentRequest::RequestIdentities)
        }
        SSH2_AGENTC_SIGN_REQUEST => {
            // Requests borrow the bounded packet buffer so signed payloads are
            // not copied into longer-lived agent state.
            let public_key = take_string(&mut input)?;
            let data = take_string(&mut input)?;
            let flags = take_u32(&mut input)?;
            ensure_empty(input)?;
            Ok(AgentRequest::Sign {
                public_key,
                data,
                flags,
            })
        }
        _ => Err(ProtocolError::UnsupportedRequest),
    }
}

#[must_use]
pub fn failure_response() -> Vec<u8> {
    frame(&[SSH_AGENT_FAILURE])
}

/// Encodes all public identities known to Keyvisor.
///
/// # Errors
///
/// Returns [`ProtocolError::PacketTooLarge`] if the aggregate response exceeds
/// the configured protocol bound.
pub fn identities_response(keys: &[KeySummary]) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    payload.push(SSH2_AGENT_IDENTITIES_ANSWER);
    let count = u32::try_from(keys.len()).map_err(|_| ProtocolError::PacketTooLarge)?;
    payload.extend_from_slice(&count.to_be_bytes());
    for key in keys {
        push_string(&mut payload, &key.public_key)?;
        push_string(&mut payload, key.name.as_bytes())?;
    }
    checked_frame(&payload)
}

/// Encodes a raw 64-byte TPM ECDSA P-256 signature for OpenSSH.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidSignature`] unless `signature` contains
/// exactly 32-byte `r` and `s` components.
pub fn ecdsa_signature_response(signature: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let (r, s) = signature
        .split_at_checked(32)
        .filter(|(_, s)| s.len() == 32)
        .ok_or(ProtocolError::InvalidSignature)?;

    let mut ecdsa = Vec::with_capacity(74);
    push_mpint(&mut ecdsa, r)?;
    push_mpint(&mut ecdsa, s)?;

    let mut signature_blob = Vec::with_capacity(104);
    push_string(&mut signature_blob, ECDSA_SHA2_NISTP256)?;
    push_string(&mut signature_blob, &ecdsa)?;

    let mut payload = Vec::with_capacity(signature_blob.len() + 5);
    payload.push(SSH2_AGENT_SIGN_RESPONSE);
    push_string(&mut payload, &signature_blob)?;
    checked_frame(&payload)
}

fn take_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], ProtocolError> {
    let length = usize::try_from(take_u32(input)?).map_err(|_| ProtocolError::PacketTooLarge)?;
    take(input, length)
}

fn take_u32(input: &mut &[u8]) -> Result<u32, ProtocolError> {
    let bytes: [u8; 4] = take(input, 4)?
        .try_into()
        .map_err(|_| ProtocolError::Truncated)?;
    Ok(u32::from_be_bytes(bytes))
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], ProtocolError> {
    if input.len() < length {
        return Err(ProtocolError::Truncated);
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn ensure_empty(input: &[u8]) -> Result<(), ProtocolError> {
    // Strict consumption avoids accepting ambiguous packets that another
    // implementation might interpret as two different requests.
    if input.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::TrailingData)
    }
}

fn push_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let length = u32::try_from(value.len()).map_err(|_| ProtocolError::PacketTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    if output.len() > MAX_PACKET_LENGTH {
        return Err(ProtocolError::PacketTooLarge);
    }
    Ok(())
}

fn push_mpint(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProtocolError> {
    let value = value
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first| &value[first..]);
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        // SSH mpints are signed. Prefixing a high-bit scalar with zero keeps
        // the TPM's unsigned ECDSA component positive.
        let mut positive = Vec::with_capacity(value.len() + 1);
        positive.push(0);
        positive.extend_from_slice(value);
        push_string(output, &positive)
    } else {
        push_string(output, value)
    }
}

fn checked_frame(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if payload.len() > MAX_PACKET_LENGTH {
        return Err(ProtocolError::PacketTooLarge);
    }
    Ok(frame(payload))
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("bounded agent response length");
    let mut packet = Vec::with_capacity(payload.len() + 4);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[cfg(test)]
mod tests {
    use keyvisor_core::{KeyAlgorithm, KeyId, KeySummary, KeyUsePolicy};

    use super::{
        AgentRequest, MAX_PACKET_LENGTH, ProtocolError, ecdsa_signature_response, failure_response,
        identities_response, parse_request,
    };

    fn ssh_string(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(
            &u32::try_from(value.len())
                .expect("test value fits")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }

    fn take_test_string<'a>(input: &mut &'a [u8]) -> &'a [u8] {
        let length = u32::from_be_bytes(
            input[..4]
                .try_into()
                .expect("encoded test string has a length"),
        );
        *input = &input[4..];
        let length = usize::try_from(length).expect("test string length fits");
        let (value, remainder) = input.split_at(length);
        *input = remainder;
        value
    }

    #[test]
    fn parses_bounded_sign_request() {
        let mut packet = vec![13];
        ssh_string(&mut packet, b"public");
        ssh_string(&mut packet, b"session payload");
        packet.extend_from_slice(&0_u32.to_be_bytes());

        assert_eq!(
            parse_request(&packet),
            Ok(AgentRequest::Sign {
                public_key: b"public",
                data: b"session payload",
                flags: 0,
            })
        );
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_requests() {
        // Empty and unknown packets must fail instead of being interpreted as
        // a harmless identity query by a more permissive code path.
        assert_eq!(parse_request(&[]), Err(ProtocolError::EmptyPacket));
        assert_eq!(parse_request(&[99]), Err(ProtocolError::UnsupportedRequest));

        // Exact consumption prevents request smuggling through bytes appended
        // after an otherwise valid identity message.
        assert_eq!(parse_request(&[11, 0]), Err(ProtocolError::TrailingData));

        // A declared SSH string length must never make the parser read a
        // partial key or payload.
        assert_eq!(
            parse_request(&[13, 0, 0, 0, 4, 1]),
            Err(ProtocolError::Truncated)
        );

        // The packet bound is enforced before parsing nested strings, limiting
        // memory and CPU use by any process that can reach the user socket.
        let oversized = vec![11; MAX_PACKET_LENGTH + 1];
        assert_eq!(
            parse_request(&oversized),
            Err(ProtocolError::PacketTooLarge)
        );
    }

    #[test]
    fn encodes_identity_response_with_the_expected_wire_shape() {
        let key = KeySummary {
            id: KeyId::new("id"),
            name: "Work".to_owned(),
            algorithm: KeyAlgorithm::EcdsaNistP256,
            use_policy: KeyUsePolicy::NoPin,
            public_key: vec![1, 2, 3],
        };
        let identities = identities_response(&[key]).expect("encode identities");

        // OpenSSH expects the outer frame, response type, and identity count in
        // this exact order before the public-key and comment strings.
        assert_eq!(&identities[..9], &[0, 0, 0, 20, 12, 0, 0, 0, 1]);
    }

    #[test]
    fn encodes_canonical_positive_ecdsa_mpints() {
        let mut raw = [0_u8; 64];
        raw[0] = 0x80;
        raw[63] = 1;
        let signature = ecdsa_signature_response(&raw).expect("encode signature");

        let mut packet = signature.as_slice();
        let framed_payload = take_test_string(&mut packet);
        assert!(packet.is_empty(), "the outer frame has no trailing bytes");
        assert_eq!(framed_payload[0], 14);

        let mut response = &framed_payload[1..];
        let mut signature_blob = take_test_string(&mut response);
        assert!(
            response.is_empty(),
            "the sign response contains one signature blob"
        );
        assert_eq!(
            take_test_string(&mut signature_blob),
            b"ecdsa-sha2-nistp256"
        );
        let mut scalars = take_test_string(&mut signature_blob);
        assert!(signature_blob.is_empty());

        let r = take_test_string(&mut scalars);
        let s = take_test_string(&mut scalars);
        assert!(scalars.is_empty());

        // An unsigned TPM scalar with its high bit set needs a zero prefix so
        // SSH's signed mpint representation remains positive.
        assert_eq!(r.len(), 33);
        assert_eq!(r[0], 0);
        assert_eq!(r[1], 0x80);

        // Leading zeroes are stripped from positive scalars to keep the mpint
        // canonical and acceptable to strict OpenSSH decoders.
        assert_eq!(s, &[1]);
    }

    #[test]
    fn encodes_zero_scalars_and_rejects_wrong_signature_lengths() {
        let signature = ecdsa_signature_response(&[0; 64]).expect("encode zero scalars");
        let mut packet = signature.as_slice();
        let framed_payload = take_test_string(&mut packet);
        let mut response = &framed_payload[1..];
        let mut signature_blob = take_test_string(&mut response);
        let _algorithm = take_test_string(&mut signature_blob);
        let mut scalars = take_test_string(&mut signature_blob);

        // SSH represents zero as an empty mpint, not as a one-byte zero. This
        // is important even though a real ECDSA signature cannot contain zero.
        assert!(take_test_string(&mut scalars).is_empty());
        assert!(take_test_string(&mut scalars).is_empty());

        // The TPM backend contract is a fixed r||s encoding. Accepting any
        // other size could silently split the two components at the wrong byte.
        assert_eq!(
            ecdsa_signature_response(&[0; 63]),
            Err(ProtocolError::InvalidSignature)
        );
        assert_eq!(
            ecdsa_signature_response(&[0; 65]),
            Err(ProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn bounds_responses_and_uses_the_standard_failure_frame() {
        let oversized_key = KeySummary {
            id: KeyId::new("large"),
            name: "Large".to_owned(),
            algorithm: KeyAlgorithm::EcdsaNistP256,
            use_policy: KeyUsePolicy::NoPin,
            public_key: vec![0; MAX_PACKET_LENGTH],
        };

        // Response bounds are as important as request bounds because persisted
        // records are not trusted to fit into a single agent packet.
        assert_eq!(
            identities_response(&[oversized_key]),
            Err(ProtocolError::PacketTooLarge)
        );

        // Unsupported and failed operations use the exact RFC agent failure
        // packet that OpenSSH understands.
        assert_eq!(failure_response(), [0, 0, 0, 1, 5]);
    }
}
