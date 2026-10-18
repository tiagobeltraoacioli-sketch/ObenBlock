//! `SetupConnection`: policy, decoding and the response.
//!
//! The server serves the Mining Protocol (protocol 0), version 2, standard
//! channels (header-only mining, which maps directly onto ObenBlock's
//! header: docs/OBENBLOCK-MINING.md §4). Mining Protocol flags of the
//! client (Stratum V2 spec §5.3.1):
//!
//! * bit 0 `REQUIRES_STANDARD_JOBS`: fine, standard channels are all there is;
//! * bit 1 `REQUIRES_WORK_SELECTION`: refused (no job declaration);
//! * bit 2 `REQUIRES_VERSION_ROLLING`: fine, BIP 320 rolling is allowed (the
//!   success flags never set `REQUIRES_FIXED_VERSION`).
//!
//! Ported from the legacy Bloch server (genesis3-node
//! `src/stratum_v2/setup_connection*.rs`); the hand-written codecs are
//! replaced by SRI's `common_messages_sv2` types.

use common_messages_sv2::{
    Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};

/// SV2 protocol versions this server speaks.
pub const MIN_SUPPORTED_VERSION: u16 = 2;
pub const MAX_SUPPORTED_VERSION: u16 = 2;

pub const FLAG_REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
pub const FLAG_REQUIRES_WORK_SELECTION: u32 = 1 << 1;
pub const FLAG_REQUIRES_VERSION_ROLLING: u32 = 1 << 2;

/// Client flags the server accepts.
pub const KNOWN_FLAG_MASK: u32 = FLAG_REQUIRES_STANDARD_JOBS | FLAG_REQUIRES_VERSION_ROLLING;

/// The SetupConnection fields, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSetupConnection {
    /// Raw protocol discriminant (0 Mining, 1 Job Declaration, 2 Template
    /// Distribution).
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub vendor: String,
    pub hardware_version: String,
    pub firmware: String,
    pub device_id: String,
}

/// Why a SetupConnection is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupRefusal {
    UnsupportedProtocol(u8),
    VersionMismatch { min: u16, max: u16 },
    UnsupportedFlags(u32),
}

impl SetupRefusal {
    /// The SV2 error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::UnsupportedProtocol(_) => "unsupported-protocol",
            Self::VersionMismatch { .. } => "protocol-version-mismatch",
            Self::UnsupportedFlags(_) => "unsupported-feature-flags",
        }
    }
}

impl std::fmt::Display for SetupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProtocol(p) => write!(f, "protocol {p} is not served (Mining Protocol only)"),
            Self::VersionMismatch { min, max } => write!(
                f, "version range {min}..={max} does not overlap {MIN_SUPPORTED_VERSION}..={MAX_SUPPORTED_VERSION}"),
            Self::UnsupportedFlags(b) => write!(f, "unsupported flags {b:#010x}"),
        }
    }
}

/// The policy: `Ok((used_version, success_flags))` or the refusal.
pub fn evaluate(s: &DecodedSetupConnection) -> Result<(u16, u32), SetupRefusal> {
    if s.protocol != Protocol::MiningProtocol as u8 {
        return Err(SetupRefusal::UnsupportedProtocol(s.protocol));
    }
    if s.max_version < MIN_SUPPORTED_VERSION || s.min_version > MAX_SUPPORTED_VERSION || s.min_version > s.max_version {
        return Err(SetupRefusal::VersionMismatch { min: s.min_version, max: s.max_version });
    }
    let unknown = s.flags & !KNOWN_FLAG_MASK;
    if unknown != 0 {
        return Err(SetupRefusal::UnsupportedFlags(unknown));
    }
    // Success flags: neither REQUIRES_FIXED_VERSION nor
    // REQUIRES_EXTENDED_CHANNELS.
    Ok((s.max_version.min(MAX_SUPPORTED_VERSION), 0))
}

/// Decode errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("expected SetupConnection (0x00), got message type {0:#04x}")]
    UnexpectedMessageType(u8),
    #[error("binary_sv2: {0}")]
    Binary(String),
    #[error("field {0} is not UTF-8")]
    NotUtf8(&'static str),
}

fn owned(bytes: &[u8], field: &'static str) -> Result<String, DecodeError> {
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| DecodeError::NotUtf8(field))
}

/// Decode the payload of a frame of type `msg_type` as SetupConnection.
pub fn decode_setup_connection(msg_type: u8, payload: &mut [u8]) -> Result<DecodedSetupConnection, DecodeError> {
    if msg_type != MESSAGE_TYPE_SETUP_CONNECTION {
        return Err(DecodeError::UnexpectedMessageType(msg_type));
    }
    let m: SetupConnection = binary_sv2::from_bytes(payload).map_err(|e| DecodeError::Binary(format!("{e:?}")))?;
    Ok(DecodedSetupConnection {
        protocol: m.protocol as u8,
        min_version: m.min_version,
        max_version: m.max_version,
        flags: m.flags,
        endpoint_host: owned(m.endpoint_host.inner_as_ref(), "endpoint_host")?,
        endpoint_port: m.endpoint_port,
        vendor: owned(m.vendor.inner_as_ref(), "vendor")?,
        hardware_version: owned(m.hardware_version.inner_as_ref(), "hardware_version")?,
        firmware: owned(m.firmware.inner_as_ref(), "firmware")?,
        device_id: owned(m.device_id.inner_as_ref(), "device_id")?,
    })
}

/// The response to a SetupConnection: `(msg_type, payload)`.
pub fn encode_response(outcome: &Result<(u16, u32), SetupRefusal>) -> Result<(u8, Vec<u8>), String> {
    match outcome {
        Ok((used_version, flags)) => {
            let m = SetupConnectionSuccess { used_version: *used_version, flags: *flags };
            Ok((MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, binary_sv2::to_bytes(m).map_err(|e| format!("{e:?}"))?))
        }
        Err(refusal) => {
            let m = SetupConnectionError {
                flags: match refusal {
                    SetupRefusal::UnsupportedFlags(b) => *b,
                    _ => 0,
                },
                error_code: refusal.error_code().to_string().try_into().map_err(|e| format!("{e:?}"))?,
            };
            Ok((MESSAGE_TYPE_SETUP_CONNECTION_ERROR, binary_sv2::to_bytes(m).map_err(|e| format!("{e:?}"))?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(protocol: u8, min: u16, max: u16, flags: u32) -> DecodedSetupConnection {
        DecodedSetupConnection {
            protocol, min_version: min, max_version: max, flags,
            endpoint_host: String::new(), endpoint_port: 3334, vendor: "v".into(),
            hardware_version: String::new(), firmware: String::new(), device_id: String::new(),
        }
    }

    #[test]
    fn accepts_mining_protocol_with_standard_jobs_and_version_rolling() {
        assert_eq!(evaluate(&setup(0, 2, 2, 0)), Ok((2, 0)));
        assert_eq!(evaluate(&setup(0, 2, 2, FLAG_REQUIRES_STANDARD_JOBS | FLAG_REQUIRES_VERSION_ROLLING)), Ok((2, 0)));
        assert_eq!(evaluate(&setup(0, 2, 3, 0)), Ok((2, 0)), "negotiates down to 2");
    }

    #[test]
    fn rejects_other_protocols_versions_and_work_selection() {
        assert_eq!(evaluate(&setup(1, 2, 2, 0)), Err(SetupRefusal::UnsupportedProtocol(1)));
        assert_eq!(evaluate(&setup(2, 2, 2, 0)), Err(SetupRefusal::UnsupportedProtocol(2)));
        assert_eq!(evaluate(&setup(9, 2, 2, 0)), Err(SetupRefusal::UnsupportedProtocol(9)));
        assert_eq!(evaluate(&setup(0, 1, 1, 0)), Err(SetupRefusal::VersionMismatch { min: 1, max: 1 }));
        assert_eq!(evaluate(&setup(0, 3, 4, 0)), Err(SetupRefusal::VersionMismatch { min: 3, max: 4 }));
        assert_eq!(evaluate(&setup(0, 2, 2, FLAG_REQUIRES_WORK_SELECTION)),
                   Err(SetupRefusal::UnsupportedFlags(FLAG_REQUIRES_WORK_SELECTION)));
        assert_eq!(evaluate(&setup(0, 2, 2, 1 | 1 << 30)), Err(SetupRefusal::UnsupportedFlags(1 << 30)));
    }

    #[test]
    fn error_codes_match_the_spec_strings() {
        assert_eq!(SetupRefusal::UnsupportedProtocol(1).error_code(), "unsupported-protocol");
        assert_eq!(SetupRefusal::VersionMismatch { min: 1, max: 1 }.error_code(), "protocol-version-mismatch");
        assert_eq!(SetupRefusal::UnsupportedFlags(2).error_code(), "unsupported-feature-flags");
    }

    #[test]
    fn decode_round_trips_an_sri_encoded_message() {
        let m = SetupConnection {
            protocol: Protocol::MiningProtocol, min_version: 2, max_version: 2, flags: 0b101,
            endpoint_host: "pool.example".to_string().try_into().unwrap(), endpoint_port: 3334,
            vendor: "sv2-test".to_string().try_into().unwrap(),
            hardware_version: "".to_string().try_into().unwrap(),
            firmware: "0.1".to_string().try_into().unwrap(),
            device_id: "rig7".to_string().try_into().unwrap(),
        };
        let mut payload = binary_sv2::to_bytes(m).unwrap();
        let d = decode_setup_connection(MESSAGE_TYPE_SETUP_CONNECTION, &mut payload).unwrap();
        assert_eq!((d.protocol, d.min_version, d.max_version, d.flags), (0, 2, 2, 0b101));
        assert_eq!((d.endpoint_host.as_str(), d.endpoint_port), ("pool.example", 3334));
        assert_eq!((d.vendor.as_str(), d.firmware.as_str(), d.device_id.as_str()), ("sv2-test", "0.1", "rig7"));
        assert_eq!(decode_setup_connection(0x01, &mut payload.clone()), Err(DecodeError::UnexpectedMessageType(1)));
        assert!(decode_setup_connection(MESSAGE_TYPE_SETUP_CONNECTION, &mut [0u8; 3]).is_err(), "truncated");
    }

    #[test]
    fn responses_decode_as_sri_types() {
        let (t, mut p) = encode_response(&Ok((2, 0))).unwrap();
        assert_eq!(t, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS);
        let s: SetupConnectionSuccess = binary_sv2::from_bytes(&mut p).unwrap();
        assert_eq!((s.used_version, s.flags), (2, 0));
        for refusal in [SetupRefusal::UnsupportedProtocol(1), SetupRefusal::VersionMismatch { min: 1, max: 1 },
                        SetupRefusal::UnsupportedFlags(2)] {
            let (t, mut p) = encode_response(&Err(refusal.clone())).unwrap();
            assert_eq!(t, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
            let e: SetupConnectionError = binary_sv2::from_bytes(&mut p).unwrap();
            assert_eq!(e.error_code.inner_as_ref(), refusal.error_code().as_bytes());
        }
    }
}
