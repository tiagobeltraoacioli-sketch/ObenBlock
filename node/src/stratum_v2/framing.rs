//! SV2 frames on a Noise transport (Stratum V2 spec §3 "Framing" and §4.5
//! "Noise transport").
//!
//! A plaintext SV2 frame is a 6-byte header followed by the payload:
//!
//! ```text
//! extension_type u16le (bit 15: channel_msg) ‖ msg_type u8 ‖ msg_length u24le ‖ payload
//! ```
//!
//! On the encrypted transport the header is one AEAD message (6 + 16 = 22
//! bytes) and the payload follows as AEAD messages of at most 65,535 bytes on
//! the wire (65,519 bytes of plaintext each). This module implements exactly
//! that with the session's `NoiseCodec` (noise_sv2), so the reader and the
//! writer of a session can each own a copy of the codec (one only decrypts,
//! the other only encrypts) instead of sharing one behind a lock. The legacy
//! Bloch server encrypted whole frames as one message and read one TCP
//! `read()` as one frame; both broke on any SRI client.
//!
//! `node/tests/stratum_e2e.rs` checks this framing against SRI's own codec
//! (`codec_sv2::NoiseEncoder` / `StandardNoiseDecoder`).

use noise_sv2::{NoiseCodec, AEAD_MAC_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Plaintext header length.
pub const HEADER_LEN: usize = 6;
/// Encrypted header length.
pub const ENCRYPTED_HEADER_LEN: usize = HEADER_LEN + AEAD_MAC_LEN;
/// Largest AEAD message on the wire.
pub const MAX_CHUNK: usize = 65_535;
/// Largest payload this server accepts: every message it serves is far
/// smaller (SetupConnection, the largest, is under 1.3 KiB); a peer cannot
/// make the server buffer more.
pub const MAX_INBOUND_PAYLOAD: usize = 16 * 1024;
/// Bit 15 of `extension_type`: the message is addressed to a channel.
pub const CHANNEL_MSG_BIT: u16 = 0x8000;

/// A decoded plaintext frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub extension_type: u16,
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    /// The extension of the frame, without the channel bit.
    pub fn extension(&self) -> u16 {
        self.extension_type & !CHANNEL_MSG_BIT
    }

    /// Whether the channel bit is set.
    pub fn is_channel_msg(&self) -> bool {
        self.extension_type & CHANNEL_MSG_BIT != 0
    }
}

/// Framing errors.
#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(String),
    #[error("payload of {0} bytes exceeds the {MAX_INBOUND_PAYLOAD}-byte limit")]
    TooLarge(usize),
    #[error("payload of {0} bytes does not fit the u24 length")]
    TooLong(usize),
}

/// The 6-byte plaintext header.
pub fn header(extension: u16, channel_msg: bool, msg_type: u8, payload_len: usize) -> Result<[u8; HEADER_LEN], FramingError> {
    if payload_len > 0x00FF_FFFF {
        return Err(FramingError::TooLong(payload_len));
    }
    let ext = (extension & !CHANNEL_MSG_BIT) | if channel_msg { CHANNEL_MSG_BIT } else { 0 };
    let e = ext.to_le_bytes();
    let l = (payload_len as u32).to_le_bytes();
    Ok([e[0], e[1], msg_type, l[0], l[1], l[2]])
}

/// Parse a plaintext header: (extension_type, msg_type, payload length).
pub fn parse_header(h: &[u8; HEADER_LEN]) -> (u16, u8, usize) {
    let ext = u16::from_le_bytes([h[0], h[1]]);
    let len = u32::from_le_bytes([h[3], h[4], h[5], 0]) as usize;
    (ext, h[2], len)
}

/// The plaintext frame (header ‖ payload), as SRI's `Sv2Frame` serializes it.
pub fn plaintext_frame(extension: u16, channel_msg: bool, msg_type: u8, payload: &[u8]) -> Result<Vec<u8>, FramingError> {
    let mut out = header(extension, channel_msg, msg_type, payload.len())?.to_vec();
    out.extend_from_slice(payload);
    Ok(out)
}

/// Encrypted wire length of a payload of `len` bytes (without the header).
pub fn encrypted_payload_len(len: usize) -> usize {
    let per = MAX_CHUNK - AEAD_MAC_LEN;
    len + len.div_ceil(per) * AEAD_MAC_LEN
}

fn noise_err(e: impl std::fmt::Debug) -> FramingError {
    FramingError::Noise(format!("{e:?}"))
}

/// Encrypt one frame for the wire.
pub fn encrypt_frame(codec: &mut NoiseCodec, extension: u16, channel_msg: bool, msg_type: u8, payload: &[u8])
    -> Result<Vec<u8>, FramingError>
{
    let mut h = header(extension, channel_msg, msg_type, payload.len())?.to_vec();
    codec.encrypt(&mut h).map_err(noise_err)?;
    let mut out = h;
    for chunk in payload.chunks(MAX_CHUNK - AEAD_MAC_LEN) {
        let mut c = chunk.to_vec();
        codec.encrypt(&mut c).map_err(noise_err)?;
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// Encrypt and write one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W, codec: &mut NoiseCodec, extension: u16, channel_msg: bool, msg_type: u8, payload: &[u8],
) -> Result<(), FramingError> {
    let bytes = encrypt_frame(codec, extension, channel_msg, msg_type, payload)?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read and decrypt one frame (not cancellation-safe: run it in a task of
/// its own, not in a `select!` arm).
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, codec: &mut NoiseCodec) -> Result<Frame, FramingError> {
    let mut h = vec![0u8; ENCRYPTED_HEADER_LEN];
    r.read_exact(&mut h).await?;
    codec.decrypt(&mut h).map_err(noise_err)?;
    let h: [u8; HEADER_LEN] = h.as_slice().try_into().map_err(|_| FramingError::Noise("header length".into()))?;
    let (extension_type, msg_type, len) = parse_header(&h);
    if len > MAX_INBOUND_PAYLOAD {
        return Err(FramingError::TooLarge(len));
    }
    let mut enc = vec![0u8; encrypted_payload_len(len)];
    r.read_exact(&mut enc).await?;
    let mut payload = Vec::with_capacity(len);
    for chunk in enc.chunks(MAX_CHUNK) {
        let mut c = chunk.to_vec();
        codec.decrypt(&mut c).map_err(noise_err)?;
        payload.extend_from_slice(&c);
    }
    Ok(Frame { extension_type, msg_type, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_encodes_channel_bit_type_and_u24_length() {
        let h = header(0, true, 0x15, 0x01_2345).unwrap();
        assert_eq!(h, [0x00, 0x80, 0x15, 0x45, 0x23, 0x01]);
        assert_eq!(parse_header(&h), (0x8000, 0x15, 0x01_2345));
        let h = header(0, false, 0x00, 50).unwrap();
        assert_eq!(h, [0, 0, 0, 50, 0, 0]);
        assert!(header(0, false, 0, 0x0100_0000).is_err(), "u24 overflow");
    }

    #[test]
    fn encrypted_lengths() {
        assert_eq!(encrypted_payload_len(0), 0);
        assert_eq!(encrypted_payload_len(1), 17);
        assert_eq!(encrypted_payload_len(65_519), 65_535);
        assert_eq!(encrypted_payload_len(65_520), 65_536 + 16);
    }

    #[test]
    fn frame_accessors() {
        let f = Frame { extension_type: 0x8001, msg_type: 0x1a, payload: vec![] };
        assert!(f.is_channel_msg());
        assert_eq!(f.extension(), 1);
    }
}
