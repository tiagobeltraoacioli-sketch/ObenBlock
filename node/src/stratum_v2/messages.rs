//! Mining Protocol messages of standard channels, encoded and decoded with
//! SRI's `mining_sv2` types (Stratum V2 spec §5.3).
//!
//! The legacy Bloch server hand-wrote these codecs; it sent the channel
//! target big-endian, `NewMiningJob.merkle_root` with a length prefix, no
//! channel bit and never a `SetNewPrevHash`, so no SRI client could mine on
//! it. Here every message is SRI's own type, so the bytes are the reference
//! implementation's by construction.
//!
//! Byte orders (SRI conventions): `U256` targets are little-endian 256-bit
//! integers; `prev_hash` and `merkle_root` are the 32 bytes exactly as they
//! sit in the 80-byte header.

use binary_sv2::{Sv2Option, U256};
use mining_sv2::{
    NewMiningJob, OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess,
    SetNewPrevHash, SetTarget, SubmitSharesError, SubmitSharesStandard, SubmitSharesSuccess,
};

pub use mining_sv2::{
    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_TARGET, MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};

/// An encoded message: type, channel bit, payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub msg_type: u8,
    pub channel_msg: bool,
    pub payload: Vec<u8>,
}

fn enc<T: binary_sv2::Encodable + binary_sv2::GetSize>(msg_type: u8, channel_msg: bool, m: T) -> Result<Encoded, String> {
    Ok(Encoded { msg_type, channel_msg, payload: binary_sv2::to_bytes(m).map_err(|e| format!("{e:?}"))? })
}

/// Big-endian 256-bit target (`gnb_smh` order) to SV2's little-endian U256.
pub fn target_to_u256(be: &[u8; 32]) -> [u8; 32] {
    let mut le = *be;
    le.reverse();
    le
}

/// SV2's little-endian U256 target to big-endian.
pub fn u256_to_target(le: &[u8]) -> [u8; 32] {
    let mut be = [0u8; 32];
    be.copy_from_slice(&le[..32]);
    be.reverse();
    be
}

/// OpenStandardMiningChannel, owned.
#[derive(Clone, Debug, PartialEq)]
pub struct OpenStandardChannel {
    pub request_id: u32,
    pub user_identity: String,
    pub nominal_hash_rate: f32,
    /// Big-endian.
    pub max_target: [u8; 32],
}

/// Decode an OpenStandardMiningChannel payload.
pub fn decode_open_standard_channel(payload: &mut [u8]) -> Result<OpenStandardChannel, String> {
    let m: OpenStandardMiningChannel = binary_sv2::from_bytes(payload).map_err(|e| format!("{e:?}"))?;
    Ok(OpenStandardChannel {
        request_id: m.request_id.as_u32(),
        user_identity: std::str::from_utf8(m.user_identity.inner_as_ref())
            .map_err(|_| "user_identity is not UTF-8".to_string())?.to_owned(),
        nominal_hash_rate: m.nominal_hash_rate,
        max_target: u256_to_target(m.max_target.inner_as_ref()),
    })
}

/// Decode a SubmitSharesStandard payload.
pub fn decode_submit_shares_standard(payload: &mut [u8]) -> Result<SubmitSharesStandard, String> {
    binary_sv2::from_bytes(payload).map_err(|e| format!("{e:?}"))
}

pub fn open_standard_channel_success(request_id: u32, channel_id: u32, target_be: &[u8; 32], extranonce_prefix: &[u8])
    -> Result<Encoded, String>
{
    enc(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, false, OpenStandardMiningChannelSuccess {
        request_id: request_id.into(),
        channel_id,
        target: U256::from(target_to_u256(target_be)),
        extranonce_prefix: extranonce_prefix.to_vec().try_into().map_err(|e| format!("{e:?}"))?,
        group_channel_id: 0,
    })
}

/// Error codes of OpenMiningChannel.Error (spec §5.3.4 plus this server's).
pub const ERR_UNKNOWN_USER: &str = "unknown-user";
pub const ERR_MAX_TARGET_OUT_OF_RANGE: &str = "max-target-out-of-range";
pub const ERR_TOO_MANY_CHANNELS: &str = "too-many-channels";
pub const ERR_EXTENDED_UNSUPPORTED: &str = "unsupported-extended-channels";

pub fn open_mining_channel_error(request_id: u32, code: &str) -> Result<Encoded, String> {
    enc(MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, false, OpenMiningChannelError {
        request_id,
        error_code: code.to_string().try_into().map_err(|e| format!("{e:?}"))?,
    })
}

/// A future job (`min_ntime` empty): it becomes active with the
/// SetNewPrevHash that names it.
pub fn new_mining_job(channel_id: u32, job_id: u32, min_ntime: Option<u32>, version: u32, merkle_root: &[u8; 32])
    -> Result<Encoded, String>
{
    enc(MESSAGE_TYPE_NEW_MINING_JOB, true, NewMiningJob {
        channel_id,
        job_id,
        min_ntime: Sv2Option::new(min_ntime),
        version,
        merkle_root: U256::from(*merkle_root),
    })
}

pub fn set_new_prev_hash(channel_id: u32, job_id: u32, prev_hash: &[u8; 32], min_ntime: u32, nbits: u32)
    -> Result<Encoded, String>
{
    enc(MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, true, SetNewPrevHash {
        channel_id, job_id, prev_hash: U256::from(*prev_hash), min_ntime, nbits,
    })
}

pub fn set_target(channel_id: u32, target_be: &[u8; 32]) -> Result<Encoded, String> {
    enc(MESSAGE_TYPE_SET_TARGET, true, SetTarget { channel_id, maximum_target: U256::from(target_to_u256(target_be)) })
}

pub fn submit_shares_success(channel_id: u32, last_sequence_number: u32, accepted: u32, shares_sum: u64)
    -> Result<Encoded, String>
{
    enc(MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, true, SubmitSharesSuccess {
        channel_id, last_sequence_number, new_submits_accepted_count: accepted, new_shares_sum: shares_sum,
    })
}

/// Error codes of SubmitShares.Error (spec §5.3.13 plus this server's).
pub const ERR_INVALID_CHANNEL_ID: &str = "invalid-channel-id";
pub const ERR_INVALID_JOB_ID: &str = "invalid-job-id";
pub const ERR_STALE_SHARE: &str = "stale-share";
pub const ERR_DIFFICULTY_TOO_LOW: &str = "difficulty-too-low";
pub const ERR_DUPLICATE_SHARE: &str = "duplicate-share";
pub const ERR_INVALID_VERSION: &str = "invalid-version";
pub const ERR_INVALID_TIME: &str = "invalid-time";
pub const ERR_BLOCK_REJECTED: &str = "block-rejected";
pub const ERR_RATE_LIMITED: &str = "rate-limited";
pub const ERR_OTHER: &str = "other";

pub fn submit_shares_error(channel_id: u32, sequence_number: u32, code: &str) -> Result<Encoded, String> {
    enc(MESSAGE_TYPE_SUBMIT_SHARES_ERROR, true, SubmitSharesError {
        channel_id, sequence_number, error_code: code.to_string().try_into().map_err(|e| format!("{e:?}"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_byte_order_round_trips() {
        let mut be = [0u8; 32];
        be[4] = 0xff;
        be[31] = 0x01;
        let le = target_to_u256(&be);
        assert_eq!(le[0], 0x01);
        assert_eq!(le[27], 0xff);
        assert_eq!(u256_to_target(&le), be);
    }

    #[test]
    fn open_channel_round_trip_with_sri_types() {
        let m = OpenStandardMiningChannel {
            request_id: 42u32.into(),
            user_identity: "obb1qexample.rig".to_string().try_into().unwrap(),
            nominal_hash_rate: 1.0e12,
            max_target: U256::from([0xffu8; 32]),
        };
        let mut p = binary_sv2::to_bytes(m).unwrap();
        let d = decode_open_standard_channel(&mut p).unwrap();
        assert_eq!((d.request_id, d.user_identity.as_str(), d.nominal_hash_rate), (42, "obb1qexample.rig", 1.0e12));
        assert_eq!(d.max_target, [0xff; 32]);
        assert!(decode_open_standard_channel(&mut [0u8; 3]).is_err());
    }

    #[test]
    fn success_and_error_decode_as_sri_types() {
        let mut target = [0u8; 32];
        target[3] = 0x7f;
        let e = open_standard_channel_success(7, 3, &target, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!((e.msg_type, e.channel_msg), (MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, false));
        let mut p = e.payload;
        let s: OpenStandardMiningChannelSuccess = binary_sv2::from_bytes(&mut p).unwrap();
        assert_eq!((s.request_id.as_u32(), s.channel_id, s.group_channel_id), (7, 3, 0));
        assert_eq!(u256_to_target(s.target.inner_as_ref()), target);
        assert_eq!(s.extranonce_prefix.inner_as_ref(), &[1, 2, 3, 4, 5, 6, 7, 8]);

        let e = open_mining_channel_error(9, ERR_UNKNOWN_USER).unwrap();
        let mut p = e.payload;
        let m: OpenMiningChannelError = binary_sv2::from_bytes(&mut p).unwrap();
        assert_eq!((m.request_id, m.error_code.inner_as_ref()), (9, ERR_UNKNOWN_USER.as_bytes()));
    }

    #[test]
    fn job_messages_carry_header_order_bytes() {
        let root = [0xAB; 32];
        let e = new_mining_job(1, 2, None, 0x2000_0000, &root).unwrap();
        assert!(e.channel_msg);
        let mut p = e.payload;
        let j: NewMiningJob = binary_sv2::from_bytes(&mut p).unwrap();
        assert_eq!((j.channel_id, j.job_id, j.version), (1, 2, 0x2000_0000));
        assert!(j.min_ntime.clone().into_inner().is_none(), "a future job");
        assert_eq!(j.merkle_root.inner_as_ref(), &root);

        let prev = [0xCD; 32];
        let e = set_new_prev_hash(1, 2, &prev, 1_800_000_000, 0x1d00_ffff).unwrap();
        let mut p = e.payload;
        let s: SetNewPrevHash = binary_sv2::from_bytes(&mut p).unwrap();
        assert_eq!((s.job_id, s.min_ntime, s.nbits), (2, 1_800_000_000, 0x1d00_ffff));
        assert_eq!(s.prev_hash.inner_as_ref(), &prev);
    }

    #[test]
    fn submit_messages_round_trip() {
        let m = SubmitSharesStandard { channel_id: 7, sequence_number: 1001, job_id: 42, nonce: 0xDEAD_BEEF,
                                       ntime: 0x6512_3456, version: 0x2000_0000 };
        let mut p = binary_sv2::to_bytes(m).unwrap();
        assert_eq!(p.len(), 24);
        let d = decode_submit_shares_standard(&mut p).unwrap();
        assert_eq!((d.channel_id, d.sequence_number, d.job_id, d.nonce, d.ntime, d.version),
                   (7, 1001, 42, 0xDEAD_BEEF, 0x6512_3456, 0x2000_0000));
        assert!(decode_submit_shares_standard(&mut [0u8; 10]).is_err());

        let mut p = submit_shares_success(7, 1001, 1, 5).unwrap().payload;
        let s: SubmitSharesSuccess = binary_sv2::from_bytes(&mut p).unwrap();
        assert_eq!((s.channel_id, s.last_sequence_number, s.new_submits_accepted_count, s.new_shares_sum), (7, 1001, 1, 5));
        for code in [ERR_INVALID_CHANNEL_ID, ERR_INVALID_JOB_ID, ERR_STALE_SHARE, ERR_DIFFICULTY_TOO_LOW,
                     ERR_DUPLICATE_SHARE, ERR_INVALID_VERSION, ERR_INVALID_TIME, ERR_BLOCK_REJECTED, ERR_OTHER] {
            let mut p = submit_shares_error(7, 3, code).unwrap().payload;
            let e: SubmitSharesError = binary_sv2::from_bytes(&mut p).unwrap();
            assert_eq!((e.sequence_number, e.error_code.inner_as_ref()), (3, code.as_bytes()));
        }
    }

    #[test]
    fn set_target_is_little_endian() {
        let mut be = [0u8; 32];
        be[0] = 0x01;
        let mut p = set_target(5, &be).unwrap().payload;
        let t: SetTarget = binary_sv2::from_bytes(&mut p).unwrap();
        assert_eq!(t.maximum_target.inner_as_ref()[31], 0x01);
    }
}
