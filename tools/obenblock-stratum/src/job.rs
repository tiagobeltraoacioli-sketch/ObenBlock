//! Jobs: one node header job (`getblocktemplate [{"header_job": …}]`,
//! docs/OBENBLOCK-MINING.md §3.2) turned into what every connection mines,
//! plus the block a winning share becomes.
//!
//! The node builds the complete candidate block (transactions, PoWit
//! section, a coinbase paying the pool's script) with a fixed 8-byte
//! extranonce, and hands back a ready Stratum V1 `mining.notify` object
//! (`header_job.stratum`, §4.1). Each connection fills those 8 bytes with
//! its own `extranonce1 ‖ extranonce2`, so all connections share one job and
//! search disjoint spaces. A share's header is rebuilt exactly as stock
//! firmware builds it: coinbase `coinb1 ‖ en1 ‖ en2 ‖ coinb2`, its SHA-256d
//! txid folded up `merkle_branch` with SHA-256d (Bitcoin's tree). A winning
//! share is submitted as the job's block with `submitblock`'s second
//! parameter `{version, time, nonce, extranonce}`; the node writes them in,
//! recomputes the root and judges the block like any other.

use std::time::Instant;

use serde_json::Value;

use crate::types::{EXTRANONCE1_LEN, EXTRANONCE2_LEN};
use crate::validator::{
    bits_to_target, block_id, effective_version, header80, merkle_root, sha256d, stratum_word_swap, RootRule, Target,
    POW_HEADER_LEN,
};

/// Bytes of the node's header-job extranonce.
pub const EXTRANONCE_LEN: usize = EXTRANONCE1_LEN + EXTRANONCE2_LEN;

/// One job, shared by every connection.
#[derive(Clone, Debug)]
pub struct ObbJob {
    pub job_id: String,
    pub height: u64,
    pub parents: Vec<[u8; 32]>,
    pub parents_commitment: [u8; 32],
    /// Block version (bits outside the rolling mask must keep it).
    pub version: u32,
    /// Version bits miners may roll (BIP 320).
    pub version_mask: u32,
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    /// Bitcoin merkle branch of the coinbase (hashing byte order, bottom-up).
    pub branch: Vec<[u8; 32]>,
    pub rule: RootRule,
    /// Header bits of this job (stall relief of `time` applied).
    pub bits: u32,
    pub target: Target,
    /// Header time of the job (the node's `curtime`).
    pub time: u32,
    /// The `ntime` window that keeps `bits` (docs/OBENBLOCK-MINING.md §3.5):
    /// every share time must be in `[mintime, maxtime]`.
    pub mintime: u64,
    pub maxtime: u64,
    /// The stall-relief step of the window (0: not late).
    pub relief_step: u64,
    /// First time with the next step's (easier) bits: fetch a new job then.
    /// `None` without stall relief at this height.
    pub next_bits_time: Option<u64>,
    /// `mining.notify` fields as the node encoded them (`header_job.stratum`).
    pub notify: NotifyFields,
    /// The node's candidate block (`submitblock` wire bytes, nonce 0).
    pub block: Vec<u8>,
    /// Offsets in `block`.
    pub merkle_offset: usize,
    pub extranonce_offset: usize,
    pub created: Instant,
}

/// The stratum encodings of a job (`header_job.stratum`): `prevhash`
/// word-swapped, `version` / `nbits` / `ntime` big-endian hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotifyFields {
    pub prevhash: String,
    pub coinb1: String,
    pub coinb2: String,
    pub merkle_branch: Vec<String>,
    pub version: String,
    pub nbits: String,
    pub ntime: String,
}

/// The header of one share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareHeader {
    pub header: [u8; POW_HEADER_LEN],
    pub id: [u8; 32],
    pub version: u32,
    pub merkle_root: [u8; 32],
}

fn hex32(v: &Value, what: &str) -> Result<[u8; 32], String> {
    let s = v.as_str().ok_or_else(|| format!("{what}: not a string"))?;
    let b = hex::decode(s).map_err(|_| format!("{what}: not hex"))?;
    b.try_into().map_err(|_| format!("{what}: not 32 bytes"))
}

fn hexbytes(v: &Value, what: &str) -> Result<Vec<u8>, String> {
    let s = v.as_str().ok_or_else(|| format!("{what}: not a string"))?;
    hex::decode(s).map_err(|_| format!("{what}: not hex"))
}

fn hexstr(v: &Value, what: &str) -> Result<String, String> {
    let s = v.as_str().ok_or_else(|| format!("{what}: not a string"))?;
    hex::decode(s).map_err(|_| format!("{what}: not hex"))?;
    Ok(s.to_ascii_lowercase())
}

fn branch_of(v: &Value, what: &str) -> Result<Vec<[u8; 32]>, String> {
    v.as_array().ok_or_else(|| format!("{what}: not an array"))?
        .iter().map(|b| hex32(b, what)).collect()
}

fn u64_of(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("{what}: not an unsigned integer"))
}

fn read_compact_size(b: &[u8], at: &mut usize) -> Result<u64, String> {
    let first = *b.get(*at).ok_or("block: truncated varint")?;
    *at += 1;
    let width = match first {
        0xFD => 2,
        0xFE => 4,
        0xFF => 8,
        n => return Ok(n as u64),
    };
    let bytes = b.get(*at..*at + width).ok_or("block: truncated varint")?;
    *at += width;
    let mut v = [0u8; 8];
    v[..width].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(v))
}

impl ObbJob {
    /// Build a job from a `getblocktemplate` result that carries a header job
    /// requested with `extranonce` (all zeros by default). Every field is
    /// checked against the others: the header job's header and root must
    /// equal the ones this server computes with Bitcoin's coinbase / Merkle
    /// math, the `stratum` object must encode the same job, and the block
    /// bytes must carry that header and the coinbase `coinb1 ‖ extranonce ‖
    /// coinb2`.
    pub fn from_template(gbt: &Value, extranonce: [u8; EXTRANONCE_LEN], job_id: String) -> Result<Self, String> {
        if let Some(e) = gbt.get("error").and_then(Value::as_str) {
            return Err(format!("getblocktemplate: {e}"));
        }
        if gbt.get("pow").and_then(Value::as_str) != Some("sha256d") {
            return Err("getblocktemplate: not a SHA-256d template (is this an ObenBlock node?)".into());
        }
        let s = gbt.get("sha256d").filter(|v| v.is_object()).ok_or("getblocktemplate: no sha256d object")?;
        let rule_name = s.get("merkle_root_rule").and_then(Value::as_str).unwrap_or("");
        let rule = RootRule::parse(rule_name)
            .ok_or_else(|| format!("getblocktemplate: unsupported merkle_root_rule {rule_name:?} \
                                    (this server needs bitcoin-sha256d)"))?;
        let n_extra = s.get("extranonce_bytes").and_then(Value::as_u64).unwrap_or(0);
        if n_extra != EXTRANONCE_LEN as u64 {
            return Err(format!("getblocktemplate: extranonce_bytes {n_extra}, this server needs {EXTRANONCE_LEN}"));
        }
        let hj = s.get("header_job").filter(|v| v.is_object()).ok_or("getblocktemplate: no header_job (request one)")?;
        let st = hj.get("stratum").filter(|v| v.is_object()).ok_or("header_job: no stratum object")?;
        let version = s.get("version").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok())
            .ok_or("sha256d.version")?;
        let version_mask = s.get("version_rolling_mask").and_then(Value::as_str)
            .and_then(crate::codec::parse_hex_u32).ok_or("sha256d.version_rolling_mask")?;
        let parents_commitment = hex32(&s["parents_commitment"], "sha256d.parents_commitment")?;
        let parents = gbt.get("parents").and_then(Value::as_array).ok_or("parents")?
            .iter().map(|p| hex32(p, "parents[]")).collect::<Result<Vec<_>, _>>()?;
        if gnb_smh::sha256d::parents_commitment(&parents) != parents_commitment {
            return Err("getblocktemplate: parents do not hash to parents_commitment".into());
        }
        let height = gbt.get("height").and_then(Value::as_u64).ok_or("height")?;
        let relief_step = s.get("relief_step").and_then(Value::as_u64).unwrap_or(0);
        let next_bits_time = match s.get("next_bits_time") {
            None | Some(Value::Null) => None,
            Some(v) => Some(u64_of(v, "sha256d.next_bits_time")?),
        };

        let header: [u8; POW_HEADER_LEN] = hexbytes(&hj["header"], "header_job.header")?
            .try_into().map_err(|_| "header_job.header: not 80 bytes")?;
        let coinb1 = hexbytes(&hj["coinb1"], "header_job.coinb1")?;
        let coinb2 = hexbytes(&hj["coinb2"], "header_job.coinb2")?;
        let branch = branch_of(&hj["merkle_branch"], "header_job.merkle_branch[]")?;
        let got_extranonce = hexbytes(&hj["extranonce"], "header_job.extranonce")?;
        if got_extranonce != extranonce {
            return Err("header_job: the node used another extranonce than requested".into());
        }
        let mintime = u64_of(&hj["mintime"], "header_job.mintime")?;
        let maxtime = u64_of(&hj["maxtime"], "header_job.maxtime")?;
        let block = hexbytes(&hj["block"], "header_job.block")?;
        let time = u32::from_le_bytes(header[68..72].try_into().unwrap());
        let bits = u32::from_le_bytes(header[72..76].try_into().unwrap());
        let target = bits_to_target(bits);
        if target.is_zero() {
            return Err(format!("header_job: malformed bits {bits:08x}"));
        }
        if !(mintime <= time as u64 && time as u64 <= maxtime) {
            return Err(format!("header_job: time {time} outside its window [{mintime}, {maxtime}]"));
        }
        if next_bits_time.is_some_and(|t| t <= maxtime) {
            return Err("header_job: maxtime reaches the next relief step".into());
        }

        // The stratum object must be this job, in stratum's encodings.
        let notify = NotifyFields {
            prevhash: hexstr(&st["prevhash"], "stratum.prevhash")?,
            coinb1: hexstr(&st["coinb1"], "stratum.coinb1")?,
            coinb2: hexstr(&st["coinb2"], "stratum.coinb2")?,
            merkle_branch: st["merkle_branch"].as_array().ok_or("stratum.merkle_branch")?
                .iter().map(|b| hexstr(b, "stratum.merkle_branch[]")).collect::<Result<Vec<_>, _>>()?,
            version: hexstr(&st["version"], "stratum.version")?,
            nbits: hexstr(&st["nbits"], "stratum.nbits")?,
            ntime: hexstr(&st["ntime"], "stratum.ntime")?,
        };
        let expect = NotifyFields {
            prevhash: hex::encode(stratum_word_swap(&parents_commitment)),
            coinb1: hex::encode(&coinb1),
            coinb2: hex::encode(&coinb2),
            merkle_branch: branch.iter().map(hex::encode).collect(),
            version: format!("{version:08x}"),
            nbits: format!("{bits:08x}"),
            ntime: format!("{time:08x}"),
        };
        if notify != expect {
            return Err(format!("header_job.stratum does not encode the header job: {notify:?} vs {expect:?}"));
        }
        if st.get("extranonce_size").and_then(Value::as_u64) != Some(EXTRANONCE_LEN as u64) {
            return Err("header_job.stratum.extranonce_size is not 8".into());
        }
        if st.get("ntime_min").and_then(Value::as_u64) != Some(mintime)
            || st.get("ntime_max").and_then(Value::as_u64) != Some(maxtime)
        {
            return Err("header_job.stratum ntime window differs from the job's".into());
        }

        let mut job = ObbJob {
            job_id, height, parents, parents_commitment, version, version_mask, coinb1, coinb2, branch, rule, bits,
            target, time, mintime, maxtime, relief_step, next_bits_time, notify, block,
            merkle_offset: 0, extranonce_offset: 0, created: Instant::now(),
        };
        // Our own header for the requested extranonce must be the node's.
        let mine = job.share_header(&extranonce[..EXTRANONCE1_LEN], &extranonce[EXTRANONCE1_LEN..], time, 0, None)?;
        if mine.header[..76] != header[..76] {
            return Err("header_job: the node's header differs from the one computed from coinb1 / coinb2 / \
                        merkle_branch with Bitcoin's coinbase and Merkle math".into());
        }
        if let Some(r) = hj.get("merkle_root").and_then(Value::as_str) {
            if r != hex::encode(mine.merkle_root) {
                return Err("header_job.merkle_root differs from the computed root".into());
            }
        }
        if u32::from_le_bytes(header[0..4].try_into().unwrap()) != version {
            return Err("header_job: header version is not sha256d.version".into());
        }
        job.locate_in_block(&extranonce, &mine.merkle_root, time)?;
        Ok(job)
    }

    /// Find (and check) the Merkle root and the coinbase extranonce in the
    /// block bytes:
    /// `version u32 | varint n | parents | merkle_root | timestamp u64 | bits u32 | nonce u64
    ///  | blue_score u64 | height u64 | varint tx_count | coinbase …`.
    fn locate_in_block(&mut self, extranonce: &[u8; EXTRANONCE_LEN], root: &[u8; 32], time: u32) -> Result<(), String> {
        let b = &self.block;
        let mut at = 4;
        if b.get(0..4).map(|v| u32::from_le_bytes(v.try_into().unwrap())) != Some(self.version) {
            return Err("block: version is not the job's".into());
        }
        let n = read_compact_size(b, &mut at)? as usize;
        let parents_end = at.checked_add(n.checked_mul(32).ok_or("block: parent count")?).ok_or("block: parent count")?;
        let parents: Vec<[u8; 32]> = b.get(at..parents_end).ok_or("block: truncated parents")?
            .chunks(32).map(|c| c.try_into().unwrap()).collect();
        if parents != self.parents {
            return Err("block: parents are not the template's".into());
        }
        let merkle_offset = parents_end;
        let fixed = b.get(merkle_offset..merkle_offset + 32 + 8 + 4 + 8 + 8 + 8).ok_or("block: truncated header")?;
        if &fixed[..32] != root {
            return Err("block: merkle root is not the job's".into());
        }
        if u64::from_le_bytes(fixed[32..40].try_into().unwrap()) != time as u64 {
            return Err("block: timestamp is not the job's".into());
        }
        if u32::from_le_bytes(fixed[40..44].try_into().unwrap()) != self.bits {
            return Err("block: bits are not the job's".into());
        }
        if u64::from_le_bytes(fixed[60..68].try_into().unwrap()) != self.height {
            return Err("block: height is not the template's".into());
        }
        let mut at = merkle_offset + fixed.len();
        let txs = read_compact_size(b, &mut at)?;
        if txs == 0 {
            return Err("block: no coinbase".into());
        }
        let cb_len = self.coinb1.len() + EXTRANONCE_LEN + self.coinb2.len();
        let cb = b.get(at..at + cb_len).ok_or("block: truncated coinbase")?;
        if cb[..self.coinb1.len()] != self.coinb1[..]
            || cb[self.coinb1.len()..self.coinb1.len() + EXTRANONCE_LEN] != extranonce[..]
            || cb[self.coinb1.len() + EXTRANONCE_LEN..] != self.coinb2[..]
        {
            return Err("block: coinbase is not coinb1 ‖ extranonce ‖ coinb2".into());
        }
        self.merkle_offset = merkle_offset;
        self.extranonce_offset = at + self.coinb1.len();
        Ok(())
    }

    /// The coinbase txid for an extranonce: `SHA-256d(coinb1 ‖ en1 ‖ en2 ‖ coinb2)`.
    pub fn coinbase_txid(&self, en1: &[u8], en2: &[u8]) -> [u8; 32] {
        let mut cb = Vec::with_capacity(self.coinb1.len() + EXTRANONCE_LEN + self.coinb2.len());
        cb.extend_from_slice(&self.coinb1);
        cb.extend_from_slice(en1);
        cb.extend_from_slice(en2);
        cb.extend_from_slice(&self.coinb2);
        sha256d(&cb)
    }

    /// The header root for an extranonce (Bitcoin's fold of the branch).
    pub fn merkle_root_for(&self, en1: &[u8], en2: &[u8]) -> [u8; 32] {
        merkle_root(self.rule, &self.coinbase_txid(en1, en2), &self.branch)
    }

    /// The header and id of a share.
    pub fn share_header(&self, en1: &[u8], en2: &[u8], time: u32, nonce: u32, rolled: Option<u32>)
        -> Result<ShareHeader, String>
    {
        if en1.len() != EXTRANONCE1_LEN || en2.len() != EXTRANONCE2_LEN {
            return Err(format!("extranonce2 must be {EXTRANONCE2_LEN} bytes"));
        }
        let root = self.merkle_root_for(en1, en2);
        let version = effective_version(self.version, self.version_mask, rolled);
        let header = header80(version, &self.parents_commitment, &root, time, self.bits, nonce);
        Ok(ShareHeader { header, id: block_id(&header), version, merkle_root: root })
    }

    /// Why a share time is not valid for this job, if it is not: outside the
    /// job's window `[mintime, maxtime]` (before the parents, or in another
    /// stall-relief step, whose bits differ), or more than `max_future`
    /// seconds past this server's clock.
    pub fn check_time(&self, time: u32, now: u64, max_future: u64) -> Result<(), &'static str> {
        let t = time as u64;
        if t < self.mintime {
            return Err("ntime before the job's window (parents' time or relief step)");
        }
        if t > self.maxtime {
            return Err("ntime past the job's window (another difficulty step, or too far ahead); take the new job");
        }
        if t > now.saturating_add(max_future) {
            return Err("ntime too far in the future");
        }
        Ok(())
    }

    /// Whether this job should be replaced at `now`: its window has ended or
    /// the next relief step (easier bits) has begun.
    pub fn window_over(&self, now: u64) -> bool {
        now > self.maxtime || self.next_bits_time.is_some_and(|t| now >= t)
    }

    /// The extranonce of a share: `extranonce1 ‖ extranonce2`.
    pub fn extranonce(en1: &[u8], en2: &[u8]) -> [u8; EXTRANONCE_LEN] {
        let mut e = [0u8; EXTRANONCE_LEN];
        e[..EXTRANONCE1_LEN].copy_from_slice(en1);
        e[EXTRANONCE1_LEN..].copy_from_slice(en2);
        e
    }

    /// The block of a winning share: the job's block with the share's
    /// extranonce, Merkle root, version, time and nonce written in, so the
    /// bytes alone are the block (the same fields also travel as
    /// `submitblock`'s second parameter, which the node applies). Self-checks
    /// that the patched coinbase reproduces the share's root.
    pub fn block_for(&self, en1: &[u8], en2: &[u8], share: &ShareHeader, time: u32, nonce: u32) -> Result<Vec<u8>, String> {
        let mut b = self.block.clone();
        b[self.extranonce_offset..self.extranonce_offset + EXTRANONCE_LEN].copy_from_slice(&Self::extranonce(en1, en2));
        b[self.merkle_offset..self.merkle_offset + 32].copy_from_slice(&share.merkle_root);
        b[0..4].copy_from_slice(&share.version.to_le_bytes());
        let t = self.merkle_offset + 32;
        b[t..t + 8].copy_from_slice(&(time as u64).to_le_bytes());
        b[t + 12..t + 20].copy_from_slice(&(nonce as u64).to_le_bytes());
        let cb_start = self.extranonce_offset - self.coinb1.len();
        let cb_end = self.extranonce_offset + EXTRANONCE_LEN + self.coinb2.len();
        let txid = sha256d(&b[cb_start..cb_end]);
        if merkle_root(self.rule, &txid, &self.branch) != share.merkle_root {
            return Err("internal: patched block does not reproduce the share's root".into());
        }
        Ok(b)
    }

    /// Standard Stratum V1 `mining.notify` params, straight from the node's
    /// `stratum` object:
    /// `[job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]`.
    pub fn notify_params(&self, clean_jobs: bool) -> Value {
        let n = &self.notify;
        Value::from(vec![
            Value::from(self.job_id.clone()),
            Value::from(n.prevhash.clone()),
            Value::from(n.coinb1.clone()),
            Value::from(n.coinb2.clone()),
            Value::from(n.merkle_branch.clone()),
            Value::from(n.version.clone()),
            Value::from(n.nbits.clone()),
            Value::from(n.ntime.clone()),
            Value::from(clean_jobs),
        ])
    }
}

/// What a miner receives in `mining.notify`, parsed back the way stock
/// firmware reads it (the CPU miner, and tests).
#[derive(Clone, Debug)]
pub struct NotifiedJob {
    pub job_id: String,
    /// Header bytes 4..36 (`prevhash` with its words swapped back).
    pub parents_commitment: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    pub branch: Vec<[u8; 32]>,
    pub version: u32,
    pub bits: u32,
    pub time: u32,
    pub clean_jobs: bool,
}

impl NotifiedJob {
    pub fn parse(params: &Value) -> Result<Self, String> {
        let a = params.as_array().ok_or("notify params: not an array")?;
        if a.len() < 9 {
            return Err(format!("notify with {} params, want 9", a.len()));
        }
        let u = |i: usize, w: &str| a[i].as_str().and_then(crate::codec::parse_hex_u32).ok_or_else(|| format!("notify {w}"));
        Ok(NotifiedJob {
            job_id: a[0].as_str().ok_or("notify job_id")?.to_string(),
            parents_commitment: stratum_word_swap(&hex32(&a[1], "notify prevhash")?),
            coinb1: hexbytes(&a[2], "notify coinb1")?,
            coinb2: hexbytes(&a[3], "notify coinb2")?,
            branch: branch_of(&a[4], "notify merkle_branch[]")?,
            version: u(5, "version")?,
            bits: u(6, "nbits")?,
            time: u(7, "ntime")?,
            clean_jobs: a[8].as_bool().unwrap_or(false),
        })
    }

    /// Bitcoin's root for an extranonce: the coinbase txid folded up the
    /// branch with SHA-256d.
    pub fn merkle_root_for(&self, en1: &[u8], en2: &[u8]) -> [u8; 32] {
        let mut cb = Vec::with_capacity(self.coinb1.len() + en1.len() + en2.len() + self.coinb2.len());
        cb.extend_from_slice(&self.coinb1);
        cb.extend_from_slice(en1);
        cb.extend_from_slice(en2);
        cb.extend_from_slice(&self.coinb2);
        merkle_root(RootRule::BitcoinSha256d, &sha256d(&cb), &self.branch)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) use crate::fixtures::{n_vectors, template_from_vector, vector_extranonce};

    #[test]
    fn every_vector_case_becomes_a_job() {
        for i in 0..n_vectors() {
            let job = ObbJob::from_template(&template_from_vector(i), vector_extranonce(i), format!("j{i}")).unwrap();
            assert_eq!(job.extranonce_offset + EXTRANONCE_LEN + job.coinb2.len() + 4, job.block.len());
        }
    }

    #[test]
    fn inconsistent_templates_are_refused() {
        let t = template_from_vector(0);
        let en = vector_extranonce(0);
        let refused = |f: &dyn Fn(&mut Value)| {
            let mut bad = t.clone();
            f(&mut bad);
            ObbJob::from_template(&bad, en, "x".into()).unwrap_err()
        };
        // A branch that does not lead to the header's root (consistent in both places).
        assert!(refused(&|b| {
            b["sha256d"]["header_job"]["merkle_branch"] = json!(["11".repeat(32)]);
            b["sha256d"]["header_job"]["stratum"]["merkle_branch"] = json!(["11".repeat(32)]);
        }).contains("differs"));
        assert!(refused(&|b| b["sha256d"]["header_job"]["merkle_branch"] = json!(["11".repeat(32)])).contains("stratum"));
        assert!(refused(&|b| b["sha256d"]["merkle_root_rule"] = json!("gnb-body-v2")).contains("merkle_root_rule"));
        assert!(refused(&|b| b["sha256d"]["merkle_root_rule"] = json!("gnb-tagged-v1")).contains("merkle_root_rule"));
        assert!(refused(&|b| b["sha256d"]["header_job"]["stratum"]["prevhash"] = json!("00".repeat(32))).contains("stratum"));
        assert!(refused(&|b| b["sha256d"]["header_job"]["stratum"]["nbits"] = json!("1d00ffff")).contains("stratum"));
        assert!(refused(&|b| b["sha256d"]["header_job"]["stratum"]["ntime_max"] = json!(1)).contains("window"));
        assert!(refused(&|b| b["sha256d"]["header_job"]["stratum"] = Value::Null).contains("stratum"));
        assert!(refused(&|b| b["sha256d"]["header_job"]["merkle_root"] = json!("00".repeat(32))).contains("merkle_root"));
        assert!(refused(&|b| b["sha256d"]["header_job"]["maxtime"] = json!(1)).contains("window"));
        assert!(refused(&|b| b["sha256d"]["next_bits_time"] = json!(1)).contains("relief"));
        assert!(refused(&|b| b["sha256d"]["header_job"] = Value::Null).contains("header_job"));
        assert!(refused(&|b| b["pow"] = json!("gnb-smh-v3")).contains("SHA-256d"));
        assert!(refused(&|b| b["parents"] = json!(["22".repeat(32)])).contains("parents"));
        assert!(refused(&|b| b["error"] = json!("busy")).contains("busy"));
        // The block bytes must carry the job.
        let e = refused(&|b| {
            let mut blk = hex::decode(b["sha256d"]["header_job"]["block"].as_str().unwrap()).unwrap();
            let n = blk.len();
            blk[n - 10] ^= 1; // inside coinb2
            b["sha256d"]["header_job"]["block"] = json!(hex::encode(blk));
        });
        assert!(e.contains("coinbase"), "{e}");
        assert!(ObbJob::from_template(&t, [9; 8], "x".into()).is_err(), "another extranonce than requested");
    }

    #[test]
    fn a_winning_share_becomes_its_block() {
        let job = ObbJob::from_template(&template_from_vector(0), vector_extranonce(0), "j".into()).unwrap();
        let (en1, en2) = ([1u8, 2, 3, 4], [5u8, 6, 7, 8]);
        let time = job.time + 5;
        let share = job.share_header(&en1, &en2, time, 77, Some(0x0000_4000)).unwrap();
        let b = job.block_for(&en1, &en2, &share, time, 77).unwrap();
        // The patched block carries the share's 80-byte header fields.
        assert_eq!(&b[0..4], &share.header[0..4]);
        assert_eq!(&b[job.merkle_offset..job.merkle_offset + 32], &share.header[36..68]);
        let t = job.merkle_offset + 32;
        assert_eq!(u64::from_le_bytes(b[t..t + 8].try_into().unwrap()), time as u64);
        assert_eq!(u32::from_le_bytes(b[t + 8..t + 12].try_into().unwrap()), job.bits);
        assert_eq!(u64::from_le_bytes(b[t + 12..t + 20].try_into().unwrap()), 77);
        assert_eq!(&b[job.extranonce_offset..job.extranonce_offset + 8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(b.len(), job.block.len());
        assert_eq!(ObbJob::extranonce(&en1, &en2), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn share_time_rules() {
        let job = ObbJob::from_template(&template_from_vector(0), vector_extranonce(0), "j".into()).unwrap();
        let now = job.time as u64;
        assert!(job.check_time(job.time, now, 600).is_ok());
        assert!(job.check_time(job.mintime as u32, now, 600).is_ok());
        assert!(job.check_time(job.mintime as u32 - 1, now, 600).is_err());
        assert!(job.check_time(job.maxtime as u32, now + 300, 600).is_ok());
        // Past maxtime is the next relief step: other bits.
        assert!(job.check_time(job.maxtime as u32 + 1, now + 300, 600).is_err());
        // Inside the window but too far past this server's clock.
        assert!(job.check_time(job.maxtime as u32, now, 10).is_err());
        // The job is 30 s after its parent: the next step starts at +240 s.
        assert_eq!(job.next_bits_time, Some(job.mintime + 240));
        assert_eq!(job.maxtime, job.mintime + 239);
        assert!(!job.window_over(job.maxtime));
        assert!(job.window_over(job.maxtime + 1));
    }

    #[test]
    fn notify_is_the_node_stratum_object_and_round_trips() {
        let i = 1.min(n_vectors() - 1);
        let t = template_from_vector(i);
        let job = ObbJob::from_template(&t, vector_extranonce(i), "j1".into()).unwrap();
        let p = job.notify_params(true);
        let a = p.as_array().unwrap();
        assert_eq!(a.len(), 9, "plain Stratum V1 notify");
        let st = &t["sha256d"]["header_job"]["stratum"];
        for (k, name) in [(1, "prevhash"), (2, "coinb1"), (3, "coinb2"), (4, "merkle_branch"), (5, "version"),
                          (6, "nbits"), (7, "ntime")] {
            assert_eq!(a[k], st[name], "{name}");
        }
        let n = NotifiedJob::parse(&p).unwrap();
        assert_eq!(n.parents_commitment, job.parents_commitment);
        assert_eq!((n.version, n.bits, n.time, n.clean_jobs), (job.version, job.bits, job.time, true));
        let (en1, en2) = ([9u8, 8, 7, 6], [1u8, 0, 0, 0]);
        assert_eq!(n.merkle_root_for(&en1, &en2), job.merkle_root_for(&en1, &en2));
        assert!(!job.branch.is_empty(), "the vector case has a branch to walk");
    }
}
