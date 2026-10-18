//! Jobs: one node header job (`getblocktemplate [{"header_job": …}]`,
//! docs/OBENBLOCK-MINING.md §3.2) turned into what every connection mines,
//! plus the block a winning share becomes.
//!
//! The node builds the complete candidate block (transactions, PoWit
//! section, a coinbase paying the pool's script) with a fixed 8-byte
//! extranonce. Each connection fills those 8 bytes with its own
//! `extranonce1 ‖ extranonce2`, so all connections share one job and search
//! disjoint spaces. For a winning share the server writes the share's
//! extranonce and Merkle root into the job's block bytes, and the share's
//! version, time and nonce travel as `submitblock`'s second parameter; the
//! node then judges the block like any other.

use std::time::Instant;

use serde_json::Value;

use crate::types::{EXTRANONCE1_LEN, EXTRANONCE2_LEN};
use crate::validator::{
    bitcoin_merkle_root, bits_to_target, block_id, effective_version, header80, meets_target, merkle_root, sha256d,
    RootRule, Target, POW_HEADER_LEN,
};

/// Bytes of the node's header-job extranonce.
pub const EXTRANONCE_LEN: usize = EXTRANONCE1_LEN + EXTRANONCE2_LEN;

/// Stall relief of the template (DESIGN-obenblock.md §5.1): the header bits
/// depend on the block's own time in steps; a share's time must stay in the
/// step of its job, or its header's bits would be wrong for that time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relief {
    pub parent_time: u64,
    pub grace_secs: u64,
    pub step_secs: u64,
}

impl Relief {
    /// Whole relief steps a block stamped `time` has earned
    /// (`gnb_smh::stall_relief::relief_steps`).
    pub fn steps(&self, time: u64) -> u64 {
        gnb_smh::stall_relief::relief_steps(
            &gnb_smh::stall_relief::StallReliefParams {
                grace_secs: self.grace_secs as i64,
                step_secs: self.step_secs as i64,
                halflife_secs: 1, // unused by relief_steps
            },
            i64::try_from(self.parent_time).unwrap_or(i64::MAX),
            i64::try_from(time).unwrap_or(i64::MAX),
        )
    }

    /// The first time after `time` whose step differs (when a pool should
    /// issue a new job with easier bits).
    pub fn next_step_time(&self, time: u64) -> u64 {
        let start = self.parent_time.saturating_add(self.grace_secs);
        if time < start {
            return start.saturating_add(self.step_secs);
        }
        let k = (time - start) / self.step_secs.max(1);
        start.saturating_add((k + 1).saturating_mul(self.step_secs.max(1)))
    }
}

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
    pub branch: Vec<[u8; 32]>,
    pub rule: RootRule,
    pub shielded_root: [u8; 32],
    pub powit_root: [u8; 32],
    /// Header bits of this job (for `time`, stall relief included).
    pub bits: u32,
    pub target: Target,
    /// Header time of the job (the node's `curtime`).
    pub time: u32,
    /// Earliest share time (the latest parent timestamp).
    pub mintime: u64,
    pub relief: Option<Relief>,
    /// The node's candidate block (`submitblock` wire bytes, nonce 0).
    pub block: Vec<u8>,
    /// Offsets in `block`.
    pub merkle_offset: usize,
    pub extranonce_offset: usize,
    pub created: Instant,
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
    /// checked against the others: the header job's header must equal the
    /// one this server computes from the job fields, and the block bytes
    /// must carry that header and the coinbase `coinb1 ‖ extranonce ‖ coinb2`.
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
            .ok_or_else(|| format!("getblocktemplate: unsupported merkle_root_rule {rule_name:?}"))?;
        let n_extra = s.get("extranonce_bytes").and_then(Value::as_u64).unwrap_or(0);
        if n_extra != EXTRANONCE_LEN as u64 {
            return Err(format!("getblocktemplate: extranonce_bytes {n_extra}, this server needs {EXTRANONCE_LEN}"));
        }
        let hj = s.get("header_job").filter(|v| v.is_object()).ok_or("getblocktemplate: no header_job (request one)")?;
        let version = s.get("version").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok())
            .ok_or("sha256d.version")?;
        let version_mask = s.get("version_rolling_mask").and_then(Value::as_str)
            .and_then(crate::codec::parse_hex_u32).ok_or("sha256d.version_rolling_mask")?;
        let parents_commitment = hex32(&s["parents_commitment"], "sha256d.parents_commitment")?;
        let shielded_root = hex32(&s["shielded_root"], "sha256d.shielded_root")?;
        let powit_root = hex32(&s["powit_root"], "sha256d.powit_root")?;
        let mintime = s.get("mintime").and_then(Value::as_u64).ok_or("sha256d.mintime")?;
        let branch = gbt.get("coinbase_merkle_branch").and_then(Value::as_array).ok_or("coinbase_merkle_branch")?
            .iter().map(|b| hex32(b, "coinbase_merkle_branch[]")).collect::<Result<Vec<_>, _>>()?;
        let parents = gbt.get("parents").and_then(Value::as_array).ok_or("parents")?
            .iter().map(|p| hex32(p, "parents[]")).collect::<Result<Vec<_>, _>>()?;
        if gnb_smh::sha256d::parents_commitment(&parents) != parents_commitment {
            return Err("getblocktemplate: parents do not hash to parents_commitment".into());
        }
        let height = gbt.get("height").and_then(Value::as_u64).ok_or("height")?;
        let relief = match gbt.get("stall_relief") {
            Some(r) if r.get("active").and_then(Value::as_bool) == Some(true) => Some(Relief {
                parent_time: gbt.get("parent_time").and_then(Value::as_u64).ok_or("parent_time")?,
                grace_secs: r.get("grace_secs").and_then(Value::as_u64).ok_or("stall_relief.grace_secs")?,
                step_secs: r.get("step_secs").and_then(Value::as_u64).filter(|&s| s > 0).ok_or("stall_relief.step_secs")?,
            }),
            _ => None,
        };

        let header: [u8; POW_HEADER_LEN] = hexbytes(&hj["header"], "header_job.header")?
            .try_into().map_err(|_| "header_job.header: not 80 bytes")?;
        let coinb1 = hexbytes(&hj["coinb1"], "header_job.coinb1")?;
        let coinb2 = hexbytes(&hj["coinb2"], "header_job.coinb2")?;
        let got_extranonce = hexbytes(&hj["extranonce"], "header_job.extranonce")?;
        if got_extranonce != extranonce {
            return Err("header_job: the node used another extranonce than requested".into());
        }
        let block = hexbytes(&hj["block"], "header_job.block")?;
        let time = u32::from_le_bytes(header[68..72].try_into().unwrap());
        let bits = u32::from_le_bytes(header[72..76].try_into().unwrap());
        let target = bits_to_target(bits);
        if target.is_zero() {
            return Err(format!("header_job: malformed bits {bits:08x}"));
        }

        let mut job = ObbJob {
            job_id, height, parents, parents_commitment, version, version_mask, coinb1, coinb2, branch, rule,
            shielded_root, powit_root, bits, target, time, mintime, relief, block,
            merkle_offset: 0, extranonce_offset: 0, created: Instant::now(),
        };
        // Our own header for the requested extranonce must be the node's.
        let mine = job.share_header(&extranonce[..EXTRANONCE1_LEN], &extranonce[EXTRANONCE1_LEN..], time, 0, None)?;
        if mine.header[..76] != header[..76] {
            return Err("header_job: the node's header differs from the one computed from the job fields \
                        (merkle_root_rule, branch or roots)".into());
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

    /// The coinbase txid for an extranonce.
    pub fn coinbase_txid(&self, en1: &[u8], en2: &[u8]) -> [u8; 32] {
        let mut cb = Vec::with_capacity(self.coinb1.len() + EXTRANONCE_LEN + self.coinb2.len());
        cb.extend_from_slice(&self.coinb1);
        cb.extend_from_slice(en1);
        cb.extend_from_slice(en2);
        cb.extend_from_slice(&self.coinb2);
        sha256d(&cb)
    }

    /// The header root for an extranonce.
    pub fn merkle_root_for(&self, en1: &[u8], en2: &[u8]) -> [u8; 32] {
        merkle_root(self.rule, &self.coinbase_txid(en1, en2), &self.branch, &self.shielded_root, &self.powit_root)
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

    /// Whether the header a Stratum V1 miner builds with Bitcoin's SHA-256d
    /// tree meets `share_target` (diagnostics: unmodified firmware).
    pub fn bitcoin_root_share_meets(&self, en1: &[u8], en2: &[u8], time: u32, nonce: u32, rolled: Option<u32>,
                                    share_target: &Target) -> bool {
        let root = bitcoin_merkle_root(&self.coinbase_txid(en1, en2), &self.branch);
        let version = effective_version(self.version, self.version_mask, rolled);
        meets_target(&block_id(&header80(version, &self.parents_commitment, &root, time, self.bits, nonce)), share_target)
    }

    /// Why a share time is not valid for this job, if it is not: before the
    /// latest parent, more than `max_future` seconds past `now`, or (stall
    /// relief) in another 60-second step than the job, whose bits it carries.
    pub fn check_time(&self, time: u32, now: u64, max_future: u64) -> Result<(), &'static str> {
        let t = time as u64;
        if t < self.mintime {
            return Err("ntime before the parents' time");
        }
        if t > now.saturating_add(max_future) {
            return Err("ntime too far in the future");
        }
        if let Some(r) = self.relief {
            if r.steps(t) != r.steps(self.time as u64) {
                return Err("ntime in another difficulty step than the job (stall relief); take the new job");
            }
        }
        Ok(())
    }

    /// The block of a winning share: the job's block with the share's
    /// extranonce and Merkle root written in. Its version, time and nonce
    /// travel as `submitblock`'s second parameter (and are written here too,
    /// so the bytes alone are the block). Self-checks that the result's header
    /// fields are the share's.
    pub fn block_for(&self, en1: &[u8], en2: &[u8], share: &ShareHeader, time: u32, nonce: u32) -> Result<Vec<u8>, String> {
        let mut b = self.block.clone();
        b[self.extranonce_offset..self.extranonce_offset + EXTRANONCE1_LEN].copy_from_slice(en1);
        b[self.extranonce_offset + EXTRANONCE1_LEN..self.extranonce_offset + EXTRANONCE_LEN].copy_from_slice(en2);
        b[self.merkle_offset..self.merkle_offset + 32].copy_from_slice(&share.merkle_root);
        b[0..4].copy_from_slice(&share.version.to_le_bytes());
        let t = self.merkle_offset + 32;
        b[t..t + 8].copy_from_slice(&(time as u64).to_le_bytes());
        b[t + 12..t + 20].copy_from_slice(&(nonce as u64).to_le_bytes());
        // Self-check: the coinbase hashes to the root's txid.
        let cb_start = self.extranonce_offset - self.coinb1.len();
        let cb_end = self.extranonce_offset + EXTRANONCE_LEN + self.coinb2.len();
        let txid = sha256d(&b[cb_start..cb_end]);
        if merkle_root(self.rule, &txid, &self.branch, &self.shielded_root, &self.powit_root) != share.merkle_root {
            return Err("internal: patched block does not reproduce the share's root".into());
        }
        Ok(b)
    }

    /// Mining-notify params for this job:
    /// `[job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]`,
    /// plus, for a connection that negotiated the `obenblock-root` extension,
    /// a tenth element with the rest of the root rule.
    pub fn notify_params(&self, clean_jobs: bool, obenblock_root: bool) -> Value {
        let mut p = vec![
            Value::from(self.job_id.clone()),
            Value::from(hex::encode(crate::validator::stratum_word_swap(&self.parents_commitment))),
            Value::from(hex::encode(&self.coinb1)),
            Value::from(hex::encode(&self.coinb2)),
            Value::from(self.branch.iter().map(hex::encode).collect::<Vec<_>>()),
            Value::from(format!("{:08x}", self.version)),
            Value::from(format!("{:08x}", self.bits)),
            Value::from(format!("{:08x}", self.time)),
            Value::from(clean_jobs),
        ];
        if obenblock_root {
            p.push(serde_json::json!({
                "merkle_root_rule": self.rule.name(),
                "shielded_root": hex::encode(self.shielded_root),
                "powit_root": hex::encode(self.powit_root),
            }));
        }
        Value::from(p)
    }
}

/// What a miner receives in `mining.notify`, parsed back (the CPU miner, and
/// tests). The tenth element is required: without it the root rule is
/// unknown.
#[derive(Clone, Debug)]
pub struct NotifiedJob {
    pub job_id: String,
    pub parents_commitment: [u8; 32],
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    pub branch: Vec<[u8; 32]>,
    pub version: u32,
    pub bits: u32,
    pub time: u32,
    pub clean_jobs: bool,
    pub rule: RootRule,
    pub shielded_root: [u8; 32],
    pub powit_root: [u8; 32],
}

impl NotifiedJob {
    pub fn parse(params: &Value) -> Result<Self, String> {
        let a = params.as_array().ok_or("notify params: not an array")?;
        if a.len() < 10 {
            return Err("notify without the obenblock-root element (negotiate the extension)".into());
        }
        let u = |i: usize, w: &str| a[i].as_str().and_then(crate::codec::parse_hex_u32).ok_or_else(|| format!("notify {w}"));
        let ext = &a[9];
        let rule_name = ext.get("merkle_root_rule").and_then(Value::as_str).unwrap_or("");
        Ok(NotifiedJob {
            job_id: a[0].as_str().ok_or("notify job_id")?.to_string(),
            parents_commitment: crate::validator::stratum_word_swap(&hex32(&a[1], "notify prevhash")?),
            coinb1: hexbytes(&a[2], "notify coinb1")?,
            coinb2: hexbytes(&a[3], "notify coinb2")?,
            branch: a[4].as_array().ok_or("notify branch")?.iter().map(|b| hex32(b, "notify branch[]"))
                .collect::<Result<Vec<_>, _>>()?,
            version: u(5, "version")?,
            bits: u(6, "nbits")?,
            time: u(7, "ntime")?,
            clean_jobs: a[8].as_bool().unwrap_or(false),
            rule: RootRule::parse(rule_name).ok_or_else(|| format!("notify: unknown root rule {rule_name:?}"))?,
            shielded_root: hex32(&ext["shielded_root"], "notify shielded_root")?,
            powit_root: hex32(&ext["powit_root"], "notify powit_root")?,
        })
    }

    pub fn merkle_root_for(&self, en1: &[u8], en2: &[u8]) -> [u8; 32] {
        let mut cb = Vec::with_capacity(self.coinb1.len() + en1.len() + en2.len() + self.coinb2.len());
        cb.extend_from_slice(&self.coinb1);
        cb.extend_from_slice(en1);
        cb.extend_from_slice(en2);
        cb.extend_from_slice(&self.coinb2);
        merkle_root(self.rule, &sha256d(&cb), &self.branch, &self.shielded_root, &self.powit_root)
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
        let mut bad = t.clone();
        bad["sha256d"]["powit_root"] = json!("00".repeat(32));
        assert!(ObbJob::from_template(&bad, en, "x".into()).unwrap_err().contains("differs"));
        let mut bad = t.clone();
        bad["sha256d"]["merkle_root_rule"] = json!("bitcoin");
        assert!(ObbJob::from_template(&bad, en, "x".into()).unwrap_err().contains("merkle_root_rule"));
        let mut bad = t.clone();
        bad["sha256d"]["header_job"] = Value::Null;
        assert!(ObbJob::from_template(&bad, en, "x".into()).is_err());
        let mut bad = t.clone();
        bad["pow"] = json!("gnb-smh-v3");
        assert!(ObbJob::from_template(&bad, en, "x".into()).is_err());
        let mut bad = t.clone();
        bad["parents"] = json!(["22".repeat(32)]);
        assert!(ObbJob::from_template(&bad, en, "x".into()).is_err());
        let mut bad = t.clone();
        bad["error"] = json!("busy");
        assert!(ObbJob::from_template(&bad, en, "x".into()).unwrap_err().contains("busy"));
        // The block bytes must carry the job.
        let mut bad = t.clone();
        let mut blk = hex::decode(bad["sha256d"]["header_job"]["block"].as_str().unwrap()).unwrap();
        let n = blk.len();
        blk[n - 10] ^= 1; // inside coinb2
        bad["sha256d"]["header_job"]["block"] = json!(hex::encode(blk));
        assert!(ObbJob::from_template(&bad, en, "x".into()).unwrap_err().contains("coinbase"));
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
    }

    #[test]
    fn share_time_rules() {
        let job = ObbJob::from_template(&template_from_vector(0), vector_extranonce(0), "j".into()).unwrap();
        let now = job.time as u64;
        assert!(job.check_time(job.time, now, 600).is_ok());
        assert!(job.check_time(job.mintime as u32 - 1, now, 600).is_err());
        assert!(job.check_time(job.time + 601, now, 600).is_err());
        // The job is 30 s after its parent: relief starts at +240 s, so a
        // share stamped there carries other bits.
        let r = job.relief.unwrap();
        assert_eq!(r.steps(job.time as u64), 0);
        assert_eq!(r.next_step_time(job.time as u64), r.parent_time + 240);
        assert!(job.check_time((r.parent_time + 239) as u32, now + 300, 600).is_ok());
        assert!(job.check_time((r.parent_time + 240) as u32, now + 300, 600).is_err());
    }

    #[test]
    fn notify_round_trips_for_the_cpu_miner() {
        let job = ObbJob::from_template(&template_from_vector(1.min(n_vectors() - 1)), vector_extranonce(1.min(n_vectors() - 1)), "j1".into()).unwrap();
        let p = job.notify_params(true, true);
        let n = NotifiedJob::parse(&p).unwrap();
        assert_eq!(n.parents_commitment, job.parents_commitment);
        assert_eq!((n.version, n.bits, n.time, n.clean_jobs), (job.version, job.bits, job.time, true));
        let (en1, en2) = ([9u8, 8, 7, 6], [1u8, 0, 0, 0]);
        assert_eq!(n.merkle_root_for(&en1, &en2), job.merkle_root_for(&en1, &en2));
        // A plain notify (no extension) has exactly the nine standard fields.
        assert_eq!(job.notify_params(false, false).as_array().unwrap().len(), 9);
        assert!(NotifiedJob::parse(&job.notify_params(false, false)).is_err());
    }
}
