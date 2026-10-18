//! Signer protection for PoWit votes (docs/DESIGN-obenblock-poci.md §8):
//! a witness key must never produce evidence against itself by accident.
//!
//! One [`VoteGuard`] per key and process, shared by every path that signs a
//! link (the node's witness duty, `gnb-cli powitattest`, a restart, a
//! failover onto a fresh data directory):
//!
//! 1. **Persist before release** ([`VoteGuard::sign_link`]): the vote entry
//!    (key, source, target, config id, the signed attestation) is written and
//!    fsynced, with the high-water mark beside the key file, before the
//!    signature is returned. A repeat of the same request returns the stored
//!    attestation (idempotent); a crash at any point never releases a
//!    signature that is not on disk.
//! 2. **Refuse double and surround votes** against every recorded link and
//!    against the high-water mark (EIP-3076's minimal protection, which alone
//!    excludes both shapes).
//! 3. **Rollback guard** ([`VoteGuard::observe`]): votes of this key seen in
//!    the chain or the pool that the record does not hold, at or above its
//!    high-water mark, mean a stale record (restored backup, second
//!    instance): the guard stops signing, raises an alert (log, the
//!    `gnb_powit_signer_halted` metric, `getpowitinfo.signers`), adopts those
//!    votes into the record (so they are refused against even after the alert
//!    is cleared) and persists the alert. Only an operator clears it
//!    (`gnb-cli powitsignerclear`).
//! 4. **One active signer per key**: an exclusive lock (`flock`) on
//!    `<record>.lock` and on `<key>.signer.lock`, and a fresh instance id
//!    written into the record at start; before every vote the record and the
//!    high-water file are re-read and must still be this instance's (another
//!    writer on storage where locks do not hold halts the signer).
//!
//! Record format v2 (`powit-votes-<key id hex>.json`): see [`RECORD_FORMAT`]
//! and [`RecordV2`]. The v1 record (a bare JSON array of `[source, target]`
//! checkpoints) is read and rewritten as v2 at the first start (explicit
//! migration); an older binary then refuses the v2 file as corrupt, which is
//! fail-closed.
//!
//! PoCI (ObenBlock, attestation message v3) plugs in through the `config_id`
//! argument of [`VoteGuard::sign_link`] and the `sign` closure, which builds
//! the v3 message; the guard compares links regardless of config id (a
//! stricter rule than PoCI's evidence, which needs the same config id).

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use gnb_crypto::core::powit::{Attestation, Checkpoint, KeyId};

/// The `format` string of a v2 vote record.
pub const RECORD_FORMAT: &str = "gnb-powit-vote-record/2";

/// A source checkpoint learned from chain state, which keeps only its
/// height: its hash is unknown and stored as all zeros.
pub const UNKNOWN_HASH: [u8; 32] = [0u8; 32];

// ── Durable files ────────────────────────────────────────────────────────────

/// Write `bytes` to `path` so that it survives a crash or a power loss:
/// a temp file in the same directory, fsync'd, renamed over `path`, then the
/// directory fsync'd (the rename itself is durable only then). Owner-only
/// permissions (the KES key file holds the encrypted seed).
pub fn write_durable(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let name = path.file_name().ok_or_else(|| format!("{}: not a file path", path.display()))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let io = |what: &str, e: std::io::Error| format!("{what} {}: {e}", tmp.display());
    let mut f = opts.open(&tmp).map_err(|e| io("create", e))?;
    f.write_all(bytes).map_err(|e| io("write", e))?;
    f.sync_all().map_err(|e| io("fsync", e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    File::open(dir).and_then(|d| d.sync_all()).map_err(|e| format!("fsync directory {}: {e}", dir.display()))
}

/// Read a JSON file that may be absent (`None`), refusing one that exists but
/// cannot be read or parsed: an unreadable vote record must never read as
/// "no votes" (that re-opens every link the key signed).
pub fn read_json_if_present<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<Option<T>, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| format!(
            "{what} {} is corrupt ({e}); refusing to sign: restore it from a backup (deleting it can make \
             this key sign a double vote and be barred)", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{what} {} is unreadable ({e}); refusing to sign", path.display())),
    }
}

// ── Record ───────────────────────────────────────────────────────────────────

/// The highest source and target heights a key ever signed, and the link
/// with that target (`last`, absent in files written before v2). Kept in the
/// record and beside the key file (`<key>.votes-highwater.json`), so it moves
/// with the key onto a fresh data directory. A link with a lower source or a
/// target not above `target` is never signed: that alone excludes double and
/// surround votes against everything the key signed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HighWater {
    pub source: u64,
    pub target: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<(Checkpoint, Checkpoint)>,
}

impl HighWater {
    pub fn max(self, o: &HighWater) -> Self {
        let last = match (self.last, o.last) {
            (Some(a), Some(b)) => Some(if b.1.height > a.1.height { b } else { a }),
            (a, b) => a.or(b),
        };
        HighWater { source: self.source.max(o.source), target: self.target.max(o.target), last }
    }
    pub fn of_link(source: &Checkpoint, target: &Checkpoint) -> Self {
        HighWater { source: source.height, target: target.height, last: Some((*source, *target)) }
    }
    pub fn allows(&self, source: &Checkpoint, target: &Checkpoint) -> bool {
        source.height >= self.source && target.height > self.target
    }
}

/// Where a recorded link came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// Signed by this guard; `attestation` holds it.
    Signed,
    /// Migrated from a v1 record (no signature kept).
    Legacy,
    /// Seen in the chain or the pool, not signed by this record's history
    /// (the rollback guard adopted it).
    Foreign,
}

/// One link in the record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteEntry {
    pub source: Checkpoint,
    pub target: Checkpoint,
    /// PoCI configuration id (hex, 32 bytes) the vote names; `None` for the
    /// v1/v2 attestation messages, which name none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_id: Option<String>,
    /// The released attestation, wire bytes (hex). `Signed` entries only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    pub origin: Origin,
    /// The instance that signed it (`Signed` entries).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl VoteEntry {
    fn same_link(&self, source: &Checkpoint, target: &Checkpoint, config_id: Option<&str>) -> bool {
        self.source == *source && self.target == *target && self.config_id.as_deref() == config_id
    }
}

/// The v2 vote record file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordV2 {
    pub format: String,
    pub key_id: String,
    /// The instance that holds (held) the record: written at every start.
    pub instance: String,
    pub highwater: HighWater,
    /// A persisted rollback-guard alert: while set, nothing is signed.
    #[serde(default)]
    pub alert: Option<String>,
    pub votes: Vec<VoteEntry>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AnyRecord {
    V2(RecordV2),
    V1(Vec<(Checkpoint, Checkpoint)>),
}

/// Read a vote record of either format; `None` if absent.
pub fn read_record(path: &Path, key_id: &KeyId) -> Result<Option<RecordV2>, String> {
    let Some(any) = read_json_if_present::<AnyRecord>(path, "witness vote record")? else { return Ok(None) };
    let rec = match any {
        AnyRecord::V2(r) => r,
        AnyRecord::V1(links) => RecordV2 {
            format: RECORD_FORMAT.into(),
            key_id: hex::encode(key_id),
            instance: String::new(),
            highwater: links.iter().fold(HighWater::default(), |h, (s, t)| h.max(&HighWater::of_link(s, t))),
            alert: None,
            votes: links.into_iter().map(|(source, target)| VoteEntry {
                source, target, config_id: None, attestation: None, origin: Origin::Legacy, instance: None,
            }).collect(),
        },
    };
    if rec.format != RECORD_FORMAT {
        return Err(format!("witness vote record {}: unknown format {:?}; refusing to sign", path.display(), rec.format));
    }
    if rec.key_id != hex::encode(key_id) {
        return Err(format!("witness vote record {} belongs to key {}, not {}; refusing to sign",
                           path.display(), rec.key_id, hex::encode(key_id)));
    }
    Ok(Some(rec))
}

/// The record a key's guard keeps in `dir` (the node's data directory, or
/// for `gnb-cli powitattest` the directory it names).
pub fn record_path(dir: &Path, key_id: &KeyId) -> PathBuf {
    dir.join(format!("powit-votes-{}.json", hex::encode(key_id)))
}

/// The high-water file beside the key file.
pub fn highwater_path(key: &Path) -> Result<PathBuf, String> {
    let mut name = key.file_name().ok_or("witness key path has no file name")?.to_os_string();
    name.push(".votes-highwater.json");
    Ok(key.with_file_name(name))
}

/// The lock file beside the key file.
pub fn key_lock_path(key: &Path) -> Result<PathBuf, String> {
    let mut name = key.file_name().ok_or("witness key path has no file name")?.to_os_string();
    name.push(".signer.lock");
    Ok(key.with_file_name(name))
}

// ── Alerts (getpowitinfo, metric) ────────────────────────────────────────────

/// What `getpowitinfo.signers` reports for one guard of this process.
#[derive(Clone, Debug, Serialize)]
pub struct SignerStatus {
    pub key: String,
    pub instance: String,
    pub record: String,
    pub halted: bool,
    pub alert: Option<String>,
    pub votes_recorded: usize,
    pub highwater: HighWater,
}

/// Guards of this process by (key, instance).
type StatusMap = BTreeMap<(KeyId, [u8; 16]), SignerStatus>;

static STATUS: std::sync::LazyLock<Mutex<StatusMap>> =
    std::sync::LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn publish_metric(map: &StatusMap) {
    crate::metrics::set_powit_signer_halted(map.values().filter(|s| s.halted).count() as i64);
}

/// The guards of this process, for `getpowitinfo`.
pub fn statuses() -> Vec<SignerStatus> {
    STATUS.lock().values().cloned().collect()
}

/// Whether any guard of this process is halted.
pub fn any_halted() -> bool {
    STATUS.lock().values().any(|s| s.halted)
}

// ── Crash points (tests) ─────────────────────────────────────────────────────

/// Where [`VoteGuard::sign_link`] can be made to "crash" (tests): it then
/// stops there as a killed process would, with the files as written so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// Checks passed, nothing signed.
    BeforeSign,
    /// Signed (KES evolved and saved), nothing recorded.
    AfterSign,
    /// The record written, the high-water file beside the key not yet.
    AfterRecord,
    /// Both written, the signature not yet returned.
    AfterPersist,
}

impl CrashPoint {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "before_sign" => CrashPoint::BeforeSign,
            "after_sign" => CrashPoint::AfterSign,
            "after_record" => CrashPoint::AfterRecord,
            "after_persist" => CrashPoint::AfterPersist,
            _ => return None,
        })
    }
}

/// The environment variable `gnb-cli powitattest` reads a crash point from
/// (tests: the process aborts there).
pub const CRASH_ENV: &str = "GNB_TEST_SIGNER_CRASH_AT";

// ── Guard ────────────────────────────────────────────────────────────────────

/// A vote seen outside the record (chain state or pool).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedVote {
    pub source_height: u64,
    /// `None` when only the height is known (chain state).
    pub source_hash: Option<[u8; 32]>,
    pub target: Checkpoint,
}

impl ObservedVote {
    pub fn of(a: &Attestation) -> Self {
        ObservedVote { source_height: a.source.height, source_hash: Some(a.source.hash), target: a.target }
    }
}

/// The result of [`VoteGuard::sign_link`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signed {
    /// Newly signed and persisted.
    Fresh(Attestation),
    /// The same request was signed before: the stored attestation.
    /// `first_release` is true the first time this process returns it
    /// (after a crash between persist and release, the restart releases it).
    Stored { att: Attestation, first_release: bool },
    /// The same link is recorded without a signature (a v1 record): it was
    /// signed and released before, nothing to release now.
    RecordedWithoutSignature,
}

struct GuardState {
    votes: Vec<VoteEntry>,
    hw: HighWater,
    alert: Option<String>,
    released: HashSet<(Checkpoint, Checkpoint, Option<String>)>,
}

/// The persistent protection of one witness key (module docs).
pub struct VoteGuard {
    key_id: KeyId,
    instance: [u8; 16],
    record_path: PathBuf,
    highwater_path: PathBuf,
    _locks: Vec<File>,
    st: Mutex<GuardState>,
    crash_at: Mutex<Option<(CrashPoint, bool)>>,
}

fn lock_exclusive(path: &Path, instance: &[u8; 16]) -> Result<File, String> {
    use std::io::{Read, Seek, Write};
    let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)
        .map_err(|e| format!("signer lock {}: {e}", path.display()))?;
    match f.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            let mut holder = String::new();
            let _ = f.read_to_string(&mut holder);
            return Err(format!(
                "another signer instance holds {} ({}); refusing to start a second signer for this key",
                path.display(), holder.trim()));
        }
        Err(std::fs::TryLockError::Error(e)) => return Err(format!("signer lock {}: {e}", path.display())),
    }
    let _ = f.set_len(0);
    let _ = f.rewind();
    let _ = writeln!(f, "instance {} pid {}", hex::encode(instance), std::process::id());
    let _ = f.sync_all();
    Ok(f)
}

/// Do two links conflict (double or surround vote)? Heights for the shapes,
/// the full target for a double vote. Config ids are not compared (module
/// docs: stricter than PoCI evidence).
pub fn links_conflict(s1: &Checkpoint, t1: &Checkpoint, s2: &Checkpoint, t2: &Checkpoint) -> bool {
    (t1.height == t2.height && t1 != t2)
        || (s1.height < s2.height && t2.height < t1.height)
        || (s2.height < s1.height && t1.height < t2.height)
}

impl VoteGuard {
    /// Open the guard of `key_id` (key file `key`, record `record`): take
    /// both locks, read the record (v1 or v2) and the high-water file beside
    /// the key (refusing either if it exists but cannot be read), then claim
    /// the record for a fresh instance id (rewriting it as v2) before
    /// anything is signed.
    pub fn open(key_id: KeyId, key: &Path, record: &Path) -> Result<Self, String> {
        let mut instance = [0u8; 16];
        rand::fill(&mut instance[..]);
        let record_lock = record.with_extension("lock");
        let locks = vec![lock_exclusive(&key_lock_path(key)?, &instance)?, lock_exclusive(&record_lock, &instance)?];
        let highwater_path = highwater_path(key)?;
        let rec = read_record(record, &key_id)?;
        let beside: HighWater = read_json_if_present(&highwater_path, "witness vote high-water file")?.unwrap_or_default();
        let (votes, rec_hw, alert) = match rec {
            Some(r) => (r.votes, r.highwater, r.alert),
            None => (Vec::new(), HighWater::default(), None),
        };
        let hw = votes.iter().fold(rec_hw.max(&beside), |h, v| h.max(&HighWater::of_link(&v.source, &v.target)));
        let guard = VoteGuard {
            key_id,
            instance,
            record_path: record.to_path_buf(),
            highwater_path,
            _locks: locks,
            st: Mutex::new(GuardState { votes, hw, alert, released: HashSet::new() }),
            crash_at: Mutex::new(None),
        };
        {
            let st = guard.st.lock();
            guard.persist(&st)?;
        }
        guard.publish();
        if let Some(a) = guard.alert() {
            log::error!("🛡  PoWit signer {} is halted by a persisted alert: {a}", hex::encode(key_id));
        }
        Ok(guard)
    }

    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn instance(&self) -> [u8; 16] {
        self.instance
    }

    pub fn record_path(&self) -> &Path {
        &self.record_path
    }

    /// The alert that halts this signer, if any.
    pub fn alert(&self) -> Option<String> {
        self.st.lock().alert.clone()
    }

    pub fn highwater(&self) -> HighWater {
        self.st.lock().hw
    }

    pub fn votes(&self) -> Vec<VoteEntry> {
        self.st.lock().votes.clone()
    }

    /// Tests: stop [`Self::sign_link`] at `p` (an error, or with `abort`
    /// the process aborts there).
    #[doc(hidden)]
    pub fn set_crash_point(&self, p: Option<CrashPoint>, abort: bool) {
        *self.crash_at.lock() = p.map(|p| (p, abort));
    }

    fn crash(&self, p: CrashPoint) -> Result<(), String> {
        match *self.crash_at.lock() {
            Some((q, abort)) if q == p => {
                if abort {
                    std::process::abort();
                }
                Err(format!("signer crash point {p:?}"))
            }
            _ => Ok(()),
        }
    }

    fn record_of(&self, st: &GuardState) -> RecordV2 {
        RecordV2 {
            format: RECORD_FORMAT.into(),
            key_id: hex::encode(self.key_id),
            instance: hex::encode(self.instance),
            highwater: st.hw,
            alert: st.alert.clone(),
            votes: st.votes.clone(),
        }
    }

    fn write_record(&self, st: &GuardState) -> Result<(), String> {
        let bytes = serde_json::to_vec(&self.record_of(st)).map_err(|e| e.to_string())?;
        write_durable(&self.record_path, &bytes).map_err(|e| format!("witness vote record: {e}"))
    }

    fn write_highwater(&self, st: &GuardState) -> Result<(), String> {
        let bytes = serde_json::to_vec(&st.hw).map_err(|e| e.to_string())?;
        write_durable(&self.highwater_path, &bytes).map_err(|e| format!("witness vote high-water file: {e}"))
    }

    fn persist(&self, st: &GuardState) -> Result<(), String> {
        self.write_record(st)?;
        self.write_highwater(st)
    }

    fn publish(&self) {
        let st = self.st.lock();
        let s = SignerStatus {
            key: hex::encode(self.key_id),
            instance: hex::encode(self.instance),
            record: self.record_path.display().to_string(),
            halted: st.alert.is_some(),
            alert: st.alert.clone(),
            votes_recorded: st.votes.len(),
            highwater: st.hw,
        };
        drop(st);
        let mut map = STATUS.lock();
        map.insert((self.key_id, self.instance), s);
        publish_metric(&map);
    }

    /// Halt with `alert` (kept on disk). `adopt` are foreign links to add to
    /// the record (and the high-water mark) first.
    fn halt(&self, st: &mut GuardState, alert: String, adopt: Vec<VoteEntry>) {
        log::error!("🛡  PoWit signer {} HALTED: {alert}", hex::encode(self.key_id));
        for e in adopt {
            st.hw = st.hw.max(&HighWater { source: e.source.height, target: e.target.height, last: None });
            st.votes.push(e);
        }
        if st.alert.is_none() {
            st.alert = Some(alert);
        }
        if let Err(e) = self.persist(st) {
            log::error!("🛡  PoWit signer {}: could not persist the alert: {e}", hex::encode(self.key_id));
        }
    }

    /// One active signer: the record and the high-water file on disk must
    /// still be this instance's and hold nothing this guard does not.
    fn check_on_disk(&self, st: &mut GuardState) -> Result<(), String> {
        let mine = hex::encode(self.instance);
        let disk = read_record(&self.record_path, &self.key_id);
        let beside = read_json_if_present::<HighWater>(&self.highwater_path, "witness vote high-water file");
        // What another writer put on disk is adopted into the record before
        // the alert is written (never overwritten away), its heights too.
        let mut adopt: Vec<VoteEntry> = Vec::new();
        let mut disk_hw = HighWater::default();
        if let Ok(Some(r)) = &disk {
            adopt.extend(r.votes.iter().filter(|v| !st.votes.contains(v)).cloned());
            disk_hw = disk_hw.max(&r.highwater);
        }
        if let Ok(Some(b)) = &beside {
            disk_hw = disk_hw.max(b);
        }
        let above = disk_hw.target > st.hw.target || disk_hw.source > st.hw.source;
        let problem = match (disk, beside) {
            (Err(e), _) | (_, Err(e)) => Some(e),
            (Ok(None), _) => Some(format!("vote record {} disappeared", self.record_path.display())),
            (Ok(Some(r)), _) if r.instance != mine => Some(format!(
                "vote record {} was claimed by another signer instance {} (this is {mine})",
                self.record_path.display(), r.instance)),
            _ if !adopt.is_empty() || above => Some(format!(
                "the vote record {} or the high-water file {} holds votes this signer did not write \
                 (another instance signs with this key or a copy of it)",
                self.record_path.display(), self.highwater_path.display())),
            _ => None,
        };
        match problem {
            None => Ok(()),
            Some(p) => {
                st.hw = st.hw.max(&HighWater { last: None, ..disk_hw });
                self.halt(st, p.clone(), adopt);
                Err(p)
            }
        }
    }

    /// Whether `source -> target` may be signed now (no disk access): not
    /// halted, above the high-water mark, no recorded conflict.
    pub fn permits(&self, source: &Checkpoint, target: &Checkpoint) -> bool {
        let st = self.st.lock();
        st.alert.is_none() && st.hw.allows(source, target)
            && !st.votes.iter().any(|v| links_conflict(&v.source, &v.target, source, target))
    }

    /// Whether the record holds `source -> target` (any config id).
    pub fn holds(&self, source: &Checkpoint, target: &Checkpoint) -> bool {
        self.st.lock().votes.iter().any(|v| v.source == *source && v.target == *target)
    }

    /// Rollback guard: `seen` are votes of this key in the chain and the
    /// pool, `evidence` whether an equivocation proof against it was seen.
    /// A vote the record does not hold whose target is at or above the
    /// high-water target (or whose source is above the high-water source)
    /// halts the signer. Lower ones are covered by the high-water mark
    /// (votes from before a failover onto a fresh data directory).
    /// Returns the alert, if halted.
    pub fn observe(&self, seen: &[ObservedVote], evidence: bool, from: &str) -> Option<String> {
        let mut st = self.st.lock();
        if st.alert.is_some() {
            return st.alert.clone();
        }
        let known = |st: &GuardState, o: &ObservedVote| {
            let matches = |s: &Checkpoint, t: &Checkpoint| s.height == o.source_height && *t == o.target
                && o.source_hash.is_none_or(|h| h == s.hash || s.hash == UNKNOWN_HASH);
            st.votes.iter().any(|v| matches(&v.source, &v.target)) || st.hw.last.is_some_and(|(s, t)| matches(&s, &t))
        };
        let mut stale: Vec<ObservedVote> = seen.iter().copied()
            .filter(|o| !known(&st, o) && (o.target.height >= st.hw.target || o.source_height > st.hw.source))
            .collect();
        stale.sort_by_key(|o| (o.target, o.source_height));
        stale.dedup();
        if stale.is_empty() && !evidence {
            return None;
        }
        let mut alert = String::new();
        if !stale.is_empty() {
            let o = stale.last().expect("non-empty");
            alert = format!(
                "{} vote(s) of this key in the {from} that the vote record {} does not hold (newest {} -> {} \
                 {}, record high-water {} -> {}): the record is stale (restored backup) or another instance \
                 signs with this key. Stop every other instance, then clear with `gnb-cli powitsignerclear`",
                stale.len(), self.record_path.display(), o.source_height, o.target.height,
                hex::encode(&o.target.hash[..8]), st.hw.source, st.hw.target);
        }
        if evidence {
            if !alert.is_empty() {
                alert.push_str("; ");
            }
            alert.push_str(&format!("an equivocation proof against this key was seen in the {from}"));
        }
        let adopt = stale.iter().map(|o| VoteEntry {
            source: Checkpoint { height: o.source_height, hash: o.source_hash.unwrap_or(UNKNOWN_HASH) },
            target: o.target,
            config_id: None,
            attestation: None,
            origin: Origin::Foreign,
            instance: None,
        }).collect();
        self.halt(&mut st, alert.clone(), adopt);
        drop(st);
        self.publish();
        Some(alert)
    }

    /// Sign `source -> target` (under `config_id`, PoCI) at most once:
    /// re-check the files on disk, return the stored attestation for a
    /// repeated request, refuse a conflict, else call `sign`, persist the
    /// entry (record, then the high-water file beside the key) and only then
    /// return the signature.
    pub fn sign_link<F>(&self, source: Checkpoint, target: Checkpoint, config_id: Option<[u8; 32]>, sign: F)
        -> Result<Signed, String>
    where
        F: FnOnce() -> Result<Attestation, String>,
    {
        let cfg = config_id.map(hex::encode);
        let mut st = self.st.lock();
        if let Some(a) = &st.alert {
            return Err(format!("PoWit signer halted: {a}"));
        }
        let r = self.check_on_disk(&mut st);
        if let Err(e) = r {
            drop(st);
            self.publish();
            return Err(format!("PoWit signer halted: {e}"));
        }
        if let Some(v) = st.votes.iter().find(|v| v.same_link(&source, &target, cfg.as_deref())).cloned() {
            let Some(hex_att) = v.attestation else { return Ok(Signed::RecordedWithoutSignature) };
            let bytes = hex::decode(&hex_att).map_err(|e| format!("stored attestation: {e}"))?;
            let att = Attestation::read_wire(&mut std::io::Cursor::new(bytes.as_slice()))?;
            let first_release = st.released.insert((source, target, cfg));
            return Ok(Signed::Stored { att, first_release });
        }
        if !st.hw.allows(&source, &target) {
            return Err(format!(
                "refusing {} -> {}: at or below the highest heights this key signed ({} -> {})",
                source.height, target.height, st.hw.source, st.hw.target));
        }
        if let Some(v) = st.votes.iter().find(|v| links_conflict(&v.source, &v.target, &source, &target)) {
            return Err(format!("refusing {} -> {}: a double or surround vote against the recorded {} -> {}",
                               source.height, target.height, v.source.height, v.target.height));
        }
        self.crash(CrashPoint::BeforeSign)?;
        let att = sign()?;
        if att.source != source || att.target != target || att.key_id() != self.key_id {
            return Err("the signer produced another link or key than requested".into());
        }
        self.crash(CrashPoint::AfterSign)?;
        st.votes.push(VoteEntry {
            source,
            target,
            config_id: cfg.clone(),
            attestation: Some(hex::encode(att.to_wire_bytes())),
            origin: Origin::Signed,
            instance: Some(hex::encode(self.instance)),
        });
        st.hw = st.hw.max(&HighWater::of_link(&source, &target));
        // The entry stays in memory even if a write fails: the signer then
        // halts and never signs a conflict with a signature that may be on
        // disk; the signature is not released.
        let persisted = self.write_record(&st).and_then(|()| {
            self.crash(CrashPoint::AfterRecord)?;
            self.write_highwater(&st)
        });
        if let Err(e) = persisted {
            if !e.starts_with("signer crash point") {
                self.halt(&mut st, format!("could not persist the vote record: {e}"), Vec::new());
                drop(st);
                self.publish();
            }
            return Err(e);
        }
        self.crash(CrashPoint::AfterPersist)?;
        st.released.insert((source, target, cfg));
        drop(st);
        self.publish();
        Ok(Signed::Fresh(att))
    }

    /// Operator: clear a persisted alert (the adopted foreign links stay in
    /// the record and keep being refused against).
    pub fn clear_alert(&self) -> Result<Option<String>, String> {
        let mut st = self.st.lock();
        let old = st.alert.take();
        self.persist(&st)?;
        drop(st);
        self.publish();
        Ok(old)
    }
}

impl Drop for VoteGuard {
    fn drop(&mut self) {
        let mut map = STATUS.lock();
        map.remove(&(self.key_id, self.instance));
        publish_metric(&map);
    }
}
