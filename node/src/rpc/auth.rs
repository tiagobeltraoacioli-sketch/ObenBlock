//! Bloch-SIS Protocol — Sprint M: RPC authentication + rate limiting
//!
//! This module wraps the JSON-RPC handler with:
//!   1. Per-IP rate limiting (reads vs writes, separate buckets)
//!   2. Optional API key authentication (constant-time comparison)
//!   3. Explicit local trust policy and a direct-loopback rate exemption
//!
//! Security properties:
//!   - API key comparison uses `subtle::ConstantTimeEq` to prevent timing attacks
//!   - Rate limits use IPv4 /32 (including mapped IPv6) and native IPv6 /64
//!   - A separate source budget bounds work before body parsing and key hashing
//!   - `WRITE_METHODS` selects the tighter method budget
//!
//! See docs/THREAT_MODEL.md section 4 for threat analysis.

use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex;

use governor::{Quota, RateLimiter};
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use subtle::ConstantTimeEq;

/// P0 (roadmap §1.6 / §4.3): drop a per-IP rate-limit entry once it has been
/// idle this long. 24h matches the sweep the original code comment proposed.
const RL_IDLE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Sweep at most this often, so the eviction scan is amortized and does not run
/// on every request (keeps `check` ~O(1) between sweeps).
const RL_GC_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// M-2 (audit): hard cap on distinct rate-limit buckets tracked at once
/// (post `/64` aggregation for IPv6 — see [`rate_limit_key`]). The map was
/// previously bounded ONLY by the 24h idle TTL, swept at most every
/// [`RL_GC_INTERVAL`] (10 minutes) — far too slow a window against a fast
/// churn attacker minting a fresh source on every request (a routed IPv6
/// `/64` is 2^64 addresses; even a single spoofed-source-per-request flood
/// reaches this cap in well under a second at any realistic request rate).
/// Once at capacity, a brand-new key is NOT inserted — see `check`'s
/// overflow-bucket fallback — so the map's peak size is this constant, not
/// "however many distinct sources an attacker can mint before the next GC".
const MAX_TRACKED_KEYS: usize = 100_000;

/// B1-R2-10: one identity for IPv4 and mapped IPv4 at BOTH trust and rate
/// boundaries. Never apply IPv6 /64 aggregation to a trust decision.
/// Bitcoin Core's CNetAddr::SetLegacyIPv6 classifies mapped IPv4 likewise:
/// https://github.com/bitcoin/bitcoin/blob/master/src/netaddress.cpp
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

/// M-2 (audit): normalize a source IP to its rate-limit key. IPv4 is
/// unchanged — a single address IS the smallest unit an operator can be
/// assigned (`/32`). IPv6 is aggregated to its `/64` network prefix: `/64`
/// is the STANDARD allocation an ISP/VPS/cloud provider hands to a single
/// customer, so per-`/128` limiting (the previous behavior) let one
/// attacker holding a routed `/64` mint 2^64 fresh, individually-unlimited
/// rate-limit buckets from addresses it legitimately controls. Aggregating
/// to `/64` means every address within one customer's allocation shares one
/// bucket, matching the real-world cost of acquiring that allocation.
fn rate_limit_key(ip: IpAddr) -> IpAddr {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            for b in &mut octets[8..] {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// Methods we treat as "writes" (mutating, gossipped to peers).
/// Anything else is a read-only query of chain state.
/// `submitblock` is the B5f pool seam (see rpc::SubmitBlockFn).
/// `euvm_buildtx` (D5, `--features euvm` only) does not mutate chain state,
/// but it may carry SECRET KEYS for server-side signing and does CPU-heavy PQ
/// signing/VM work — auth + the tighter write rate limit apply. Listing the
/// name here is harmless when the feature is off (the method never registers).
/// `submitauxblock` injects a merged-mined block into consensus and
/// `createauxblock` mints/caches full candidate blocks (CPU + memory) — both
/// are the AuxPoW pool seam (R3-audit H-R3-5): auth + the write bucket apply.
/// `getblocktemplate` (L-8) does not mutate consensus state, but it is
/// listed here anyway: it is EXPENSIVE (dual DAG reads, an ancestry walk for
/// `bits`, draining + serialising up to 2000 mempool transactions) and was
/// previously unauthenticated at the loose read bucket, letting a poll loop
/// force that cost repeatedly for free. Its own short-TTL/single-flight gate
/// (`rpc::mod::gated_dispatch`, `AppState::template_gate`) adds a cache on top
/// of the stricter auth + rate limit this listing gives it.
pub const WRITE_METHODS: &[&str] = &[
    "sendrawtransaction",
    "submitblock",
    "getblocktemplate",
    "submitpowititem",
    "invalidateblock",
    "reconsiderblock",
    "ignorefinalized",
    "reconsiderfinalized",
    "setfinalitycheckpoint",
];

/// Operator chain-override methods (audit DAG-6): `invalidateblock` /
/// `reconsiderblock` make this node leave or rejoin a chain regardless of its
/// work, and the PoWit finality settings (`ignorefinalized`,
/// `reconsiderfinalized`, `setfinalitycheckpoint`; PoWit audit findings 2
/// and 3) change which finalized checkpoint pins it, so they are write-class (Host/Origin gate, never a wildcard origin,
/// write rate bucket — see [`WRITE_METHODS`]) AND they are never served to an
/// anonymous caller: they need either a fully trusted caller (loopback with
/// `--rpc-trust-loopback`, or a trusted private range) or the configured API
/// key, whatever `--rpc-require-auth-for-writes` says. With no key configured
/// and no trusted caller they are refused (fail-safe), like Bitcoin Core, where
/// every RPC requires credentials.
pub const ADMIN_METHODS: &[&str] = &[
    "invalidateblock",
    "reconsiderblock",
    "ignorefinalized",
    "reconsiderfinalized",
    "setfinalitycheckpoint",
];

/// Type alias for a direct (non-keyed) in-memory rate limiter.
type IpRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Clone, Copy)]
enum Bucket {
    Read,
    Write,
    BeforeAuth,
}

/// Per-IP rate-limit buckets plus a last-seen timestamp for eviction.
struct IpEntry {
    reads:     Arc<IpRateLimiter>,
    writes:    Arc<IpRateLimiter>,
    before_auth: Arc<IpRateLimiter>,
    last_seen: Instant,
}

/// Guarded interior state. A single mutex covers both the map and the last-GC
/// clock so eviction needs no second lock (no lock-ordering hazard).
struct Inner {
    buckets: HashMap<IpAddr, IpEntry>,
    last_gc: Instant,
    /// M-2: shared fallback buckets used ONLY once `buckets` is at
    /// [`MAX_TRACKED_KEYS`] and a request arrives from a key not already
    /// tracked. Every such "overflow" source shares these buckets, so
    /// the map's memory is bounded by the cap regardless of how many
    /// distinct (post-aggregation) sources actually show up.
    overflow_reads:  Arc<IpRateLimiter>,
    overflow_writes: Arc<IpRateLimiter>,
    overflow_before_auth: Arc<IpRateLimiter>,
}

/// Per-source rate-limit state. Each source gets read, write, and pre-auth
/// buckets, created lazily on first hit and subject to the same map cap.
///
/// P0 (roadmap §1.6 / §4.3): the map is now bounded by *time*. Previously it
/// never evicted, so a spoofed-source-IP or many-client flood grew it forever
/// → memory-exhaustion DoS. `check` runs an amortized sweep (at most once per
/// `RL_GC_INTERVAL`) that drops entries idle longer than `RL_IDLE_TTL`.
pub struct RateLimiterSet {
    reads_per_min:  u32,
    writes_per_min: u32,
    inner:          Mutex<Inner>,
}

impl RateLimiterSet {
    pub fn new(reads_per_min: u32, writes_per_min: u32) -> Self {
        let reads = Quota::per_minute(NonZeroU32::new(reads_per_min.max(1)).unwrap());
        let writes = Quota::per_minute(NonZeroU32::new(writes_per_min.max(1)).unwrap());
        let before_auth = Quota::per_minute(NonZeroU32::new(
            reads_per_min.max(1).saturating_add(writes_per_min.max(1))).unwrap());
        Self {
            reads_per_min,
            writes_per_min,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                last_gc: Instant::now(),
                overflow_reads:  Arc::new(RateLimiter::direct(reads)),
                overflow_writes: Arc::new(RateLimiter::direct(writes)),
                overflow_before_auth: Arc::new(RateLimiter::direct(before_auth)),
            }),
        }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    /// `is_write` selects which bucket. Caller should have already
    /// determined whether the method is a write (see `WRITE_METHODS`).
    pub fn check(&self, ip: IpAddr, is_write: bool) -> bool {
        let ip = canonical_ip(ip);
        // Localhost bypass
        if ip.is_loopback() {
            return true;
        }
        self.check_key(ip, is_write)
    }

    /// [`Self::check`] without the loopback bypass: the bucket of `ip`
    /// whatever it is. B2-T11: a request that came through a reverse proxy
    /// is limited per the client the proxy names, and an unnamed proxied
    /// client shares the bucket of the proxy's own (loopback) address.
    pub fn check_key(&self, ip: IpAddr, is_write: bool) -> bool {
        self.check_bucket(ip, if is_write { Bucket::Write } else { Bucket::Read })
    }

    fn check_bucket(&self, ip: IpAddr, bucket: Bucket) -> bool {
        // M-2: aggregate IPv6 to its /64 allocation before using it as a key.
        let key = rate_limit_key(ip);

        let now = Instant::now();
        let mut inner = self.inner.lock();

        // Amortized time-based eviction (bounds the map — see struct docs).
        if now.duration_since(inner.last_gc) >= RL_GC_INTERVAL {
            inner.buckets.retain(|_, e| now.duration_since(e.last_seen) < RL_IDLE_TTL);
            inner.last_gc = now;
        }

        // M-2: hard cap, independent of and tighter than the idle-TTL sweep
        // above. A brand-new key arriving once the map is already at
        // capacity is NOT inserted — it is routed through a single shared
        // overflow bucket instead, so the map can never grow past
        // MAX_TRACKED_KEYS regardless of source churn between GC sweeps.
        if !inner.buckets.contains_key(&key) && inner.buckets.len() >= MAX_TRACKED_KEYS {
            let limiter = match bucket {
                Bucket::Read => inner.overflow_reads.clone(),
                Bucket::Write => inner.overflow_writes.clone(),
                Bucket::BeforeAuth => inner.overflow_before_auth.clone(),
            };
            drop(inner);
            return limiter.check().is_ok();
        }

        let (reads_pm, writes_pm) = (self.reads_per_min, self.writes_per_min);
        let entry = inner.buckets.entry(key).or_insert_with(|| {
            let reads = Quota::per_minute(
                NonZeroU32::new(reads_pm.max(1)).unwrap()
            );
            let writes = Quota::per_minute(
                NonZeroU32::new(writes_pm.max(1)).unwrap()
            );
            let before_auth = Quota::per_minute(NonZeroU32::new(
                reads_pm.max(1).saturating_add(writes_pm.max(1))).unwrap());
            IpEntry {
                reads:     Arc::new(RateLimiter::direct(reads)),
                writes:    Arc::new(RateLimiter::direct(writes)),
                before_auth: Arc::new(RateLimiter::direct(before_auth)),
                last_seen: now,
            }
        });
        entry.last_seen = now;

        let limiter = match bucket {
            Bucket::Read => &entry.reads,
            Bucket::Write => &entry.writes,
            Bucket::BeforeAuth => &entry.before_auth,
        };
        limiter.check().is_ok()
    }

    /// Number of distinct IPs currently tracked. For diagnostics/metrics.
    pub fn tracked_ips(&self) -> usize {
        self.inner.lock().buckets.len()
    }
}

/// NET-16: constant-time key comparison over FIXED-LENGTH digests.
///
/// `subtle`'s slice `ct_eq` returns early when the lengths differ, which
/// leaks the configured key's length through timing. Hashing both sides to
/// SHA-256 first makes every comparison 32 bytes against 32 bytes, whatever
/// the presented key looks like; equality of the digests is equality of the
/// keys (collision resistance).
pub fn keys_match(presented: &str, configured: &str) -> bool {
    #[cfg(test)]
    KEY_HASH_BYTES.with(|n| n.set(n.get() + presented.len() + configured.len()));
    use sha2::{Digest, Sha256};
    let p: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    let c: [u8; 32] = Sha256::digest(configured.as_bytes()).into();
    p.ct_eq(&c).unwrap_u8() == 1
}

#[cfg(test)]
thread_local! {
    pub(crate) static KEY_HASH_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Authentication decision for a single incoming request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDecision {
    /// Proceed with the request.
    Allow,
    /// Reject with 401.
    Unauthorized,
    /// Reject with 429.
    RateLimited,
}

/// Returns true if the IP should be treated as "trusted local" and exempt
/// from auth + rate limiting.
///
/// Always exempt: loopback (127.0.0.1, ::1).
///
/// Exempt only when `trust_private_ranges` is true: RFC1918 / ULA.
/// This flag exists because Docker's default bridge rewrites the source IP
/// to the bridge gateway (e.g. 172.17.0.1), which is NOT loopback. Without
/// this flag, the operator running `curl 127.0.0.1` on the Docker host
/// gets 401s for writes. SECURITY: enabling this on a node sharing a
/// subnet with untrusted tenants (Kubernetes, shared VLANs) lets those
/// tenants bypass auth. Only enable on trusted single-tenant hosts.
///
/// Ranges covered when trust_private_ranges = true:
///   - IPv4 RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
///   - IPv6 ULA:     fc00::/7
/// Explicitly NOT covered (even with the flag):
///   - IPv4 link-local 169.254.0.0/16 (spoofable, APIPA)
///   - Carrier-grade NAT 100.64.0.0/10 (shared with other tenants by definition)
pub fn is_trusted_local_ip(ip: IpAddr, trust_private_ranges: bool) -> bool {
    let ip = canonical_ip(ip);
    if ip.is_loopback() {
        return true;
    }
    if !trust_private_ranges {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8
            o[0] == 10
                // 172.16.0.0/12
                || (o[0] == 172 && (o[1] & 0xF0) == 16)
                // 192.168.0.0/16
                || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => {
            // fc00::/7 — Unique Local Address (RFC 4193)
            let first = v6.octets()[0];
            (first & 0xFE) == 0xFC
        }
    }
}

/// Apply auth + rate-limit checks with explicit control over BOTH trust
/// bypasses (R3-audit H-R3-5).
///
/// `trust_loopback_auth` gates the historical "127.0.0.1 / ::1 bypasses
/// everything" behaviour. That blanket bypass let ANY local process — and,
/// critically, any web page running in a browser on the operator's machine
/// (the browser connects from 127.0.0.1) — call write methods without the
/// configured API key. It is now an explicit opt-in (`--rpc-trust-loopback`).
/// With it off, loopback still skips the per-IP rate limiter (localhost
/// cannot be spoofed remotely and operator tooling / the co-located pool
/// hammer the port), but must satisfy the same API-key policy as any remote
/// caller.
pub fn authorize_with_policy(
    ip: IpAddr,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    trust_private_ranges: bool,
    trust_loopback_auth: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    let ip = canonical_ip(ip);
    let fully_trusted = if ip.is_loopback() {
        trust_loopback_auth
    } else {
        is_trusted_local_ip(ip, trust_private_ranges)
    };
    if fully_trusted {
        return AuthDecision::Allow;
    }

    let is_write = WRITE_METHODS.contains(&method);

    // Loopback keeps its rate-limit exemption (see doc comment) but falls
    // through to the key checks below. `RateLimiterSet::check` already
    // returns true for loopback, so calling it would be a no-op; skip it to
    // keep the exemption in one obvious place.
    if !ip.is_loopback() && !rate_limiter.check(ip, is_write) {
        return AuthDecision::RateLimited;
    }

    if (is_write && require_auth_for_writes) || ADMIN_METHODS.contains(&method) {
        match (presented_key, configured_key) {
            (Some(p), Some(c)) => {
                if keys_match(p, c) {
                    AuthDecision::Allow
                } else {
                    AuthDecision::Unauthorized
                }
            }
            _ => AuthDecision::Unauthorized,
        }
    } else if let (Some(p), Some(c)) = (presented_key, configured_key) {
        if keys_match(p, c) {
            AuthDecision::Allow
        } else {
            AuthDecision::Unauthorized
        }
    } else {
        AuthDecision::Allow
    }
}

/// Apply auth + rate-limit checks to an incoming request, with explicit
/// control over whether private IP ranges are trusted.
///
/// This is the Sprint M-patch1 signature. The older `authorize()` wraps
/// this with `trust_private_ranges = false` for backward compatibility.
///
/// NOTE (H-R3-5): keeps the historical blanket loopback bypass
/// (`trust_loopback_auth = true`). The server path uses
/// `authorize_with_policy` and only passes true behind `--rpc-trust-loopback`.
pub fn authorize_with_trust(
    ip: IpAddr,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    trust_private_ranges: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    let ip = canonical_ip(ip);
    if is_trusted_local_ip(ip, trust_private_ranges) {
        return AuthDecision::Allow;
    }

    let is_write = WRITE_METHODS.contains(&method);

    if !rate_limiter.check(ip, is_write) {
        return AuthDecision::RateLimited;
    }

    if (is_write && require_auth_for_writes) || ADMIN_METHODS.contains(&method) {
        match (presented_key, configured_key) {
            (Some(p), Some(c)) => {
                if keys_match(p, c) {
                    AuthDecision::Allow
                } else {
                    AuthDecision::Unauthorized
                }
            }
            _ => AuthDecision::Unauthorized,
        }
    } else if let (Some(p), Some(c)) = (presented_key, configured_key) {
        if keys_match(p, c) {
            AuthDecision::Allow
        } else {
            AuthDecision::Unauthorized
        }
    } else {
        AuthDecision::Allow
    }
}

/// M-1 (audit): `authorize_with_policy` — like every function in this file
/// before this one — only ever required a key for WRITE methods; there was
/// no configuration in which a read could be denied for lacking a key. That
/// was a deliberate default ("reads remain public (explorers need them)",
/// `main.rs`'s CLI help), but it left an operator with NO way to actually
/// close the endpoint: the read surface is not innocuous (`getutxos`,
/// `getbalance`, `listtransactions`, `getaddressinfo` are a complete
/// chain-analysis toolkit against any address; `getrawmempool verbose`
/// exposes first-seen mempool contents — the input Dandelion++ exists to
/// deny; `getpeers` returns the full peer list, the reconnaissance step for
/// an eclipse attempt — see `SECURITY.md`'s explicit in-scope privacy list).
///
/// This function adds `require_auth_for_reads`, orthogonal to
/// `require_auth_for_writes`: when true, a read is authorized under EXACTLY
/// the same rule writes already use — present the configured key, or be
/// refused. Same fail-safe as the write rule: if the operator sets this true
/// but no `configured_key` exists at all, every non-trusted read is refused
/// rather than silently staying public (an operator cannot accidentally
/// believe reads are locked down while they remain open because no key was
/// configured).
///
/// The reads-are-public DEFAULT is unchanged — this is strictly additive;
/// passing `require_auth_for_reads = false` reproduces `authorize_with_policy`
/// exactly.
pub fn authorize_with_read_policy(
    ip: IpAddr,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    require_auth_for_reads: bool,
    trust_private_ranges: bool,
    trust_loopback_auth: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    let ip = canonical_ip(ip);
    let fully_trusted = if ip.is_loopback() {
        trust_loopback_auth
    } else {
        is_trusted_local_ip(ip, trust_private_ranges)
    };
    if fully_trusted {
        return AuthDecision::Allow;
    }

    let is_write = WRITE_METHODS.contains(&method);

    if !ip.is_loopback() && !rate_limiter.check(ip, is_write) {
        return AuthDecision::RateLimited;
    }

    let requires_key = (is_write && require_auth_for_writes)
        || (!is_write && require_auth_for_reads)
        || ADMIN_METHODS.contains(&method);

    if requires_key {
        match (presented_key, configured_key) {
            (Some(p), Some(c)) if keys_match(p, c) => {
                AuthDecision::Allow
            }
            _ => AuthDecision::Unauthorized,
        }
    } else if let (Some(p), Some(c)) = (presented_key, configured_key) {
        if keys_match(p, c) {
            AuthDecision::Allow
        } else {
            AuthDecision::Unauthorized
        }
    } else {
        AuthDecision::Allow
    }
}

// ── B2-T11: requests that came through a reverse proxy ──────────────────────
//
// docs/RUNNING.md recommends a TLS reverse proxy (or a tunnel) in front of a
// remote node's RPC port. A proxy on the same host makes every remote request
// arrive from 127.0.0.1, and loopback was exempt from the rate limiter and,
// with `--rpc-trust-loopback`, from authentication: every proxied client got
// the operator's privileges (unlimited anonymous `submitblock`; anonymous
// `invalidateblock` with the flag). Proxies announce themselves with
// forwarding headers (nginx, HAProxy, Caddy, Apache, Cloudflare and
// cloudflared all set at least one). A request that carries one is treated as
// the remote request it is: rate-limited per the client the proxy names, and
// never fully trusted. Bitcoin Core has no anonymous RPC at all.

/// Headers by which a reverse proxy, load balancer or tunnel names the
/// original client (or says that it forwarded the request).
pub const FORWARDING_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
    "x-forwarded-host",
    "via",
];

/// The client a forwarded request came from, as far as the proxy said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardedClient {
    /// The address the proxy reported in the operator's client header
    /// (`--rpc-proxy-client-header`; for `X-Forwarded-For` and `Forwarded`
    /// the LAST hop, the one the nearest proxy appended).
    Client(IpAddr),
    /// A forwarding header without a usable address in the client header.
    Unknown,
}

/// The default client header (`--rpc-proxy-client-header`): nginx with
/// `$proxy_add_x_forwarded_for`, HAProxy `option forwardfor`, Caddy, Apache
/// `mod_proxy`, Cloudflare and cloudflared all append the address they saw
/// to `X-Forwarded-For`.
pub const DEFAULT_PROXY_CLIENT_HEADER: &str = "x-forwarded-for";

/// Headers `--rpc-proxy-client-header` may name: the ones that carry a
/// client address.
pub const PROXY_CLIENT_HEADERS: &[&str] = &[
    "x-forwarded-for", "forwarded", "x-real-ip", "cf-connecting-ip", "true-client-ip",
    "x-client-ip", "fastly-client-ip", "x-cluster-client-ip",
];

/// Validate `--rpc-proxy-client-header` (case-insensitive); the lower-case
/// header name.
pub fn validate_proxy_client_header(name: &str) -> Result<String, String> {
    let lower = name.trim().to_ascii_lowercase();
    if PROXY_CLIENT_HEADERS.contains(&lower.as_str()) {
        Ok(lower)
    } else {
        Err(format!("--rpc-proxy-client-header {name:?}: expected one of {}", PROXY_CLIENT_HEADERS.join(", ")))
    }
}

/// Parse an address as proxies write it: `1.2.3.4`, `1.2.3.4:5678`,
/// `2001:db8::1`, `[2001:db8::1]:5678`, optionally quoted.
fn parse_forwarded_addr(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_matches('"');
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next()?.parse().ok();
    }
    match s.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host.parse().ok(),
        _ => None,
    }
}

/// `Some` iff the request carries a forwarding header (it came through a
/// proxy), with the client named by `client_header`, the ONE header the
/// operator's proxy writes (`--rpc-proxy-client-header`, lower case).
///
/// B2-T11 (review): only that header is read. With a fixed precedence over
/// several headers, a client could write the header the proxy does not
/// control and choose its own rate-limit bucket: nginx with only
/// `proxy_set_header X-Real-IP $remote_addr` passes a client's own
/// `X-Forwarded-For` through unchanged, and that header used to win. For
/// `X-Forwarded-For` / `Forwarded` only the LAST hop is used: earlier
/// entries are whatever the client sent (nginx's
/// `$proxy_add_x_forwarded_for` appends the address it saw); for a
/// single-address header, the last value (a proxy that sets it replaces the
/// client's). Like nginx's `real_ip_header`.
pub fn forwarded_client(headers: &axum::http::HeaderMap, client_header: &str) -> Option<ForwardedClient> {
    if !FORWARDING_HEADERS.iter().any(|h| headers.contains_key(*h)) {
        return None;
    }
    let values = || headers.get_all(client_header).iter().filter_map(|v| v.to_str().ok());
    let client = match client_header {
        "x-forwarded-for" => values()
            .flat_map(|v| v.split(','))
            .rfind(|s| !s.trim().is_empty())
            .and_then(parse_forwarded_addr),
        "forwarded" => values()
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|elem| elem.split(';')
                .find_map(|kv| kv.trim().strip_prefix("for=").or_else(|| kv.trim().strip_prefix("For="))))
            .and_then(parse_forwarded_addr),
        _ => values().next_back().and_then(parse_forwarded_addr),
    };
    Some(match client {
        Some(ip) => ForwardedClient::Client(ip),
        None => ForwardedClient::Unknown,
    })
}

/// B2-T11 (review): a TCP peer whose forwarding headers name the client for
/// rate limiting: a proxy on this host (loopback) or, with
/// `--rpc-trust-private-ranges`, in a trusted private range. Any other peer
/// wrote those headers itself, so it is limited by its own address (and a
/// client that rotates `X-Forwarded-For` cannot mint a bucket per request or
/// fill the limiter's table).
pub fn peer_may_name_client(peer: IpAddr, trust_private_ranges: bool) -> bool {
    let peer = canonical_ip(peer);
    peer.is_loopback() || is_trusted_local_ip(peer, trust_private_ranges)
}

fn request_source(peer: IpAddr, forwarded: Option<ForwardedClient>, trust_private_ranges: bool) -> IpAddr {
    match forwarded {
        Some(ForwardedClient::Client(ip)) if peer_may_name_client(peer, trust_private_ranges) => canonical_ip(ip),
        _ => canonical_ip(peer),
    }
}

/// B1-R2-9: admit a source BEFORE hashing a key or reading its body. The
/// independent budget is reads/min + writes/min (each at least one), and
/// applies even if the request later presents a correct key. Trust cannot
/// be established by doing the very work this budget is meant to bound.
/// Direct local exemptions match the existing method-rate policy.
///
/// Bitcoin Core checks ClientAllowed and a bounded WorkQueue before its
/// RPC authentication handler; GnB's public reads additionally need a
/// per-source budget: https://github.com/bitcoin/bitcoin/blob/v30.0/src/httpserver.cpp#L275-L316
pub(crate) fn admit_before_auth(
    peer: IpAddr,
    forwarded: Option<ForwardedClient>,
    trust_private_ranges: bool,
    rate_limiter: &RateLimiterSet,
) -> bool {
    if forwarded.is_none() && is_trusted_local_ip(peer, trust_private_ranges) {
        return true;
    }
    rate_limiter.check_bucket(request_source(peer, forwarded, trust_private_ranges), Bucket::BeforeAuth)
}

/// True when the caller is the operator for the purpose of node-wide
/// budgets: it presented the configured API key, or it is a fully trusted
/// direct caller (`--rpc-trust-loopback` on loopback, a trusted private range)
/// that did not come through a proxy.
pub fn caller_is_trusted(
    peer: IpAddr,
    forwarded: Option<ForwardedClient>,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    trust_private_ranges: bool,
    trust_loopback_auth: bool,
) -> bool {
    let peer = canonical_ip(peer);
    if let (Some(p), Some(c)) = (presented_key, configured_key) {
        if keys_match(p, c) {
            return true;
        }
    }
    if forwarded.is_some() {
        return false;
    }
    if peer.is_loopback() {
        trust_loopback_auth
    } else {
        is_trusted_local_ip(peer, trust_private_ranges)
    }
}

/// B1-T10: a node-wide token bucket of bytes (refilled continuously at
/// `per_sec`, capped at `burst`). `sendrawtransaction` charges every
/// transaction an untrusted caller submits by its wire size before the
/// signatures are verified, and refunds it once the transaction is admitted:
/// valid transactions never use the budget up, and the verification work of
/// invalid ones (a forged-signature flood relayed by the explorer API over
/// loopback, from any number of client addresses) is bounded node-wide,
/// like the per-connection budget of the gossip path (MEM-5).
pub struct ByteBudget {
    burst:   f64,
    per_sec: f64,
    state:   Mutex<(f64, Instant)>,
}

impl ByteBudget {
    pub fn new(burst: u64, per_sec: u64) -> Self {
        Self { burst: burst as f64, per_sec: per_sec as f64, state: Mutex::new((burst as f64, Instant::now())) }
    }

    fn refill(&self, s: &mut (f64, Instant), now: Instant) {
        let dt = now.saturating_duration_since(s.1).as_secs_f64();
        s.0 = (s.0 + dt * self.per_sec).min(self.burst);
        s.1 = now;
    }

    /// Take `n` bytes; false (nothing taken) when fewer are left.
    pub fn take(&self, n: usize) -> bool {
        let mut s = self.state.lock();
        self.refill(&mut s, Instant::now());
        if (n as f64) > s.0 {
            return false;
        }
        s.0 -= n as f64;
        true
    }

    /// Give back `n` bytes taken earlier (never above the burst).
    pub fn refund(&self, n: usize) {
        let mut s = self.state.lock();
        s.0 = (s.0 + n as f64).min(self.burst);
    }
}

/// [`authorize_with_read_policy`] for a request that may have come through a
/// reverse proxy (B2-T11). With `forwarded == None` it is exactly
/// `authorize_with_read_policy(peer, ...)`. With `Some(_)` the request is a
/// remote one whatever its TCP peer: never fully trusted (no loopback /
/// private-range bypass, `--rpc-trust-loopback` included). A caller that
/// presents the configured API key is the operator (its pool behind the
/// TLS proxy polling `getblocktemplate`): it skips the method limiter but
/// still consumes the separate budget enforced before key verification.
/// Anyone else is rate-limited in the bucket of the client the proxy named
/// (IPv6 by /64) when the peer is a proxy ([`peer_may_name_client`]), else
/// in the bucket of the peer address itself (a proxied request that names no
/// client shares it); the API-key policy is unchanged.
#[allow(clippy::too_many_arguments)]
pub fn authorize_request(
    peer: IpAddr,
    forwarded: Option<ForwardedClient>,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    require_auth_for_reads: bool,
    trust_private_ranges: bool,
    trust_loopback_auth: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    if !admit_before_auth(peer, forwarded, trust_private_ranges, rate_limiter) {
        return AuthDecision::RateLimited;
    }
    authorize_admitted_request(peer, forwarded, method, presented_key, configured_key,
        require_auth_for_writes, require_auth_for_reads, trust_private_ranges,
        trust_loopback_auth, rate_limiter)
}

/// The HTTP handler already admitted the request before buffering its body.
/// Keep that path from charging the same request twice. All other callers
/// must use `authorize_request`.
#[allow(clippy::too_many_arguments)]
pub(super) fn authorize_admitted_request(
    peer: IpAddr,
    forwarded: Option<ForwardedClient>,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    require_auth_for_reads: bool,
    trust_private_ranges: bool,
    trust_loopback_auth: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    let Some(forwarded) = forwarded else {
        return authorize_with_read_policy(
            peer, method, presented_key, configured_key, require_auth_for_writes,
            require_auth_for_reads, trust_private_ranges, trust_loopback_auth, rate_limiter,
        );
    };
    if let (Some(p), Some(c)) = (presented_key, configured_key) {
        if keys_match(p, c) {
            return AuthDecision::Allow;
        }
    }
    let is_write = WRITE_METHODS.contains(&method);
    let key = request_source(peer, Some(forwarded), trust_private_ranges);
    if !rate_limiter.check_key(key, is_write) {
        return AuthDecision::RateLimited;
    }
    let requires_key = (is_write && require_auth_for_writes)
        || (!is_write && require_auth_for_reads)
        || ADMIN_METHODS.contains(&method);
    match (presented_key, configured_key) {
        // A present key was already checked above; do not hash it twice.
        (Some(_), Some(_)) => AuthDecision::Unauthorized,
        _ if requires_key => AuthDecision::Unauthorized,
        _ => AuthDecision::Allow,
    }
}

/// Apply auth + rate-limit checks to an incoming request.
///
/// Parameters:
///   - `ip`: peer IP (localhost is exempt from everything)
///   - `method`: JSON-RPC method name (decides read vs write)
///   - `presented_key`: value of X-API-Key or Bearer, if any
///   - `configured_key`: server's configured API key, if any
///   - `require_auth_for_writes`: whether writes without a key are blocked
///   - `rate_limiter`: shared rate-limit state
///
/// NOTE: Backward-compatible shim. Defaults to `trust_private_ranges=false`.
/// New code should call `authorize_with_trust()` directly.
pub fn authorize(
    ip: IpAddr,
    method: &str,
    presented_key: Option<&str>,
    configured_key: Option<&str>,
    require_auth_for_writes: bool,
    rate_limiter: &RateLimiterSet,
) -> AuthDecision {
    authorize_with_trust(
        ip,
        method,
        presented_key,
        configured_key,
        require_auth_for_writes,
        false,
        rate_limiter,
    )
}

/// L-6 (audit): minimum acceptable configured API key length, in bytes.
/// `--rpc-api-key x` was previously accepted outright — the constant-time
/// comparison in this file then faithfully protects a one-character secret,
/// which is security theater. 16 bytes (128 bits) is a floor, not a
/// recommendation; operators should prefer a CSPRNG-generated key well past
/// this length.
pub const MIN_API_KEY_LEN: usize = 16;

/// L-6 (audit): validate a configured API key BEFORE it is used for any
/// comparison. Two properties, both about the key's LOADING, not its use:
///
/// 1. **No control characters.** The key travels into at least one
///    hand-built HTTP header context (`bin/gnb-cli.rs`'s `x-api-key: {}`
///    interpolation — see the M-11 fix there) and potentially others. A key
///    containing `\r`/`\n`/other control bytes is a header-injection
///    primitive wherever it is later interpolated into raw text, and no
///    legitimate secret needs one.
/// 2. **Minimum length.** See [`MIN_API_KEY_LEN`].
///
/// This does not (and cannot, from here) check the file permissions of a
/// `--rpc-api-key-file` — that requires the file PATH, which is consumed by
/// `main.rs` before the key ever reaches this module. Call this at load time
/// (main.rs) AND defensively at server start (`start_rpc_server` does, on
/// `RpcConfig.api_key`, regardless of how the caller sourced it).
pub fn validate_api_key(key: &str) -> Result<(), &'static str> {
    validate_api_key_inner(key)
}

/// NET-16: permission policy for `--rpc-api-key-file` (Unix).
///
/// - any access for "other" (world bits) or group WRITE: refuse (`Err`);
/// - group READ (e.g. `0640 root:gnb`, a common service layout): allowed
///   with a warning (`Ok(Some(..))`);
/// - owner-only: `Ok(None)`.
///
/// On non-Unix platforms there are no mode bits to check (`Ok(None)`).
pub fn check_key_file_permissions(path: &std::path::Path) -> Result<Option<String>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("cannot stat API key file {}: {e}", path.display()))?;
        return key_file_mode_policy(meta.permissions().mode(), path);
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}

/// Mode-bit half of [`check_key_file_permissions`] (testable without files).
pub fn key_file_mode_policy(mode: u32, path: &std::path::Path) -> Result<Option<String>, String> {
    let mode = mode & 0o777;
    if mode & 0o027 != 0 {
        return Err(format!(
            "API key file {} has mode {:04o}: it must not be writable by its group or \
             accessible to other users (chmod 600 or 640)",
            path.display(), mode
        ));
    }
    if mode & 0o040 != 0 {
        return Ok(Some(format!(
            "API key file {} is readable by its group (mode {:04o}); make sure only the \
             node's service group can read it, or chmod 600",
            path.display(), mode
        )));
    }
    Ok(None)
}

fn validate_api_key_inner(key: &str) -> Result<(), &'static str> {
    if key.chars().any(|c| c.is_control()) {
        return Err("API key contains a control character (e.g. CR/LF) — refusing to use it");
    }
    if key.len() < MIN_API_KEY_LEN {
        return Err("API key is shorter than the minimum acceptable length");
    }
    Ok(())
}

/// Extract API key from either `X-API-Key` header or `Authorization: Bearer <key>`.
pub fn extract_api_key<'a>(headers: &'a axum::http::HeaderMap) -> Option<&'a str> {
    if let Some(v) = headers.get("x-api-key") {
        if let Ok(s) = v.to_str() {
            return Some(s);
        }
    }
    if let Some(v) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(stripped) = s.strip_prefix("Bearer ") {
                return Some(stripped);
            }
        }
    }
    None
}

// ── Browser-request gate: Host + Origin checks (R3-audit H-R3-5) ──────
//
// CORS alone does not stop a hostile web page from *sending* requests to the
// RPC port — it only stops the page from reading responses, and
// `sendrawtransaction` does its damage on send. Two header checks close the
// browser as an attack vector:
//
//   Host   — defeats DNS rebinding. A page at evil.example that rebinds its
//            hostname to 127.0.0.1 makes the browser send `Host: evil.example`
//            with a request that reaches this port. Legitimate clients either
//            connect by IP literal / localhost (Host is the address they
//            dialed) or by an operator-allowlisted hostname.
//   Origin — defeats cross-site request forgery. Browsers ALWAYS attach
//            `Origin` to cross-origin POSTs; non-browser clients (curl, the
//            pool, wallets) send none. A request carrying an Origin that the
//            operator did not allowlist is browser-borne and refused. The
//            wildcard entry "*" is honoured for READ methods only — write
//            methods never accept a wildcard (the finding's exact ask).

/// Reason a request was refused by the browser gate. Stable strings so the
/// handler can log/metric them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserGateRefusal {
    MissingHost,
    HostNotAllowed,
    OriginNotAllowed,
}

/// Strip the port from an HTTP Host header value. Handles `[v6]:port`,
/// `[v6]`, `host:port`, `host`.
fn host_without_port(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6: everything up to the closing bracket.
        match rest.find(']') {
            Some(i) => &rest[..i],
            None => host, // malformed; will fail the literal parse below
        }
    } else {
        // At most one ':' means host[:port]; more than one is an unbracketed
        // IPv6 literal (no port possible in a Host header without brackets).
        match (host.find(':'), host.rfind(':')) {
            (Some(f), Some(l)) if f == l => &host[..f],
            _ => host,
        }
    }
}

/// Host-header policy: IP literals and localhost are always fine (rebinding
/// requires a DNS *name*), any other hostname must be operator-allowlisted.
/// `"*"` in the allowlist disables the check (explicit opt-out).
pub fn host_allowed(host_header: Option<&str>, allowed_hosts: &[String]) -> Result<(), BrowserGateRefusal> {
    let raw = match host_header {
        Some(h) if !h.trim().is_empty() => h,
        _ => return Err(BrowserGateRefusal::MissingHost),
    };
    if allowed_hosts.iter().any(|h| h == "*") {
        return Ok(());
    }
    let host = host_without_port(raw);
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let host_lc = host.to_ascii_lowercase();
    if host_lc == "localhost" {
        return Ok(());
    }
    if allowed_hosts.iter().any(|h| h.to_ascii_lowercase() == host_lc) {
        return Ok(());
    }
    Err(BrowserGateRefusal::HostNotAllowed)
}

/// Origin-header policy. `is_write` selects the stricter rule: the wildcard
/// allowlist entry `"*"` never applies to write methods.
pub fn origin_allowed(
    origin_header: Option<&str>,
    allowed_origins: &[String],
    is_write: bool,
) -> Result<(), BrowserGateRefusal> {
    let origin = match origin_header {
        None => return Ok(()), // not a cross-origin browser request
        Some(o) => o.trim(),
    };
    // "null" is what browsers send for sandboxed iframes, file:// pages and
    // some redirects — never allowlistable.
    if origin.is_empty() || origin.eq_ignore_ascii_case("null") {
        return Err(BrowserGateRefusal::OriginNotAllowed);
    }
    let origin_lc = origin.to_ascii_lowercase();
    let listed_exact = allowed_origins
        .iter()
        .any(|o| o.trim_end_matches('/').to_ascii_lowercase() == origin_lc);
    let listed_wildcard = allowed_origins.iter().any(|o| o == "*");
    if listed_exact || (listed_wildcard && !is_write) {
        Ok(())
    } else {
        Err(BrowserGateRefusal::OriginNotAllowed)
    }
}

/// Combined gate, applied BEFORE auth/rate-limit so refused browser traffic
/// never touches the buckets. Pure so it is unit-testable without a server.
pub fn gate_browser_request(
    host_header: Option<&str>,
    origin_header: Option<&str>,
    method: &str,
    allowed_hosts: &[String],
    allowed_origins: &[String],
) -> Result<(), BrowserGateRefusal> {
    host_allowed(host_header, allowed_hosts)?;
    origin_allowed(origin_header, allowed_origins, WRITE_METHODS.contains(&method))
}

// ── Tests ─────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn rl() -> RateLimiterSet {
        RateLimiterSet::new(60, 5)
    }

    #[test]
    fn r7_mapped_ipv4_shares_only_its_native_bucket() {
        for is_write in [false, true] {
            let rl = RateLimiterSet::new(1, 1);
            let native: IpAddr = "198.51.100.7".parse().unwrap();
            let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
            assert!(rl.check_key(native, is_write));
            assert!(!rl.check_key(mapped, is_write), "mapped spelling must not mint a second budget");
            assert!(rl.check_key("::ffff:198.51.100.8".parse().unwrap(), is_write),
                "unrelated IPv4 clients must not share the ::/64 bucket");
            assert_eq!(rl.tracked_ips(), 2);
        }
    }

    #[test]
    fn r7_distinct_mapped_ipv4_clients_have_independent_budgets() {
        let rl = RateLimiterSet::new(1, 1);
        assert!(rl.check_key("::ffff:198.51.100.7".parse().unwrap(), false));
        assert!(rl.check_key("::ffff:198.51.100.8".parse().unwrap(), false),
            "one mapped client must not exhaust every other IPv4 client's budget");
        assert!(rl.check_key("::1".parse().unwrap(), false),
            "mapped clients must not share the native IPv6 ::/64 budget");
        assert_eq!(rl.tracked_ips(), 3);
    }

    #[test]
    fn r7_forwarded_key_hash_work_is_bounded() {
        let rl = RateLimiterSet::new(2, 1);
        let key = "k".repeat(32);
        let attack = "x".repeat(8192);
        KEY_HASH_BYTES.with(|n| n.set(0));
        for _ in 0..100 {
            authorize_request("127.0.0.1".parse().unwrap(),
                Some(ForwardedClient::Client("198.51.100.7".parse().unwrap())),
                "submitblock", Some(&attack), Some(&key), true, false, false, false, &rl);
        }
        let hashed = KEY_HASH_BYTES.with(|n| n.get());
        assert!(hashed <= 3 * (attack.len() + key.len()), "pre-auth budget exceeded: {hashed} hashed bytes");
    }

    #[test]
    fn r7_valid_key_cannot_bypass_pre_auth_budget() {
        let rl = RateLimiterSet::new(2, 1);
        let key = "k".repeat(32);
        let authorize = || authorize_request("127.0.0.1".parse().unwrap(),
            Some(ForwardedClient::Client("198.51.100.7".parse().unwrap())),
            "submitblock", Some(&key), Some(&key), true, false, false, false, &rl);
        for _ in 0..3 { assert_eq!(authorize(), AuthDecision::Allow); }
        assert_eq!(authorize(), AuthDecision::RateLimited);
    }

    #[test]
    fn r7_proxy_clients_keep_independent_pre_auth_budgets() {
        let rl = RateLimiterSet::new(2, 1);
        let key = "k".repeat(32);
        for client in ["198.51.100.7", "198.51.100.8", "2001:db8:1::7"] {
            let authorize = || authorize_request("127.0.0.1".parse().unwrap(),
                Some(ForwardedClient::Client(client.parse().unwrap())),
                "submitblock", Some(&key), Some(&key), true, false, false, false, &rl);
            for _ in 0..3 { assert_eq!(authorize(), AuthDecision::Allow, "client {client} has its own quota"); }
            assert_eq!(authorize(), AuthDecision::RateLimited);
        }
        assert_eq!(rl.tracked_ips(), 3, "the proxy socket is not a shared quota");
    }

    #[test]
    fn r7_mapped_proxy_peers_preserve_client_budgets() {
        for (peer, trust_private) in [("::ffff:127.0.0.1", false), ("::ffff:10.0.0.1", true)] {
            let rl = RateLimiterSet::new(2, 1);
            let key = "k".repeat(32);
            for client in ["198.51.100.7", "198.51.100.8"] {
                let authorize = || authorize_request(peer.parse().unwrap(),
                    Some(ForwardedClient::Client(client.parse().unwrap())),
                    "submitblock", Some(&key), Some(&key), true, false, trust_private, false, &rl);
                for _ in 0..3 { assert_eq!(authorize(), AuthDecision::Allow, "peer {peer}, client {client}"); }
                assert_eq!(authorize(), AuthDecision::RateLimited);
            }
            assert_eq!(rl.tracked_ips(), 2);
        }
    }

    #[test]
    fn r7_mapped_loopback_preserves_explicit_auth_policy() {
        for address in ["127.0.0.1", "::ffff:127.0.0.1"] {
            let ip = address.parse().unwrap();
            let rl = RateLimiterSet::new(1, 1);
            // Normalizing only inside is_trusted_local_ip would bypass
            // this guard by classifying mapped loopback as a private peer.
            assert_eq!(authorize_with_policy(ip, "submitblock", None, Some("key"), true, true, false, &rl),
                AuthDecision::Unauthorized, "loopback trust remains opt-in for {address}");
            assert_eq!(authorize_with_read_policy(ip, "getblockcount", None, Some("key"), true, true, true, false, &rl),
                AuthDecision::Unauthorized, "read auth also remains required for {address}");
            assert!(!caller_is_trusted(ip, None, None, None, true, false));
            assert_eq!(authorize_with_policy(ip, "submitblock", None, Some("key"), true, false, true, &rl),
                AuthDecision::Allow, "explicit loopback trust applies to {address}");
            assert!(caller_is_trusted(ip, None, None, None, false, true));
            for _ in 0..3 { assert!(rl.check(ip, true), "direct loopback retains its rate exemption"); }
        }
    }

    #[test]
    fn localhost_bypasses_everything() {
        let r = rl();
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        for _ in 0..100 {
            let d = authorize(
                loopback,
                "sendrawtransaction",
                None,
                Some("secret"),
                true, // require auth for writes
                &r,
            );
            assert_eq!(d, AuthDecision::Allow, "loopback must always pass");
        }
    }

    #[test]
    fn localhost_v6_bypasses_everything() {
        let r = rl();
        let loopback_v6: IpAddr = Ipv6Addr::LOCALHOST.into();
        let d = authorize(loopback_v6, "sendrawtransaction", None, Some("s"), true, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn remote_read_without_auth_allowed() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(remote, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn remote_write_without_auth_blocked_when_required() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "sendrawtransaction", None, Some("secret"), true, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn remote_write_with_correct_key_allowed() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "sendrawtransaction", Some("secret"), Some("secret"), true, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn remote_write_with_wrong_key_unauthorized() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "sendrawtransaction", Some("wrong"), Some("secret"), true, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn wrong_key_on_read_still_rejected() {
        // Probing with wrong keys should not be indistinguishable from no key.
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(
            remote, "getblockcount", Some("wrong"), Some("secret"), false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn no_configured_key_means_auth_always_passes_reads() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize(remote, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn rate_limit_kicks_in_on_remote_reads() {
        let r = RateLimiterSet::new(3, 2); // 3 reads/min for this test
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let mut allowed = 0;
        let mut rate_limited = 0;
        for _ in 0..10 {
            match authorize(remote, "getblockcount", None, None, false, &r) {
                AuthDecision::Allow => allowed += 1,
                AuthDecision::RateLimited => rate_limited += 1,
                _ => unreachable!(),
            }
        }
        assert!(allowed >= 1, "at least one should pass");
        assert!(rate_limited >= 1, "some should be rate-limited");
    }

    #[test]
    fn rate_limits_are_separate_per_ip() {
        let r = RateLimiterSet::new(2, 1);
        let ip1: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let ip2: IpAddr = Ipv4Addr::new(5, 6, 7, 8).into();

        // Exhaust ip1's reads
        for _ in 0..5 {
            authorize(ip1, "getblockcount", None, None, false, &r);
        }
        // ip2 should still be fresh
        let d = authorize(ip2, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn write_and_read_buckets_are_separate() {
        let r = RateLimiterSet::new(2, 2);
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        // Drain reads
        for _ in 0..3 {
            authorize(remote, "getblockcount", None, None, false, &r);
        }
        // Writes should still work (separate bucket)
        let d = authorize(
            remote, "sendrawtransaction", None, None, false, &r,
        );
        // Could be Allow or RateLimited depending on whether write bucket
        // has capacity; we just check it is not Unauthorized (which would
        // mean we somehow confused the two checks).
        assert_ne!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn timing_attack_resistance_smoke_test() {
        // Correct-length wrong-prefix, wrong-length: both should fail
        // equally. We don't measure timing, just behavior.
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();

        let d1 = authorize(remote, "getblockcount", Some("xxxxxx"), Some("secret"), false, &r);
        let d2 = authorize(remote, "getblockcount", Some("s"),       Some("secret"), false, &r);
        let d3 = authorize(remote, "getblockcount", Some("secretx"), Some("secret"), false, &r);

        assert_eq!(d1, AuthDecision::Unauthorized);
        assert_eq!(d2, AuthDecision::Unauthorized);
        assert_eq!(d3, AuthDecision::Unauthorized);
    }

    // ── L-6: API key validation ──────────────────────────────────────

    #[test]
    fn valid_key_is_accepted() {
        assert!(validate_api_key("a-reasonably-long-random-secret-key-1234").is_ok());
    }

    #[test]
    fn key_with_crlf_is_rejected() {
        assert!(validate_api_key("goodlength_key\r\nX-Evil: 1").is_err());
        assert!(validate_api_key("goodlength_key\n").is_err());
        assert!(validate_api_key("goodlength_key\r").is_err());
    }

    #[test]
    fn key_with_other_control_chars_is_rejected() {
        assert!(validate_api_key("goodlength_key\0nul").is_err());
        assert!(validate_api_key("goodlength_key\tvalue").is_err());
    }

    #[test]
    fn too_short_key_is_rejected() {
        assert!(validate_api_key("x").is_err());
        assert!(validate_api_key("short").is_err());
        assert_eq!(MIN_API_KEY_LEN, 16, "test assumes the documented floor");
        assert!(validate_api_key(&"a".repeat(MIN_API_KEY_LEN - 1)).is_err());
        assert!(validate_api_key(&"a".repeat(MIN_API_KEY_LEN)).is_ok());
    }

    // ── M-1: --rpc-require-auth-for-reads ───────────────────────────

    /// THE M-1 regression: with `require_auth_for_reads = true` and a key
    /// configured, an unauthenticated remote read must be refused. Before
    /// this function existed, there was no way to express this at all — a
    /// read was unconditionally `Allow` regardless of any flag.
    #[test]
    fn read_without_key_refused_when_required() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize_with_read_policy(
            remote, "getutxos", None, Some("secret"),
            false, true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    #[test]
    fn read_with_correct_key_allowed_when_required() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize_with_read_policy(
            remote, "getutxos", Some("secret"), Some("secret"),
            false, true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn read_with_wrong_key_unauthorized_when_required() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize_with_read_policy(
            remote, "getutxos", Some("wrong"), Some("secret"),
            false, true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    /// The default (require_auth_for_reads = false) is UNCHANGED: reads stay
    /// public even with a key configured, exactly like `authorize_with_policy`.
    #[test]
    fn read_default_stays_public_when_not_required() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize_with_read_policy(
            remote, "getutxos", None, Some("secret"),
            false, false, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    /// Fail-safe: require_auth_for_reads = true with NO key configured at
    /// all must refuse every non-trusted read, not silently fall through to
    /// public — an operator who sets the flag but forgets the key must not
    /// believe reads are locked down while they are actually still open.
    #[test]
    fn read_required_but_no_key_configured_refuses_everything() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let d = authorize_with_read_policy(
            remote, "getutxos", None, None,
            false, true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    /// Write policy is unaffected by the new read flag — both can be
    /// configured independently.
    #[test]
    fn write_policy_independent_of_read_policy() {
        let r = rl();
        let remote: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        // Reads required, writes NOT required, no key presented on a write:
        // the write must still pass under its own (looser) policy.
        let d = authorize_with_read_policy(
            remote, "sendrawtransaction", None, Some("secret"),
            false, true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    /// Loopback trust still bypasses everything, same as `authorize_with_policy`.
    #[test]
    fn loopback_still_bypasses_read_auth_requirement_with_flag() {
        let r = rl();
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        let d = authorize_with_read_policy(
            loopback, "getutxos", None, Some("secret"),
            false, true, false, true, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    // ── M-2: IPv6 /64 aggregation + tracked-key cap ─────────────────

    /// Two IPv6 addresses in the SAME /64 must share one rate-limit bucket —
    /// the core M-2 fix. Before it, per-/128 keying let one attacker with a
    /// routed /64 (a standard single-customer allocation) mint an
    /// unbounded number of individually-fresh buckets.
    #[test]
    fn ipv6_addresses_in_same_64_share_one_bucket() {
        let r = RateLimiterSet::new(3, 2);
        let a: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
        let b: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff).into();
        assert_eq!(rate_limit_key(a), rate_limit_key(b), "same /64 must normalize to the same key");

        // Draining `a`'s reads must also drain `b`'s — they are the SAME bucket.
        for _ in 0..3 {
            authorize(a, "getblockcount", None, None, false, &r);
        }
        let d = authorize(b, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::RateLimited, "addresses in the same /64 must share the exhausted bucket");
    }

    /// IPv6 addresses in DIFFERENT /64s must NOT share a bucket — the
    /// aggregation must not be so coarse it merges unrelated allocations.
    #[test]
    fn ipv6_addresses_in_different_64_do_not_share_a_bucket() {
        let r = RateLimiterSet::new(1, 1);
        let a: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into();
        let b: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1).into();
        assert_ne!(rate_limit_key(a), rate_limit_key(b));

        authorize(a, "getblockcount", None, None, false, &r); // exhausts a's 1/min
        let d = authorize(b, "getblockcount", None, None, false, &r);
        assert_eq!(d, AuthDecision::Allow, "a different /64 must have its own fresh bucket");
    }

    /// IPv4 keying is unchanged: two different IPv4 addresses never share a
    /// bucket, and an address maps to itself (no aggregation).
    #[test]
    fn ipv4_key_is_unaggregated() {
        let a: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        assert_eq!(rate_limit_key(a), a);
    }

    /// M-2 regression — THE core memory-bound property: flooding the
    /// limiter with far more distinct sources than `MAX_TRACKED_KEYS` must
    /// never grow the tracked-key map past that cap. Before the fix, the map
    /// was bounded only by a 24h idle TTL swept at most every 10 minutes, so
    /// this exact flood (one request per distinct new IPv4) grew it without
    /// bound. `MAX_TRACKED_KEYS` is scaled down via a second, small-capacity
    /// `RateLimiterSet` is not possible (the cap is a fixed constant, not a
    /// constructor parameter) — so this test drives the REAL constant
    /// directly with `MAX_TRACKED_KEYS + 1000` distinct sources and asserts
    /// the map never exceeds it, proving the cap holds at the scale it is
    /// actually defined for.
    #[test]
    fn tracked_key_map_never_exceeds_max_tracked_keys_under_source_flood() {
        let r = RateLimiterSet::new(60, 5);
        let flood = MAX_TRACKED_KEYS + 1_000;
        for i in 0..flood {
            // Distinct IPv4 addresses: walk the whole u32 space starting an
            // offset in so we never touch 127.0.0.0/8 (loopback bypasses the
            // limiter entirely and would not exercise this path) or 0.0.0.0.
            let addr = u32::from(Ipv4Addr::new(1, 0, 0, 0)) + i as u32;
            let ip: IpAddr = Ipv4Addr::from(addr).into();
            authorize(ip, "getblockcount", None, None, false, &r);
        }
        assert!(
            r.tracked_ips() <= MAX_TRACKED_KEYS,
            "tracked key count {} exceeded MAX_TRACKED_KEYS {} after a {}-source flood",
            r.tracked_ips(), MAX_TRACKED_KEYS, flood
        );
    }

    /// Overflow sources (arriving after the map is full) must still be rate
    /// limited, not silently always-allowed — the shared overflow bucket has
    /// its own finite quota. This complements the memory-bound test above:
    /// that test proves the map stays small; this one proves the sources
    /// routed around the map are still governed, not given a free pass.
    #[test]
    fn overflow_sources_are_still_rate_limited_not_always_allowed() {
        let r = RateLimiterSet::new(60, 5);
        // Fill the map to capacity first.
        for i in 0..MAX_TRACKED_KEYS {
            let addr = u32::from(Ipv4Addr::new(1, 0, 0, 0)) + i as u32;
            let ip: IpAddr = Ipv4Addr::from(addr).into();
            authorize(ip, "getblockcount", None, None, false, &r);
        }
        assert_eq!(r.tracked_ips(), MAX_TRACKED_KEYS, "test premise: map is exactly at capacity");

        // Now flood the SHARED overflow bucket (60/min) with brand-new
        // never-tracked sources — it must start rejecting once its own
        // quota is spent, exactly like any single per-IP bucket would.
        let mut allowed = 0usize;
        let mut rate_limited = 0usize;
        for i in 0..200u32 {
            let addr = u32::from(Ipv4Addr::new(2, 0, 0, 0)) + i;
            let ip: IpAddr = Ipv4Addr::from(addr).into();
            match authorize(ip, "getblockcount", None, None, false, &r) {
                AuthDecision::Allow => allowed += 1,
                AuthDecision::RateLimited => rate_limited += 1,
                other => panic!("unexpected decision for an overflow source: {:?}", other),
            }
        }
        assert!(rate_limited > 0, "the shared overflow bucket must eventually reject — it is not unlimited");
        assert!(allowed > 0, "the overflow bucket must still allow some requests before its quota is spent");
        // And the map itself must not have grown from serving overflow traffic.
        assert_eq!(r.tracked_ips(), MAX_TRACKED_KEYS, "overflow sources must never be inserted into the map");
    }

    // ── Sprint M-patch1: trust_private_ranges tests ─────────────────

    #[test]
    fn is_trusted_loopback_always_true() {
        assert!(is_trusted_local_ip(Ipv4Addr::LOCALHOST.into(), false));
        assert!(is_trusted_local_ip(Ipv4Addr::LOCALHOST.into(), true));
        assert!(is_trusted_local_ip(Ipv6Addr::LOCALHOST.into(), false));
        assert!(is_trusted_local_ip(Ipv6Addr::LOCALHOST.into(), true));
    }

    #[test]
    fn is_trusted_docker_bridge_without_flag() {
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        assert!(!is_trusted_local_ip(docker_bridge, false));
    }

    #[test]
    fn is_trusted_docker_bridge_with_flag() {
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        assert!(is_trusted_local_ip(docker_bridge, true));
    }

    #[test]
    fn is_trusted_rfc1918_10_range() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 255, 255, 255),
            Ipv4Addr::new(10, 42, 7, 99),
        ] {
            assert!(is_trusted_local_ip(ip.into(), true));
            assert!(!is_trusted_local_ip(ip.into(), false));
        }
    }

    #[test]
    fn is_trusted_rfc1918_172_16_range() {
        for ip in [
            Ipv4Addr::new(172, 16, 0, 0),
            Ipv4Addr::new(172, 17, 0, 1),
            Ipv4Addr::new(172, 31, 255, 255),
        ] {
            assert!(is_trusted_local_ip(ip.into(), true));
        }
        for ip in [
            Ipv4Addr::new(172, 15, 255, 255),
            Ipv4Addr::new(172, 32, 0, 0),
        ] {
            assert!(!is_trusted_local_ip(ip.into(), true));
        }
    }

    #[test]
    fn is_trusted_rfc1918_192_168_range() {
        assert!(is_trusted_local_ip(Ipv4Addr::new(192, 168, 0, 1).into(), true));
        assert!(is_trusted_local_ip(Ipv4Addr::new(192, 168, 255, 255).into(), true));
        assert!(!is_trusted_local_ip(Ipv4Addr::new(192, 167, 0, 1).into(), true));
        assert!(!is_trusted_local_ip(Ipv4Addr::new(192, 169, 0, 1).into(), true));
    }

    #[test]
    fn is_trusted_link_local_never_trusted() {
        let apipa: IpAddr = Ipv4Addr::new(169, 254, 1, 1).into();
        assert!(!is_trusted_local_ip(apipa, false));
        assert!(!is_trusted_local_ip(apipa, true));
    }

    #[test]
    fn is_trusted_cgnat_never_trusted() {
        let cgnat: IpAddr = Ipv4Addr::new(100, 64, 0, 1).into();
        assert!(!is_trusted_local_ip(cgnat, true));
    }

    #[test]
    fn is_trusted_public_ipv4_never_trusted() {
        for ip in [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(9, 255, 255, 255),
            Ipv4Addr::new(11, 0, 0, 0),
            Ipv4Addr::new(193, 0, 0, 1),
        ] {
            assert!(!is_trusted_local_ip(ip.into(), true));
        }
    }

    #[test]
    fn is_trusted_ipv6_ula() {
        let ula1: IpAddr = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).into();
        let ula2: IpAddr = Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1).into();
        assert!(is_trusted_local_ip(ula1, true));
        assert!(is_trusted_local_ip(ula2, true));
        assert!(!is_trusted_local_ip(ula1, false));
    }

    #[test]
    fn is_trusted_ipv6_public_not_trusted() {
        let public_v6: IpAddr = Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1).into();
        assert!(!is_trusted_local_ip(public_v6, true));
    }

    #[test]
    fn authorize_with_trust_docker_bridge_write_bypass() {
        let r = rl();
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        let d = authorize_with_trust(
            docker_bridge,
            "sendrawtransaction",
            None,
            Some("secret"),
            true, true, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn authorize_with_trust_docker_bridge_write_blocked_without_flag() {
        let r = rl();
        let docker_bridge: IpAddr = Ipv4Addr::new(172, 17, 0, 1).into();
        let d = authorize_with_trust(
            docker_bridge,
            "sendrawtransaction",
            None,
            Some("secret"),
            true, false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
    }

    // ── Audit DAG-6: operator chain overrides are never anonymous ──
    #[test]
    fn admin_methods_need_a_key_or_a_trusted_caller() {
        let rl = RateLimiterSet::new(1000, 1000);
        let remote: IpAddr = "203.0.113.7".parse().unwrap();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        let key = "k".repeat(32);
        for m in ADMIN_METHODS {
            assert!(WRITE_METHODS.contains(m), "{m} must be write-class");
            // Even with --rpc-require-auth-for-writes OFF, no key = refused.
            for ip in [remote, lo] {
                assert_eq!(
                    authorize_with_read_policy(ip, m, None, None, false, false, false, false, &rl),
                    AuthDecision::Unauthorized, "{m} anonymous from {ip}",
                );
                assert_eq!(
                    authorize_with_read_policy(ip, m, None, Some(&key), false, false, false, false, &rl),
                    AuthDecision::Unauthorized, "{m} without the key from {ip}",
                );
                assert_eq!(
                    authorize_with_read_policy(ip, m, Some(&key), Some(&key), false, false, false, false, &rl),
                    AuthDecision::Allow, "{m} with the key from {ip}",
                );
                assert_eq!(
                    authorize_with_policy(ip, m, None, None, false, false, false, &rl),
                    AuthDecision::Unauthorized,
                );
            }
            // A fully trusted caller (--rpc-trust-loopback) needs no key.
            assert_eq!(
                authorize_with_read_policy(lo, m, None, None, false, false, false, true, &rl),
                AuthDecision::Allow,
            );
        }
        // Ordinary writes keep their policy (anonymous allowed when writes
        // do not require auth).
        assert_eq!(
            authorize_with_read_policy(remote, "submitblock", None, None, false, false, false, false, &rl),
            AuthDecision::Allow,
        );
    }

    // ── WRITE_METHODS must cover external block submission ──

    #[test]
    fn submitblock_is_a_write() {
        assert!(WRITE_METHODS.contains(&"submitblock"),
            "submitblock injects blocks into consensus; it must be a write method");
    }

    /// L-8 mutation guard: `getblocktemplate` is expensive (dual DAG reads,
    /// an ancestry walk, up to a 2000-tx mempool drain) and must stay
    /// privileged — removing it from WRITE_METHODS fails here.
    #[test]
    fn getblocktemplate_is_privileged() {
        assert!(WRITE_METHODS.contains(&"getblocktemplate"),
            "getblocktemplate is expensive and must require auth");
    }

    // ── R3-audit H-R3-5: loopback auth bypass is now an explicit opt-in ──

    #[test]
    fn loopback_write_without_key_refused_unless_flag() {
        let r = rl();
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        // Key configured, writes require auth, no key presented, loopback NOT
        // trusted for auth: must be Unauthorized. This is the browser-CSRF
        // hole — with the blanket bypass this was Allow.
        let d = authorize_with_policy(
            loopback, "sendrawtransaction", None, Some("secret"),
            true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
        // Same for block submission.
        let d = authorize_with_policy(
            loopback, "submitblock", None, Some("secret"),
            true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Unauthorized);
        // With the explicit flag the old operator-tooling behaviour returns.
        let d = authorize_with_policy(
            loopback, "sendrawtransaction", None, Some("secret"),
            true, false, true, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn loopback_with_correct_key_allowed_without_flag() {
        let r = rl();
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        let d = authorize_with_policy(
            loopback, "sendrawtransaction", Some("secret"), Some("secret"),
            true, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    #[test]
    fn loopback_never_rate_limited_even_without_trust() {
        // Availability: the co-located pool polls fast; loopback keeps its
        // rate-limit exemption even when its AUTH bypass is off.
        let r = RateLimiterSet::new(1, 1);
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        for _ in 0..50 {
            let d = authorize_with_policy(
                loopback, "getblockcount", None, None, false, false, false, &r,
            );
            assert_eq!(d, AuthDecision::Allow);
        }
    }

    #[test]
    fn loopback_no_key_configured_still_works_without_flag() {
        // Default deployment (no API key): behaviour unchanged.
        let r = rl();
        let loopback: IpAddr = Ipv4Addr::LOCALHOST.into();
        let d = authorize_with_policy(
            loopback, "sendrawtransaction", None, None, false, false, false, &r,
        );
        assert_eq!(d, AuthDecision::Allow);
    }

    // ── R3-audit H-R3-5: Host / Origin browser gate ─────────────────

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn host_ip_literals_and_localhost_allowed() {
        for h in ["127.0.0.1:17210", "127.0.0.1", "45.76.89.225:17210",
                  "[::1]:17210", "[2001:db8::1]", "localhost:17210", "LOCALHOST"] {
            assert_eq!(host_allowed(Some(h), &[]), Ok(()), "host {h:?} should pass");
        }
    }

    #[test]
    fn host_dns_name_refused_unless_allowlisted() {
        // DNS rebinding: evil.example resolves to this node's IP; the browser
        // sends the attacker's hostname in Host.
        assert_eq!(host_allowed(Some("evil.example"), &[]),
                   Err(BrowserGateRefusal::HostNotAllowed));
        assert_eq!(host_allowed(Some("evil.example:17210"), &[]),
                   Err(BrowserGateRefusal::HostNotAllowed));
        // Operator allowlists their tunnel hostname → allowed (any case).
        let allow = v(&["g2rpc.posternpool.com"]);
        assert_eq!(host_allowed(Some("G2RPC.posternpool.com:443"), &allow), Ok(()));
        // Allowlisting one name does not open others.
        assert_eq!(host_allowed(Some("evil.example"), &allow),
                   Err(BrowserGateRefusal::HostNotAllowed));
    }

    #[test]
    fn host_missing_or_empty_refused() {
        assert_eq!(host_allowed(None, &[]), Err(BrowserGateRefusal::MissingHost));
        assert_eq!(host_allowed(Some(""), &[]), Err(BrowserGateRefusal::MissingHost));
        assert_eq!(host_allowed(Some("   "), &[]), Err(BrowserGateRefusal::MissingHost));
    }

    #[test]
    fn origin_absent_is_not_a_browser_request() {
        // curl / pool / wallet clients send no Origin: always pass.
        assert_eq!(origin_allowed(None, &[], true), Ok(()));
        assert_eq!(origin_allowed(None, &[], false), Ok(()));
    }

    #[test]
    fn origin_refused_by_default_even_for_reads() {
        assert_eq!(origin_allowed(Some("https://evil.example"), &[], false),
                   Err(BrowserGateRefusal::OriginNotAllowed));
        assert_eq!(origin_allowed(Some("https://evil.example"), &[], true),
                   Err(BrowserGateRefusal::OriginNotAllowed));
        assert_eq!(origin_allowed(Some("null"), &v(&["*"]), false),
                   Err(BrowserGateRefusal::OriginNotAllowed));
    }

    #[test]
    fn origin_wildcard_never_applies_to_writes() {
        let allow = v(&["*"]);
        // Reads: wildcard OK (public explorers).
        assert_eq!(origin_allowed(Some("https://explorer.example"), &allow, false), Ok(()));
        // Writes: wildcard MUST NOT open the door (the finding's exact ask).
        assert_eq!(origin_allowed(Some("https://explorer.example"), &allow, true),
                   Err(BrowserGateRefusal::OriginNotAllowed));
        // An exact allowlisted origin can still write.
        let allow = v(&["https://wallet.posternlabs.com"]);
        assert_eq!(origin_allowed(Some("https://wallet.posternlabs.com"), &allow, true), Ok(()));
    }

    #[test]
    fn gate_refuses_rebinding_and_csrf_shapes() {
        // DNS-rebinding shape: attacker hostname in Host, no Origin needed.
        assert_eq!(
            gate_browser_request(Some("evil.example"), None, "getblockcount", &[], &[]),
            Err(BrowserGateRefusal::HostNotAllowed)
        );
        // CSRF shape: legitimate Host (browser connected to 127.0.0.1) but a
        // web-page Origin, on a write method.
        assert_eq!(
            gate_browser_request(
                Some("127.0.0.1:17210"), Some("https://evil.example"),
                "sendrawtransaction", &[], &v(&["*"]),
            ),
            Err(BrowserGateRefusal::OriginNotAllowed)
        );
        // Block submission gets write-strictness.
        assert_eq!(
            gate_browser_request(
                Some("127.0.0.1:17210"), Some("https://evil.example"),
                "submitblock", &[], &v(&["*"]),
            ),
            Err(BrowserGateRefusal::OriginNotAllowed)
        );
        // Non-browser operator curl on loopback: passes untouched.
        assert_eq!(
            gate_browser_request(Some("127.0.0.1:17210"), None, "sendrawtransaction", &[], &[]),
            Ok(())
        );
    }
}

#[cfg(test)]
mod b2_t11_proxy_tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    /// The client of a proxied request is the LAST forwarded hop (what the
    /// nearest proxy saw), never a client-written earlier entry.
    #[test]
    fn forwarded_client_takes_the_last_hop() {
        let xff = DEFAULT_PROXY_CLIENT_HEADER;
        assert_eq!(forwarded_client(&headers(&[]), xff), None);
        assert_eq!(forwarded_client(&headers(&[("user-agent", "curl")]), xff), None);
        let ip = |s: &str| ForwardedClient::Client(s.parse().unwrap());
        assert_eq!(forwarded_client(&headers(&[("x-forwarded-for", "10.9.9.9, 198.51.100.7")]), xff), Some(ip("198.51.100.7")));
        assert_eq!(forwarded_client(&headers(&[("x-forwarded-for", "1.1.1.1"), ("x-forwarded-for", "203.0.113.4:5000")]), xff),
            Some(ip("203.0.113.4")));
        assert_eq!(forwarded_client(&headers(&[("x-real-ip", "2001:db8::7")]), "x-real-ip"), Some(ip("2001:db8::7")));
        assert_eq!(forwarded_client(&headers(&[("cf-connecting-ip", "[2001:db8::8]:443")]), "cf-connecting-ip"), Some(ip("2001:db8::8")));
        assert_eq!(forwarded_client(&headers(&[("forwarded", "for=192.0.2.60;proto=https, for=\"[2001:db8:cafe::17]:4711\"")]), "forwarded"),
            Some(ip("2001:db8:cafe::17")));
        assert_eq!(forwarded_client(&headers(&[("via", "1.1 nginx")]), xff), Some(ForwardedClient::Unknown));
        assert_eq!(forwarded_client(&headers(&[("x-forwarded-for", "unknown")]), xff), Some(ForwardedClient::Unknown));
        // Only the operator's client header names the client.
        assert_eq!(forwarded_client(&headers(&[("x-real-ip", "2001:db8::7")]), xff), Some(ForwardedClient::Unknown));
        assert_eq!(validate_proxy_client_header("X-Real-IP"), Ok("x-real-ip".into()));
        assert!(validate_proxy_client_header("via").is_err());
        assert!(validate_proxy_client_header("x-api-key").is_err());
    }

    /// B2-T11 (review): the client is read from the one header the
    /// operator's proxy writes. nginx with only
    /// `proxy_set_header X-Real-IP $remote_addr` passes a client's own
    /// `X-Forwarded-For` through; with the old fixed precedence (last XFF
    /// hop before X-Real-IP) such a client chose a fresh bucket per request.
    #[test]
    fn a_client_written_header_never_picks_the_bucket() {
        let lo: IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        let rl = RateLimiterSet::new(60, 2);
        let mut statuses = Vec::new();
        for i in 0..5u8 {
            let spoofed = HeaderValue::from_str(&format!("10.0.0.{i}")).unwrap();
            let mut h = headers(&[("x-real-ip", "198.51.100.40")]);
            h.append("x-forwarded-for", spoofed);
            let f = forwarded_client(&h, "x-real-ip");
            statuses.push(authorize_request(lo, f, "submitblock", None, None, false, false, false, false, &rl));
        }
        assert_eq!(statuses, [AuthDecision::Allow, AuthDecision::Allow, AuthDecision::RateLimited,
            AuthDecision::RateLimited, AuthDecision::RateLimited], "limited in the X-Real-IP bucket");
        assert_eq!(rl.tracked_ips(), 1, "one bucket, not one per spoofed value");
    }

    /// B2-T11 (review): forwarding headers name the client only when the
    /// TCP peer is a proxy (loopback, or a trusted private range). A remote
    /// peer (`--rpc-public`) that rotates `X-Forwarded-For` stays in its own
    /// bucket: it can neither escape the limit nor fill the limiter's table
    /// with spoofed keys (each held for 24 h, after which every new client
    /// lands in the shared overflow bucket). It still loses any trust.
    #[test]
    fn a_remote_peer_cannot_mint_buckets_with_forwarding_headers() {
        let peer: IpAddr = "203.0.113.50".parse().unwrap();
        let rl = RateLimiterSet::new(3, 1);
        let mut allowed = 0;
        for i in 0..50u32 {
            let spoofed = HeaderValue::from_str(&format!("10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255)).unwrap();
            let mut h = HeaderMap::new();
            h.append("x-forwarded-for", spoofed);
            let f = forwarded_client(&h, DEFAULT_PROXY_CLIENT_HEADER);
            if authorize_request(peer, f, "getblockcount", None, None, false, false, false, false, &rl) == AuthDecision::Allow {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3, "the peer's own read bucket");
        assert_eq!(rl.tracked_ips(), 1);
        // A trusted private-range peer that forwards is not fully trusted.
        let lan: IpAddr = "10.1.2.3".parse().unwrap();
        let f = Some(ForwardedClient::Client("198.51.100.1".parse().unwrap()));
        assert_eq!(authorize_request(lan, f, "invalidateblock", None, None, false, false, true, true, &rl),
            AuthDecision::Unauthorized);
        assert!(peer_may_name_client(lan, true) && !peer_may_name_client(lan, false));
    }

    /// A keyed pool skips the method buckets, so template polling leaves
    /// the write-method budget untouched. B1-R2-9 still charges every
    /// request to the pre-auth budget: exhausting it blocks submitblock
    /// too. Operators must size the quotas for their combined request rate.
    #[test]
    fn a_keyed_proxy_skips_method_buckets_within_the_pre_auth_budget() {
        let lo: IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        let rl = RateLimiterSet::new(60, 5);
        let key = "k".repeat(32);
        let fwd = Some(ForwardedClient::Client("198.51.100.77".parse().unwrap()));
        for _ in 0..20 {
            assert_eq!(authorize_request(lo, fwd, "getblocktemplate", Some(&key), Some(&key), true, false, false, false, &rl),
                AuthDecision::Allow);
        }
        assert_eq!(authorize_request(lo, fwd, "submitblock", Some(&key), Some(&key), true, false, false, false, &rl),
            AuthDecision::Allow, "the found block reaches the node below the pre-auth bound");
        for _ in 21..64 {
            assert_eq!(authorize_request(lo, fwd, "getblocktemplate", Some(&key), Some(&key), true, false, false, false, &rl),
                AuthDecision::Allow);
        }
        assert_eq!(authorize_request(lo, fwd, "submitblock", Some(&key), Some(&key), true, false, false, false, &rl),
            AuthDecision::Allow, "the last available pre-auth token admits a block");
        assert_eq!(authorize_request(lo, fwd, "submitblock", Some(&key), Some(&key), true, false, false, false, &rl),
            AuthDecision::RateLimited, "an exhausted pre-auth budget blocks every method, even with the correct key");
        let other = Some(ForwardedClient::Client("198.51.100.78".parse().unwrap()));
        let wrong: Vec<_> = (0..7).map(|_| authorize_request(lo, other, "submitblock", Some("wrong"), Some(&key),
            true, false, false, false, &rl)).collect();
        assert_eq!(wrong.last(), Some(&AuthDecision::RateLimited), "{wrong:?}");
    }

    /// Proxied requests from loopback: limited (IPv6 clients by /64, unnamed
    /// clients in one shared bucket), never fully trusted; the direct
    /// loopback exemption is unchanged.
    #[test]
    fn proxied_loopback_requests_are_remote_requests() {
        let lo: IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        let rl = RateLimiterSet::new(60, 1);
        let fwd = |s: &str| Some(ForwardedClient::Client(s.parse().unwrap()));
        let auth = |f: Option<ForwardedClient>, m: &str, trust: bool| authorize_request(
            lo, f, m, None, None, false, false, false, trust, &rl);
        assert_eq!(auth(fwd("2001:db8:1:2::1"), "submitblock", false), AuthDecision::Allow);
        assert_eq!(auth(fwd("2001:db8:1:2::ffff"), "submitblock", false), AuthDecision::RateLimited,
            "the same /64 shares a bucket");
        assert_eq!(auth(Some(ForwardedClient::Unknown), "submitblock", false), AuthDecision::Allow);
        assert_eq!(auth(Some(ForwardedClient::Unknown), "submitblock", false), AuthDecision::RateLimited);
        // A proxied client claiming loopback is still limited (it shares the
        // bucket of the proxy's own address, already spent above).
        assert_eq!(auth(fwd("127.0.0.1"), "submitblock", false), AuthDecision::RateLimited);
        for _ in 0..5 {
            assert_eq!(auth(None, "submitblock", false), AuthDecision::Allow, "direct loopback exempt");
        }
        // --rpc-trust-loopback never covers a proxied request.
        let rl = RateLimiterSet::new(60, 60);
        let admin = |f: Option<ForwardedClient>| authorize_request(
            lo, f, "invalidateblock", None, None, false, false, false, true, &rl);
        assert_eq!(admin(fwd("198.51.100.1")), AuthDecision::Unauthorized);
        assert_eq!(admin(None), AuthDecision::Allow);
        // The key still works through a proxy.
        let key = "k".repeat(32);
        assert_eq!(authorize_request(lo, fwd("198.51.100.1"), "invalidateblock", Some(&key), Some(&key),
            true, false, false, false, &rl), AuthDecision::Allow);
        assert_eq!(authorize_request(lo, fwd("198.51.100.1"), "getblockcount", Some("wrong"), Some(&key),
            false, false, false, false, &rl), AuthDecision::Unauthorized);
    }
}

#[cfg(test)]
mod net16_tests {
    use super::*;

    /// NET-16: comparison is over fixed-length digests, so keys of any
    /// length compare correctly (and in constant time w.r.t. length).
    #[test]
    fn keys_match_compares_fixed_length_digests() {
        let key = "0123456789abcdef0123456789abcdef";
        assert!(keys_match(key, key));
        assert!(!keys_match("0123456789abcdef0123456789abcdee", key));
        assert!(!keys_match("short", key));
        assert!(!keys_match(&format!("{key}x"), key));
        assert!(!keys_match("", key));
        // The authorizer uses it for both reads and writes.
        let rl = RateLimiterSet::new(60, 5);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(authorize_with_read_policy(ip, "getblockcount", Some(key), Some(key),
            true, true, false, false, &rl), AuthDecision::Allow);
        assert_eq!(authorize_with_read_policy(ip, "sendrawtransaction", Some("short"), Some(key),
            true, true, false, false, &rl), AuthDecision::Unauthorized);
    }

    /// NET-16: key files readable or writable by others are refused; group
    /// read only warns.
    #[test]
    fn api_key_file_mode_policy() {
        let p = std::path::Path::new("/etc/gnb/rpc.key");
        assert_eq!(key_file_mode_policy(0o100600, p), Ok(None));
        assert_eq!(key_file_mode_policy(0o400, p), Ok(None));
        assert!(key_file_mode_policy(0o640, p).unwrap().unwrap().contains("readable by its group"));
        for bad in [0o644, 0o604, 0o660, 0o666, 0o601, 0o602] {
            assert!(key_file_mode_policy(bad, p).is_err(), "{bad:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn api_key_file_permissions_are_checked_on_disk() {
        use std::os::unix::fs::PermissionsExt;
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(check_key_file_permissions(file.path()), Ok(None));
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_key_file_permissions(file.path()).is_err());
    }
}
