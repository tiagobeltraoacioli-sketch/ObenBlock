//! Mine a genesis block: GnB's GnB-SMH nonce, or an ObenBlock SHA-256d
//! genesis (docs/DESIGN-obenblock.md §3, docs/OBENBLOCK-GENESIS.md).
//!
//! Each genesis is fully determined by constants in the code (coinbase text,
//! timestamp, bits); only the proof of work has to be found. This tool
//! searches for it with every core and prints the constants to paste back:
//!
//! ```text
//! gnb-mine-genesis                     # GnB: the baked timestamp and bits
//! gnb-mine-genesis --threads 8
//! gnb-mine-genesis --timestamp 1791331200 --bits 0x2000ffff
//!
//! gnb-mine-genesis --chain obenblock --timestamp <launch unix time>   # ObenBlock mainnet, at launch
//! gnb-mine-genesis --chain obenblock --regtest                        # ObenBlock regtest
//! ```
//!
//! GnB: changing the coinbase text, the timestamp or the bits invalidates
//! `GENESIS_NONCE`, and the node refuses to start until it is re-mined.
//!
//! ObenBlock: the header is the 80-byte SHA-256d header at the network's
//! genesis bits (mainnet: the pow limit `0x1d00ffff`, about 2^32 hashes;
//! regtest: `0x207fffff`, about 2). The search covers the 32-bit nonce and,
//! when a nonce range is exhausted, the BIP 320 version bits (16 bits), so
//! the timestamp stays the one given. The constants go into
//! `crates/gnb-crypto/src/core/genesis.rs`.

use clap::Parser;
use gnb::core::{self, create_genesis_block_with};
use gnb::core::chain::Chain;
use gnb::core::pow_scheme::{check_sha256d_pow, PowScheme};
use gnb::core::ChainId;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "gnb-mine-genesis")]
#[command(about = "Mine a genesis block: GnB (GnB-SMH) or ObenBlock (SHA-256d)")]
struct Cli {
    /// Chain: `gnb` (default) or `obenblock`.
    #[arg(long, value_parser = Chain::parse)]
    chain: Option<Chain>,
    /// ObenBlock regtest instead of mainnet (needs `--chain obenblock`).
    #[arg(long)]
    regtest: bool,
    /// Genesis timestamp (unix seconds). GnB: defaults to
    /// core::GENESIS_TIMESTAMP. ObenBlock mainnet: required (the launch
    /// time); regtest: defaults to its baked timestamp.
    #[arg(long)]
    timestamp: Option<u64>,
    /// Compact difficulty bits (0x-prefixed hex or decimal). GnB only;
    /// defaults to core::GENESIS_BITS. ObenBlock's are fixed per network.
    #[arg(long, value_parser = parse_u32_hex_or_dec)]
    bits: Option<u32>,
    /// Worker threads. Defaults to all logical CPUs.
    #[arg(long)]
    threads: Option<usize>,
    /// First nonce to try (GnB only).
    #[arg(long, default_value_t = 0)]
    start_nonce: u64,
}

fn parse_u32_hex_or_dec(s: &str) -> Result<u32, String> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).map_err(|e| e.to_string()),
        None => s.parse().map_err(|e: std::num::ParseIntError| e.to_string()),
    }
}

fn main() {
    let cli = Cli::parse();
    let threads = cli
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
        .max(1);
    match (cli.chain.unwrap_or(Chain::Gnb), cli.regtest) {
        (Chain::Gnb, false) => mine_gnb(&cli, threads),
        (Chain::Gnb, true) => fail("--regtest needs --chain obenblock (GnB has no regtest)"),
        (Chain::ObenBlock, regtest) => {
            if cli.bits.is_some() || cli.start_nonce != 0 {
                fail("--bits and --start-nonce are GnB options; ObenBlock's genesis bits are fixed per network");
            }
            let id = if regtest { ChainId::ObenBlockRegtest } else { ChainId::ObenBlockMainnet };
            mine_obenblock(id, cli.timestamp, threads)
        }
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2);
}

fn mine_gnb(cli: &Cli, threads: usize) {
    let timestamp = cli.timestamp.unwrap_or(core::GENESIS_TIMESTAMP);
    let bits = cli.bits.unwrap_or(core::GENESIS_BITS);

    let template = create_genesis_block_with(timestamp, bits, 0);
    let preimage = template.header.pow_preimage();
    println!("GnB genesis search");
    println!("  coinbase   : {}", core::GENESIS_COINBASE_TEXT);
    println!("  timestamp  : {timestamp}");
    println!("  bits       : 0x{bits:08x} (difficulty {:.2})", core::difficulty_from_bits(bits));
    println!("  merkle     : {}", template.header.merkle_root);
    println!("  threads    : {threads} (64 MiB each)");

    let t0 = Instant::now();
    let mut start = cli.start_nonce;
    const CHUNK: u64 = 256;
    let nonce = loop {
        if let Some(n) = gnb::pow::mine_parallel(&preimage, bits, 0, start, CHUNK, threads, None) {
            break n;
        }
        start = start.wrapping_add(CHUNK * threads as u64);
        println!("  … {} nonces tried, {:.0} s", start - cli.start_nonce, t0.elapsed().as_secs_f64());
    };

    let block = create_genesis_block_with(timestamp, bits, nonce);
    assert!(block.validate_pow(), "found nonce must validate");
    let hash = block.block_hash();
    println!();
    println!("Found in {:.1} s. Paste into crates/gnb-crypto/src/core/mod.rs:", t0.elapsed().as_secs_f64());
    println!();
    println!("pub const GENESIS_TIMESTAMP: u64 = {timestamp};");
    println!("pub const GENESIS_BITS:      u32 = 0x{bits:08X};");
    println!("pub const GENESIS_NONCE:     u64 = {nonce};");
    println!("pub const GENESIS_EXPECTED_HASH: [u8; 32] = {};", rust_bytes(&hash));
    println!();
    println!("genesis block hash: {}", hex::encode(hash));
}

/// The ObenBlock search: every nonce of one version, then the next BIP 320
/// version (bits 13..=28 counted up from the block version).
fn mine_obenblock(id: ChainId, timestamp: Option<u64>, threads: usize) {
    let constants = core::genesis::chain_genesis(id);
    let timestamp = match (id, timestamp) {
        (_, Some(t)) => t,
        (ChainId::ObenBlockRegtest, None) => constants.timestamp,
        _ => fail("ObenBlock mainnet needs --timestamp <launch unix time> (for example $(date -u +%s))"),
    };
    if u32::try_from(timestamp).is_err() || timestamp == 0 {
        fail("the timestamp must be a non-zero u32 (seconds until 2106)");
    }
    let PowScheme::Sha256d(params) = core::genesis::pow_scheme_for(id) else { unreachable!("ObenBlock is SHA-256d") };
    let base_version = params.block_version;
    let template = constants.block_with(base_version, timestamp, 0);
    println!("ObenBlock {} genesis search (SHA-256d)", id.params().network_name);
    println!("  coinbase   : {}", constants.text);
    println!("  timestamp  : {timestamp}");
    println!("  bits       : 0x{:08x} (ASERT anchor bits 0x{:08x})", constants.bits, params.genesis_bits);
    println!("  merkle     : {}", hex::encode(template.header.merkle_root.0));
    println!("  threads    : {threads}");

    let t0 = Instant::now();
    let target = gnb_smh::difficulty::bits_to_target(constants.bits);
    let mut found = None;
    for roll in 0u32..=0xFFFF {
        let version = base_version | (roll << 13);
        let mut h = template.header.clone();
        h.version = version;
        let bytes = h.sha256d_pow_bytes().expect("u32 timestamp and nonce");
        if let Some(nonce) = search_nonces(&bytes, &target, threads) {
            found = Some((version, nonce));
            break;
        }
        println!("  … version 0x{version:08x}: 2^32 nonces exhausted, {:.0} s", t0.elapsed().as_secs_f64());
    }
    let Some((version, nonce)) = found else { fail("no solution in 2^48 headers (impossible at these bits)") };

    let block = constants.block_with(version, timestamp, u64::from(nonce));
    assert_eq!(check_sha256d_pow(&block.header, &params), Ok(()), "found nonce must validate");
    let hash = block.header.sha256d_block_id();
    let (prefix, file) = match id {
        ChainId::ObenBlockMainnet => ("OBB_MAINNET", "crates/gnb-crypto/src/core/genesis.rs (replace the LAUNCH PLACEHOLDER)"),
        _ => ("OBB_REGTEST", "crates/gnb-crypto/src/core/genesis.rs"),
    };
    println!();
    println!("Found in {:.1} s. Paste into {file}:", t0.elapsed().as_secs_f64());
    println!();
    println!("pub const {prefix}_GENESIS_TIMESTAMP: u64 = {timestamp};");
    println!("pub const {prefix}_GENESIS_VERSION: u32 = 0x{version:08X};");
    println!("pub const {prefix}_GENESIS_NONCE: u64 = {nonce};");
    println!("pub const {prefix}_GENESIS_HASH: [u8; 32] = {};", rust_bytes(&hash));
    println!();
    println!("genesis block id (raw digest): {}", hex::encode(hash));
    let mut display = hash;
    display.reverse();
    println!("genesis block id (Bitcoin display order): {}", hex::encode(display));
}

/// Search the 2^32 nonces of the 80-byte `header` for one whose SHA-256d
/// meets `target`, in `threads` disjoint ranges; the smallest hit reported
/// before the workers stop wins (any hit is a valid genesis). The first 64
/// bytes are hashed once (the SHA-256 midstate).
fn search_nonces(header: &[u8; 80], target: &gnb_smh::difficulty::Target, threads: usize) -> Option<u32> {
    use sha2::{Digest, Sha256};
    let mut midstate = Sha256::new();
    midstate.update(&header[..64]);
    let stop = AtomicBool::new(false);
    let winner = AtomicU64::new(u64::MAX);
    let per = (1u64 << 32).div_ceil(threads as u64);
    std::thread::scope(|s| {
        for k in 0..threads as u64 {
            let (stop, winner, midstate) = (&stop, &winner, &midstate);
            s.spawn(move || {
                let mut tail = [0u8; 16];
                tail.copy_from_slice(&header[64..]);
                let lo = k * per;
                let hi = ((k + 1) * per).min(1u64 << 32);
                for n in lo..hi {
                    if (n - lo).is_multiple_of(65_536) && stop.load(Ordering::Relaxed) {
                        return;
                    }
                    tail[12..].copy_from_slice(&(n as u32).to_le_bytes());
                    let mut h = midstate.clone();
                    h.update(tail);
                    let id: [u8; 32] = Sha256::digest(h.finalize()).into();
                    if gnb_smh::sha256d::meets_target(&id, target) {
                        winner.fetch_min(n, Ordering::AcqRel);
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            });
        }
    });
    match winner.load(Ordering::Acquire) {
        u64::MAX => None,
        n => Some(n as u32),
    }
}

fn rust_bytes(b: &[u8; 32]) -> String {
    let parts: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    let lines: Vec<String> = parts.chunks(8).map(|c| format!("    {},", c.join(", "))).collect();
    format!("[\n{}\n]", lines.join("\n"))
}
