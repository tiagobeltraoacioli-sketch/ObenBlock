//! CPU miner helpers over full block headers (GnB-SMH for GnB, SHA-256d for
//! ObenBlock, by the process's `core::pow_scheme`), and the SHA-256d
//! pool interface of `getblocktemplate` / `submitblock` ([`sha256d`]).

pub mod sha256d;

use crate::core::BlockHeader;
use log::info;

pub struct MineResult {
    pub found: bool,
    pub nonce: u64,
}

/// Mine `header` (of a block at `height`) in place using all available cores.
/// `max_attempts` applies per thread. Under the SHA-256d scheme the search
/// covers the 32-bit nonce (at most 2^32 nonces in all).
pub fn mine_block(header: &mut BlockHeader, height: u64, max_attempts: u64) -> MineResult {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let nonce = if crate::core::pow_scheme::node_sha256d_params().is_some() {
        let mut h = header.clone();
        h.nonce = 0;
        h.sha256d_pow_bytes().ok().and_then(|bytes| {
            crate::pow::mine_sha256d_parallel(&bytes, header.bits, header.nonce as u32, max_attempts, threads, None)
        }).map(u64::from)
    } else {
        let preimage = header.pow_preimage();
        crate::pow::mine_parallel(&preimage, header.bits, height, header.nonce, max_attempts, threads, None)
    };
    match nonce {
        Some(nonce) => {
            header.nonce = nonce;
            info!("Block mined! nonce={} ({} threads)", nonce, threads);
            MineResult { found: true, nonce }
        }
        None => MineResult { found: false, nonce: header.nonce },
    }
}
