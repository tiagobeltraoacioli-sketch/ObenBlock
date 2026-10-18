//! A process that runs ObenBlock mainnet (`core::set_node_chain_id`): the
//! stall relief the validator, the templates and the anti-DoS references use
//! is clamped to the SHA-256d pow limit `0x1d00ffff`, never to GnB's ASERT
//! limit (review, mainnet launch blocker). Own test process: the chain id is
//! process-wide.

use gnb_crypto::core::genesis::OBB_MAINNET_GENESIS_TIMESTAMP;
use gnb_crypto::core::pow_scheme::{self, check_sha256d_pow, Sha256dHeaderError, OBB_BLOCK_VERSION, OBB_LAUNCH_BITS,
                                   OBB_POW_LIMIT_BITS};
use gnb_crypto::core::{self, activation, liveness, BlockHeader, ChainId, MerkleRoot};
use gnb_smh::difficulty::{bits_to_target, target_to_bits, Target};

#[test]
fn obenblock_mainnet_relief_never_exceeds_the_sha256d_limit() {
    assert_eq!(core::set_node_chain_id(ChainId::ObenBlockMainnet), Ok(()));
    let p = pow_scheme::node_sha256d_params().expect("ObenBlock runs SHA-256d");
    assert_eq!(liveness::scheme_pow_limit_at(1, activation::hardening_activation_height()), p.pow_limit());
    let g = OBB_MAINNET_GENESIS_TIMESTAMP;
    let base = core::expected_bits(g, 1).unwrap();
    if !core::TEST_POW_LIMIT {
        assert_eq!(base, OBB_LAUNCH_BITS);
    }
    for late_h in [20u64, 100] {
        let t = g + late_h * 3_600;
        // Validator / miner.
        let bits = liveness::expected_block_bits(g, 1, t).unwrap();
        assert_eq!(bits, OBB_POW_LIMIT_BITS, "{late_h} h late");
        // Template producers (getblocktemplate, the stratum job refresh).
        let tmpl = liveness::relieve_at(base, g, 1, t, activation::hardening_activation_height(),
                                        liveness::liveness_activation_height());
        assert_eq!(tmpl, OBB_POW_LIMIT_BITS, "{late_h} h late");
        // Anti-DoS reference.
        let r = liveness::relieved_reference(&bits_to_target(base).0, g, 1, t);
        assert_eq!(target_to_bits(&Target(r)), OBB_POW_LIMIT_BITS);
        // The SHA-256d PoW check takes those bits (only the work is missing).
        let h = BlockHeader { version: OBB_BLOCK_VERSION, parents: vec![[1; 32]], merkle_root: MerkleRoot([7; 32]),
                              timestamp: t, bits, nonce: 0 };
        assert!(matches!(check_sha256d_pow(&h, &p), Ok(()) | Err(Sha256dHeaderError::InsufficientWork)));
    }
}
