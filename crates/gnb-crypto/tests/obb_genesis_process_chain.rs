//! A wallet or CLI process that selected the ObenBlock chain only
//! (`chain::set_process_chain`, no node chain id): it still runs ObenBlock's
//! proof of work and genesis, never GnB-SMH, and sees the mainnet genesis
//! as the launch placeholder until it is mined. Own test process.

use gnb_crypto::core::chain::{self, Chain};
use gnb_crypto::core::genesis::{self, chain_genesis, OBB_MAINNET_GENESIS_TIMESTAMP};
use gnb_crypto::core::pow_scheme::{self, PowScheme, Sha256dParams};
use gnb_crypto::core::{self, ChainId};

#[test]
fn an_obenblock_process_never_falls_back_to_gnb_rules() {
    assert_eq!(chain::set_process_chain(Chain::ObenBlock), Ok(()));
    assert_eq!(core::node_chain_id(), ChainId::ObenBlockMainnet);
    assert_eq!(pow_scheme::node_pow_scheme(),
               PowScheme::Sha256d(Sha256dParams::obenblock_mainnet(OBB_MAINNET_GENESIS_TIMESTAMP)));
    let g = core::genesis_block();
    let c = chain_genesis(ChainId::ObenBlockMainnet);
    assert_eq!(g.block_hash(), c.block().header.sha256d_block_id());
    assert_eq!(g.header.version, c.version);
    assert_eq!(core::powit_height(), 0);
    assert_eq!(genesis::witness_commitment_height(), 0);
    if c.is_placeholder() {
        let why = genesis::launch_refusal(ChainId::ObenBlockMainnet).unwrap();
        assert!(why.contains("gnb-mine-genesis -- --chain obenblock --timestamp"), "{why}");
    }
    // The chain id fixes the scheme explicitly from here on.
    assert_eq!(core::set_node_chain_id(ChainId::ObenBlockMainnet), Ok(()));
    assert_eq!(pow_scheme::set_node_pow_scheme(PowScheme::GnbSmh).map_err(|s| s.name()), Err("sha256d"));
}
