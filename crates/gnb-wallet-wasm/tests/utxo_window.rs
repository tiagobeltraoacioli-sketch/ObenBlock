// Pre-launch review (wallet, low): the web wallet asked for and counted 50
// spendable outputs (site/wallet/core.js UTXO_WINDOW), but one hybrid-signed
// transaction holds at most 47 inputs under MAX_STANDARD_TX_BYTES, so "Max"
// and "Spendable now" promised amounts the core refuses to build. This pins
// the page's window to the core's own size bound.
use gnb_crypto::wallet::payment::{signed_size_upper_bound, MAX_STANDARD_TX_BYTES};

/// A hybrid (ML-DSA-65 + Falcon-1024) public key's length.
const HYBRID_PUBLIC_KEY_LEN: usize = 3745;
/// Payment and change, at the longest script an address names (a policy
/// address's 32-byte hash plus its opcodes, with room to spare).
const OUTPUTS: [usize; 2] = [40, 40];

fn page_window() -> usize {
    let core = include_str!("../../../site/wallet/core.js");
    let line = core.lines().find(|l| l.starts_with("export const UTXO_WINDOW = ")).expect("UTXO_WINDOW in core.js");
    line["export const UTXO_WINDOW = ".len()..].split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
}

#[test]
fn the_web_wallet_utxo_window_fits_one_standard_transaction() {
    assert!(gnb_crypto::crypto::is_hybrid_public_key(&vec![7u8; HYBRID_PUBLIC_KEY_LEN]));
    let window = page_window();
    assert!(signed_size_upper_bound(window, &OUTPUTS, HYBRID_PUBLIC_KEY_LEN) <= MAX_STANDARD_TX_BYTES,
            "{window} hybrid inputs exceed MAX_STANDARD_TX_BYTES");
    assert!(signed_size_upper_bound(window + 1, &OUTPUTS, HYBRID_PUBLIC_KEY_LEN) > MAX_STANDARD_TX_BYTES,
            "the window is smaller than one transaction allows");
}
