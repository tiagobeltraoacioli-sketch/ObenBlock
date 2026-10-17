//! Bloch-SIS Protocol Wallet Library (v0.5.4 — Sprint C)
//!
//! This module unifies the wallet functionality that was previously scattered
//! across `main.rs` (CLI commands), `hd_wallet/`, and ad-hoc scripts.
//!
//! Primary consumer: the Tauri desktop wallet in `bloch-layer-wallet-desktop/`.
//! Secondary consumer: the `bloch` CLI binary.
//!
//! Architecture:
//!
//!   Wallet — holds keypair + network + optional encrypted keyfile state
//!     │
//!     ├─ generate()            — new wallet with random seed
//!     ├─ from_seed()           — deterministic from BIP39 seed phrase
//!     ├─ load_encrypted()      — unlock keyfile with password
//!     ├─ save_encrypted()      — write AES-GCM encrypted keyfile
//!     ├─ address()             — derive and cache address
//!     ├─ public_key()          — raw pk bytes
//!     ├─ sign_tx(tx)           — detached, pure function
//!     └─ build_tx(...)         — pure tx construction (no network)
//!
//!   WalletClient (separate struct) — talks to a Bloch-SIS Protocol node
//!     │
//!     ├─ balance(addr)         — via getbalance RPC
//!     ├─ history(addr)         — via getaddresshistory / listtransactions
//!     ├─ utxos(addr)           — via getutxos RPC
//!     ├─ broadcast(tx)         — via sendrawtransaction RPC
//!     └─ estimate_fee()        — via estimatefeeadvanced RPC (Sprint B)
//!
//! Rationale for separation: Wallet holds keys (secret), WalletClient holds
//! network connection (not secret). They compose for convenience but can be
//! used independently — e.g. cold-signing, airgapped tx construction.

use crate::address::{Address, Network};
use crate::core::{Transaction, TxInput, TxOutput, TESTNET_PREFIX};
use crate::crypto;
use sha3::{Sha3_256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use crate::crypto::SecretBytes;
use serde::{Serialize, Deserialize};

pub mod seed;
pub mod encryption;
#[cfg(feature = "node")]
pub mod client;
pub mod errors;
pub mod policy_spend;   // multi-party spends from policy (multisig/timelock) addresses
pub mod pqpsbt;         // bounded policy transaction interchange and signing preflight
pub mod descriptor;     // static public descriptors and portable watch-only pools
pub mod http_rpc;
pub mod disclosure;
pub mod payment;
pub mod send;

pub use seed::{SeedPhrase, SeedVersion, phrase_grid, print_phrase_grid};
pub use payment::{
    BuiltPayment, FeeChoice, FeePolicy, PaymentOptions, PrevTxs, DUST_THRESHOLD_SATS,
    MAX_STANDARD_TX_BYTES,
};
pub use errors::WalletError;
pub use disclosure::{DisclosureBundle, DisclosureEntry, VerifiedDisclosure, DisclosureError};

/// Read a satoshi-denominated field out of a node JSON-RPC response.
///
/// V4 rule R3 (docs/specs/BLOCH-RPC-V4.md) puts every satoshi amount on the
/// wire as a decimal STRING — the V4 supply exceeds `i64::MAX` and is far past
/// JavaScript's `Number.MAX_SAFE_INTEGER`, so a JSON number cannot carry it.
/// Live Genesis-3 nodes still send JSON numbers, so wallet code accepts BOTH
/// and one binary talks to either wire. Returns `None` for anything else
/// (float, null, non-numeric string) so callers keep their existing
/// missing-field handling.
pub fn sat_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.trim().parse::<u64>().ok())
}

/// Parse an exact BLOCH decimal amount into satoshis without floating point.
/// Accepts unsigned decimal notation with at most eight fractional digits.
/// Exponents, signs, sub-satoshi precision and u64 overflow are rejected.
pub fn parse_bloch_satoshis(amount: &str) -> Result<u64, &'static str> {
    let amount = amount.trim();
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    if (whole.is_empty() && fraction.is_empty()) || fraction.len() > 8
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("amount must use unsigned decimal notation with at most 8 fractional digits");
    }
    let whole = if whole.is_empty() { 0 } else {
        whole.parse::<u64>().map_err(|_| "amount exceeds u64 satoshis")?
    };
    let mut fractional = if fraction.is_empty() { 0 } else {
        fraction.parse::<u64>().map_err(|_| "invalid fractional amount")?
    };
    for _ in fraction.len()..8 {
        fractional = fractional.checked_mul(10).ok_or("amount exceeds u64 satoshis")?;
    }
    whole.checked_mul(100_000_000).and_then(|value| value.checked_add(fractional))
        .ok_or("amount exceeds u64 satoshis")
}

/// Local UTXO representation for wallet operations.
#[derive(Debug, Clone)]
pub struct Utxo {
    pub txid:   [u8; 32],
    pub index:  u32,
    pub output: TxOutput,
}


// ─────────────────────────────────────────────────────────────────────────────
// Wallet — primary user-facing struct
// ─────────────────────────────────────────────────────────────────────────────

/// A single-key wallet (no HD derivation in this version).
///
/// v0.6+ roadmap: BIP-32 style HD derivation for multi-address wallets.
pub struct Wallet {
    /// Raw keypair material. Zeroed on drop.
    keypair: KeyMaterial,
    /// Cached address (derived from pubkey).
    address: Address,
    /// Mainnet or testnet — affects address encoding, NOT signing.
    network: Network,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyMaterial {
    /// Hybrid ML-DSA-65 ‖ Falcon-1024 secret key (CRY-4: locked where the
    /// platform allows, wiped on drop, never `Copy` or `Clone`).
    secret: SecretBytes,
    /// Hybrid public key.
    public: Vec<u8>,
}

// CRY-4: secret holders are never duplicated implicitly.
gnb_secret::assert_not_copy_or_clone!(KeyMaterial);
gnb_secret::assert_not_copy_or_clone!(Wallet);
gnb_secret::assert_not_copy_or_clone!(Keypair);

impl Wallet {
    /// Generate a new wallet with a fresh random seed phrase.
    ///
    /// Returns `(wallet, seed_phrase)`. The caller MUST display the seed
    /// phrase to the user for backup and MUST NOT persist it unencrypted.
    /// Always derives under the CURRENT default seed version
    /// ([`SeedVersion::V2Bip39Sha512`]) — a brand-new mnemonic has no prior
    /// version to preserve.
    pub fn generate(network: Network) -> Result<(Self, SeedPhrase), WalletError> {
        let seed = SeedPhrase::generate()?;
        let wallet = Self::from_seed_versioned(&seed, "", SeedVersion::V2Bip39Sha512, network)?;
        Ok((wallet, seed))
    }

    /// Deterministically derive a wallet from a seed phrase under the CURRENT
    /// default seed version ([`SeedVersion::V2Bip39Sha512`]) and no BIP39
    /// passphrase.
    ///
    /// K-M3: kept for source compatibility with callers written before the
    /// versioned API existed. This can only reopen a wallet created under
    /// V2 (every wallet created after the K-M3 fix). To reopen a wallet that
    /// might predate the fix, use [`Self::from_seed_versioned`] with an
    /// explicit version, or [`Self::recover_ambiguous`] /
    /// [`Self::recover_resolved`] when the version is not known.
    pub fn from_seed(seed: &SeedPhrase, network: Network) -> Result<Self, WalletError> {
        Self::from_seed_versioned(seed, "", SeedVersion::V2Bip39Sha512, network)
    }

    /// Deterministically derive a wallet from a seed phrase under an
    /// EXPLICIT [`SeedVersion`] and BIP39 passphrase (`""` for none).
    ///
    /// This is pure — same (seed, passphrase, version) always produces the
    /// same wallet. It is the only path that can reopen a PRE-K-M3 (V1)
    /// wallet: the caller must know (or resolve, see
    /// [`Self::recover_resolved`]) which version created it.
    pub fn from_seed_versioned(
        seed: &SeedPhrase,
        passphrase: &str,
        version: SeedVersion,
        network: Network,
    ) -> Result<Self, WalletError> {
        // CRY-4: the master seed is derived straight into secret memory
        // (locked where possible, wiped on drop) and stays there for the
        // complete (potentially slow) hybrid key-generation call.
        let seed_bytes = seed.to_seed_bytes_versioned(version, passphrase)?;
        // Hybrid keygen from the 32-byte seed, the secret generated in place
        // in secret memory (CRY-4).
        let (public, secret) = crypto::generate_keypair_from_seed_secret(&seed_bytes[..32])
            .map_err(|e| WalletError::Crypto(e.to_string()))?;

        let hash_full = Sha3_256::digest(&public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let addr = Address::from_hash(addr_hash, network);

        Ok(Wallet {
            keypair: KeyMaterial {
                secret,
                public,
            },
            address: addr,
            network,
        })
    }

    /// K-M3: recover every candidate wallet a mnemonic COULD produce when the
    /// seed version that created it is NOT known (e.g. restoring from a paper
    /// backup with no other record). Derives under every [`SeedVersion`] and
    /// returns all of them, tagged by version, instead of silently picking
    /// one — picking wrong derives the WRONG keys with no error at all.
    pub fn recover_ambiguous(
        seed: &SeedPhrase,
        passphrase: &str,
        network: Network,
    ) -> Result<Vec<(SeedVersion, Self)>, WalletError> {
        let mut out = Vec::with_capacity(2);
        for version in [SeedVersion::V2Bip39Sha512, SeedVersion::V1LegacyPbkdf2Sha256] {
            out.push((version, Self::from_seed_versioned(seed, passphrase, version, network)?));
        }
        Ok(out)
    }

    /// K-M3: resolve the seed-version ambiguity from a hint instead of
    /// guessing. Tries, in order:
    ///   1. `expected_address` — a string the caller already trusts (typed by
    ///      the user, read from an old keyfile's `meta.address`, etc.).
    ///   2. `has_history` — a caller-supplied SEAM for an on-chain-history
    ///      lookup (e.g. `WalletClient::balance`/`history`), so this
    ///      network-free module never dials out itself; pass `|_| false`
    ///      when no such lookup is available.
    ///
    /// Returns [`WalletError::AmbiguousSeedVersion`] if neither resolves it —
    /// never silently returns one of the two candidates.
    pub fn recover_resolved(
        seed: &SeedPhrase,
        passphrase: &str,
        network: Network,
        expected_address: Option<&str>,
        mut has_history: impl FnMut(&Address) -> bool,
    ) -> Result<(SeedVersion, Self), WalletError> {
        let mut candidates = Self::recover_ambiguous(seed, passphrase, network)?;

        // Cheapest check first: a string comparison against a caller-supplied
        // hint, before ever calling into `has_history` (which may dial a
        // node). `position` (not `into_iter().find`) so `candidates` is not
        // consumed — falling through to the history seam below must not
        // re-derive (expensive PQ keygen) every candidate a second time.
        if let Some(addr) = expected_address {
            if let Some(idx) = candidates.iter().position(|(_, w)| w.address().to_string() == addr) {
                return Ok(candidates.remove(idx));
            }
        }

        for (v, w) in candidates {
            if has_history(w.address()) {
                return Ok((v, w));
            }
        }
        Err(WalletError::AmbiguousSeedVersion)
    }

    /// Load an encrypted keyfile from disk and unlock with password.
    pub fn load_encrypted(path: &std::path::Path, password: &str) -> Result<Self, WalletError> {
        Self::load_encrypted_with_file_limit(path, password, crate::util::DEFAULT_WALLET_FILE_LIMIT)
    }

    /// Explicit bounded recovery override; byte budget does not bound KDF or parsed memory.
    pub fn load_encrypted_with_file_limit(path: &std::path::Path, password: &str, max_bytes: usize) -> Result<Self, WalletError> {
        let bytes = crate::util::read_wallet_file(path, max_bytes).map_err(|e| WalletError::Io(e.to_string()))?;
        Self::from_encrypted_bytes(&bytes, password)
    }

    /// Open v1 keyfile JSON bytes (no filesystem).
    pub fn from_encrypted_bytes(bytes: &[u8], password: &str) -> Result<Self, WalletError> {
        if bytes.len() > crate::util::DEFAULT_WALLET_FILE_LIMIT {
            return Err(WalletError::Io("keyfile exceeds the wallet file size limit".into()));
        }
        let ef: encryption::EncryptedKeyfile = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::Parse(e.to_string()))?;

        let (secret, public, network) = ef.decrypt_zeroizing(password)?;
        let hash_full = Sha3_256::digest(&public);
        let mut addr_hash = [0u8; 20];
        addr_hash.copy_from_slice(&hash_full[..20]);
        let addr = Address::from_hash(addr_hash, network);

        Ok(Wallet {
            keypair: KeyMaterial {
                // CRY-4: into secret memory; the decrypted `Zeroizing`
                // buffer is wiped when it drops here.
                secret: SecretBytes::from_slice(&secret),
                public,
            },
            address: addr,
            network,
        })
    }

    /// The signing keypair of this wallet, for the transaction builder.
    pub fn into_keypair(mut self) -> Keypair {
        Keypair {
            private_key: std::mem::take(&mut self.keypair.secret),
            public_key: std::mem::take(&mut self.keypair.public),
            address: self.address.to_string(),
        }
    }

    /// Save wallet to an encrypted keyfile.
    ///
    /// Uses AES-GCM with Argon2id KDF (configurable params in `encryption::KdfParams`).
    /// Sprint T.5 — Audit L-4: writes are atomic (temp + fsync + rename) so a
    /// crash during save cannot corrupt the existing keystore.
    pub fn save_encrypted(&self, path: &std::path::Path, password: &str) -> Result<(), WalletError> {
        let ef = encryption::EncryptedKeyfile::encrypt(
            &self.keypair.secret,
            &self.keypair.public,
            self.network,
            password,
        )?;
        let bytes = serde_json::to_vec_pretty(&ef)
            .map_err(|e| WalletError::Parse(e.to_string()))?;
        crate::util::atomic_write(path, &bytes)
            .map_err(|e| WalletError::Io(e.to_string()))?;
        Ok(())
    }

    /// Returns the wallet's address (cached, cheap to call).
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the wallet's network (mainnet or testnet).
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the raw public key bytes (for inspection or signing verification).
    pub fn public_key(&self) -> &[u8] {
        &self.keypair.public
    }

    /// Sign a version-1/2 (sighash v2) transaction in-place.
    ///
    /// Each input gets a signature derived from the tx sighash. The wallet
    /// MUST own the UTXOs referenced by the inputs (i.e., their script_pubkey
    /// equals this wallet's address hash) — otherwise signing produces an
    /// invalid tx that the network will reject.
    ///
    /// A version-3 transaction commits to the outputs it spends, which this
    /// entry point does not have: it is refused; use
    /// [`Self::sign_tx_with_prevouts`].
    pub fn sign_tx(&self, tx: Transaction) -> Result<Transaction, WalletError> {
        if tx.version == crate::core::sighash::TX_VERSION_V3 {
            return Err(WalletError::Payment(
                "a version-3 transaction commits to the outputs it spends; \
                 sign it with sign_tx_with_prevouts".into(),
            ));
        }
        // Sighash v2 does not read the spent outputs; any placeholders do.
        let placeholders = vec![TxOutput { value: 0, script_pubkey: Vec::new() }; tx.inputs.len()];
        self.sign_tx_with_prevouts(tx, &placeholders)
    }

    /// Sign every input of `tx`, which spends `prevouts` (one output per
    /// input, in order: the value and `script_pubkey` each input spends), under
    /// the digest the transaction's version selects (sighash v3 for version
    /// 3, which commits to `prevouts`; v2 otherwise). Witnesses are canonical
    /// and every signature is verified under this wallet's key before use.
    pub fn sign_tx_with_prevouts(&self, mut tx: Transaction, prevouts: &[TxOutput]) -> Result<Transaction, WalletError> {
        if !crypto::is_hybrid_public_key(&self.keypair.public) {
            return Err(WalletError::Crypto("wallets sign only with the hybrid suite (0x0001)".into()));
        }
        // Chain-id (Roadmap #8) derived from the wallet's own network — the
        // signer and the node validator must fold the SAME domain into the sighash.
        let chain_id = crate::core::ChainId::for_network(self.network);
        payment::sign_inputs(&mut tx, prevouts, &self.keypair.public, chain_id,
            &|digest, version| self.sign_digest(digest, version))
            .map_err(WalletError::Crypto)?;
        Ok(tx)
    }

    /// Verified signature of a transaction digest under the binding of
    /// `version` (CRY-5 / CRY-2).
    fn sign_digest(&self, digest: &[u8; 32], version: crate::core::sighash::SighashVersion) -> Result<Vec<u8>, String> {
        let (secret, public) = (&self.keypair.secret, &self.keypair.public);
        match version {
            crate::core::sighash::SighashVersion::V2 => crypto::sign_checked(secret, public, digest),
            crate::core::sighash::SighashVersion::V3 => crypto::sign_bound_checked(secret, public, digest),
        }
        .map_err(|e| e.to_string())
    }

    /// Build an unsigned transaction paying `amount` to `recipient` from the
    /// given UTXOs with an exact `fee`, for the block at `next_block_height`
    /// (the node's `getdaginfo` `next_block_height`).
    ///
    /// This is pure — no network call required. Caller must provide UTXOs
    /// (typically from `WalletClient::utxos()`).
    ///
    /// Logic:
    ///   - Verify the UTXOs can cover `amount + fee`
    ///   - Select inputs (WAL-6: the smallest single UTXO that covers the
    ///     payment, else largest first) instead of spending every UTXO
    ///   - Create output to `recipient` with `amount`
    ///   - Create a change output to self if the change is at least the dust
    ///     threshold; sub-dust change becomes fee
    ///   - Enforce the default maximum-fee guard (WAL-1) on the resulting
    ///     fee; [`Self::build_tx_with_policy`] overrides it explicitly
    ///   - Version 3 at/after the hardening activation of the wallet's chain,
    ///     1 below it (`core::sighash::tx_version_for_height`)
    ///   - Return the unsigned tx: version 1 is ready for `sign_tx()`,
    ///     version 3 for `sign_tx_with_prevouts()` with the selected UTXOs'
    ///     outputs
    pub fn build_tx(
        &self,
        utxos: Vec<Utxo>,
        recipient: &Address,
        amount: u64,
        fee: u64,
        next_block_height: u64,
    ) -> Result<Transaction, WalletError> {
        self.build_tx_with_policy(utxos, recipient, amount, fee, &FeePolicy::DEFAULT, next_block_height)
    }

    /// Build and sign a payment with coin selection, size-aware fees, the
    /// maximum-fee guard and (when `opts.prev_txs` is set) verification of
    /// the claimed UTXO values (WAL-1, WAL-6). Reports the actual fee.
    pub fn build_payment(
        &self,
        utxos: &[Utxo],
        recipient: &Address,
        amount: u64,
        opts: &PaymentOptions<'_>,
    ) -> Result<BuiltPayment, WalletError> {
        if recipient.network() != self.network {
            return Err(WalletError::NetworkMismatch);
        }
        let chain_id = crate::core::ChainId::for_network(self.network);
        payment::build_payment(
            utxos, recipient.hash(), amount, self.address.hash(), &self.keypair.public, chain_id, opts,
            &|digest, version| self.sign_digest(digest, version),
        ).map_err(WalletError::Payment)
    }

    /// [`Self::build_tx`] with an explicit fee guard.
    pub fn build_tx_with_policy(
        &self,
        utxos: Vec<Utxo>,
        recipient: &Address,
        amount: u64,
        fee: u64,
        fee_policy: &FeePolicy,
        next_block_height: u64,
    ) -> Result<Transaction, WalletError> {
        if recipient.network() != self.network {
            return Err(WalletError::NetworkMismatch);
        }
        let needed = amount.checked_add(fee).ok_or(WalletError::Overflow)?;
        if utxos.is_empty() {
            return Err(WalletError::InsufficientFunds { needed, have: 0 });
        }
        let mut outpoints = std::collections::BTreeSet::new();
        for utxo in &utxos {
            if !outpoints.insert((utxo.txid, utxo.index)) {
                return Err(WalletError::Parse("duplicate UTXO outpoint".into()));
            }
        }
        let total_in = utxos.iter().try_fold(0u64, |total, utxo| {
            total.checked_add(utxo.output.value).ok_or(WalletError::Overflow)
        })?;

        if total_in < needed {
            return Err(WalletError::InsufficientFunds { needed, have: total_in });
        }

        let (selected, change) =
            payment::select_exact_fee(&utxos, amount, fee, self.keypair.public.len())
                .ok_or(WalletError::InsufficientFunds { needed, have: total_in })?;
        let selected_total = selected.iter().map(|&i| utxos[i].output.value).sum::<u64>();

        let inputs: Vec<TxInput> = selected.iter().map(|&i| TxInput {
            prev_txid: utxos[i].txid,
            prev_index: utxos[i].index,
            script_sig: Vec::new(), // filled by sign_tx
            sequence: 0xffffffff,
        }).collect();

        let mut outputs = vec![
            TxOutput {
                value: amount,
                script_pubkey: recipient.hash().to_vec(),
            },
        ];

        // Change output when it is at least the dust threshold (the single
        // comparison of every builder, `payment::keeps_change`); a sub-dust
        // remainder is fee and is counted by the guard below.
        if change > 0 {
            outputs.push(TxOutput {
                value: change,
                script_pubkey: self.address.hash().to_vec(),
            });
        }

        let chain_id = crate::core::ChainId::for_network(self.network);
        let opts = PaymentOptions { next_block_height: Some(next_block_height), ..PaymentOptions::default() };
        let tx = Transaction {
            version: opts.tx_version(chain_id).map_err(WalletError::Payment)?,
            inputs,
            outputs,
            locktime: 0,
        };
        let actual_fee = selected_total - amount - change;
        payment::check_unsigned_fee(&tx, actual_fee, self.keypair.public.len(), fee_policy)
            .map_err(WalletError::FeeTooHigh)?;
        Ok(tx)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// CRY-4: a wallet's and a keypair's secret key lives in secret memory,
    /// and the memory a dropped `Wallet` / `Keypair` leaves behind is all
    /// zeros (read after the drop through the test quarantine). Replaces the
    /// ownership-type test of the removed `wallet_secret_owner` helper.
    #[test]
    fn dropped_wallets_and_keypairs_leave_no_secret_behind() {
        let q = gnb_secret::test_support::Quarantine::start();
        let (wallet, _phrase) = Wallet::generate(Network::Testnet).unwrap();
        let kp = generate_keypair(false);
        let legacy_raw = Keypair {
            private_key: kp.private_key[crypto::SUITE_HEADER_LEN..].to_vec().into(),
            public_key: kp.public_key.clone(),
            address: kp.address.clone(),
        };
        // Signing with a raw legacy key builds its enveloped copy in secret
        // memory as well.
        assert!(legacy_raw.sign(b"m").is_ok());
        let copy = kp.duplicate();
        assert_eq!(copy.private_key, kp.private_key);
        let moved = wallet.into_keypair();
        drop((moved, kp, legacy_raw, copy));
        assert!(q.released().len() >= 5);
        assert!(q.all_released_zeroed(), "a dropped wallet or keypair left secret bytes behind");
    }

    /// P5-S: one seed phrase derives one key per suite. The hybrid key is
    /// exactly the one every earlier release derived; the conservative key
    /// is deterministic, independent of it, survives the keystore, signs
    /// under sighash v3 only, and its secret must be the enveloped form.
    #[test]
    fn seed_phrase_derives_one_key_per_suite() {
        use crate::crypto::{KeySuite, SuiteRules};
        let (wallet, phrase) = Wallet::generate(Network::Testnet).unwrap();
        let hybrid = keypair_from_seed_phrase_for_suite(&phrase, Network::Testnet, KeySuite::Hybrid).unwrap();
        let legacy = wallet.into_keypair();
        assert_eq!((&hybrid.public_key, &hybrid.address), (&legacy.public_key, &legacy.address));
        let words = phrase.words().join(" ");
        let c1 = keypair_from_mnemonic_for_suite(&words, Network::Testnet, KeySuite::Conservative).unwrap();
        let c2 = keypair_from_seed_phrase_for_suite(&phrase, Network::Testnet, KeySuite::Conservative).unwrap();
        assert_eq!((&c1.public_key, &c1.address), (&c2.public_key, &c2.address));
        assert_eq!(c1.private_key, c2.private_key);
        assert!(crypto::is_conservative_public_key(&c1.public_key));
        assert_ne!(c1.address, hybrid.address);
        assert_ne!(&c1.public_key[crypto::SUITE_HEADER_LEN + 32..],
                   &hybrid.public_key[crypto::SUITE_HEADER_LEN + crypto::MLDSA_PUBKEY_LEN..],
                   "independent Falcon keys");

        let password = "synthetic-conservative-password-23!";
        let json = c1.to_encrypted_json(password).unwrap();
        let back = Keypair::from_encrypted_bytes(json.as_bytes(), password).unwrap();
        assert_eq!((&back.public_key, &back.address), (&c1.public_key, &c1.address));
        let digest = [0x33u8; 32];
        let sig = back.sign_tx_digest(&digest, crate::core::sighash::SighashVersion::V3).unwrap();
        assert!(crypto::verify_bound_under(&back.public_key, &digest, &sig, SuiteRules::HARDENING2));
        assert!(!crypto::verify_bound(&back.public_key, &digest, &sig), "invalid under the earlier rules");
        assert!(back.sign_tx_digest(&digest, crate::core::sighash::SighashVersion::V2).is_err());
        assert!(back.sign_message(b"hello").is_err(), "messages are never signed with this suite");
        // The secret must be the whole enveloped conservative key.
        let truncated = Keypair {
            private_key: back.private_key[..back.private_key.len() - 1].to_vec().into(),
            public_key: back.public_key.clone(),
            address: back.address.clone(),
        };
        assert!(truncated.sign_bound(&digest).unwrap_err().contains("conservative"));
    }

    #[test]
    fn current_wallet_custom_file_budget_preserves_authenticated_roundtrip() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        let password = "synthetic-backup-password-19!";
        let encrypted = encryption::EncryptedKeyfile::encrypt_with_params(
            &wallet.keypair.secret, &wallet.keypair.public, wallet.network, password,
            encryption::KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 }).unwrap();
        let bytes = serde_json::to_vec(&encrypted).unwrap();
        let path = std::env::temp_dir().join(format!("bloch-current-wallet-budget-{}.json", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let loaded = Wallet::load_encrypted_with_file_limit(&path, password, bytes.len()).unwrap();
        assert_eq!(loaded.address, wallet.address);
        assert_eq!(loaded.keypair.secret, wallet.keypair.secret);
        assert_eq!(loaded.network, Network::Testnet);
        assert!(matches!(Wallet::load_encrypted_with_file_limit(&path, "wrong", bytes.len() - 1),
            Err(WalletError::Io(message)) if message.contains("byte limit")));
        assert!(matches!(Wallet::load_encrypted_with_file_limit(&path, "wrong", bytes.len()),
            Err(WalletError::WrongPassword)));
        std::fs::remove_file(path).unwrap();
    }

    /// V4 rule R3: satoshi amounts arrive as decimal strings; live G3 nodes
    /// still send numbers. Wallet parsing must accept BOTH, exactly — including
    /// values past 2^53, which is the whole reason the wire changed.
    #[test]
    fn sat_u64_reads_both_wires_exactly() {
        assert_eq!(sat_u64(&serde_json::json!(8_400_000_000u64)), Some(8_400_000_000));
        assert_eq!(sat_u64(&serde_json::json!("8400000000")), Some(8_400_000_000));
        assert_eq!(sat_u64(&serde_json::json!(u64::MAX.to_string())), Some(u64::MAX));
        assert_eq!(sat_u64(&serde_json::json!(" 42 ")), Some(42));

        // Anything that is not an exact non-negative integer is None, so
        // callers keep their missing-field handling instead of silently
        // reading a corrupted amount.
        assert_eq!(sat_u64(&serde_json::json!(1.5f64)), None);
        assert_eq!(sat_u64(&serde_json::json!("-1")), None);
        assert_eq!(sat_u64(&serde_json::json!("not-a-number")), None);
        assert_eq!(sat_u64(&serde_json::Value::Null), None);
    }

    // ── K-M3: versioned seed derivation ──────────────────────────────────────

    /// `from_seed_versioned` under the two versions must produce DIFFERENT
    /// wallets for the identical mnemonic — this is the exact bug K-M3
    /// reported (the PRF changed with no way to ask for the old one back).
    #[test]
    fn from_seed_versioned_v1_and_v2_diverge() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let v1 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V1LegacyPbkdf2Sha256, Network::Mainnet).unwrap();
        let v2 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V2Bip39Sha512, Network::Mainnet).unwrap();
        assert_ne!(v1.address().to_string(), v2.address().to_string());
        // from_seed()/generate() must be the V2 default, never silently V1.
        let default = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(default.address().to_string(), v2.address().to_string());
    }

    /// The master seed a wallet derives from is a `SecretBytes` (CRY-4:
    /// it used to be a `[u8; 64]` returned by value), and the wallet's key
    /// is the hybrid key of its first 32 bytes.
    #[test]
    fn wallet_master_seed_is_secret_memory_and_drives_the_key() {
        let seed = SeedPhrase::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let mut seed_bytes: SecretBytes =
            seed.to_seed_bytes_versioned(SeedVersion::V2Bip39Sha512, "TREZOR").unwrap();
        assert_eq!(seed_bytes.len(), 64);
        let (expected_public, expected_secret) =
            crypto::generate_keypair_from_seed_secret(&seed_bytes[..32]).unwrap();
        let wallet = Wallet::from_seed_versioned(
            &seed,
            "TREZOR",
            SeedVersion::V2Bip39Sha512,
            Network::Mainnet,
        ).unwrap();
        assert_eq!(wallet.keypair.public, expected_public);
        assert_eq!(wallet.keypair.secret.as_slice(), expected_secret.as_slice());

        seed_bytes.zeroize();
        assert!(seed_bytes.is_empty());
    }

    /// K-M3: `recover_ambiguous` must return BOTH candidates, never guess.
    #[test]
    fn recover_ambiguous_returns_both_versions() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let candidates = Wallet::recover_ambiguous(&seed, "", Network::Mainnet).unwrap();
        assert_eq!(candidates.len(), 2);
        let versions: Vec<SeedVersion> = candidates.iter().map(|(v, _)| *v).collect();
        assert!(versions.contains(&SeedVersion::V1LegacyPbkdf2Sha256));
        assert!(versions.contains(&SeedVersion::V2Bip39Sha512));
        assert_ne!(candidates[0].1.address().to_string(), candidates[1].1.address().to_string());
    }

    /// K-M3: `recover_resolved` must pick the candidate matching a supplied
    /// address — this is the "never silently choosing" contract: given a
    /// hint, resolve it; given none, fail rather than guess.
    #[test]
    fn recover_resolved_matches_expected_address() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let v1 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V1LegacyPbkdf2Sha256, Network::Mainnet).unwrap();
        let v1_addr = v1.address().to_string();

        let (resolved_version, resolved_wallet) = Wallet::recover_resolved(
            &seed, "", Network::Mainnet, Some(&v1_addr), |_| false,
        ).unwrap();
        assert_eq!(resolved_version, SeedVersion::V1LegacyPbkdf2Sha256);
        assert_eq!(resolved_wallet.address().to_string(), v1_addr);
    }

    /// K-M3: the on-chain-history seam resolves the ambiguity when no
    /// address hint is given.
    #[test]
    fn recover_resolved_uses_history_seam() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let v1 = Wallet::from_seed_versioned(
            &seed, "", SeedVersion::V1LegacyPbkdf2Sha256, Network::Mainnet).unwrap();
        let v1_hash = *v1.address().hash();

        let (resolved_version, _) = Wallet::recover_resolved(
            &seed, "", Network::Mainnet, None,
            |addr| *addr.hash() == v1_hash,
        ).unwrap();
        assert_eq!(resolved_version, SeedVersion::V1LegacyPbkdf2Sha256);
    }

    /// K-M3: with NO matching hint at all, resolution must fail closed
    /// rather than default to either version.
    #[test]
    fn recover_resolved_fails_closed_with_no_match() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let result = Wallet::recover_resolved(&seed, "", Network::Mainnet, None, |_| false);
        assert!(matches!(result, Err(WalletError::AmbiguousSeedVersion)));
    }

    #[test]
    fn sign_tx_script_sig_is_length_prefixed_and_verifies() {
        // Regression: Wallet::sign_tx must emit the canonical length-prefixed
        // script_sig that consensus parses with parse_script_sig — a raw
        // sig||pubkey (the old bug) fails verification and the tx is rejected.
        let (wallet, _seed) = Wallet::generate(Network::Testnet).unwrap();
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [1u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput { value: 100, script_pubkey: vec![2u8; 20] }],
            locktime: 0,
        };
        let signed = wallet.sign_tx(tx).unwrap();
        let (sig, pk) = Transaction::parse_script_sig(&signed.inputs[0].script_sig)
            .expect("script_sig must be parseable (length-prefixed)");
        assert!(
            crypto::verify(&pk, &signed.sighash(0, crate::core::ChainId::Testnet), &sig),
            "the signature the consensus verifier extracts must verify"
        );
    }

    #[test]
    fn generate_produces_valid_address() {
        let (wallet, _seed) = Wallet::generate(Network::Mainnet).unwrap();
        assert!(wallet.address().to_string().starts_with("gnb1q"));
        assert_eq!(wallet.network(), Network::Mainnet);
        assert!(!wallet.public_key().is_empty());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let w1 = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        let w2 = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        assert_eq!(w1.address().to_string(), w2.address().to_string());
        assert_eq!(w1.public_key(), w2.public_key());
    }

    #[test]
    fn same_seed_different_network_different_prefix() {
        let (_, seed) = Wallet::generate(Network::Mainnet).unwrap();
        let main = Wallet::from_seed(&seed, Network::Mainnet).unwrap();
        let test = Wallet::from_seed(&seed, Network::Testnet).unwrap();
        assert!(main.address().to_string().starts_with("gnb1q"));
        assert!(test.address().to_string().starts_with("gnb1t"));
        // Same underlying hash, different encoding
        assert_eq!(main.public_key(), test.public_key());
    }

    #[test]
    fn build_tx_rejects_insufficient_funds() {
        let (wallet, _) = Wallet::generate(Network::Mainnet).unwrap();
        let (other_wallet, _) = Wallet::generate(Network::Mainnet).unwrap();

        let utxos = vec![Utxo {
            txid: [0u8; 32],
            index: 0,
            output: TxOutput { value: 1000, script_pubkey: wallet.address().hash().to_vec() },
        }];

        // Try to send 2000 with 1000 UTXO
        let result = wallet.build_tx(utxos, other_wallet.address(), 2000, 100, 1);
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })));
    }

    #[test]
    fn build_tx_creates_change_output() {
        let (wallet, _) = Wallet::generate(Network::Mainnet).unwrap();
        let (other_wallet, _) = Wallet::generate(Network::Mainnet).unwrap();

        let utxos = vec![Utxo {
            txid: [0u8; 32],
            index: 0,
            output: TxOutput { value: 100_000, script_pubkey: wallet.address().hash().to_vec() },
        }];

        let tx = wallet.build_tx(utxos, other_wallet.address(), 50_000, 1000, 1).unwrap();

        // 2 outputs: recipient + change
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, 50_000);
        assert_eq!(tx.outputs[1].value, 49_000); // 100k - 50k - 1k fee
    }

    #[test]
    fn build_tx_no_change_when_exact() {
        let (wallet, _) = Wallet::generate(Network::Mainnet).unwrap();
        let (other, _) = Wallet::generate(Network::Mainnet).unwrap();

        let utxos = vec![Utxo {
            txid: [0u8; 32],
            index: 0,
            output: TxOutput { value: 51_000, script_pubkey: wallet.address().hash().to_vec() },
        }];

        // Send exactly (utxo - fee) — no change
        let tx = wallet.build_tx(utxos, other.address(), 50_000, 1_000, 1).unwrap();
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 50_000);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Legacy Compatibility Layer (Sprint C transitional)
// ───────────────────────────────────────────────────────────────────────────
// The following code is preserved from the pre-Sprint-C wallet/mod.rs to
// keep existing consumers compiling: hd_wallet, gnb-cli, bloch-wallet.
//
// Planned removal: Sprint C.1 migrates these consumers to the new `Wallet`
// API defined above. Until then, both APIs coexist.
//
// Do NOT write new code against the types below — use `Wallet` instead.
// ═══════════════════════════════════════════════════════════════════════════


use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, AeadInPlace, KeyInit}};
use argon2::{Argon2, Algorithm, Version, Params};
use base64::{Engine as _, engine::general_purpose as b64};
use rand::RngCore;
use std::borrow::Cow;
use std::path::Path;

// ── Encrypted keystore ────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKeystore {
    pub version:     u32,
    pub address:     String,
    pub network:     String,
    pub crypto:      KeystoreCrypto,
    pub created_at:  String,
    pub description: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeystoreCrypto {
    pub cipher: String, pub ciphertext: String, pub nonce: String,
    pub kdf: String,    pub kdf_params: KdfParams,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_cost: u32, pub time_cost: u32, pub parallelism: u32,
    pub salt: String,     pub output_len: u32,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct KeystorePayload { private_key_hex: String, public_key_hex: String }

/// Borrow ordinary unescaped key strings from the zeroizing decrypted JSON.
/// Historical escaped JSON still works through `Cow::Owned`; the fallback is
/// explicitly wiped instead of leaving a second secret string allocation.
#[derive(Deserialize)]
struct BorrowedKeystorePayload<'a> {
    #[serde(borrow)]
    private_key_hex: Cow<'a, str>,
    #[serde(borrow)]
    public_key_hex: Cow<'a, str>,
}

impl Drop for BorrowedKeystorePayload<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(private_key_hex) = &mut self.private_key_hex {
            private_key_hex.zeroize();
        }
        if let Cow::Owned(public_key_hex) = &mut self.public_key_hex {
            public_key_hex.zeroize();
        }
    }
}

// ── Keypair ───────────────────────────────────────────────────────────────────

/// A signing key pair with its address.
///
/// CRY-4: the secret key is a [`SecretBytes`] (locked in RAM where the
/// platform allows, wiped on drop) and `Keypair` is neither `Clone` nor
/// `Deserialize` (it used to derive both: every clone was another unwiped
/// copy of the secret). Build one from a `Vec` with `private_key:
/// vec.into()` (the `Vec` is wiped), and copy one deliberately with
/// [`Keypair::duplicate`].
pub struct Keypair {
    pub private_key: SecretBytes,
    pub public_key:  Vec<u8>,
    pub address:     String,
}

/// SECURITY (A4 lows): hand-written so the private key can NEVER reach a
/// `serde_json::to_*`/`to_vec`/etc. call on `Keypair` — a careless log line,
/// debug endpoint, or accidental persist that serializes a `Keypair` must not
/// be able to leak the secret key. Only the address and public key travel;
/// encrypted persistence goes through `KeystorePayload`/`EncryptedKeyfile`,
/// which are separate types with their own AEAD, not this impl.
impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Keypair", 2)?;
        s.serialize_field("public_key", &hex::encode(&self.public_key))?;
        s.serialize_field("address", &self.address)?;
        s.end()
    }
}

impl Drop for Keypair {
    fn drop(&mut self) { self.private_key.zeroize(); }
}

impl Keypair {
    /// A deliberate copy (with its own secret region). `Keypair` is not
    /// `Clone`, so a secret is never duplicated by accident (CRY-4).
    pub fn duplicate(&self) -> Keypair {
        Keypair {
            private_key: self.private_key.duplicate(),
            public_key: self.public_key.clone(),
            address: self.address.clone(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        // Legacy v2 keystores stored the RAW private key (no 4-byte suite envelope),
        // while newer keys and crypto::sign use the enveloped form. If this key is
        // un-enveloped, wrap it under the SAME suite the (enveloped) public key
        // declares, so the signature matches the address's suite. Never mutates
        // the stored key. The temporary owned wrapper contains the entire secret,
        // so keep it in zeroizing storage instead of a plain `Cow::Owned` buffer.
        //
        // CRY-5: `sign_checked` verifies both hybrid halves of the produced
        // signature under `self.public_key` (and its canonical encoding)
        // before returning it, so a corrupted or mismatched secret key is an
        // error here, never a transaction the network rejects later.
        self.with_enveloped_secret(|sk| crypto::sign_checked(sk, &self.public_key, msg))
    }

    /// Verified sighash-v3 signature (component-bound, CRY-2) of `digest`,
    /// with the same legacy-key handling as [`Self::sign`].
    pub fn sign_bound(&self, digest: &[u8; 32]) -> Result<Vec<u8>, String> {
        self.with_enveloped_secret(|sk| crypto::sign_bound_checked(sk, &self.public_key, digest))
    }

    /// Verified signature of a transaction digest under the binding of
    /// `version`: [`Self::sign`] for sighash v2, [`Self::sign_bound`] for v3.
    pub fn sign_tx_digest(&self, digest: &[u8; 32], version: crate::core::sighash::SighashVersion) -> Result<Vec<u8>, String> {
        match version {
            crate::core::sighash::SighashVersion::V2 => self.sign(digest),
            crate::core::sighash::SighashVersion::V3 => self.sign_bound(digest),
        }
    }

    /// Run `f` with the secret key in its enveloped form (wrapping a legacy
    /// raw key under the public key's suite in zeroizing storage).
    ///
    /// B2-T2: the encoding is decided from exact lengths, never from leading
    /// bytes. The suite is the public key's (`crypto::public_key_suite`: the
    /// exact raw hybrid length is suite 0x0001, otherwise its envelope);
    /// a secret of exactly that suite's raw length is a raw key and is
    /// wrapped; otherwise it must be a well-formed envelope of that same
    /// suite with a body of exactly the raw length. Guessing from the first
    /// two bytes misread 1 in 65,536 raw keys (an ML-DSA secret starts with
    /// the uniformly random `rho`) as enveloped under a bogus suite, and such
    /// a wallet could never sign. Bitcoin Core takes a key's type from its
    /// size and metadata in the same way, never from its first bytes.
    ///
    /// P5-S: a conservative suite-0x0003 key has no raw form; its secret must
    /// be exactly the enveloped [`crypto::CONSERVATIVE_SECRET_KEY_LEN`] bytes
    /// naming that suite. (Only sighash-v3 signing accepts such a key:
    /// [`Self::sign`] refuses it inside `crypto::sign`.)
    fn with_enveloped_secret(
        &self,
        f: impl FnOnce(&[u8]) -> Result<Vec<u8>, crypto::CryptoError>,
    ) -> Result<Vec<u8>, String> {
        if crypto::is_conservative_public_key(&self.public_key) {
            let sk: &[u8] = &self.private_key;
            return match crypto::split_envelope(sk) {
                Some((crypto::SUITE_CONSERVATIVE, _)) if sk.len() == crypto::CONSERVATIVE_SECRET_KEY_LEN => {
                    f(sk).map_err(|e| e.to_string())
                }
                _ => Err(format!(
                    "secret key ({} bytes) is not the enveloped conservative suite-0x0003 secret key \
                     ({} bytes) of the public key", sk.len(), crypto::CONSERVATIVE_SECRET_KEY_LEN)),
            };
        }
        let suite = crypto::public_key_suite(&self.public_key).ok_or_else(|| {
            "public key is neither the raw hybrid encoding nor a supported suite envelope".to_string()
        })?;
        let raw_len = crypto::raw_secret_key_len(suite)
            .ok_or_else(|| format!("public key suite {suite:#06x} has no secret-key encoding"))?;
        let sk: &[u8] = &self.private_key;
        if sk.len() == raw_len {
            // CRY-4: the enveloped copy of a legacy raw key lives in secret
            // memory too (it is the whole secret).
            let wrapped = crypto::wrap_envelope_secret(suite, sk);
            return f(&wrapped).map_err(|e| e.to_string());
        }
        match crypto::parse_envelope(sk) {
            Some((s, body)) if s == suite && body.len() == raw_len => f(sk).map_err(|e| e.to_string()),
            Some((s, _)) if s != suite => Err(format!(
                "secret key envelope names suite {s:#06x}, the public key suite {suite:#06x}")),
            _ => Err(format!(
                "secret key ({} bytes) is neither the raw encoding ({raw_len} bytes) nor the envelope \
                 of the public key's suite {suite:#06x}", sk.len())),
        }
    }

    /// Network of this keypair, from its (authenticated, for keystore v3)
    /// address prefix.
    pub fn network(&self) -> Result<Network, String> {
        Address::parse(&self.address).map(|a| a.network()).map_err(|e| format!("invalid wallet address: {e}"))
    }

    /// Verify arbitrary wallet data while preserving legacy format compatibility.
    ///
    /// Matching enveloped and raw-hybrid pairs are attempted explicitly before
    /// the historical autodetecting verifier. The final fallback preserves mixed
    /// raw/enveloped inputs previously accepted by this broad compatibility API.
    pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        crypto::verify_enveloped(pk, msg, sig)
            || crypto::verify_legacy_hybrid_raw(pk, msg, sig)
            || crypto::verify(pk, msg, sig)
    }

    /// A4-M-4: sign an arbitrary user-supplied MESSAGE (never a raw digest).
    /// Signs a domain-separated digest of `message`, not `message` itself —
    /// the caller must pass the message's raw bytes, never hex-decoded text,
    /// so a 64-hex-character message can never be reinterpreted as a raw
    /// 32-byte tx sighash / disclosure digest / PoS signing root. Pair with
    /// [`Self::verify_message_on`] (or [`Self::verify_message`]).
    ///
    /// CRY-8: signatures use the chain-bound v2 domain
    /// ([`crypto::signed_message_digest_v2`]) with the chain of this
    /// keypair's network, so they do not carry over between GnB mainnet,
    /// GnB testnet and Bloch (which share keys). Verifiers accept only v2 of
    /// the chain they check, unless a caller explicitly opts into the legacy
    /// v1 domain ([`Self::verify_message_allowing_legacy_v1`]).
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let chain = crate::core::ChainId::for_network(self.network()?);
        let digest = crypto::signed_message_digest_v2(chain, message);
        self.sign(&digest)
    }

    /// Sign under the legacy v1 message domain (no chain id), which Bloch
    /// signers still use. Only for interoperability with verifiers that
    /// predate v2: a v1 signature proves nothing about which chain it was
    /// meant for, and no default GnB verifier accepts it (CRY-8).
    pub fn sign_message_v1(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let digest = crypto::signed_message_digest(message);
        self.sign(&digest)
    }

    /// Compatibility verification of one digest: explicit enveloped and
    /// raw-hybrid pairs first, the generic verifier last (older mixed
    /// envelope/raw records whose storage metadata was not retained).
    fn verify_digest_compat(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        crypto::verify_enveloped(pk, digest, sig)
            || crypto::verify_legacy_hybrid_raw(pk, digest, sig)
            || crypto::verify(pk, digest, sig)
    }

    /// Message digests a verifier accepts: the v2 digest of `network`'s
    /// chain (of either GnB chain for `None`) and, only with `legacy_v1`, the
    /// chain-less v1 digest.
    fn message_digests(network: Option<Network>, message: &[u8], legacy_v1: bool) -> Vec<[u8; 32]> {
        use crate::core::ChainId;
        let mut digests = match network {
            Some(n) => vec![crypto::signed_message_digest_v2(ChainId::for_network(n), message)],
            None => vec![
                crypto::signed_message_digest_v2(ChainId::Mainnet, message),
                crypto::signed_message_digest_v2(ChainId::Testnet, message),
            ],
        };
        if legacy_v1 {
            digests.push(crypto::signed_message_digest(message));
        }
        digests
    }

    /// Verify a signature produced by [`Self::sign_message`] over `message`
    /// under public key `pk` (compatible key and signature encodings).
    ///
    /// Accepts a v2 signature for EITHER GnB chain, never a chain-less v1
    /// one (CRY-8: a Bloch v1 signature verified as a GnB proof); callers
    /// that know the chain should use [`Self::verify_message_on`].
    pub fn verify_message(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        Self::message_digests(None, message, false).iter().any(|d| Self::verify_digest_compat(pk, d, sig))
    }

    /// Verify a message signature for a specific network: the v2 signature
    /// must name that network's chain id. Legacy v1 signatures (no chain id)
    /// are refused (CRY-8).
    pub fn verify_message_on(network: Network, pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        Self::message_digests(Some(network), message, false).iter().any(|d| Self::verify_digest_compat(pk, d, sig))
    }

    /// Explicit legacy mode (CRY-8): like [`Self::verify_message_on`] (or
    /// [`Self::verify_message`] for `None`), but ALSO accepts a chain-less
    /// v1 signature. A v1 signature binds no network: one made on Bloch, on
    /// GnB mainnet or on GnB testnet verifies here for all of them, so a
    /// caller must only use this to check old v1 records whose meaning does
    /// not depend on the chain. Never used by any default verifier.
    pub fn verify_message_allowing_legacy_v1(network: Option<Network>, pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        Self::message_digests(network, message, true).iter().any(|d| Self::verify_digest_compat(pk, d, sig))
    }

    /// Verify a newly-issued wallet message using the strict modern policy.
    /// Both objects must carry suite envelopes and the signature encoding must
    /// be canonical; legacy raw and mixed-format records, and v1 signatures,
    /// are rejected.
    pub fn verify_message_canonical(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        Self::message_digests(None, message, false).iter()
            .any(|d| crypto::verify_enveloped_canonical(pk, d, sig))
    }

    /// [`Self::verify_message_canonical`] for a specific network.
    pub fn verify_message_canonical_on(network: Network, pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
        Self::message_digests(Some(network), message, false).iter()
            .any(|d| crypto::verify_enveloped_canonical(pk, d, sig))
    }

    pub fn address_bytes(&self) -> Vec<u8> {
        use sha3::{Sha3_256, Digest};
        Sha3_256::digest(&self.public_key)[..20].to_vec()
    }

    // ── Keystore ──────────────────────────────────────────────────────────────

    pub fn save_encrypted(&self, path: &Path, password: &str) -> Result<(), String> {
        let json = self.to_encrypted_json(password)?;
        // Sprint T.5 — Audit L-4: atomic write (temp + fsync + rename).
        crate::util::atomic_write(path, json.as_bytes()).map_err(|e| e.to_string())
    }

    /// The encrypted keystore JSON for this keypair (what `save_encrypted`
    /// writes). Used directly where there is no filesystem (the web wallet).
    ///
    /// CRY-7 / WAL-7: writes keystore **v3**, whose AES-GCM associated data
    /// binds the format version, the network and the address (which commits
    /// to SHA3-256 of the public key, re-derived from the decrypted key on
    /// load). Editing the `network` or `address` field of a v3 file makes it
    /// fail to decrypt. v2 files (empty associated data) still load.
    pub fn to_encrypted_json(&self, password: &str) -> Result<String, String> {
        self.to_encrypted_json_version(password, KEYSTORE_VERSION_V3)
    }

    /// Writer for both formats. Production writes only v3; v2 output exists
    /// so compatibility tests can produce the files older releases (and
    /// Bloch) wrote.
    fn to_encrypted_json_version(&self, password: &str, version: u32) -> Result<String, String> {
        self.to_encrypted_json_with_policy(password, version, true)
    }

    /// `enforce_policy = false` only for the CRY-7 v2 -> v3 migration, which
    /// re-encrypts under the password the user already has.
    fn to_encrypted_json_with_policy(&self, password: &str, version: u32, enforce_policy: bool)
        -> Result<String, String>
    {
        // SECURITY (A4 lows): enforce the SAME blocking password policy as
        // the new-style `EncryptedKeyfile` (length + breach denylist) here
        // too — this legacy path is reachable directly (e.g. the CLI's `New`
        // command), and Argon2 hardening is moot behind a weak password.
        if enforce_policy {
            encryption::validate_password_strength(password).map_err(|e| e.to_string())?;
        }

        let address = Address::parse(&self.address)
            .map_err(|e| format!("keypair address is invalid: {e}"))?;
        if address.to_string() != self.address
            || crypto::address_from_pubkey(&self.public_key, address.is_testnet()) != self.address
        {
            return Err("keypair address does not match its public key".into());
        }
        let network = if address.is_testnet() { "testnet" } else { "mainnet" };

        let mut salt = vec![0u8; 32];
        rand::rng().fill_bytes(&mut salt);
        let enc_key = derive_key(password, &salt)?;
        let mut nonce_b = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_b);

        let ct = encrypt_keystore_payload_with_aad(
            &enc_key,
            &nonce_b,
            &self.private_key,
            &self.public_key,
            &match version {
                KEYSTORE_VERSION_V3 => keystore_v3_aad(network, &self.address),
                LEGACY_KEYSTORE_VERSION_V2 => Vec::new(),
                other => return Err(format!("cannot write keystore version {other}")),
            },
        )?;
        // The derived key is no longer needed once the private helper has
        // returned the ciphertext. Wipe it before public metadata assembly,
        // final JSON serialization and atomic write/fsync below.
        drop(enc_key);

        let ks = EncryptedKeystore {
            version,
            address: self.address.clone(),
            network: network.into(),
            crypto: KeystoreCrypto {
                cipher:     "aes-256-gcm".into(),
                ciphertext: b64::STANDARD.encode(&ct),
                nonce:      b64::STANDARD.encode(nonce_b),
                kdf:        "argon2id".into(),
                kdf_params: KdfParams { memory_cost: 262144, time_cost: 4, parallelism: 4,
                    salt: b64::STANDARD.encode(&salt), output_len: 32 },
            },
            created_at:  chrono::Utc::now().to_rfc3339(),
            description: format!(
                "GnB hybrid ML-DSA-65 + Falcon-1024 keystore v{version}{}",
                if version == KEYSTORE_VERSION_V3 { " (network and address authenticated)" } else { "" }
            ),
        };
        serde_json::to_string_pretty(&ks).map_err(|e| e.to_string())
    }

    /// Open a keystore file whose format authenticates its network
    /// (keystore v3). A v2 file is refused: open it with
    /// [`Self::load_encrypted_on`] and the network it belongs to (CRY-7).
    pub fn load_encrypted(path: &Path, password: &str) -> Result<Self, String> {
        Self::load_encrypted_with_file_limit(path, password, crate::util::DEFAULT_WALLET_FILE_LIMIT)
    }

    /// Open a keystore file of `network`: a v3 file must be that network's
    /// (authenticated); a v2 file, which authenticates nothing, must record an
    /// address of that network (prefix and checksum) and must not name the
    /// other network (CRY-7).
    pub fn load_encrypted_on(path: &Path, password: &str, network: Network) -> Result<Self, String> {
        let bytes = crate::util::read_wallet_file(path, crate::util::DEFAULT_WALLET_FILE_LIMIT)
            .map_err(|e| e.to_string())?;
        Self::from_encrypted_bytes_on(&bytes, password, network)
    }

    /// Explicit bounded recovery override for authentic large keystores
    /// (maximum 512 MiB). Same network rule as [`Self::load_encrypted`].
    pub fn load_encrypted_with_file_limit(path: &Path, password: &str, max_bytes: usize) -> Result<Self, String> {
        let bytes = crate::util::read_wallet_file(path, max_bytes).map_err(|e| e.to_string())?;
        Self::from_encrypted_bytes(&bytes, password)
    }

    /// [`Self::load_encrypted_with_file_limit`] for a stated network
    /// ([`Self::load_encrypted_on`]).
    pub fn load_encrypted_with_file_limit_on(path: &Path, password: &str, max_bytes: usize, network: Network)
        -> Result<Self, String>
    {
        let bytes = crate::util::read_wallet_file(path, max_bytes).map_err(|e| e.to_string())?;
        Self::from_encrypted_bytes_on(&bytes, password, network)
    }

    /// Open keystore v3 JSON bytes (no filesystem); inputs above the default
    /// wallet file limit are refused.
    ///
    /// CRY-7 (re-audit): every open path authenticates the network. A v3
    /// file authenticates its network and address (AEAD associated data). A
    /// v2 file authenticates neither, and the address checksum does not cover
    /// the prefix, so editing `gnb1q…` to `gnb1t…` (and its `network` field)
    /// loaded the key for the other network on every path that did not use
    /// the spending unlock (the web wallet's `open`, `gnb-cli import-founder`
    /// and `keyinfo`). A v2 file is therefore refused here, before any key
    /// derivation; [`Self::from_encrypted_bytes_on`] opens it for a network
    /// the caller states.
    pub fn from_encrypted_bytes(bytes: &[u8], password: &str) -> Result<Self, String> {
        Self::open_keystore_bytes(bytes, password, None)
    }

    /// Open keystore v2 or v3 JSON bytes for `network`: a v3 file must be
    /// that network's (authenticated); a v2 file must record an address of
    /// that network (prefix and checksum, checked before any key derivation)
    /// whose public key it holds, and must not name the other network in its
    /// `network` field. Nothing is rewritten ([`Self::load_for_spending`]
    /// also migrates a v2 file to v3).
    pub fn from_encrypted_bytes_on(bytes: &[u8], password: &str, network: Network) -> Result<Self, String> {
        Self::open_keystore_bytes(bytes, password, Some(network))
    }

    /// The one keystore decoder (v2 / v3) behind every open path; `stated`
    /// is the network the caller expects (required for v2, CRY-7).
    fn open_keystore_bytes(bytes: &[u8], password: &str, stated: Option<Network>) -> Result<Self, String> {
        if bytes.len() > crate::util::DEFAULT_WALLET_FILE_LIMIT {
            return Err("keystore exceeds the wallet file size limit".into());
        }
        let ks: EncryptedKeystore = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if ks.version != LEGACY_KEYSTORE_VERSION_V2 && ks.version != KEYSTORE_VERSION_V3 {
            return Err("unsupported keystore version".into());
        }
        let name = |n: Network| if n == Network::Testnet { "testnet" } else { "mainnet" };
        // v3: the AAD binds version, network and address. Both cleartext
        // fields must be canonical and agree before they are authenticated.
        let aad = if ks.version == KEYSTORE_VERSION_V3 {
            let network = match ks.network.as_str() {
                "mainnet" => Network::Mainnet,
                "testnet" => Network::Testnet,
                _ => return Err("keystore v3 network must be \"mainnet\" or \"testnet\"".into()),
            };
            let address = Address::parse_for_network(&ks.address, network)
                .map_err(|e| format!("keystore v3 address invalid for its network: {e}"))?;
            if address.to_string() != ks.address {
                return Err("keystore v3 address is not in canonical GnB form".into());
            }
            if let Some(stated) = stated {
                if stated != network {
                    return Err(format!(
                        "keystore is a {} key (authenticated) but {} was requested",
                        name(network), name(stated)));
                }
            }
            keystore_v3_aad(&ks.network, &ks.address)
        } else {
            // v2 authenticates nothing: the network comes from the caller,
            // and the cleartext fields must agree with it (the address is
            // also bound to the decrypted public key below).
            let stated = stated.ok_or_else(|| {
                "keystore v2 does not authenticate its network: state the network (mainnet or \
                 testnet) to open it (Keypair::from_encrypted_bytes_on / load_encrypted_on)".to_string()
            })?;
            let address = crate::address::normalize_legacy_address(&ks.address);
            Address::parse_for_network(&address, stated).map_err(|e| format!(
                "keystore v2 address {} is not a {} address: {e}", address, name(stated)))?;
            let other = name(if stated == Network::Testnet { Network::Mainnet } else { Network::Testnet });
            if ks.network == other {
                return Err(format!(
                    "keystore v2 records network {:?} but {} was requested", ks.network, name(stated)));
            }
            Vec::new()
        };

        // Reject attacker-controlled Argon2 work before any Base64 decoder can
        // allocate output for the remaining untrusted fields.
        validate_kdf_params(&ks.crypto.kdf_params)?;
        validate_legacy_nonce_base64_length(&ks.crypto.nonce)?;

        let salt      = b64::STANDARD.decode(&ks.crypto.kdf_params.salt).map_err(|e| e.to_string())?;
        let nonce_b   = b64::STANDARD.decode(&ks.crypto.nonce).map_err(|e| e.to_string())?;
        // Reuse the decoded ciphertext allocation for authenticated plaintext.
        // The wrapper wipes it if validation, KDF setup or authentication fails.
        let mut plain = Zeroizing::new(
            b64::STANDARD.decode(&ks.crypto.ciphertext).map_err(|e| e.to_string())?,
        );

        // SECURITY (A4 lows): `Nonce::from_slice` PANICS on any length other
        // than 12 bytes. `nonce_b` comes from an untrusted keystore file, so
        // guard the length BEFORE it reaches the fixed-size AES-GCM nonce —
        // a truncated/corrupt file must return an error, never crash the
        // process.
        const NONCE_LEN: usize = 12;
        const GCM_TAG_LEN: usize = 16;
        if nonce_b.len() != NONCE_LEN {
            return Err(format!(
                "keystore nonce has invalid length: expected {} bytes, got {}",
                NONCE_LEN, nonce_b.len()
            ));
        }
        if plain.len() < GCM_TAG_LEN {
            return Err(format!(
                "keystore ciphertext too short: {} bytes, need at least the {}-byte GCM tag",
                plain.len(), GCM_TAG_LEN
            ));
        }

        // SECURITY (A4 lows): honour the KDF params the keystore file
        // actually carries (a change to the default cost in `save_encrypted`
        // must not break decrypting an older file) but BOUND them first — an
        // untrusted file with e.g. `memory_cost` near `u32::MAX` (KiB) would
        // otherwise force a multi-terabyte Argon2 allocation (OOM) on unlock,
        // and `output_len != 32` would panic the AES-256 key conversion below.
        let enc_k = derive_key_with_params(password, &salt, &ks.crypto.kdf_params)?;

        decrypt_keystore_in_place_with_aad(&enc_k, &nonce_b, &aad, &mut plain)?;
        drop(enc_k);

        let (private_key, public_key) = decode_legacy_keystore_payload(plain)?;

        // Bloch keystores record a bloch1q/bloch1t address: same key, same
        // hash, GnB prefix.
        let address = crate::address::normalize_legacy_address(&ks.address);
        let testnet = address.starts_with(TESTNET_PREFIX);
        let derived = crypto::address_from_pubkey(&public_key, testnet);
        if derived != address { return Err("address mismatch — keystore may be tampered".into()); }
        Ok(Keypair { private_key: SecretBytes::from_slice(&private_key), public_key, address })
    }

    /// Open a keystore file for SPENDING or signing (CRY-7 migration).
    ///
    /// * **v3** authenticates its network and address (AEAD associated
    ///   data). If the caller states `network`, it must be the keystore's.
    /// * **v2** authenticates neither, so the caller MUST state the network
    ///   (`None` is refused). The stored address must be a valid address of
    ///   that network (prefix and checksum) and match the decrypted public
    ///   key, and the file's `network` field must not name the other network.
    ///   After the unlock succeeds the file is rewritten as keystore **v3**
    ///   under the same password (see [`PendingKeystoreMigration::commit`]):
    ///   the original v2 bytes are first kept in a new `<file>.v2.bak`
    ///   (Bloch wallets and GnB before v3 read only version 2), then the
    ///   file is replaced atomically (temp file, fsync, rename), mode 0600,
    ///   once the new bytes have been decrypted and checked to hold the same
    ///   key. From then on the network is authenticated.
    ///
    /// The migration keeps the user's existing password even if it predates
    /// the current password policy (re-encrypting does not weaken it, and
    /// refusing would leave the file unauthenticated). Returns the keypair and
    /// what was done to the file. Front ends that should rewrite the file only
    /// once the spend went ahead use [`Self::unlock_for_spending`].
    pub fn load_for_spending(path: &Path, password: &str, network: Option<Network>)
        -> Result<(Self, KeystoreMigration), String>
    {
        let (kp, pending) = Self::unlock_for_spending(path, password, network)?;
        match pending {
            None => Ok((kp, KeystoreMigration::AlreadyV3)),
            Some(pending) => {
                let backup = pending.commit()?;
                Ok((kp, KeystoreMigration::MigratedV2ToV3 { backup }))
            }
        }
    }

    /// [`Self::load_for_spending`] without touching the file: a v2 keystore
    /// is unlocked and checked in memory, and the verified migration is
    /// returned for the caller to [`PendingKeystoreMigration::commit`] once
    /// the spend or signature it was unlocked for has passed its checks and
    /// been confirmed (an aborted send leaves the v2 file exactly as it was).
    pub fn unlock_for_spending(path: &Path, password: &str, network: Option<Network>)
        -> Result<(Self, Option<PendingKeystoreMigration>), String>
    {
        let bytes = crate::util::read_wallet_file(path, crate::util::DEFAULT_WALLET_FILE_LIMIT)
            .map_err(|e| e.to_string())?;
        let (kp, v3_json) = Self::unlock_for_spending_bytes(&bytes, password, network)?;
        let pending = v3_json.map(|v3_json| PendingKeystoreMigration {
            path: path.to_path_buf(),
            original: bytes,
            v3_json,
        });
        Ok((kp, pending))
    }

    /// The filesystem-free part of [`Self::load_for_spending`] (for front ends
    /// that hold the keystore in memory, e.g. the web wallet): unlock `bytes`,
    /// apply the network checks, and for a v2 keystore also return the v3
    /// JSON that replaces it (already verified to decrypt, under `password`,
    /// to the same key and address). A caller that stores the v3 JSON must
    /// keep (or offer the user) the original v2 bytes as well: Bloch wallets
    /// and GnB releases before keystore v3 cannot open the v3 file.
    pub fn unlock_for_spending_bytes(bytes: &[u8], password: &str, network: Option<Network>)
        -> Result<(Self, Option<String>), String>
    {
        let header: EncryptedKeystore = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        // The shared decoder applies the network rules (CRY-7): a v3 key must
        // be of the stated network, a v2 file needs one.
        let kp = Self::open_keystore_bytes(bytes, password, network)?;
        match header.version {
            KEYSTORE_VERSION_V3 => Ok((kp, None)),
            LEGACY_KEYSTORE_VERSION_V2 => {
                let stated = network.ok_or("keystore v2 needs a stated network")?;
                let json = kp.to_encrypted_json_with_policy(password, KEYSTORE_VERSION_V3, false)?;
                let check = Self::from_encrypted_bytes(json.as_bytes(), password)?;
                if check.private_key != kp.private_key || check.public_key != kp.public_key
                    || check.address != kp.address || check.network()? != stated
                {
                    return Err("keystore v2 -> v3 migration produced a different key; file left unchanged".into());
                }
                Ok((kp, Some(json)))
            }
            other => Err(format!("unsupported keystore version {other}")),
        }
    }
}

/// What [`Keypair::load_for_spending`] did with the keystore file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreMigration {
    /// Already keystore v3 (network and address authenticated); unchanged.
    AlreadyV3,
    /// A v2 keystore was verified against the stated network and rewritten
    /// as v3 (atomic write, mode 0600); `backup` holds the original v2 file,
    /// byte for byte.
    MigratedV2ToV3 { backup: std::path::PathBuf },
}

/// A verified v2 -> v3 keystore migration that has not touched the file yet
/// (CRY-7). Returned by [`Keypair::unlock_for_spending`]; dropping it leaves
/// the v2 file as it is.
pub struct PendingKeystoreMigration {
    path: std::path::PathBuf,
    original: Vec<u8>,
    v3_json: String,
}

impl std::fmt::Debug for PendingKeystoreMigration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingKeystoreMigration").field("path", &self.path).finish_non_exhaustive()
    }
}

impl PendingKeystoreMigration {
    /// The keystore file this migration rewrites.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rewrite the keystore as v3, keeping the original. In order:
    /// 1. the file must still hold exactly the bytes that were unlocked
    ///    (otherwise nothing is done);
    /// 2. those bytes are written to a NEW sibling `<file>.v2.bak` (or
    ///    `<file>.v2.bak.<n>` if that name is taken: an existing backup is
    ///    never overwritten), mode 0600, fsynced with its directory — if this
    ///    fails, the migration stops and the file is left untouched;
    /// 3. the file is replaced by the v3 keystore (atomic write, mode 0600).
    ///
    /// Returns the backup's path, for the front end to show the user.
    pub fn commit(self) -> Result<std::path::PathBuf, String> {
        let shown = self.path.display();
        let current = crate::util::read_wallet_file(&self.path, crate::util::DEFAULT_WALLET_FILE_LIMIT)
            .map_err(|e| format!("keystore v2 -> v3 migration: cannot re-read {shown}: {e}"))?;
        if current != self.original {
            return Err(format!("keystore v2 -> v3 migration: {shown} changed since it was unlocked; left as it is"));
        }
        let backup = crate::util::write_new_backup(&self.path, ".v2.bak", &self.original).map_err(|e| format!(
            "keystore v2 -> v3 migration: cannot write a backup of {shown} ({e}); the file is left unchanged"))?;
        crate::util::atomic_write(&self.path, self.v3_json.as_bytes()).map_err(|e| format!(
            "keystore v2 -> v3 migration: cannot rewrite {shown}: {e} (the v2 original is unchanged; a copy is at {})",
            backup.display()))?;
        Ok(backup)
    }
}

/// Parse the authenticated legacy plaintext while keeping its complete
/// private-key JSON inside this short-lived ownership boundary. Canonical key
/// strings borrow this zeroizing allocation; historical escaped strings use
/// the wiping `Cow::Owned` fallback. Both the parsed view and plaintext are
/// dropped before address authentication resumes in the caller.
fn decode_legacy_keystore_payload(
    plain: Zeroizing<Vec<u8>>,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), String> {
    let payload: BorrowedKeystorePayload<'_> =
        serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
    let private_key = Zeroizing::new(
        hex::decode(payload.private_key_hex.as_ref()).map_err(|e| e.to_string())?,
    );
    let public_key = hex::decode(payload.public_key_hex.as_ref()).map_err(|e| e.to_string())?;
    drop(payload);
    drop(plain);
    Ok((private_key, public_key))
}

/// Serialize and encrypt the legacy keypair while keeping repository-owned
/// secret copies inside this short-lived boundary. The structured hex payload
/// is wiped as soon as serialization succeeds; the zeroizing JSON plaintext
/// is wiped when this helper returns, before public metadata is assembled or
/// the final keystore is written.
#[cfg(test)]
fn encrypt_legacy_keystore_payload(
    key: &[u8],
    nonce: &[u8; 12],
    private_key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    encrypt_keystore_payload_with_aad(key, nonce, private_key, public_key, b"")
}

/// Keystore format versions handled by [`Keypair`]. v2 encrypts with empty
/// associated data; v3 (written since the CRY-7 fix) authenticates the
/// version, network and address.
pub const LEGACY_KEYSTORE_VERSION_V2: u32 = 2;
pub const KEYSTORE_VERSION_V3: u32 = 3;

/// v3 associated data: domain tag ‖ version u32 LE ‖ network byte ‖
/// address length u32 LE ‖ address. Fixed-width fields before the single
/// variable one, so the encoding is unambiguous.
fn keystore_v3_aad(network: &str, address: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + 1 + 4 + address.len());
    aad.extend_from_slice(b"GNB-KEYSTORE-v3\0");
    aad.extend_from_slice(&KEYSTORE_VERSION_V3.to_le_bytes());
    aad.push(if network == "testnet" { 1 } else { 0 });
    aad.extend_from_slice(&(address.len() as u32).to_le_bytes());
    aad.extend_from_slice(address.as_bytes());
    aad
}

fn encrypt_keystore_payload_with_aad(
    key: &[u8],
    nonce: &[u8; 12],
    private_key: &[u8],
    public_key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Payload;
    let payload = KeystorePayload {
        private_key_hex: hex::encode(private_key),
        public_key_hex: hex::encode(public_key),
    };
    let plain = Zeroizing::new(
        serde_json::to_vec(&payload).map_err(|e| e.to_string())?,
    );
    drop(payload);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), Payload { msg: plain.as_ref(), aad })
        .map_err(|e| e.to_string())
}

#[cfg(test)]
fn decrypt_legacy_keystore_in_place(
    key: &[u8],
    nonce_b: &[u8],
    ciphertext: &mut Vec<u8>,
) -> Result<(), String> {
    decrypt_keystore_in_place_with_aad(key, nonce_b, b"", ciphertext)
}

fn decrypt_keystore_in_place_with_aad(
    key: &[u8],
    nonce_b: &[u8],
    aad: &[u8],
    ciphertext: &mut Vec<u8>,
) -> Result<(), String> {
    const NONCE_LEN: usize = 12;
    const GCM_TAG_LEN: usize = 16;
    if key.len() != 32 {
        return Err("AES-256 key must contain 32 bytes".into());
    }
    if nonce_b.len() != NONCE_LEN {
        return Err(format!(
            "keystore nonce has invalid length: expected {} bytes, got {}",
            NONCE_LEN, nonce_b.len()
        ));
    }
    if ciphertext.len() < GCM_TAG_LEN {
        return Err(format!(
            "keystore ciphertext too short: {} bytes, need at least the {}-byte GCM tag",
            ciphertext.len(), GCM_TAG_LEN
        ));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt_in_place(Nonce::from_slice(nonce_b), aad, ciphertext)
        .map_err(|_| "decryption failed — wrong password or corrupted file".to_string())
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("address", &self.address)
            .field("pubkey_len", &self.public_key.len())
            .field("privkey", &"[REDACTED]")
            .finish()
    }
}

// ── TX builder ────────────────────────────────────────────────────────────────

pub struct TxBuilder;

impl TxBuilder {
    /// Build and sign a transaction with an exact fee (legacy entry point).
    ///
    /// Selects UTXOs from `available_utxos` (WAL-6: smallest single covering
    /// UTXO, else largest first), signs each input with `keypair` through the
    /// verifying signer, and enforces the default maximum-fee guard (WAL-1)
    /// on the actual fee. A change below the dust threshold is added to the
    /// fee. New callers should use [`Self::build_payment`], which also
    /// verifies claimed UTXO values and reports the actual fee.
    ///
    /// `next_block_height` (the node's `getdaginfo` `next_block_height`)
    /// selects the transaction version (3 at/after the hardening activation,
    /// 1 below).
    pub fn build(
        keypair:         &Keypair,
        available_utxos: &[(Vec<u8>, u32, TxOutput)],  // (txid, index, output)
        to_address_hex:  &str,                           // 20-byte hex address
        amount_sats:     u64,
        fee_sats:        u64,
        next_block_height: u64,
    ) -> Result<Transaction, String> {
        amount_sats.checked_add(fee_sats).ok_or("amount + fee overflow")?;
        let to_bytes = hex::decode(to_address_hex)
            .map_err(|_| "invalid destination address hex")?;
        let utxos = Self::utxos_from_rows(available_utxos)?;
        let opts = PaymentOptions {
            fee: FeeChoice::Exact(fee_sats),
            next_block_height: Some(next_block_height),
            ..PaymentOptions::default()
        };
        Self::build_payment_to_spk(keypair, &utxos, &to_bytes, amount_sats, &opts).map(|p| p.tx)
    }

    /// Build and sign a transaction paying exactly `outputs` (in order),
    /// change last, back to the wallet. Every output must be a valid script
    /// (a 20-byte key hash or a 33-byte policy script) and at least the dust
    /// threshold. `next_block_height` selects the transaction version and
    /// sighash, as in [`Self::build`].
    pub fn build_outputs(
        keypair:         &Keypair,
        available_utxos: &[(Vec<u8>, u32, TxOutput)],
        outputs:         Vec<TxOutput>,
        fee_sats:        u64,
        next_block_height: u64,
    ) -> Result<Transaction, String> {
        if outputs.is_empty() {
            return Err("no outputs".into());
        }
        let mut amount_sats: u64 = 0;
        for o in &outputs {
            // A 20-byte key hash or a 33-byte policy script (core::policy).
            if crate::core::policy::output_kind(&o.script_pubkey).is_none() {
                return Err("destination must be a 20-byte key hash or a 33-byte policy script".into());
            }
            if o.value < crate::core::DUST_THRESHOLD {
                return Err("output below the dust threshold".into());
            }
            amount_sats = amount_sats.checked_add(o.value).ok_or("output total overflow")?;
        }
        let total_needed = amount_sats.checked_add(fee_sats)
            .ok_or("amount + fee overflow")?;
        let mut outpoints = std::collections::BTreeSet::new();
        for (txid, index, _) in available_utxos {
            if txid.len() != 32 {
                return Err("UTXO transaction ID must contain exactly 32 bytes".into());
            }
            if !outpoints.insert((txid.as_slice(), *index)) {
                return Err("duplicate UTXO outpoint".into());
            }
        }

        // Coin selection: greedy, smallest-first
        let mut selected: Vec<&(Vec<u8>, u32, TxOutput)> = vec![];
        let mut selected_total = 0u64;
        let mut sorted = available_utxos.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|(_, _, o)| o.value);

        for utxo in &sorted {
            selected.push(utxo);
            selected_total = selected_total.checked_add(utxo.2.value)
                .ok_or("selected UTXO value overflow")?;
            if selected_total >= total_needed { break; }
        }

        if selected_total < total_needed {
            return Err(format!(
                "insufficient funds: have {} sats, need {} sats",
                selected_total, total_needed
            ));
        }

        // Build inputs (script_sig empty for now — filled after sighash)
        let inputs: Vec<TxInput> = selected.iter().map(|(txid, idx, _)| {
            let mut prev_txid = [0u8; 32];
            prev_txid.copy_from_slice(txid);
            TxInput { prev_txid, prev_index: *idx, script_sig: vec![], sequence: u32::MAX }
        }).collect();

        // Outputs (validated above), then change.
        let mut outputs = outputs;

        // Change output
        let change = selected_total - total_needed;
        if change > 546 { // dust threshold
            outputs.push(TxOutput {
                value:         change,
                script_pubkey: keypair.address_bytes(),
            });
        }

        let chain_id = crate::core::ChainId::for_network(keypair.network()?);
        let opts = PaymentOptions { next_block_height: Some(next_block_height), ..PaymentOptions::default() };
        // CRY-2 / P5-S: the key's suite must be one a wallet signs with for
        // this block (`payment::check_signing_suite`).
        payment::check_signing_suite(&keypair.public_key, chain_id, &opts)?;
        let version = opts.tx_version(chain_id)?;
        let mut tx = Transaction { version, inputs, outputs, locktime: 0 };
        let spent: Vec<TxOutput> = selected.iter().map(|(_, _, o)| o.clone()).collect();
        payment::sign_inputs(&mut tx, &spent, &keypair.public_key, chain_id,
                             &|digest, version| keypair.sign_tx_digest(digest, version))?;
        Ok(tx)
    }

    /// Convert `(txid, index, output)` rows, refusing malformed txids.
    pub fn utxos_from_rows(rows: &[(Vec<u8>, u32, TxOutput)]) -> Result<Vec<Utxo>, String> {
        rows.iter().map(|(txid, index, output)| {
            let txid: [u8; 32] = txid.as_slice().try_into()
                .map_err(|_| "UTXO transaction ID must contain exactly 32 bytes".to_string())?;
            Ok(Utxo { txid, index: *index, output: output.clone() })
        }).collect()
    }

    /// Build and sign a payment to `to` (WAL-1, WAL-6): coin selection,
    /// size-aware fee, maximum-fee guard on the actual fee, verification of
    /// the claimed UTXO values against `opts.prev_txs`, and a report of the
    /// actual fee, change and verified/unverified inputs.
    pub fn build_payment(
        keypair: &Keypair,
        utxos:   &[Utxo],
        to:      &Address,
        amount:  u64,
        opts:    &PaymentOptions<'_>,
    ) -> Result<BuiltPayment, String> {
        if to.network() != keypair.network()? {
            return Err("destination address network differs from wallet".into());
        }
        Self::build_payment_to_spk(keypair, utxos, to.hash(), amount, opts)
    }

    /// Outpoints [`Self::build_payment`] would spend, chosen on the claimed
    /// values: fetch their creating transactions into a [`PrevTxs`] first.
    pub fn plan_inputs(
        keypair: &Keypair,
        utxos:   &[Utxo],
        amount:  u64,
        fee:     FeeChoice,
    ) -> Result<Vec<([u8; 32], u32)>, String> {
        payment::plan_payment_inputs(utxos, amount, keypair.public_key.len(), fee)
    }

    fn build_payment_to_spk(
        keypair: &Keypair,
        utxos:   &[Utxo],
        to_spk:  &[u8],
        amount:  u64,
        opts:    &PaymentOptions<'_>,
    ) -> Result<BuiltPayment, String> {
        // Chain-id: folded into every input's sighash, so it must match the
        // validator's node_chain_id(). Derived from the address prefix, which
        // keystore v3 authenticates.
        let chain_id = crate::core::ChainId::for_network(keypair.network()?);
        payment::build_payment(
            utxos, to_spk, amount, &keypair.address_bytes(), &keypair.public_key,
            chain_id, opts, &|digest, version| keypair.sign_tx_digest(digest, version),
        )
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn generate_keypair(testnet: bool) -> Keypair {
    // CRY-4: the secret is generated in place in secret memory and moved
    // (never copied) into the `Keypair`.
    let (public_key, private_key) = crypto::generate_keypair_secret();
    let address = crypto::address_from_pubkey(&public_key, testnet);
    Keypair {
        private_key,
        public_key,
        address,
    }
}

/// WAL-7: create a keypair backed by a fresh 24-word BIP39 mnemonic (the
/// same derivation as [`Wallet::generate`]: seed version V2, no passphrase),
/// so the words are a complete backup of the key. Show the phrase to the
/// user once; it is wiped when dropped.
pub fn generate_mnemonic_keypair(network: Network) -> Result<(Keypair, SeedPhrase), WalletError> {
    let (wallet, phrase) = Wallet::generate(network)?;
    Ok((wallet.into_keypair(), phrase))
}

/// WAL-7: restore the keypair of [`generate_mnemonic_keypair`] (or of a
/// [`Wallet`] created from a seed phrase) from its words.
pub fn keypair_from_mnemonic(phrase: &str, network: Network) -> Result<Keypair, WalletError> {
    let phrase = SeedPhrase::parse(phrase)?;
    Ok(Wallet::from_seed(&phrase, network)?.into_keypair())
}

/// P5-S: a fresh keypair of `suite` (OS randomness). [`generate_keypair`]
/// for [`crypto::KeySuite::Hybrid`].
pub fn generate_keypair_for_suite(testnet: bool, suite: crypto::KeySuite) -> Result<Keypair, WalletError> {
    let (public_key, private_key) = crypto::generate_keypair_for_suite_secret(suite)
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    let address = crypto::address_from_pubkey(&public_key, testnet);
    Ok(Keypair { private_key, public_key, address })
}

/// P5-S: the keypair of `suite` a seed phrase derives (seed version V2, no
/// passphrase, like [`Wallet::from_seed`]): for the hybrid suite exactly
/// [`keypair_from_mnemonic`]; for the conservative suite the key of
/// `crypto::generate_conservative_keypair_from_seed_secret`, an independent
/// key (its own domain-separated seed) of the same phrase.
pub fn keypair_from_seed_phrase_for_suite(
    phrase: &SeedPhrase,
    network: Network,
    suite: crypto::KeySuite,
) -> Result<Keypair, WalletError> {
    let seed_bytes = phrase.to_seed_bytes_versioned(SeedVersion::V2Bip39Sha512, "")?;
    let (public_key, private_key) = crypto::generate_keypair_from_seed_for_suite_secret(suite, &seed_bytes[..32])
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    let address = crypto::address_from_pubkey(&public_key, network == Network::Testnet);
    Ok(Keypair { private_key, public_key, address })
}

/// P5-S: [`generate_mnemonic_keypair`] for a key of `suite`.
pub fn generate_mnemonic_keypair_for_suite(network: Network, suite: crypto::KeySuite)
    -> Result<(Keypair, SeedPhrase), WalletError>
{
    let phrase = SeedPhrase::generate()?;
    let keypair = keypair_from_seed_phrase_for_suite(&phrase, network, suite)?;
    Ok((keypair, phrase))
}

/// P5-S: [`keypair_from_mnemonic`] for a key of `suite`.
pub fn keypair_from_mnemonic_for_suite(phrase: &str, network: Network, suite: crypto::KeySuite)
    -> Result<Keypair, WalletError>
{
    keypair_from_seed_phrase_for_suite(&SeedPhrase::parse(phrase)?, network, suite)
}

pub fn validate_password(pw: &str) -> Result<(), String> {
    if pw.len() < 12 { return Err("at least 12 characters".into()); }
    let c = [
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ];
    if c.iter().filter(|&&x| x).count() < 3 {
        return Err("need 3 of: uppercase, lowercase, digit, special".into());
    }
    Ok(())
}

fn derive_key(pw: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let params = Params::new(262144, 4, 4, Some(32)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new(vec![0u8; 32]);
    argon2.hash_password_into(pw.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

/// Bounds mirrored from `encryption::EncryptedKeyfile::decrypt` (audit L1):
/// an untrusted keystore file's `kdf_params` must be sanity-checked BEFORE
/// they drive an Argon2 allocation. `memory_cost` near `u32::MAX` (KiB) forces
/// a multi-terabyte allocation (OOM-kills the process on unlock); a huge
/// `time_cost` is a CPU slow-loris. `output_len` is pinned to exactly 32 —
/// this keystore format always feeds the result straight into AES-256-GCM,
/// whose `Key::from_slice` panics on anything but 32 bytes.
const MAX_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 16;
const LEGACY_NONCE_B64_LEN: usize = 16; // 12 decoded bytes

fn validate_legacy_nonce_base64_length(nonce_b64: &str) -> Result<(), String> {
    if nonce_b64.len() != LEGACY_NONCE_B64_LEN {
        return Err(format!(
            "keystore nonce Base64 has invalid encoded length: expected {} bytes, got {}",
            LEGACY_NONCE_B64_LEN,
            nonce_b64.len()
        ));
    }
    Ok(())
}

fn validate_kdf_params(p: &KdfParams) -> Result<(), String> {
    if p.memory_cost > MAX_M_COST_KIB || p.time_cost > MAX_T_COST || p.parallelism > MAX_P_COST {
        return Err(format!(
            "KDF params out of bounds (memory_cost={} KiB, time_cost={}, parallelism={})",
            p.memory_cost, p.time_cost, p.parallelism
        ));
    }
    if p.output_len != 32 {
        return Err(format!(
            "KDF output_len must be 32 (AES-256 key), got {}", p.output_len
        ));
    }
    Ok(())
}

fn derive_key_with_params(
    pw: &str,
    salt: &[u8],
    p: &KdfParams,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // Keep validation here as a defense for any future non-file caller.
    validate_kdf_params(p)?;
    let params = Params::new(p.memory_cost, p.time_cost, p.parallelism, Some(32))
        .map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new(vec![0u8; 32]);
    argon2.hash_password_into(pw.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

// Terminal CLI (clap + rpassword) — gated so the pure wallet/crypto subset
// cross-compiles to wasm32 for the mobile WASM wallet. Native CLI builds enable
// `wallet-cli` (the `postern-wallet` bin already requires it).
#[cfg(feature = "wallet-cli")]
pub mod cli;


#[cfg(test)]
mod legacy_keystore_tests {
    use super::*;

    #[test]
    fn legacy_keygen_preserves_address_and_signing_on_both_networks() {
        assert!(std::mem::needs_drop::<Keypair>());

        for testnet in [false, true] {
            let keypair = generate_keypair(testnet);
            assert_eq!(
                keypair.address,
                crypto::address_from_pubkey(&keypair.public_key, testnet),
            );
            let signature = keypair.sign(b"wave-136-keygen-parity").unwrap();
            assert!(Keypair::verify(
                &keypair.public_key,
                b"wave-136-keygen-parity",
                &signature,
            ));
        }
    }

    #[test]
    fn legacy_save_temporaries_have_zeroizing_ownership_and_exact_json() {
        let _: fn(&str, &[u8]) -> Result<Zeroizing<Vec<u8>>, String> = derive_key;
        let _: fn(&[u8], &[u8; 12], &[u8], &[u8]) -> Result<Vec<u8>, String> =
            encrypt_legacy_keystore_payload;
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());
        assert!(std::mem::needs_drop::<KeystorePayload>());

        let payload = KeystorePayload {
            private_key_hex: "a1b2c3d4".into(),
            public_key_hex: "01020304".into(),
        };
        let expected = serde_json::to_vec(&payload).unwrap();
        let key = [0x52; 32];
        let nonce = [0x73; 12];
        let historical_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let expected_ciphertext = historical_cipher
            .encrypt(Nonce::from_slice(&nonce), expected.as_slice())
            .unwrap();
        let mut ciphertext = Zeroizing::new(
            encrypt_legacy_keystore_payload(
                &key,
                &nonce,
                &[0xa1, 0xb2, 0xc3, 0xd4],
                &[0x01, 0x02, 0x03, 0x04],
            ).unwrap(),
        );
        assert_eq!(&ciphertext[..], &expected_ciphertext);
        decrypt_legacy_keystore_in_place(&key, &nonce, &mut ciphertext).unwrap();
        assert_eq!(&ciphertext[..], &expected);
        ciphertext.zeroize();
        assert!(ciphertext.is_empty() || ciphertext.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn legacy_load_kdf_returns_exact_zeroizing_owner() {
        let _: fn(
            &str,
            &[u8],
            &KdfParams,
        ) -> Result<Zeroizing<Vec<u8>>, String> = derive_key_with_params;

        let kdf = KdfParams {
            memory_cost: 8,
            time_cost: 1,
            parallelism: 1,
            salt: String::new(),
            output_len: 32,
        };
        let salt = [0x39; 16];
        let mut expected = vec![0u8; 32];
        let params = Params::new(8, 1, 1, Some(32)).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"synthetic-test-password", &salt, &mut expected)
            .unwrap();

        let mut actual =
            derive_key_with_params("synthetic-test-password", &salt, &kdf).unwrap();
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());
        assert_eq!(&actual[..], &expected);
        actual.zeroize();
        assert!(actual.is_empty() || actual.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn legacy_loader_checks_every_kdf_bound_before_base64() {
        let password = "synthetic-test-password";
        let path = std::env::temp_dir().join(format!(
            "bloch-wave176-legacy-kdf-order-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let baseline = KdfParams {
            memory_cost: 8,
            time_cost: 1,
            parallelism: 1,
            salt: b64::STANDARD.encode([0x19; 32]),
            output_len: 32,
        };
        let cases = [
            (
                KdfParams { memory_cost: MAX_M_COST_KIB + 1, ..baseline.clone() },
                format!(
                    "KDF params out of bounds (memory_cost={} KiB, time_cost=1, parallelism=1)",
                    MAX_M_COST_KIB + 1
                ),
            ),
            (
                KdfParams { time_cost: MAX_T_COST + 1, ..baseline.clone() },
                format!(
                    "KDF params out of bounds (memory_cost=8 KiB, time_cost={}, parallelism=1)",
                    MAX_T_COST + 1
                ),
            ),
            (
                KdfParams { parallelism: MAX_P_COST + 1, ..baseline.clone() },
                format!(
                    "KDF params out of bounds (memory_cost=8 KiB, time_cost=1, parallelism={})",
                    MAX_P_COST + 1
                ),
            ),
            (
                KdfParams { output_len: 31, ..baseline.clone() },
                "KDF output_len must be 32 (AES-256 key), got 31".to_string(),
            ),
        ];

        for (kdf_params, expected) in cases {
            let keystore = EncryptedKeystore {
                version: 2,
                // CRY-7: a v2 file opens for a stated network, and its
                // address must belong to it (checked before the KDF bounds).
                address: Address::from_hash([0x77; 20], Network::Mainnet).to_string(),
                network: "mainnet".into(),
                crypto: KeystoreCrypto {
                    cipher: "aes-256-gcm".into(),
                    // If policy ordering regresses, this deliberately invalid
                    // large sentinel produces a Base64 error instead.
                    ciphertext: "!".repeat(64 * 1024),
                    nonce: b64::STANDARD.encode([0x28; 12]),
                    kdf: "argon2id".into(),
                    kdf_params,
                },
                created_at: String::new(),
                description: String::new(),
            };
            let bytes = serde_json::to_vec(&keystore).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(
                Keypair::load_encrypted_with_file_limit_on(&path, password, bytes.len(), Network::Mainnet)
                    .unwrap_err(),
                expected
            );
        }

        // A valid, inexpensive parameter set still reaches the unchanged
        // Argon2/AES path and round-trips an authentic legacy keystore.
        let keypair = generate_keypair(false);
        let salt = [0x19; 32];
        let nonce = [0x28; 12];
        let kdf_params = baseline;
        let key = derive_key_with_params(password, &salt, &kdf_params).unwrap();
        let payload = Zeroizing::new(serde_json::to_vec(&KeystorePayload {
            private_key_hex: hex::encode(&keypair.private_key),
            public_key_hex: hex::encode(&keypair.public_key),
        }).unwrap());
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .unwrap();
        let keystore = EncryptedKeystore {
            version: 2,
            address: keypair.address.clone(),
            network: "mainnet".into(),
            crypto: KeystoreCrypto {
                cipher: "aes-256-gcm".into(),
                ciphertext: b64::STANDARD.encode(ciphertext),
                nonce: b64::STANDARD.encode(nonce),
                kdf: "argon2id".into(),
                kdf_params,
            },
            created_at: String::new(),
            description: String::new(),
        };
        let bytes = serde_json::to_vec(&keystore).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let loaded = Keypair::load_encrypted_with_file_limit_on(&path, password, bytes.len(), Network::Mainnet)
            .unwrap();
        assert_eq!(loaded.private_key, keypair.private_key);
        assert_eq!(loaded.public_key, keypair.public_key);
        assert_eq!(loaded.address, keypair.address);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_nonce_base64_length_precedes_decode_without_restricting_salt() {
        let path = std::env::temp_dir().join(format!(
            "bloch-wave181-legacy-nonce-shape-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let password = "synthetic-test-password";
        let keypair = generate_keypair(false);
        let salt = [0x19; 8];
        let nonce = [0x28; 12];
        let kdf_params = KdfParams {
            memory_cost: 8,
            time_cost: 1,
            parallelism: 1,
            salt: b64::STANDARD.encode(salt),
            output_len: 32,
        };
        let key = derive_key_with_params(password, &salt, &kdf_params).unwrap();
        let payload = Zeroizing::new(serde_json::to_vec(&KeystorePayload {
            private_key_hex: hex::encode(&keypair.private_key),
            public_key_hex: hex::encode(&keypair.public_key),
        }).unwrap());
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .unwrap();
        let baseline = EncryptedKeystore {
            version: 2,
            address: keypair.address.clone(),
            network: "mainnet".into(),
            crypto: KeystoreCrypto {
                cipher: "aes-256-gcm".into(),
                ciphertext: b64::STANDARD.encode(ciphertext),
                nonce: b64::STANDARD.encode(nonce),
                kdf: "argon2id".into(),
                // Legacy load historically accepts any Argon2-valid salt
                // length; this non-save-produced salt pins that compatibility.
                kdf_params,
            },
            created_at: String::new(),
            description: String::new(),
        };
        let load = |keystore: &EncryptedKeystore| {
            let bytes = serde_json::to_vec(keystore).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            Keypair::load_encrypted_with_file_limit_on(
                &path,
                password,
                bytes.len(),
                Network::Mainnet,
            )
        };

        assert_eq!(baseline.crypto.nonce.len(), LEGACY_NONCE_B64_LEN);
        let loaded = load(&baseline).unwrap();
        assert_eq!(loaded.private_key, keypair.private_key);
        assert_eq!(loaded.public_key, keypair.public_key);
        assert_eq!(loaded.address, keypair.address);

        let mut exact_sentinel = baseline.clone();
        exact_sentinel.crypto.nonce = "!".repeat(LEGACY_NONCE_B64_LEN);
        assert!(
            !load(&exact_sentinel).unwrap_err().contains("invalid encoded length"),
            "an exact-length nonce sentinel must reach the Base64 decoder",
        );

        let mut one_over = baseline;
        one_over.crypto.nonce = "!".repeat(LEGACY_NONCE_B64_LEN + 1);
        assert_eq!(
            load(&one_over).unwrap_err(),
            format!(
                "keystore nonce Base64 has invalid encoded length: expected {} bytes, got {}",
                LEGACY_NONCE_B64_LEN,
                LEGACY_NONCE_B64_LEN + 1
            ),
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_decrypted_key_strings_borrow_plaintext_and_preserve_escaped_json() {
        let _: fn(Zeroizing<Vec<u8>>)
            -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), String> =
            decode_legacy_keystore_payload;
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());

        let plain = Zeroizing::new(
            serde_json::to_vec(&KeystorePayload {
                private_key_hex: "a1b2c3d4".into(),
                public_key_hex: "01020304".into(),
            }).unwrap(),
        );
        let parsed: BorrowedKeystorePayload<'_> = serde_json::from_slice(&plain).unwrap();
        assert!(matches!(&parsed.private_key_hex, Cow::Borrowed(_)));
        assert!(matches!(&parsed.public_key_hex, Cow::Borrowed(_)));
        let start = plain.as_ptr() as usize;
        let end = start + plain.len();
        for pointer in [
            parsed.private_key_hex.as_ptr() as usize,
            parsed.public_key_hex.as_ptr() as usize,
        ] {
            assert!(pointer >= start && pointer < end);
        }
        assert_eq!(
            hex::decode(parsed.private_key_hex.as_ref()).unwrap(),
            [0xa1, 0xb2, 0xc3, 0xd4]
        );
        drop(parsed);
        let (private_key, public_key) = decode_legacy_keystore_payload(plain).unwrap();
        assert_eq!(&private_key[..], &[0xa1, 0xb2, 0xc3, 0xd4]);
        assert_eq!(public_key, [0x01, 0x02, 0x03, 0x04]);

        let escaped = br#"{
            "private_key_hex":"\u0061\u0062",
            "public_key_hex":"\u0063\u0064"
        }"#;
        let escaped_parsed: BorrowedKeystorePayload<'_> =
            serde_json::from_slice(escaped).unwrap();
        assert!(matches!(&escaped_parsed.private_key_hex, Cow::Owned(_)));
        assert!(matches!(&escaped_parsed.public_key_hex, Cow::Owned(_)));
        assert_eq!(hex::decode(escaped_parsed.private_key_hex.as_ref()).unwrap(), [0xab]);
        assert_eq!(hex::decode(escaped_parsed.public_key_hex.as_ref()).unwrap(), [0xcd]);
        assert!(std::mem::needs_drop::<BorrowedKeystorePayload<'_>>());
        drop(escaped_parsed);

        let (escaped_private, escaped_public) = decode_legacy_keystore_payload(
            Zeroizing::new(escaped.to_vec()),
        ).unwrap();
        assert_eq!(&escaped_private[..], &[0xab]);
        assert_eq!(escaped_public, [0xcd]);

        for (private_key_hex, public_key_hex) in [("zz", "01"), ("01", "zz")] {
            let invalid = Zeroizing::new(
                serde_json::to_vec(&KeystorePayload {
                    private_key_hex: private_key_hex.into(),
                    public_key_hex: public_key_hex.into(),
                }).unwrap(),
            );
            assert_eq!(
                decode_legacy_keystore_payload(invalid).unwrap_err(),
                hex::decode("zz").unwrap_err().to_string(),
            );
        }
    }

    #[test]
    fn legacy_keystore_decryption_reuses_ciphertext_allocation_at_tag_boundary() {
        let key = [0x82; 32];
        let nonce = [0x28; 12];
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

        for plaintext in [b"".as_slice(), b"legacy wallet secret".as_slice()] {
            let mut buffer = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).unwrap();
            let allocation = buffer.as_ptr();
            let encrypted_len = buffer.len();

            decrypt_legacy_keystore_in_place(&key, &nonce, &mut buffer).unwrap();

            assert_eq!(
                buffer.as_ptr(), allocation,
                "legacy decrypt must reuse the Base64-decoded allocation"
            );
            assert_eq!(buffer, plaintext);
            assert_eq!(encrypted_len, plaintext.len() + 16);
        }

        let mut below_tag = vec![0u8; 15];
        assert_eq!(
            decrypt_legacy_keystore_in_place(&key, &nonce, &mut below_tag).unwrap_err(),
            "keystore ciphertext too short: 15 bytes, need at least the 16-byte GCM tag"
        );

        let mut tampered = Zeroizing::new(
            cipher.encrypt(
                Nonce::from_slice(&nonce),
                b"authenticated legacy secret".as_slice(),
            ).unwrap(),
        );
        tampered[0] ^= 1;
        let allocation = tampered.as_ptr();
        assert_eq!(
            decrypt_legacy_keystore_in_place(&key, &nonce, &mut tampered).unwrap_err(),
            "decryption failed — wrong password or corrupted file"
        );
        assert_eq!(tampered.as_ptr(), allocation);
        assert!(std::mem::needs_drop::<Zeroizing<Vec<u8>>>());
    }

    #[test]
    fn keypair_verify_accepts_genuine_magic_prefixed_raw_signature_explicitly() {
        const MESSAGE: &[u8] = b"BLOCH-CR10-MAGIC-PREFIX-FIXTURE-v1";
        const SEARCH_COUNTER: u64 = 23_156;
        const SIGNING_SEED_HEX: &str =
            "5d051b8c445a2f169a9a0104877500c39332cb493ec6de2723cb37dfbb233042";

        let (enveloped_public_key, enveloped_secret_key) =
            crypto::generate_keypair_from_seed(&[0x64; 32]).unwrap();
        let mut h = Sha3_256::new();
        h.update(b"bloch/cr10/signing-rng/v1");
        h.update(SEARCH_COUNTER.to_le_bytes());
        let signing_seed: [u8; 32] = h.finalize().into();
        assert_eq!(hex::encode(signing_seed), SIGNING_SEED_HEX);
        let enveloped_signature =
            pqcrypto_internals::with_seeded_rng_scope(&signing_seed, || {
                crypto::sign(&enveloped_secret_key, MESSAGE).unwrap()
            });

        assert!(Keypair::verify(
            &enveloped_public_key,
            MESSAGE,
            &enveloped_signature,
        ));
        assert!(crypto::verify_enveloped_canonical(
            &enveloped_public_key,
            MESSAGE,
            &enveloped_signature,
        ));

        let raw_public_key = &enveloped_public_key[crypto::SUITE_HEADER_LEN..];
        let raw_signature = &enveloped_signature[crypto::SUITE_HEADER_LEN..];
        assert_eq!(&raw_signature[..2], &[0xb1, 0x0c]);
        assert!(
            !crypto::verify(raw_public_key, MESSAGE, raw_signature),
            "generic autodetection must misclassify this genuine raw signature"
        );
        assert!(Keypair::verify(raw_public_key, MESSAGE, raw_signature));
    }

    /// A4 lows: `Keypair::save_encrypted` must enforce the same blocking
    /// password policy as the new-style keyfile — a weak password must never
    /// produce a keystore file at all.
    #[test]
    fn save_encrypted_rejects_weak_password() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join(format!("bloch-kp-weak-pw-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let result = kp.save_encrypted(&tmp, "short");
        assert!(result.is_err(), "a short password must be rejected");
        assert!(!tmp.exists(), "no keystore file must be written on a rejected password");
    }

    /// A4 lows: a keystore with a corrupt/truncated nonce must return an
    /// error, not panic. `Nonce::from_slice` panics on any length other than
    /// 12 bytes; before the length guard this crashed the process.
    #[test]
    fn load_encrypted_corrupt_nonce_returns_error_not_panic() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join(format!("bloch-kp-corrupt-nonce-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        kp.save_encrypted(&tmp, "correct-horse-battery-9!").unwrap();

        let json = std::fs::read_to_string(&tmp).unwrap();
        let mut ks: serde_json::Value = serde_json::from_str(&json).unwrap();
        ks["crypto"]["nonce"] = serde_json::json!(b64::STANDARD.encode([0u8; 4]));
        std::fs::write(&tmp, serde_json::to_string(&ks).unwrap()).unwrap();

        let result = Keypair::load_encrypted(&tmp, "correct-horse-battery-9!");
        assert!(result.is_err(), "a truncated nonce must be a clean error");

        let _ = std::fs::remove_file(&tmp);
    }

    /// A4 lows: an out-of-bounds `kdf_params.memory_cost` in an untrusted
    /// keystore file must be rejected BEFORE it reaches Argon2 (which would
    /// otherwise attempt a multi-terabyte allocation).
    #[test]
    fn load_encrypted_rejects_out_of_bounds_kdf_params() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join(format!("bloch-kp-bad-kdf-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        kp.save_encrypted(&tmp, "correct-horse-battery-9!").unwrap();

        let json = std::fs::read_to_string(&tmp).unwrap();
        let mut ks: serde_json::Value = serde_json::from_str(&json).unwrap();
        ks["crypto"]["kdf_params"]["memory_cost"] = serde_json::json!(u32::MAX - 1);
        std::fs::write(&tmp, serde_json::to_string(&ks).unwrap()).unwrap();

        let result = Keypair::load_encrypted(&tmp, "correct-horse-battery-9!");
        assert!(result.is_err(), "an absurd memory_cost must be rejected, not attempted");

        let _ = std::fs::remove_file(&tmp);
    }

    /// A4 lows: `Keypair`'s hand-written `Serialize` must never emit the
    /// private key, however the type is serialized.
    #[test]
    fn keypair_serialize_never_emits_private_key() {
        let kp = generate_keypair(false);
        let json = serde_json::to_string(&kp).unwrap();
        let hex_priv = hex::encode(&kp.private_key);
        assert!(!json.contains(&hex_priv), "serialized Keypair must not contain the private key hex");
        assert!(json.contains(&kp.address), "serialized Keypair must still carry the address");
    }

    /// A4-M-4 regression: signing a 64-hex-character MESSAGE must NOT produce
    /// a signature valid over the raw 32 bytes that hex decodes to — the
    /// exact phishing shape the finding reported ("sign this challenge",
    /// where the challenge is secretly a tx sighash / disclosure digest
    /// preimage). Before the fix, the CLI auto-hex-decoded the message and
    /// signed those raw bytes directly, so this assertion would have failed
    /// (the signature over the digest string via the OLD path IS a valid
    /// signature over the raw bytes).
    #[test]
    fn sign_message_of_64_hex_chars_does_not_forge_a_raw_digest_signature() {
        let kp = generate_keypair(false);

        // A 64-hex-char "message" a phishing flow could ask the user to sign
        // — it decodes to exactly 32 bytes, the same shape as a tx sighash.
        let hex_message = "ab".repeat(32);
        assert_eq!(hex_message.len(), 64);
        let raw_digest = hex::decode(&hex_message).unwrap();
        assert_eq!(raw_digest.len(), 32);

        let sig = kp.sign_message(hex_message.as_bytes()).unwrap();

        // The new signed-message API verifies over the message bytes.
        assert!(Keypair::verify_message(&kp.public_key, hex_message.as_bytes(), &sig));

        // But the OLD vulnerable path — treat `sig` as a signature over the
        // raw hex-decoded 32 bytes (e.g. a tx sighash preimage) — must fail.
        assert!(
            !crypto::verify(&kp.public_key, &raw_digest, &sig),
            "a signed MESSAGE must never verify as a signature over the raw \
             hex-decoded digest — that would let a signed challenge double as \
             a transaction/disclosure signature"
        );

        // And a genuine raw-digest signature (the tx-sighash-style path) must
        // NOT verify as a signed message over the hex string either — the two
        // domains are symmetric-safe, not just one-directional.
        let raw_sig = crypto::sign(&kp.private_key, &raw_digest).unwrap();
        assert!(!Keypair::verify_message(&kp.public_key, hex_message.as_bytes(), &raw_sig));
    }

    /// Sanity: normal save/load with a strong password still round-trips —
    /// the new guards must not break the legitimate path.
    #[test]
    fn save_load_roundtrip_still_works() {
        let kp = generate_keypair(false);
        let tmp = std::env::temp_dir().join(format!("bloch-kp-roundtrip-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        kp.save_encrypted(&tmp, "correct-horse-battery-9!").unwrap();
        let file_len = std::fs::metadata(&tmp).unwrap().len() as usize;
        assert!(Keypair::load_encrypted_with_file_limit(&tmp, "wrong", file_len - 1)
            .err().unwrap().contains("byte limit"));
        assert!(matches!(Wallet::load_encrypted_with_file_limit(&tmp, "wrong", file_len - 1), Err(WalletError::Io(message)) if message.contains("byte limit")));
        let exact = Keypair::load_encrypted_with_file_limit(&tmp, "correct-horse-battery-9!", file_len).unwrap();
        assert_eq!(exact.private_key, kp.private_key);
        let loaded = Keypair::load_encrypted(&tmp, "correct-horse-battery-9!").unwrap();
        assert_eq!(loaded.address, kp.address);
        assert_eq!(loaded.private_key, kp.private_key);
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod legacy_sign_tests {
    use super::*;
    // A legacy-format key (raw sk, enveloped pk — the founder v2 shape) must sign and
    // the signature must verify under the enveloped pubkey (the exact consensus check).
    #[test]
    fn legacy_raw_sk_signs_and_verifies() {
        let (pk_env, sk_env) = crypto::generate_keypair(); // both enveloped
        // strip the 4-byte envelope from the sk to simulate the legacy v2 keystore
        let raw_sk = sk_env[4..].to_vec();
        assert!(crypto::parse_envelope(&raw_sk).map(|(s,_)| s) != Some(0xB10C_u16) , "raw sk must look un-enveloped");
        let kp = Keypair {
            private_key: raw_sk.into(),
            public_key: pk_env.clone(),
            address: crypto::address_from_pubkey(&pk_env, false),
        };
        let msg = b"experimental-tx-sighash";
        let sig = kp.sign(msg).expect("legacy sign must succeed");
        assert!(crypto::verify(&pk_env, msg, &sig), "signature must verify under enveloped pubkey");
    }

    /// The zeroizing legacy-wrapper path must remain fail-closed when hostile
    /// wallet material has the expected raw shape but does not belong to the
    /// stored public key. Some backends accept any correctly-sized secret
    /// byte string and emit an unusable signature; others reject it. Neither
    /// outcome may authenticate the corrupted wallet record.
    #[test]
    fn corrupted_legacy_raw_secret_never_authenticates() {
        let (pk_env, _) = crypto::generate_keypair();
        // Use a different, structurally valid secret of the exact legacy raw
        // length. Flipping an arbitrary byte is not a reliable corruption:
        // Falcon's encoded secret can contain representation bits that do not
        // change the effective key, making this regression probabilistic.
        let (_, unrelated_sk_env) = crypto::generate_keypair();
        let raw_sk = unrelated_sk_env[crypto::SUITE_HEADER_LEN..].to_vec();
        let kp = Keypair {
            private_key: raw_sk.into(),
            public_key: pk_env.clone(),
            address: crypto::address_from_pubkey(&pk_env, false),
        };
        let message = b"wallet-legacy-secret-authentication-regression";
        if let Ok(signature) = kp.sign(message) {
            assert!(
                !Keypair::verify(&pk_env, message, &signature),
                "a signature from corrupted legacy secret bytes must not authenticate"
            );
        }
    }

    /// THE founder case: a fully PRE-ENVELOPE wallet — RAW pubkey AND RAW privkey,
    /// address = SHA3-256(raw pubkey) — must produce a spend that passes the node's
    /// EXACT acceptance path (main.rs: pk_hash==script_pubkey AND crypto::verify).
    #[test]
    fn pre_envelope_founder_style_spend_verifies() {
        use sha3::{Sha3_256, Digest};
        let (pk_env, sk_env) = crypto::generate_keypair();
        let raw_pk = pk_env[4..].to_vec();   // 3745 — like the founder pubkey
        let raw_sk = sk_env[4..].to_vec();   // 6337 — like the founder privkey
        // address the OLD chain stored: SHA3-256(RAW pubkey)[..20]
        let script_pubkey = Sha3_256::digest(&raw_pk)[..20].to_vec();

        let kp = Keypair {
            private_key: raw_sk.into(),
            public_key: raw_pk.clone(),      // the CLI puts THIS raw pk in script_sig
            address: crypto::address_from_pubkey(&raw_pk, false),
        };
        let sighash = b"genesis2-input-sighash";
        let sig = kp.sign(sighash).expect("founder-style sign must succeed");

        // Replicate the node's two consensus checks (src/main.rs:2764-2778):
        // 1) pubkey hash matches the UTXO's script_pubkey
        let pk_hash = Sha3_256::digest(&raw_pk)[..20].to_vec();
        assert_eq!(pk_hash, script_pubkey, "raw pubkey must hash to the carry-over address");
        // 2) crypto::verify accepts the raw pubkey + signature (the legacy fix)
        assert!(crypto::verify(&raw_pk, sighash, &sig), "node verify must accept the pre-envelope spend");

        // And a wrong key must still be rejected (no weakening).
        let (other_env, _) = crypto::generate_keypair();
        assert!(!crypto::verify(&other_env[4..], sighash, &sig), "a different pubkey must NOT verify");
    }

    /// The raw (pre-envelope) keypair of seed 22561: its ML-DSA `rho`, the
    /// first bytes of both the raw public and the raw secret key, starts with
    /// the envelope magic `B1 0C` (probability 2^-16 for a random key).
    fn raw_keypair_with_magic_prefix() -> (Vec<u8>, Vec<u8>) {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&22561u64.to_le_bytes());
        let (pk_env, sk_env) = crypto::generate_keypair_from_seed(&seed).unwrap();
        let raw_pk = pk_env[crypto::SUITE_HEADER_LEN..].to_vec();
        let raw_sk = sk_env[crypto::SUITE_HEADER_LEN..].to_vec();
        assert_eq!(&raw_pk[..4], &[0xB1, 0x0C, 0x8B, 0x1E], "fixture: raw pk starts with the magic");
        assert_eq!(&raw_sk[..4], &[0xB1, 0x0C, 0x8B, 0x1E], "fixture: raw sk starts with the magic");
        (raw_pk, raw_sk)
    }

    /// B2-T2: the signer classified a secret key as enveloped from its first
    /// two bytes, so a raw key whose `rho` starts with `B1 0C` was read as
    /// enveloped under the bogus suite `0x1e8b` and could never sign (sign,
    /// sign_bound, sign_message and every payment failed), although consensus
    /// accepts its signatures. Exact lengths decide now, as they do in
    /// consensus (`crypto::public_key_suite`).
    #[test]
    fn raw_key_starting_with_the_envelope_magic_signs_everything() {
        let (raw_pk, raw_sk) = raw_keypair_with_magic_prefix();
        let kp = Keypair {
            private_key: raw_sk.clone().into(),
            public_key: raw_pk.clone(),
            address: crypto::address_from_pubkey(&raw_pk, false),
        };
        let sig = kp.sign(b"founder-message").expect("sign");
        assert!(crypto::verify(&raw_pk, b"founder-message", &sig));
        let digest = [0x5Au8; 32];
        let sig = kp.sign_bound(&digest).expect("sign_bound");
        assert!(crypto::verify_bound(&raw_pk, &digest, &sig));
        let sig = kp.sign_message(b"I own this address").expect("sign_message");
        assert!(Keypair::verify_message_on(Network::Mainnet, &raw_pk, b"I own this address", &sig));

        // A payment at a version-1 height and at the hardening activation
        // (version 3, sighash v3).
        let spk: [u8; 20] = kp.address_bytes().try_into().unwrap();
        let utxos = vec![Utxo {
            txid: [0x31; 32], index: 0,
            output: TxOutput { value: 5_000_000_000, script_pubkey: spk.to_vec() },
        }];
        let to = Address::from_hash([7u8; 20], Network::Mainnet);
        for height in [10, crate::core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT] {
            let opts = PaymentOptions { next_block_height: Some(height), ..PaymentOptions::default() };
            let paid = TxBuilder::build_payment(&kp, &utxos, &to, 100_000_000, &opts)
                .unwrap_or_else(|e| panic!("payment at height {height}: {e}"));
            let spent = [utxos[0].output.clone()];
            crate::core::sighash::verify_tx_scripts(&paid.tx, &spent, crate::core::ChainId::Mainnet,
                height, crate::core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT)
                .unwrap_or_else(|e| panic!("consensus refuses the payment at height {height}: {e:?}"));
        }

        // Main's multisig / timelock signing paths, same raw secret: a payment
        // to a policy script (TxBuilder::build_outputs) and its signature on a
        // 1-of-1 policy spend (PolicySpend::sign_digest with sign_tx_digest),
        // at both heights. A policy names its keys enveloped (its sighash-v2
        // witnesses are verified with the enveloped canonical verifier).
        let policy_pk = crypto::wrap_envelope(crypto::SUITE_MLDSA65_FALCON1024, &raw_pk);
        let policy_signer = Keypair {
            private_key: raw_sk.clone().into(),
            public_key: policy_pk.clone(),
            address: crypto::address_from_pubkey(&policy_pk, false),
        };
        let policy = crate::core::policy::SpendPolicy::new(1, vec![policy_pk], 0, 0).expect("hybrid key");
        let rows = vec![(utxos[0].txid.to_vec(), 0u32, utxos[0].output.clone())];
        for height in [10, crate::core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT] {
            let out = TxOutput { value: 100_000_000, script_pubkey: policy.script_pubkey() };
            let tx = TxBuilder::build_outputs(&kp, &rows, vec![out.clone()], 100_000, height)
                .unwrap_or_else(|e| panic!("build_outputs at height {height}: {e}"));
            crate::core::sighash::verify_tx_scripts(&tx, &[utxos[0].output.clone()], crate::core::ChainId::Mainnet,
                height, crate::core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT)
                .unwrap_or_else(|e| panic!("consensus refuses build_outputs at height {height}: {e:?}"));
            let mut spend = policy_spend::PolicySpend::new(Network::Mainnet, policy.clone(),
                &[(tx.txid(), 0, out.value)], spk.to_vec(), 50_000_000, 0, 0).expect("policy spend");
            spend.target_height(height).unwrap();
            spend.sign_digest(&policy_signer.public_key, |d, v| policy_signer.sign_tx_digest(d, v))
                .unwrap_or_else(|e| panic!("policy signature at height {height}: {e}"));
            spend.finalize().unwrap_or_else(|e| panic!("finalize at height {height}: {e}"));
        }

        // The same raw secret with the enveloped public key, and the
        // enveloped secret with the raw public key, sign as well.
        let env_pk = crypto::wrap_envelope(crypto::SUITE_MLDSA65_FALCON1024, &raw_pk);
        let env_sk = crypto::wrap_envelope(crypto::SUITE_MLDSA65_FALCON1024, &raw_sk);
        for (sk, pk) in [(raw_sk.clone(), env_pk.clone()), (env_sk.clone(), raw_pk.clone()), (env_sk, env_pk)] {
            let kp = Keypair { private_key: sk.into(), public_key: pk.clone(), address: crypto::address_from_pubkey(&pk, false) };
            let sig = kp.sign(b"m").expect("mixed encodings sign");
            assert!(crypto::verify(&pk, b"m", &sig));
        }
    }

    /// B2-T2: a secret that is neither the exact raw hybrid encoding nor a
    /// well-formed envelope of the public key's suite is refused before any
    /// signing, instead of being guessed at.
    #[test]
    fn secret_key_encoding_is_classified_by_exact_lengths() {
        let (raw_pk, raw_sk) = raw_keypair_with_magic_prefix();
        let env_pk = crypto::wrap_envelope(crypto::SUITE_MLDSA65_FALCON1024, &raw_pk);
        let refused = |sk: Vec<u8>, pk: &[u8]| {
            let kp = Keypair { private_key: sk.into(), public_key: pk.to_vec(), address: crypto::address_from_pubkey(pk, false) };
            kp.sign(b"m").unwrap_err()
        };
        // One byte short of the raw length: neither encoding.
        assert!(refused(raw_sk[..raw_sk.len() - 1].to_vec(), &raw_pk).contains("secret key"));
        // An envelope naming another suite than the public key's.
        let wrong_suite = crypto::wrap_envelope(crypto::SUITE_MLDSA65_ONLY, &raw_sk);
        assert!(refused(wrong_suite, &env_pk).contains("suite"));
        // A public key that names no suite at all.
        assert!(refused(raw_sk.clone(), &raw_pk[..100]).contains("public key"));
    }
}

#[cfg(test)]
mod audit_transaction_boundaries {
    use super::*;
    #[test]
    fn cross_network_addresses_with_identical_hashes_are_refused() {
        for network in [Network::Mainnet, Network::Testnet] {
            let (wallet, _) = Wallet::generate(network).unwrap();
            let other = if network == Network::Mainnet { Network::Testnet } else { Network::Mainnet };
            let wrong = Address::from_hash([42;20], other);
            let right = Address::from_hash([42;20], network);
            let utxos = || vec![Utxo { txid:[1;32], index:0,
                output: TxOutput { value:1000, script_pubkey:wallet.address().hash().to_vec() } }];
            assert!(matches!(wallet.build_tx(utxos(), &wrong, 900, 100, 1), Err(WalletError::NetworkMismatch)));
            assert!(wallet.build_tx(utxos(), &right, 900, 100, 1).is_ok());
        }
    }
    #[test]
    fn empty_and_aggregate_input_overflows_return_errors() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        assert!(matches!(wallet.build_tx(vec![], wallet.address(), u64::MAX, 1, 1), Err(WalletError::Overflow)));
        let inputs = [u64::MAX, 1].into_iter().enumerate().map(|(index, value)| Utxo {
            txid:[1;32], index:index as u32, output:TxOutput { value, script_pubkey:wallet.address().hash().to_vec() }
        }).collect();
        assert!(matches!(wallet.build_tx(inputs, wallet.address(), 1, 0, 1), Err(WalletError::Overflow)));
    }
}

#[cfg(test)]
mod audit_coin_selection_inputs {
    use super::*;

    #[test]
    fn legacy_builder_refuses_malformed_outpoints_destinations_duplicates_and_overflow() {
        let keypair = generate_keypair(true);
        let output = |value| TxOutput { value, script_pubkey: keypair.address_bytes() };
        let destination = "ab".repeat(20);
        for length in [0, 1, 31, 33, 64] {
            let inputs = vec![(vec![1; length], 0, output(1000))];
            assert!(TxBuilder::build(&keypair, &inputs, &destination, 900, 100, 1)
                .err().unwrap().contains("exactly 32 bytes"));
        }
        let valid = vec![(vec![1; 32], 0, output(1000))];
        for destination in [String::new(), "ab".repeat(19), "ab".repeat(21), "zz".repeat(20)] {
            assert!(TxBuilder::build(&keypair, &valid, &destination, 900, 100, 1).is_err());
        }
        let repeated = vec![(vec![1; 32], 0, output(500)), (vec![1; 32], 0, output(500))];
        assert!(TxBuilder::build(&keypair, &repeated, &destination, 900, 100, 1)
            .err().unwrap().contains("duplicate"));
        let overflow = vec![(vec![1; 32], 0, output(1)), (vec![2; 32], 0, output(u64::MAX))];
        assert!(TxBuilder::build(&keypair, &overflow, &destination, u64::MAX, 0, 1)
            .err().unwrap().contains("overflow"));
        // Distinct output indices from the same transaction are legitimate.
        let distinct = vec![(vec![1; 32], 0, output(500)), (vec![1; 32], 1, output(500))];
        let tx = TxBuilder::build(&keypair, &distinct, &destination, 900, 100, 1).unwrap();
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs[0].value, 900);
        assert_eq!(tx.outputs[0].script_pubkey, vec![0xab; 20]);
    }

    #[test]
    fn current_builder_refuses_repeated_outpoint_without_rejecting_other_indices() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        let utxo = |index| Utxo { txid: [3; 32], index,
            output: TxOutput { value: 500, script_pubkey: wallet.address().hash().to_vec() } };
        assert!(matches!(wallet.build_tx(vec![utxo(0), utxo(0)], wallet.address(), 900, 100, 1),
            Err(WalletError::Parse(message)) if message.contains("duplicate")));
        let tx = wallet.build_tx(vec![utxo(0), utxo(1)], wallet.address(), 900, 100, 1).unwrap();
        assert_eq!(tx.inputs.len(), 2);
    }
}

#[cfg(test)]
mod audit_exact_decimal_amounts {
    use super::parse_bloch_satoshis;
    #[test]
    fn exact_values_cover_float_precision_and_u64_boundaries() {
        for (input, expected) in [("0", 0), (".5", 50_000_000), ("1.", 100_000_000),
            ("0.00000001", 1), ("90071992.54740993", 9_007_199_254_740_993),
            ("184467440737.09551615", u64::MAX), (" 0001.2500 ", 125_000_000)] {
            assert_eq!(parse_bloch_satoshis(input), Ok(expected));
        }
        for invalid in ["", ".", "-1", "+1", "NaN", "inf", "1e3", "1.2.3",
            "0.000000001", "1.000000000", "184467440737.09551616", "184467440738",
            "999999999999999999999999999", "１", "1,000"] {
            assert!(parse_bloch_satoshis(invalid).is_err());
        }
    }
}

#[cfg(test)]
mod bloch_keystore_compat_tests {
    use super::*;

    /// A Bloch keystore records a bloch1q… address. Loading it in GnB yields
    /// the same key under the gnb1q… address with the same hash; a keystore
    /// whose address names a different hash is still rejected.
    #[test]
    fn bloch_keystore_loads_under_its_gnb_address() {
        let dir = tempfile_dir();
        let kp = generate_keypair(false);
        // Bloch (and GnB before the CRY-7 fix) wrote keystore v2; build one
        // explicitly, since `save_encrypted` now writes v3.
        let json = kp.to_encrypted_json_version("correct horse battery 9!", LEGACY_KEYSTORE_VERSION_V2).unwrap();
        assert!(json.contains("\"version\": 2"));
        let body = kp.address.strip_prefix(crate::core::MAINNET_PREFIX).unwrap();
        let bloch_path = dir.join("bloch.json");
        std::fs::write(&bloch_path, json.replace(&kp.address, &format!("bloch1q{body}"))).unwrap();
        // CRY-7: a v2 file opens for a stated network only.
        assert!(Keypair::load_encrypted(&bloch_path, "correct horse battery 9!").is_err());
        let loaded = Keypair::load_encrypted_on(&bloch_path, "correct horse battery 9!", Network::Mainnet).unwrap();
        assert_eq!(loaded.address, kp.address);
        assert_eq!(loaded.public_key, kp.public_key);

        let mut other = body.to_string();
        let last = other.pop().unwrap();
        other.push(if last == '0' { '1' } else { '0' });
        let bad_path = dir.join("bad.json");
        std::fs::write(&bad_path, json.replace(&kp.address, &format!("bloch1q{other}"))).unwrap();
        assert!(Keypair::load_encrypted_on(&bad_path, "correct horse battery 9!", Network::Mainnet).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bloch_address_strings_parse_as_the_same_owner() {
        let gnb = crate::address::Address::from_hash([9u8; 20], crate::address::Network::Mainnet).to_string();
        let bloch = format!("bloch1q{}", &gnb[crate::core::MAINNET_PREFIX.len()..]);
        assert_eq!(crate::address::Address::parse(&bloch).unwrap().hash(), &[9u8; 20]);
        assert_eq!(crate::address::Address::parse(&bloch).unwrap().to_string(), gnb);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("gnb-bloch-ks-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

#[cfg(test)]
mod audit_2026_10_wallet_fixes {
    use super::*;

    const SAT: u64 = 100_000_000;
    const PW: &str = "Audit-PoC-password-17!";

    /// CRY-7 regression: keystore v3 authenticates network and address, so
    /// the gnb1q -> gnb1t edit that a v2 file accepts makes v3 fail to open.
    #[test]
    fn keystore_v3_rejects_network_and_address_edits() {
        let kp = generate_keypair(false);
        let json = kp.to_encrypted_json(PW).unwrap();
        assert!(json.contains("\"version\": 3"));
        let loaded = Keypair::from_encrypted_bytes(json.as_bytes(), PW).unwrap();
        assert_eq!(loaded.address, kp.address);
        assert_eq!(loaded.private_key, kp.private_key);

        let flipped = format!("gnb1t{}", &kp.address[5..]);
        // Address prefix edited, network field left alone: refused up front.
        let tampered = json.replace(&kp.address, &flipped);
        assert!(Keypair::from_encrypted_bytes(tampered.as_bytes(), PW).is_err());
        // Both fields edited consistently: the AEAD tag no longer verifies.
        let tampered = tampered.replace("\"network\": \"mainnet\"", "\"network\": \"testnet\"");
        assert_eq!(
            Keypair::from_encrypted_bytes(tampered.as_bytes(), PW).unwrap_err(),
            "decryption failed — wrong password or corrupted file"
        );
        // Downgrading the version to v2 (empty AAD) fails the same way.
        let downgraded = json.replace("\"version\": 3", "\"version\": 2");
        assert!(Keypair::from_encrypted_bytes(downgraded.as_bytes(), PW).is_err());
    }

    /// v2 keystores keep loading, for the network the caller states (CRY-7:
    /// a v2 file authenticates no network, so none is taken from it).
    #[test]
    fn keystore_v2_loads_for_its_stated_network() {
        let kp = generate_keypair(true);
        let json = kp.to_encrypted_json_version(PW, LEGACY_KEYSTORE_VERSION_V2).unwrap();
        assert!(Keypair::from_encrypted_bytes(json.as_bytes(), PW).is_err());
        let loaded = Keypair::from_encrypted_bytes_on(json.as_bytes(), PW, Network::Testnet).unwrap();
        assert_eq!(loaded.address, kp.address);
        assert_eq!(loaded.network().unwrap(), Network::Testnet);
        assert!(Keypair::from_encrypted_bytes_on(json.as_bytes(), PW, Network::Mainnet).is_err());
    }

    fn temp_keystore(tag: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gnb-cry7-{tag}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// CRY-7 residual: a v2 keystore opened for spending must have its
    /// network stated; it is checked against the stored address and the file
    /// is rewritten as v3 (0600), after which the network is authenticated.
    #[test]
    fn v2_keystore_is_migrated_to_v3_when_unlocked_for_spending() {
        let kp = generate_keypair(true);
        let v2 = kp.to_encrypted_json_version(PW, LEGACY_KEYSTORE_VERSION_V2).unwrap();
        let path = temp_keystore("migrate", &v2);

        // No network stated: refused, file untouched.
        let err = Keypair::load_for_spending(&path, PW, None).unwrap_err();
        assert!(err.contains("state the network"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), v2);
        // The wrong network: refused, file untouched.
        let err = Keypair::load_for_spending(&path, PW, Some(Network::Mainnet)).unwrap_err();
        assert!(err.contains("not a mainnet address"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), v2);
        // Wrong password: refused, file untouched.
        assert!(Keypair::load_for_spending(&path, "Wrong-password-123!", Some(Network::Testnet)).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), v2);

        // The right network: unlocked and migrated.
        let (loaded, what) = Keypair::load_for_spending(&path, PW, Some(Network::Testnet)).unwrap();
        let mut backup_name = path.file_name().unwrap().to_os_string();
        backup_name.push(".v2.bak");
        assert_eq!(what, KeystoreMigration::MigratedV2ToV3 { backup: path.with_file_name(backup_name) });
        assert_eq!(loaded.address, kp.address);
        assert_eq!(loaded.private_key, kp.private_key);
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(rewritten.contains("\"version\": 3"), "{rewritten}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // The rewritten file authenticates its network: the prefix edit that
        // a v2 file accepted now fails, and a second unlock is a no-op.
        let flipped = rewritten
            .replace(&kp.address, &format!("gnb1q{}", &kp.address[5..]))
            .replace("\"network\": \"testnet\"", "\"network\": \"mainnet\"");
        assert!(Keypair::from_encrypted_bytes(flipped.as_bytes(), PW).is_err());
        let (_, again) = Keypair::load_for_spending(&path, PW, Some(Network::Testnet)).unwrap();
        assert_eq!(again, KeystoreMigration::AlreadyV3);
        let (_, unstated) = Keypair::load_for_spending(&path, PW, None).unwrap();
        assert_eq!(unstated, KeystoreMigration::AlreadyV3, "v3 needs no stated network");
        assert!(Keypair::load_for_spending(&path, PW, Some(Network::Mainnet)).unwrap_err()
            .contains("testnet key (authenticated)"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The audit's attack on v2: the address prefix edited to the other
    /// network. With the owner's network stated the forged address is
    /// refused; stating the forged network is refused because the network
    /// field contradicts it. (If both fields were edited, the key is unlocked
    /// for exactly the network the caller stated, never silently for another.)
    #[test]
    fn v2_network_edits_are_caught_by_the_stated_network() {
        let kp = generate_keypair(false); // mainnet
        let v2 = kp.to_encrypted_json_version(PW, LEGACY_KEYSTORE_VERSION_V2).unwrap();
        let flipped_addr = format!("gnb1t{}", &kp.address[5..]);
        // Only the prefix edited: the stored address names testnet, the
        // network field still says mainnet.
        let edited = v2.replace(&kp.address, &flipped_addr);
        let path = temp_keystore("edit", &edited);
        // The owner states mainnet: the forged testnet address is refused.
        assert!(Keypair::load_for_spending(&path, PW, Some(Network::Mainnet)).unwrap_err()
            .contains("not a mainnet address"));
        // Stating testnet: the network field contradicts it.
        assert!(Keypair::load_for_spending(&path, PW, Some(Network::Testnet)).unwrap_err()
            .contains("records network"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edited, "nothing rewritten");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// CRY-7 (re-audit): EVERY open path authenticates the network, not
    /// only the spending unlock. A v2 file authenticates neither its
    /// `network` field nor its address prefix: with both edited to testnet
    /// (the checksum does not cover the prefix), `from_encrypted_bytes` /
    /// `load_encrypted` (the web wallet's `open`, `gnb-cli import-founder`
    /// and `keyinfo`) loaded a mainnet key as a testnet key. A v2 file now
    /// opens only for a stated network; v3 files authenticate their own.
    #[test]
    fn every_open_path_authenticates_the_network() {
        let kp = generate_keypair(false); // mainnet
        let v2 = kp.to_encrypted_json_version(PW, LEGACY_KEYSTORE_VERSION_V2).unwrap();
        let flipped = format!("gnb1t{}", &kp.address[5..]);
        let forged = v2.replace(&kp.address, &flipped).replace("\"network\": \"mainnet\"", "\"network\": \"testnet\"");
        assert!(forged.contains(&flipped) && forged.contains("\"testnet\""), "fixture");
        for bytes in [v2.as_bytes(), forged.as_bytes()] {
            let err = Keypair::from_encrypted_bytes(bytes, PW).unwrap_err();
            assert!(err.contains("state the network"), "{err}");
            let path = temp_keystore("open", std::str::from_utf8(bytes).unwrap());
            assert!(Keypair::load_encrypted(&path, PW).unwrap_err().contains("state the network"));
            let _ = std::fs::remove_dir_all(path.parent().unwrap());
        }
        // The owner's network opens the genuine file, never the forged one.
        let opened = Keypair::from_encrypted_bytes_on(v2.as_bytes(), PW, Network::Mainnet).unwrap();
        assert_eq!((opened.address.as_str(), opened.network().unwrap()), (kp.address.as_str(), Network::Mainnet));
        assert!(Keypair::from_encrypted_bytes_on(forged.as_bytes(), PW, Network::Mainnet).is_err());
        assert!(Keypair::from_encrypted_bytes_on(v2.as_bytes(), PW, Network::Testnet).is_err());
        let path = temp_keystore("open-on", &v2);
        assert_eq!(Keypair::load_encrypted_on(&path, PW, Network::Mainnet).unwrap().address, kp.address);
        assert!(Keypair::load_encrypted_on(&path, PW, Network::Testnet).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        // v3 authenticates its network: opens without a stated network, and
        // refuses another stated network.
        let v3 = kp.to_encrypted_json(PW).unwrap();
        assert_eq!(Keypair::from_encrypted_bytes(v3.as_bytes(), PW).unwrap().address, kp.address);
        assert!(Keypair::from_encrypted_bytes_on(v3.as_bytes(), PW, Network::Mainnet).is_ok());
        assert!(Keypair::from_encrypted_bytes_on(v3.as_bytes(), PW, Network::Testnet).is_err());
    }

    /// Bloch v2 keystores (bloch1q… addresses) migrate under their GnB
    /// address; a v2 password below today's policy is kept (not refused).
    #[test]
    fn bloch_v2_keystore_with_a_legacy_password_migrates() {
        let kp = generate_keypair(false);
        let weak = "short";
        assert!(kp.to_encrypted_json_version(weak, LEGACY_KEYSTORE_VERSION_V2).is_err(), "policy applies to new files");
        let v2 = kp.to_encrypted_json_with_policy(weak, LEGACY_KEYSTORE_VERSION_V2, false).unwrap();
        let body = kp.address.strip_prefix(crate::core::MAINNET_PREFIX).unwrap();
        let bloch = v2.replace(&kp.address, &format!("bloch1q{body}"));
        let (loaded, json) = Keypair::unlock_for_spending_bytes(bloch.as_bytes(), weak, Some(Network::Mainnet)).unwrap();
        assert_eq!(loaded.address, kp.address);
        let json = json.expect("v2 is migrated");
        let reopened = Keypair::from_encrypted_bytes(json.as_bytes(), weak).unwrap();
        assert_eq!(reopened.address, kp.address);
        assert!(json.contains(&kp.address) && json.contains("\"version\": 3"));
    }

    fn with_suffix(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
        let mut name = path.file_name().unwrap().to_os_string();
        name.push(suffix);
        path.with_file_name(name)
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Review follow-up (CRY-7): migrating a Bloch v2 keystore keeps the
    /// original — the only file Bloch wallets and pre-v3 GnB can open —
    /// byte for byte in a new `<file>.v2.bak` (0600), and a later migration
    /// never overwrites an existing backup.
    #[test]
    fn v2_migration_keeps_a_byte_identical_backup_and_never_overwrites_one() {
        let kp = generate_keypair(false);
        let v2 = kp.to_encrypted_json_version(PW, LEGACY_KEYSTORE_VERSION_V2).unwrap();
        let body = kp.address.strip_prefix(crate::core::MAINNET_PREFIX).unwrap();
        let bloch = v2.replace(&kp.address, &format!("bloch1q{body}"));
        let path = temp_keystore("backup", &bloch);

        let (_, what) = Keypair::load_for_spending(&path, PW, Some(Network::Mainnet)).unwrap();
        let first = with_suffix(&path, ".v2.bak");
        assert_eq!(what, KeystoreMigration::MigratedV2ToV3 { backup: first.clone() });
        assert_eq!(std::fs::read(&first).unwrap(), bloch.as_bytes(), "the backup is the original, byte for byte");
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"version\": 3"));
        #[cfg(unix)]
        assert_eq!(mode_of(&first), 0o600);
        // The backup still opens as the v2 keystore it was.
        let reopened = Keypair::from_encrypted_bytes_on(&std::fs::read(&first).unwrap(), PW, Network::Mainnet).unwrap();
        assert_eq!(reopened.address, kp.address);

        // The same v2 file migrated again (e.g. restored from the backup):
        // the first backup is kept and a new name is used.
        std::fs::write(&path, &bloch).unwrap();
        let (_, what) = Keypair::load_for_spending(&path, PW, Some(Network::Mainnet)).unwrap();
        let second = with_suffix(&path, ".v2.bak.1");
        assert_eq!(what, KeystoreMigration::MigratedV2ToV3 { backup: second.clone() });
        assert_eq!(std::fs::read(&first).unwrap(), bloch.as_bytes());
        assert_eq!(std::fs::read(&second).unwrap(), bloch.as_bytes());
        // An unrelated file squatting on the next name is not touched either.
        std::fs::write(with_suffix(&path, ".v2.bak.2"), b"not a keystore").unwrap();
        std::fs::write(&path, &bloch).unwrap();
        let (_, what) = Keypair::load_for_spending(&path, PW, Some(Network::Mainnet)).unwrap();
        assert_eq!(what, KeystoreMigration::MigratedV2ToV3 { backup: with_suffix(&path, ".v2.bak.3") });
        assert_eq!(std::fs::read(with_suffix(&path, ".v2.bak.2")).unwrap(), b"not a keystore");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Review follow-up (CRY-7): `unlock_for_spending` verifies the
    /// migration in memory and changes nothing until `commit`, so a send that
    /// is aborted (mistyped address, refused confirmation) leaves the v2 file
    /// as it was; a file changed in between is not overwritten.
    #[test]
    fn unlock_for_spending_rewrites_nothing_until_commit() {
        let kp = generate_keypair(true);
        let v2 = kp.to_encrypted_json_version(PW, LEGACY_KEYSTORE_VERSION_V2).unwrap();
        let path = temp_keystore("pending", &v2);
        let (loaded, pending) = Keypair::unlock_for_spending(&path, PW, Some(Network::Testnet)).unwrap();
        assert_eq!(loaded.private_key, kp.private_key);
        let pending = pending.expect("a v2 file has a pending migration");
        assert_eq!(pending.path(), path.as_path());
        drop(pending);                                  // the spend was aborted
        assert_eq!(std::fs::read_to_string(&path).unwrap(), v2, "nothing written");
        assert!(!with_suffix(&path, ".v2.bak").exists(), "no backup either");

        let (_, pending) = Keypair::unlock_for_spending(&path, PW, Some(Network::Testnet)).unwrap();
        let backup = pending.unwrap().commit().unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), v2);
        let (_, again) = Keypair::unlock_for_spending(&path, PW, None).unwrap();
        assert!(again.is_none(), "v3 now: nothing left to migrate");

        // Changed between unlock and commit: refused, left alone.
        std::fs::write(&path, &v2).unwrap();
        let (_, pending) = Keypair::unlock_for_spending(&path, PW, Some(Network::Testnet)).unwrap();
        std::fs::write(&path, format!("{v2} ")).unwrap();
        let err = pending.unwrap().commit().unwrap_err();
        assert!(err.contains("changed since it was unlocked"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{v2} "));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Review follow-up (CRY-7): if the backup cannot be written the
    /// migration stops and the v2 file is left untouched (here the backup's
    /// name would exceed the file-name length limit).
    #[test]
    fn migration_stops_when_the_backup_cannot_be_written() {
        let kp = generate_keypair(true);
        let v2 = kp.to_encrypted_json_version(PW, LEGACY_KEYSTORE_VERSION_V2).unwrap();
        let dir = temp_keystore("nobackup", "").parent().unwrap().to_path_buf();
        let path = dir.join("w".repeat(250));
        std::fs::write(&path, &v2).unwrap();
        let err = Keypair::load_for_spending(&path, PW, Some(Network::Testnet)).unwrap_err();
        assert!(err.contains("cannot write a backup") && err.contains("left unchanged"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), v2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WAL-1 regression: `Wallet::build_tx` refuses a fee equal to almost
    /// all inputs, and no longer spends every UTXO it is handed (WAL-6).
    #[test]
    fn build_tx_enforces_the_fee_guard_and_selects_inputs() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        let dest = Address::from_hash([9u8; 20], Network::Testnet);
        let spk = wallet.address().hash().to_vec();
        let utxos = vec![
            Utxo { txid: [1; 32], index: 0, output: TxOutput { value: 50 * SAT, script_pubkey: spk.clone() } },
            Utxo { txid: [2; 32], index: 0, output: TxOutput { value: 50 * SAT, script_pubkey: spk.clone() } },
        ];
        assert!(matches!(wallet.build_tx(utxos.clone(), &dest, 1, 100 * SAT - 1, 1),
            Err(WalletError::FeeTooHigh(_))));
        // An explicit override is honoured.
        assert!(wallet.build_tx_with_policy(utxos.clone(), &dest, 1, 100 * SAT - 1, &FeePolicy::UNLIMITED, 1).is_ok());
        // A normal payment spends one coin, not both.
        let tx = wallet.build_tx(utxos.clone(), &dest, SAT, 50_000, 1).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs[1].value, 50 * SAT - SAT - 50_000);

        // Signed payments report the actual fee.
        let paid = wallet.build_payment(&utxos, &dest, SAT, &PaymentOptions { next_block_height: Some(1), ..PaymentOptions::default() }).unwrap();
        assert_eq!(paid.tx.inputs.len(), 1);
        assert_eq!(paid.inputs_total - paid.amount - paid.change, paid.fee);
        assert!(paid.fee >= crate::core::tokenomics::min_tx_fee_sat(paid.size));
    }

    /// WAL-1 regression on the legacy builder: an explicit fee above the
    /// guard is refused.
    #[test]
    fn tx_builder_build_enforces_the_fee_guard() {
        let kp = generate_keypair(false);
        let rows = vec![(vec![0xAB; 32], 0u32, TxOutput { value: 100 * SAT, script_pubkey: kp.address_bytes() })];
        let err = TxBuilder::build(&kp, &rows, &"05".repeat(20), SAT, 99 * SAT, 1).unwrap_err();
        assert!(err.contains("guard"), "{err}");
    }

    /// CRY-8: message signatures are chain-bound (v2), and a chain-less v1
    /// signature (what Bloch signers still produce, with the same keys) is
    /// accepted by no default verifier and never by a canonical one: it used
    /// to verify as a GnB mainnet AND testnet proof. Only the explicit legacy
    /// mode accepts it.
    #[test]
    fn message_signatures_are_chain_bound_and_v1_needs_the_legacy_flag() {
        let kp = generate_keypair(false);
        let pk = &kp.public_key;
        let sig = kp.sign_message(b"hello").unwrap();
        assert!(Keypair::verify_message_on(Network::Mainnet, pk, b"hello", &sig));
        assert!(!Keypair::verify_message_on(Network::Testnet, pk, b"hello", &sig));
        assert!(Keypair::verify_message_canonical_on(Network::Mainnet, pk, b"hello", &sig));
        assert!(Keypair::verify_message(pk, b"hello", &sig));
        assert!(!crypto::verify(pk, &crypto::signed_message_digest(b"hello"), &sig));

        // A Bloch / v1 signature over the same message with the same key.
        let v1 = kp.sign_message_v1(b"hello").unwrap();
        assert!(crypto::verify(pk, &crypto::signed_message_digest(b"hello"), &v1), "fixture: a genuine v1 signature");
        for n in [Network::Mainnet, Network::Testnet] {
            assert!(!Keypair::verify_message_on(n, pk, b"hello", &v1), "v1 accepted as a {n:?} proof");
            assert!(!Keypair::verify_message_canonical_on(n, pk, b"hello", &v1));
        }
        assert!(!Keypair::verify_message(pk, b"hello", &v1));
        assert!(!Keypair::verify_message_canonical(pk, b"hello", &v1));
        // Explicit legacy mode only.
        assert!(Keypair::verify_message_allowing_legacy_v1(Some(Network::Mainnet), pk, b"hello", &v1));
        assert!(Keypair::verify_message_allowing_legacy_v1(None, pk, b"hello", &v1));
        assert!(Keypair::verify_message_allowing_legacy_v1(Some(Network::Mainnet), pk, b"hello", &sig));
        assert!(!Keypair::verify_message_allowing_legacy_v1(Some(Network::Testnet), pk, b"hello", &sig),
            "the legacy mode still binds a v2 signature to its chain");
        assert!(!Keypair::verify_message_allowing_legacy_v1(None, pk, b"other", &v1));
    }

    /// CRY-5 through the wallet: a corrupted Falcon secret never signs.
    #[test]
    fn keypair_sign_fails_on_corrupted_falcon_secret() {
        let mut kp = generate_keypair(false);
        kp.private_key[crypto::SUITE_HEADER_LEN + crypto::MLDSA_SECRET_LEN] ^= 0xFF;
        assert!(kp.sign(b"m").is_err());
        let rows = vec![(vec![1; 32], 0u32, TxOutput { value: SAT, script_pubkey: kp.address_bytes() })];
        assert!(TxBuilder::build(&kp, &rows, &"05".repeat(20), SAT / 2, 50_000, 1).is_err());
    }

    /// WAL-7: mnemonic-backed keypairs restore from their words.
    #[test]
    fn mnemonic_keypair_restores_from_its_words() {
        let (kp, phrase) = generate_mnemonic_keypair(Network::Mainnet).unwrap();
        let words = Zeroizing::new(phrase.words().join(" "));
        assert_eq!(words.split_whitespace().count(), 24);
        let restored = keypair_from_mnemonic(&words, Network::Mainnet).unwrap();
        assert_eq!(restored.address, kp.address);
        assert_eq!(restored.public_key, kp.public_key);
        assert!(keypair_from_mnemonic("not a mnemonic", Network::Mainnet).is_err());
    }

    /// CRY-4: the bip39 mnemonic type now wipes itself on drop.
    #[test]
    fn bip39_mnemonic_has_a_wiping_destructor() {
        assert!(std::mem::needs_drop::<bip39::Mnemonic>());
    }
}

#[cfg(test)]
mod sighash_v3_signers {
    //! WAL-1 full fix / CRY-1 / CRY-2 on the detached signers: `Wallet`
    //! and `Keypair` produce sighash-v3 transactions that pass the shared
    //! consensus input-script rule (`core::sighash::verify_tx_scripts`).
    use super::*;
    use crate::core::sighash::{self, SighashVersion};
    use crate::core::{activation, ChainId};

    const SAT: u64 = 100_000_000;

    #[test]
    fn wallet_signs_v3_with_prevouts_and_refuses_v3_without() {
        let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
        let spk = wallet.address().hash().to_vec();
        let utxos = vec![
            Utxo { txid: [1; 32], index: 0, output: TxOutput { value: 2 * SAT, script_pubkey: spk.clone() } },
            Utxo { txid: [2; 32], index: 3, output: TxOutput { value: 3 * SAT, script_pubkey: spk.clone() } },
        ];
        let dest = Address::from_hash([9u8; 20], Network::Testnet);
        // Testnet activates at 0: version 3.
        let tx = wallet.build_tx(utxos.clone(), &dest, 4 * SAT, 100_000, 7).unwrap();
        assert_eq!(tx.version, 3);
        assert!(matches!(wallet.sign_tx(tx.clone()), Err(WalletError::Payment(m)) if m.contains("sign_tx_with_prevouts")));
        let spent: Vec<TxOutput> = tx.inputs.iter()
            .map(|i| utxos.iter().find(|u| u.txid == i.prev_txid).unwrap().output.clone())
            .collect();
        let signed = wallet.sign_tx_with_prevouts(tx, &spent).unwrap();
        assert_eq!(sighash::verify_tx_scripts(&signed, &spent, ChainId::Testnet, 7, 0), Ok(SighashVersion::V3));
        for input in &signed.inputs {
            assert!(sighash::canonical_witness(&input.script_sig).is_ok());
        }
        // Mainnet below its activation: version 1, the historical signer.
        let (main, _) = Wallet::generate(Network::Mainnet).unwrap();
        let mspk = main.address().hash().to_vec();
        let mutxo = vec![Utxo { txid: [5; 32], index: 0, output: TxOutput { value: 2 * SAT, script_pubkey: mspk } }];
        let tx = main.build_tx(mutxo.clone(), &Address::from_hash([9u8; 20], Network::Mainnet), SAT, 100_000, 7).unwrap();
        assert_eq!(tx.version, 1);
        let signed = main.sign_tx(tx).unwrap();
        assert_eq!(sighash::verify_tx_scripts(&signed, &[mutxo[0].output.clone()], ChainId::Mainnet, 7,
            activation::MAINNET_HARDENING_ACTIVATION_HEIGHT), Ok(SighashVersion::V2));
    }

    /// A genesis carry-over key (raw, pre-envelope public AND secret key; the
    /// address commits to the raw key) still spends under sighash v3: the
    /// public key is not forced into an envelope, the signature is enveloped.
    #[test]
    fn raw_carryover_key_spends_under_v3() {
        use sha3::{Digest, Sha3_256};
        let (pk_env, sk_env) = crypto::generate_keypair();
        let raw_pk = pk_env[4..].to_vec();
        let kp = Keypair {
            private_key: sk_env[4..].to_vec().into(),
            public_key: raw_pk.clone(),
            address: crypto::address_from_pubkey(&raw_pk, true),
        };
        let spk = Sha3_256::digest(&raw_pk)[..20].to_vec();
        assert_eq!(spk, kp.address_bytes());
        let utxo = Utxo { txid: [0xCA; 32], index: 0, output: TxOutput { value: 5 * SAT, script_pubkey: spk } };
        let opts = PaymentOptions { next_block_height: Some(1), ..PaymentOptions::default() };
        let paid = TxBuilder::build_payment(&kp, std::slice::from_ref(&utxo),
            &Address::from_hash([3; 20], Network::Testnet), SAT, &opts).unwrap();
        assert_eq!(paid.tx.version, 3);
        let (sig, pk) = Transaction::parse_script_sig_exact(&paid.tx.inputs[0].script_sig).unwrap();
        assert_eq!(pk, &raw_pk[..], "the raw key goes into the witness unchanged");
        assert!(crypto::split_envelope(sig).is_some(), "the signature carries its suite envelope");
        assert_eq!(sighash::verify_tx_scripts(&paid.tx, &[utxo.output], ChainId::Testnet, 1, 0),
            Ok(SighashVersion::V3));
    }
}
