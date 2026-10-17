//! bloch-wallet — Bloch-SIS Protocol CLI Wallet
//! Colors: amber accent · green success · red error · muted gray

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

// ── ANSI colors ───────────────────────────────────────────────────────────────
const AMBER:   &str = "\x1b[38;5;214m";   // #EF9F27 equivalent
const GREEN:   &str = "\x1b[38;5;71m";    // #639922 equivalent
const RED:     &str = "\x1b[38;5;167m";   // #E24B4A equivalent
const MUTED:   &str = "\x1b[38;5;245m";   // gray secondary
const BOLD:    &str = "\x1b[1m";
const DIM:     &str = "\x1b[2m";
const RESET:   &str = "\x1b[0m";

// The `disclose` command documents index zero as the base single-key wallet
// address. Keep that product policy explicit instead of inheriting a public
// compatibility wrapper's default convention.
const CLI_DISCLOSURE_KEY_CONVENTION:
    crate::wallet::disclosure::DisclosureKeyConvention =
    crate::wallet::disclosure::DisclosureKeyConvention::SingleKeyWallet;

// Verified bundles have bounded entry counts and bounded text/key/signature
// fields; 64 MiB leaves ample headroom over the ordinary serialization of
// those bounded typed fields. Keep the CLI file read itself bounded too,
// before JSON allocates its fields.
const CLI_DISCLOSURE_FILE_LIMIT: usize = crate::util::DEFAULT_WALLET_FILE_LIMIT;

fn amber(s: &str)  -> String { format!("{}{}{}", AMBER, s, RESET) }
fn green(s: &str)  -> String { format!("{}{}{}", GREEN, s, RESET) }
fn red(s: &str)    -> String { format!("{}{}{}", RED, s, RESET) }
fn muted(s: &str)  -> String { format!("{}{}{}", MUTED, s, RESET) }
fn bold(s: &str)   -> String { format!("{}{}{}", BOLD, s, RESET) }
fn dim(s: &str)    -> String { format!("{}{}{}", DIM, s, RESET) }

fn banner() {
    println!();
    println!("  {}◆{}  {} B L O C H {}  {}◆{}",
        AMBER, RESET, BOLD, RESET, AMBER, RESET);
    println!("  {}Hybrid signatures: ML-DSA-65 + Falcon-1024 · SHA3-256{}",
        MUTED, RESET);
    println!("  {}Keystore encryption: AES-256-GCM · Argon2id{}", MUTED, RESET);
    println!();
}

fn ok(msg: &str) {
    println!("  {} {}", green("✓"), msg);
}

fn err(msg: &str) -> ! {
    println!("  {} {}", red("✗"), msg);
    std::process::exit(1);
}

fn label(k: &str, v: &str) {
    println!("  {:<14} {}", muted(k), v);
}

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "gnb-wallet")]
#[command(about = "ObenBlock wallet — hybrid ML-DSA-65 + Falcon-1024 signatures")]
#[command(version)]
#[command(disable_help_flag = false)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// New wallets are testnet; for `send` and `sign`, the network the
    /// keystore must belong to (a v2 keystore needs it stated, CRY-7).
    #[arg(long, global = true, conflicts_with = "mainnet")]
    testnet: bool,
    /// For `send` and `sign`: the keystore must be a mainnet key (required
    /// to unlock, and migrate to v3, a v2 keystore; CRY-7).
    #[arg(long, global = true)]
    mainnet: bool,
    /// Node RPC endpoint: http://host:port, or https://host[:port] (TLS,
    /// certificate verified; GNB_RPC_CA=<PEM/DER file> for a private CA).
    #[arg(long, global = true, default_value = "http://127.0.0.1:17210")]
    rpc: String,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new keypair and encrypted keystore. By default the key is
    /// derived from a new 24-word recovery phrase, shown once (WAL-7).
    New {
        #[arg(long, default_value = "./gnb-wallet.json")]
        output: PathBuf,
        /// Generate a random key with no recovery phrase: the encrypted
        /// keystore file is then the ONLY backup.
        #[arg(long)]
        random_key: bool,
    },
    /// Restore a phrase-backed key into a new encrypted keystore
    Restore {
        #[arg(long, default_value = "./gnb-wallet.json")]
        output: PathBuf,
    },
    /// Show address of a keystore
    Address { keystore: PathBuf },
    /// Show public key (hex)
    Pubkey { keystore: PathBuf },
    /// Check balance via RPC
    Balance { address: String },
    /// Build, sign, and broadcast a transaction (asks for confirmation)
    Send {
        keystore: PathBuf,
        to:       String,
        amount:   String,
        /// Fee in GNB, or `auto`: the consensus minimum for the signed
        /// transaction's actual size (max(0.0001 GNB, 0.00002 GNB/kB)). A
        /// lower value is raised to that minimum.
        #[arg(long, default_value = "auto")]
        fee:      String,
        /// Explicit maximum fee in GNB, replacing the default guard
        /// (0.02 GNB and 0.001 GNB/kB).
        #[arg(long)]
        max_fee:  Option<String>,
        /// Broadcast without asking for confirmation.
        #[arg(long)]
        yes:      bool,
        /// With --yes: allow inputs whose value the node could not prove
        /// (carryover or pruned history).
        #[arg(long)]
        allow_unverified_inputs: bool,
    },
    /// Sign a message (domain-separated digest — see `verify-message`)
    Sign { keystore: PathBuf, message: String },
    /// Verify a signature produced by `sign` against a public key
    VerifyMessage {
        /// Signer's public key, hex-encoded (see the `pubkey` command).
        pubkey: String,
        /// The exact message text that was signed.
        message: String,
        /// The signature, hex-encoded.
        signature: String,
        /// Require suite envelopes and canonical signature encoding.
        #[arg(long)]
        canonical: bool,
        /// CRY-8: ALSO accept a chain-less v1 signature (Bloch, or GnB before
        /// v2). A v1 signature binds no network: it is valid for Bloch, GnB
        /// mainnet and GnB testnet alike. Never combined with --canonical.
        #[arg(long, conflicts_with = "canonical")]
        legacy_v1: bool,
    },
    /// P4.3 — Create a signed selective-disclosure bundle (view/audit key).
    /// Prompts for the BIP39 seed phrase; discloses ONLY the given receive
    /// indices (0 = base address). The bundle contains public data + signatures
    /// only — never the seed or any secret key.
    Disclose {
        /// Comma-separated receive indices, e.g. "0,2,5"
        indices: String,
        /// What this disclosure is for (bound into the signatures)
        #[arg(long)]
        purpose: String,
        /// Who this disclosure is addressed to (bound in; verifiers must check it)
        #[arg(long)]
        audience: String,
        #[arg(long, default_value = "./bloch-disclosure.json")]
        output: PathBuf,
    },
    /// Verify a disclosure bundle OFFLINE (no node needed)
    VerifyBundle {
        bundle: PathBuf,
        /// Require suite envelopes and canonical Falcon encoding.
        #[arg(long)]
        canonical: bool,
    },
    /// Watch-only audit: verify a bundle, then sum balances over its addresses
    Watch {
        bundle: PathBuf,
        /// Require suite envelopes and canonical Falcon encoding.
        #[arg(long)]
        canonical: bool,
    },
}

pub fn main() {
    let cli = Cli::parse();
    banner();

    match cli.cmd {

        Cmd::New { output, random_key } => {
            println!("  {}Generating hybrid ML-DSA-65 + Falcon-1024 keypair...{}", MUTED, RESET);
            println!("  {}(post-quantum key generation may take a moment){}",
                DIM, RESET);
            println!();

            let network = cli_network(cli.testnet);
            let kp = if random_key {
                crate::wallet::generate_keypair(cli.testnet)
            } else {
                // WAL-7: phrase-backed by default; the words are a complete
                // backup of the key (shown once, wiped on drop).
                let (kp, phrase) = crate::wallet::generate_mnemonic_keypair(network)
                    .unwrap_or_else(|e| err(&format!("Key generation failed: {e}")));
                show_recovery_phrase(&phrase);
                kp
            };

            println!("  {} {}", amber("address"), bold(&kp.address));
            println!();
            label("pubkey size",  &format!("{} bytes", kp.public_key.len()));
            label("privkey size", &format!("{} bytes (never share!)", kp.private_key.len()));
            label("algorithm",    "ML-DSA-65 + Falcon-1024 (hybrid)");
            label("network",      if cli.testnet { "testnet" } else { "mainnet" });
            println!();

            let pw = prompt_new_password();
            println!();
            let saved = kp.save_encrypted(&output, &pw);
            drop(pw);
            match saved {
                Ok(()) => {
                    ok(&format!("Keystore saved: {}", amber(&output.display().to_string())));
                    println!();
                    println!("  {}Keep your password safe — it cannot be recovered.{}",
                        MUTED, RESET);
                }
                Err(e) => err(&format!("Save failed: {}", e)),
            }
        }

        Cmd::Restore { output } => {
            let network = cli_network(cli.testnet);
            let phrase = prompt_password(&format!("  {}recovery phrase (24 words):{} ", MUTED, RESET));
            let kp = crate::wallet::keypair_from_mnemonic(&phrase, network)
                .unwrap_or_else(|e| err(&format!("Restore failed: {e}")));
            drop(phrase);
            println!("  {} {}", amber("address"), bold(&kp.address));
            label("network", if cli.testnet { "testnet" } else { "mainnet" });
            println!();
            let pw = prompt_new_password();
            let saved = kp.save_encrypted(&output, &pw);
            drop(pw);
            match saved {
                Ok(()) => ok(&format!("Keystore saved: {}", amber(&output.display().to_string()))),
                Err(e) => err(&format!("Save failed: {}", e)),
            }
        }

        Cmd::Address { keystore } => {
            let kp = load_kp(&keystore, stated_network(cli.testnet, cli.mainnet));
            println!("  {}", amber(&kp.address));
        }

        Cmd::Pubkey { keystore } => {
            let kp = load_kp(&keystore, stated_network(cli.testnet, cli.mainnet));
            let hex = hex::encode(&kp.public_key);
            // Public-key export must include every byte for native script hashing.
            println!("{hex}");
        }

        Cmd::Balance { address } => {
            print!("  {}querying node...{}\r", MUTED, RESET);
            let resp = rpc_call(&cli.rpc, "getbalance",
                serde_json::json!([address]));

            match resp.get("error") {
                Some(e) => err(&format!("RPC error: {}", e)),
                None => {
                    // R3: satoshi amounts are decimal strings on the V4 wire,
                    // numbers on the G3 wire — `sat_u64` reads both.
                    let sats = crate::wallet::sat_u64(&resp["satoshis"]).unwrap_or(0);
                    let bloch = sats as f64 / 1e8;
                    let utxos = resp["utxo_count"].as_u64().unwrap_or(0);

                    println!();
                    println!("  {} {}", amber("balance"),
                        bold(&format!("{:.8} GNB", bloch)));
                    println!();
                    label("satoshis",   &format!("{}", sats));
                    label("utxos",      &format!("{}", utxos));
                    label("address",    &dim(&address));
                }
            }
        }

        Cmd::Send { keystore, to, amount, fee, max_fee, yes, allow_unverified_inputs } => {
            let (kp, pending_migration) = load_kp_for_spending(&keystore, stated_network(cli.testnet, cli.mainnet));
            let amount_sats = checked_cli_satoshis(&amount, false).unwrap_or_else(|message| err(message));
            let fee_choice  = crate::wallet::send::parse_fee_arg(&fee).unwrap_or_else(|message| err(message));
            let fee_policy  = crate::wallet::send::parse_max_fee_arg(max_fee.as_deref())
                .unwrap_or_else(|message| err(message));
            checked_destination(&to, &kp.address).unwrap_or_else(|message| err(&message));
            let to_addr = crate::address::Address::parse(&to).unwrap_or_else(|_| err("invalid destination address"));

            // 1-4: fetch UTXOs, select, verify claimed values against their
            // transactions (WAL-1), build and sign under the fee guard.
            print!("  {}fetching UTXOs and previous transactions...{}\r", MUTED, RESET);
            let endpoint = cli.rpc.clone();
            let rpc = move |method: &str, params: &serde_json::Value| rpc_result(&endpoint, method, params.clone());
            let request = crate::wallet::send::SendRequest {
                keypair: &kp,
                to: &to_addr,
                amount: amount_sats,
                fee: fee_choice,
                fee_policy,
                // Non-interactive sends refuse unprovable inputs unless asked.
                require_verified_inputs: yes && !allow_unverified_inputs,
                utxo_limit: 200,
            };
            let prepared = crate::wallet::send::prepare_send(&rpc, &request)
                .unwrap_or_else(|e| err(&format!("Build failed: {e}")));

            // 5. Show what will be signed — the ACTUAL fee — and confirm (WAL-7).
            println!("  {}transaction preview{}", BOLD, RESET);
            println!();
            for (k, v) in prepared.summary(&kp.address, &to) {
                if k == "warning" { label(&k, &red(&v)) } else { label(&k, &v) }
            }
            println!();
            if !yes && !crate::wallet::send::confirm("  Broadcast this transaction?") {
                err("Not broadcast.");
            }
            // CRY-7: the spend passed every check and was confirmed.
            finish_keystore_migration(pending_migration);

            print!("  {}broadcasting via sendrawtransaction...{}\r", MUTED, RESET);
            match crate::wallet::send::broadcast(&rpc, &prepared) {
                Ok(txid) => {
                    ok("Broadcast accepted by node");
                    println!();
                    println!("  {} {}", amber("txid"), bold(&txid));
                }
                Err(e) => err(&format!("Broadcast failed: {e}")),
            }
        }

        Cmd::Disclose { indices, purpose, audience, output } => {
            let idx: Vec<u32> = match indices.split(',')
                .map(|s| s.trim().parse::<u32>())
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(v) if !v.is_empty() => v,
                _ => { err("indices must be a comma-separated list of numbers, e.g. 0,2,5") }
            };

            println!("  {}Selective disclosure — reveals ONLY the listed indices.{}", MUTED, RESET);
            println!("  {}The bundle proves control of those addresses; it cannot and{}", DIM, RESET);
            println!("  {}does not prove they are ALL of your addresses (by design).{}", DIM, RESET);
            println!();

            let phrase = prompt_password(&format!("  {}seed phrase:{} ", MUTED, RESET));
            let parsed_seed = crate::wallet::SeedPhrase::parse(&phrase);
            drop(phrase);
            let seed = match parsed_seed {
                Ok(s) => s,
                Err(e) => { err(&format!("Invalid seed phrase: {}", e)) }
            };
            let network = if cli.testnet { crate::address::Network::Testnet }
                          else { crate::address::Network::Mainnet };

            print!("  {}deriving {} keypair(s) + signing (slow: hybrid PQ keygen)...{}\r",
                MUTED, idx.len(), RESET);
            // Disclosure key generation can be slow and derive many children;
            // the master seed stays in secret memory for that lifetime (CRY-4).
            let seed_bytes = seed.to_seed_bytes();
            let bundle = match crate::wallet::DisclosureBundle::create_with_convention(
                &seed_bytes[..], &idx, network, &purpose, &audience,
                CLI_DISCLOSURE_KEY_CONVENTION)
            {
                Ok(b) => b,
                Err(e) => { err(&format!("Disclosure failed: {}", e)) }
            };
            if let Err(e) = bundle.verify_canonical() {
                err(&format!("Disclosure canonical self-check failed: {}", e));
            }

            let json = serde_json::to_string_pretty(&bundle).unwrap();
            match crate::util::atomic_write(&output, json.as_bytes()) {
                Ok(()) => {
                    ok(&format!("Disclosure bundle saved: {}", amber(&output.display().to_string())));
                    println!();
                    for e in &bundle.entries {
                        label(&format!("index {}", e.index), &e.address);
                    }
                    println!();
                    println!("  {}Share this file with '{}' only — anyone holding it can see{}",
                        MUTED, audience, RESET);
                    println!("  {}these addresses' full on-chain history, forever.{}", MUTED, RESET);
                }
                Err(e) => err(&format!("Save failed: {}", e)),
            }
        }

        Cmd::VerifyBundle { bundle, canonical } => {
            let verified = load_and_verify_bundle(&bundle, canonical);
            ok("bundle signatures + address bindings verified");
            println!();
            label("network",  &format!("{:?}", verified.network));
            label("purpose",  &verified.purpose);
            label("audience", &verified.audience);
            label("created",  &verified.created_at);
            println!();
            for (index, addr) in &verified.addresses {
                label(&format!("index {}", index), &addr.to_string());
            }
            println!();
            println!("  {}Proven: the discloser controls these addresses.{}", MUTED, RESET);
            println!("  {}NOT proven: that these are all of their addresses (selective).{}", DIM, RESET);
            println!("  {}Check the audience field names YOU before trusting the bundle.{}", DIM, RESET);
        }

        Cmd::Watch { bundle, canonical } => {
            let verified = load_and_verify_bundle(&bundle, canonical);
            ok(&format!("bundle verified — {} address(es)", verified.addresses.len()));
            println!();

            let mut total: u64 = 0;
            for (index, addr) in &verified.addresses {
                let addr_str = addr.to_string();
                let resp = rpc_call(&cli.rpc, "getbalance", serde_json::json!([addr_str]));
                match resp.get("error") {
                    Some(e) if !e.is_null() =>
                        label(&format!("index {}", index), &red(&format!("RPC error: {}", e))),
                    _ => {
                        let sats = crate::wallet::sat_u64(&resp["satoshis"]).unwrap_or(0);
                        total = total.saturating_add(sats);
                        label(&format!("index {}", index),
                            &format!("{:.8} GNB  {}{}{}", sats as f64 / 1e8, DIM, addr_str, RESET));
                    }
                }
            }
            println!();
            println!("  {} {}", amber("disclosed total"),
                bold(&format!("{:.8} GNB", total as f64 / 1e8)));
            println!("  {}(total over the DISCLOSED subset only — not a whole-wallet total){}",
                MUTED, RESET);
        }

        Cmd::Sign { keystore, message } => {
            let (kp, pending_migration) = load_kp_for_spending(&keystore, stated_network(cli.testnet, cli.mainnet));
            // A4-M-4 FIX: sign a DOMAIN-SEPARATED digest of the message's raw
            // bytes — NEVER hex-decode user-supplied text first. The old
            // code's `hex::decode(&message).unwrap_or_else(|_| message.into_bytes())`
            // meant a 64-hex-character "message" signed the raw 32 decoded
            // bytes directly: indistinguishable at the signature layer from a
            // tx sighash / disclosure digest / PoS signing root. A "prove you
            // own this address by signing this challenge" phishing prompt
            // could then harvest a valid transaction signature.
            print!("  {}signing message ({} bytes)...{}\r", MUTED, message.len(), RESET);
            match kp.sign_message(message.as_bytes()) {
                Ok(sig) => {
                    ok(&format!("Signature ({} bytes)", sig.len()));
                    println!();
                    let h = hex::encode(&sig);
                    println!("  {}", muted(&h[..64]));
                    println!("  {}...{}", DIM, RESET);
                    finish_keystore_migration(pending_migration);
                }
                Err(e) => err(&format!("Sign failed: {}", e)),
            }
        }

        Cmd::VerifyMessage { pubkey, message, signature, canonical, legacy_v1 } => {
            let pk = match hex::decode(&pubkey) {
                Ok(b) => b,
                Err(e) => { err(&format!("Invalid pubkey hex: {}", e)) }
            };
            let sig = match hex::decode(&signature) {
                Ok(b) => b,
                Err(e) => { err(&format!("Invalid signature hex: {}", e)) }
            };
            // Same domain-separated digest `sign` uses — never hex-decode
            // `message` either; verification must mirror signing exactly.
            // CRY-8: a v2 signature must name this network's chain id; a
            // chain-less v1 signature only with --legacy-v1.
            let network = cli_network(cli.testnet);
            if legacy_v1 && crate::wallet::Keypair::verify_message_allowing_legacy_v1(
                Some(network), &pk, message.as_bytes(), &sig)
            {
                ok("signature verifies for this message and public key (legacy v1 accepted: \
                    a v1 signature does not say which network it was made for)");
            } else if verify_message_on_network(network, &pk, message.as_bytes(), &sig, canonical) {
                ok("signature verifies for this message and public key");
            } else {
                err("signature does NOT verify for this message and public key");
            }
        }
    }

    println!();
}

// ── Helpers ────────────────────────────────────────────────────────────────────

fn verify_bundle_with_policy(
    bundle: &crate::wallet::DisclosureBundle,
    canonical: bool,
) -> Result<crate::wallet::VerifiedDisclosure, crate::wallet::DisclosureError> {
    if canonical {
        bundle.verify_canonical()
    } else {
        bundle.verify()
    }
}

/// The two encoding policies the message verifiers apply, on one digest:
/// compatible (enveloped, raw hybrid, generic) or canonical (envelopes and
/// canonical encoding only). Which digests are acceptable (v2 of a chain;
/// v1 only in the explicit legacy mode, CRY-8) is the verifiers' concern.
#[cfg(test)]
fn verify_digest_with_policy(
    public_key: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
    canonical: bool,
) -> bool {
    if canonical {
        crate::crypto::verify_enveloped_canonical(public_key, digest, signature)
    } else {
        crate::wallet::Keypair::verify_digest_compat(public_key, digest, signature)
    }
}

fn verify_message_on_network(
    network: crate::address::Network,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    canonical: bool,
) -> bool {
    if canonical {
        crate::wallet::Keypair::verify_message_canonical_on(network, public_key, message, signature)
    } else {
        crate::wallet::Keypair::verify_message_on(network, public_key, message, signature)
    }
}

fn cli_network(testnet: bool) -> crate::address::Network {
    if testnet { crate::address::Network::Testnet } else { crate::address::Network::Mainnet }
}

/// Show a new recovery phrase once, numbered, and require an explicit
/// acknowledgement before the key is used.
fn show_recovery_phrase(phrase: &crate::wallet::SeedPhrase) {
    println!("  {}RECOVERY PHRASE — write these 24 words down, offline:{}", BOLD, RESET);
    println!();
    // CRY-4: one wiping buffer, written straight to the terminal.
    if let Err(e) = crate::wallet::print_phrase_grid(&phrase.words(), "  ") {
        err(&format!("cannot print the recovery phrase: {e}"));
    }
    println!();
    println!("  {}Anyone with these words controls the funds. They are not stored.{}", MUTED, RESET);
    if !crate::wallet::send::confirm("  I have written the 24 words down") {
        err("Aborted: no keystore was written.");
    }
    println!();
}

fn load_and_verify_bundle(
    path: &PathBuf,
    canonical: bool,
) -> crate::wallet::VerifiedDisclosure {
    let bundle = match read_disclosure_bundle_with_limit(path, CLI_DISCLOSURE_FILE_LIMIT) {
        Ok(b) => b,
        Err(e) => { err(&e) }
    };
    match verify_bundle_with_policy(&bundle, canonical) {
        Ok(v) => v,
        Err(e) => { err(&format!("Bundle verification FAILED: {}", e)) }
    }
}

fn read_disclosure_bundle_with_limit(
    path: &Path,
    max_bytes: usize,
) -> Result<crate::wallet::DisclosureBundle, String> {
    let bytes = crate::util::read_wallet_file(path, max_bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            format!("Disclosure bundle exceeds {}-byte input limit", max_bytes)
        } else {
            format!("Cannot read bundle: {}", error)
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|error| format!("Bundle parse failed: {}", error))
}

/// The network the caller stated with `--mainnet` / `--testnet` (CRY-7).
fn stated_network(testnet: bool, mainnet: bool) -> Option<crate::address::Network> {
    match (testnet, mainnet) {
        (true, _) => Some(crate::address::Network::Testnet),
        (false, true) => Some(crate::address::Network::Mainnet),
        (false, false) => None,
    }
}

/// Unlock a keystore for spending or signing (CRY-7): a v2 keystore needs
/// the network stated. Its rewrite as v3 is returned pending: the caller
/// commits it with [`finish_keystore_migration`] only once the spend or
/// signature went ahead, so an aborted command leaves the v2 file untouched.
fn load_kp_for_spending(path: &std::path::Path, network: Option<crate::address::Network>)
    -> (crate::wallet::Keypair, Option<crate::wallet::PendingKeystoreMigration>)
{
    let pw = prompt_password(&format!("  {}password:{} ", MUTED, RESET));
    let loaded = crate::wallet::Keypair::unlock_for_spending(path, &pw, network);
    drop(pw);
    match loaded {
        Ok((kp, pending)) => {
            ok("keystore decrypted");
            if pending.is_some() {
                println!("  {}keystore v2: it is rewritten as v3 (network and address authenticated) once{}", MUTED, RESET);
                println!("  {}this command completes; the original is kept as <file>.v2.bak for Bloch{}", MUTED, RESET);
                println!("  {}wallets and GnB releases before v3, which read only version 2.{}", MUTED, RESET);
            }
            println!();
            (kp, pending)
        }
        Err(e) => err(&format!("Load failed: {e} (pass --mainnet or --testnet for a v2 keystore)")),
    }
}

/// Commit a pending v2 -> v3 keystore migration (CRY-7) and report where the
/// original went. A failure is reported but does not undo the command: the
/// v2 file is then simply left as it was.
fn finish_keystore_migration(pending: Option<crate::wallet::PendingKeystoreMigration>) {
    let Some(pending) = pending else { return };
    match pending.commit() {
        Ok(backup) => {
            ok("keystore v2 rewritten as v3: its network and address are now authenticated");
            label("v2 original", &backup.display().to_string());
            println!("  {}keep it if you use this key with Bloch or an older GnB release{}", MUTED, RESET);
        }
        Err(e) => println!("  {} keystore not migrated: {e}", red("!")),
    }
}

/// Open a keystore without spending (CRY-7): a v3 file authenticates its
/// network (and must be the stated one, if any); a v2 file opens only for
/// the network stated with --mainnet / --testnet.
fn load_kp(path: &PathBuf, network: Option<crate::address::Network>) -> crate::wallet::Keypair {
    let pw = prompt_password(&format!("  {}password:{} ", MUTED, RESET));
    let loaded = match network {
        Some(n) => crate::wallet::Keypair::load_encrypted_on(path, &pw, n),
        None => crate::wallet::Keypair::load_encrypted(path, &pw),
    };
    drop(pw);
    match loaded {
        Ok(kp) => { ok("keystore decrypted"); println!(); kp }
        Err(e) => { err(&format!("Load failed: {e} (pass --mainnet or --testnet for a v2 keystore)")) }
    }
}

fn own_prompt_secret(secret: String) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(secret)
}

fn prompt_password(prompt: &str) -> zeroize::Zeroizing<String> {
    own_prompt_secret(rpassword::prompt_password(prompt).unwrap_or_default())
}

fn confirmed_prompt_secret(
    password: zeroize::Zeroizing<String>,
    confirmation: zeroize::Zeroizing<String>,
) -> Option<zeroize::Zeroizing<String>> {
    if password.as_str() == confirmation.as_str() {
        Some(password)
    } else {
        None
    }
}

fn prompt_new_password() -> zeroize::Zeroizing<String> {
    loop {
        let pw = own_prompt_secret(rpassword::prompt_password(
            &format!("  {}new password:{} ", MUTED, RESET)
        ).unwrap_or_default());
        if let Err(e) = crate::wallet::validate_password(&pw) {
            println!("  {} {}", red("✗"), muted(&format!("weak password: {}", e)));
            continue;
        }
        // `save_encrypted` also enforces `encryption::validate_password_strength`
        // (length + breach denylist) — check it here too so a rejected
        // password re-prompts instead of failing the whole `New` command.
        if let Err(e) = crate::wallet::encryption::validate_password_strength(&pw) {
            println!("  {} {}", red("✗"), muted(&format!("weak password: {}", e)));
            continue;
        }
        let pw2 = own_prompt_secret(rpassword::prompt_password(
            &format!("  {}confirm:     {} ", MUTED, RESET)
        ).unwrap_or_default());
        if let Some(confirmed) = confirmed_prompt_secret(pw, pw2) {
            return confirmed;
        }
        println!("  {} {}", red("✗"), muted("passwords do not match"));
    }
}

fn rpc_call(endpoint: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    rpc_result(endpoint, method, params).unwrap_or_else(|error| serde_json::json!({"error":error}))
}

/// WAL-7: `http://host:port` (plain) or `https://host[:port]` (rustls,
/// certificate and host name verified against the webpki roots, or against
/// the `GNB_RPC_CA` PEM/DER file for a private CA). An https endpoint is never
/// downgraded to plain HTTP.
fn rpc_endpoint(endpoint: &str) -> Result<crate::wallet::http_rpc::Endpoint, String> {
    crate::wallet::http_rpc::Endpoint::parse(endpoint)
}

fn rpc_trust() -> Result<crate::wallet::http_rpc::TlsTrust, String> {
    match std::env::var_os("GNB_RPC_CA") {
        Some(path) => crate::wallet::http_rpc::TlsTrust::from_cert_file(std::path::Path::new(&path)),
        None => Ok(crate::wallet::http_rpc::TlsTrust::WebPkiRoots),
    }
}

fn rpc_result(endpoint: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    rpc_endpoint(endpoint)?;
    crate::wallet::http_rpc::call_with_trust(endpoint, method, &params, None, &rpc_trust()?)
}

// Parse once from the original CLI token: no float may choose the spend amount.
fn checked_cli_satoshis(value: &str, allow_zero: bool) -> Result<u64, &'static str> {
    let satoshis = crate::wallet::parse_bloch_satoshis(value)?;
    if !allow_zero && satoshis == 0 { return Err("payment must contain at least one satoshi"); }
    Ok(satoshis)
}

fn checked_destination(destination: &str, source: &str) -> Result<String, String> {
    let destination = crate::address::Address::parse(destination).map_err(|_| "invalid destination address".to_string())?;
    let source = crate::address::Address::parse(source).map_err(|_| "invalid wallet address".to_string())?;
    if destination.network() != source.network() { return Err("destination address network differs from wallet".into()); }
    Ok(hex::encode(destination.hash()))
}

/// Test view of the production UTXO-row parser (`send::parse_utxo_rows`,
/// which `Send` uses): malformed rows are refused, never filtered.
#[cfg(test)]
fn parse_send_utxos(response: &serde_json::Value) -> Result<Vec<(Vec<u8>, u32, crate::core::TxOutput)>, String> {
    Ok(crate::wallet::send::parse_utxo_rows(response)?
        .into_iter().map(|u| (u.txid.to_vec(), u.index, u.output)).collect())
}

#[cfg(test)]
mod audit_cli_input_tests {
    use super::*;
    use crate::address::{Address, Network};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use sha3::{Digest, Sha3_256};
    use zeroize::Zeroize;

    #[test]
    fn cli_prompt_secret_owner_preserves_content_and_zeroizes_while_live() {
        let mut secret = own_prompt_secret(String::from("abandon abandon secret"));
        assert!(std::mem::needs_drop::<zeroize::Zeroizing<String>>());
        assert_eq!(secret.as_str(), "abandon abandon secret");
        secret.zeroize();
        assert!(secret.is_empty());
    }

    #[test]
    fn new_password_confirmation_preserves_only_an_exact_zeroizing_owner() {
        let password = own_prompt_secret(String::from("correct-horse-battery-9!"));
        let confirmation = own_prompt_secret(String::from("correct-horse-battery-9!"));
        let mut confirmed = confirmed_prompt_secret(password, confirmation).unwrap();
        assert!(std::mem::needs_drop::<zeroize::Zeroizing<String>>());
        assert_eq!(confirmed.as_str(), "correct-horse-battery-9!");

        assert!(confirmed_prompt_secret(
            own_prompt_secret(String::from("correct-horse-battery-9!")),
            own_prompt_secret(String::from("wrong-confirmation")),
        ).is_none());

        confirmed.zeroize();
        assert!(confirmed.is_empty());
    }

    #[test]
    fn cli_disclosure_uses_explicit_single_key_convention() {
        use crate::wallet::disclosure::{
            keypair_at_with_convention, DisclosureKeyConvention,
        };

        assert_eq!(
            CLI_DISCLOSURE_KEY_CONVENTION,
            DisclosureKeyConvention::SingleKeyWallet,
        );

        let seed = [0x47; 64];
        let (base_public, base_secret) =
            crate::crypto::generate_keypair_from_seed(&seed[..32]).unwrap();
        let _base_secret = zeroize::Zeroizing::new(base_secret);
        let (cli_zero_public, cli_zero_secret) = keypair_at_with_convention(
            &seed,
            0,
            CLI_DISCLOSURE_KEY_CONVENTION,
        )
        .unwrap();
        let _cli_zero_secret = zeroize::Zeroizing::new(cli_zero_secret);
        let (hd_zero_public, hd_zero_secret) = keypair_at_with_convention(
            &seed,
            0,
            DisclosureKeyConvention::HdWalletV3,
        )
        .unwrap();
        let _hd_zero_secret = zeroize::Zeroizing::new(hd_zero_secret);

        assert_eq!(cli_zero_public, base_public);
        assert_ne!(cli_zero_public, hd_zero_public);

        let (cli_child_public, cli_child_secret) = keypair_at_with_convention(
            &seed,
            7,
            CLI_DISCLOSURE_KEY_CONVENTION,
        )
        .unwrap();
        let _cli_child_secret = zeroize::Zeroizing::new(cli_child_secret);
        let (hd_child_public, hd_child_secret) = keypair_at_with_convention(
            &seed,
            7,
            DisclosureKeyConvention::HdWalletV3,
        )
        .unwrap();
        let _hd_child_secret = zeroize::Zeroizing::new(hd_child_secret);

        assert_eq!(cli_child_public, hd_child_public);
    }

    #[test]
    fn cli_disclosure_file_budget_accepts_exact_limit_and_rejects_one_more_byte() {
        let bundle = crate::wallet::DisclosureBundle {
            version: crate::wallet::disclosure::DISCLOSURE_VERSION,
            network: "testnet".into(),
            purpose: "budget fixture".into(),
            audience: "auditor".into(),
            created_at: "2026-09-19T00:00:00Z".into(),
            entries: Vec::new(),
        };
        let mut bytes = serde_json::to_vec(&bundle).unwrap();
        let exact_limit = bytes.len() + 32;
        bytes.resize(exact_limit, b' ');

        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let parsed = read_disclosure_bundle_with_limit(file.path(), exact_limit).unwrap();
        assert_eq!(parsed.purpose, bundle.purpose);

        bytes.push(b' ');
        std::fs::write(file.path(), &bytes).unwrap();
        let error = read_disclosure_bundle_with_limit(file.path(), exact_limit).unwrap_err();
        assert_eq!(
            error,
            format!("Disclosure bundle exceeds {}-byte input limit", exact_limit),
        );
        assert!(!error.contains("Bundle parse failed"));
    }

    #[test]
    fn cli_amount_refuses_nonfinite_negative_saturating_and_zero_payment() {
        for value in ["NaN", "inf", "-inf", "-1", "1e30"] {
            assert!(checked_cli_satoshis(value, true).is_err());
        }
        assert!(checked_cli_satoshis("0", false).is_err());
        assert!(checked_cli_satoshis("0.000000001", false).is_err());
        assert_eq!(checked_cli_satoshis("0", true), Ok(0));
        assert_eq!(checked_cli_satoshis("1.25", false), Ok(125_000_000));
        assert_eq!(checked_cli_satoshis("0.00000001", false), Ok(1));
    }

    #[test]
    fn clap_preserves_exact_amount_and_fee_tokens() {
        let cli = Cli::try_parse_from(["postern-wallet", "send", "wallet.json", "recipient",
            "90071992.54740993", "--fee", "0.00000001"]).unwrap();
        match cli.cmd {
            Cmd::Send { amount, fee, .. } => {
                assert_eq!(checked_cli_satoshis(&amount, false).unwrap(), 9_007_199_254_740_993);
                assert_eq!(checked_cli_satoshis(&fee, true).unwrap(), 1);
            }
            _ => panic!("expected send command"),
        }
    }

    #[test]
    fn cli_destination_preserves_network_before_converting_to_hash() {
        let main = Address::from_hash([1; 20], Network::Mainnet).to_string();
        let test = Address::from_hash([1; 20], Network::Testnet).to_string();
        assert!(checked_destination(&main, &test).is_err());
        assert!(checked_destination(&test, &main).is_err());
        assert_eq!(checked_destination(&main, &main).unwrap(), "01".repeat(20));
        assert!(checked_destination("invalid", &main).is_err());
    }

    #[test]
    fn cli_utxo_parser_refuses_invalid_rows_without_silent_filtering() {
        let row = serde_json::json!({"txid": "ab".repeat(32), "index": u32::MAX,
            "value": "9007199254740993", "script_pubkey": "cd".repeat(20)});
        let parsed = parse_send_utxos(&serde_json::json!({"utxos": [row.clone()]})).unwrap();
        assert_eq!(parsed[0].1, u32::MAX);
        assert_eq!(parsed[0].2.value, 9_007_199_254_740_993);
        for invalid in [serde_json::json!(4294967296u64), serde_json::json!(-1), serde_json::json!(1.5)] {
            let mut bad = row.clone(); bad["index"] = invalid;
            assert!(parse_send_utxos(&serde_json::json!({"utxos": [row.clone(), bad]})).is_err());
        }
        let mut bad = row; bad["txid"] = serde_json::json!("ab");
        assert!(parse_send_utxos(&serde_json::json!({"utxos": [bad]})).is_err());
        assert!(parse_send_utxos(&serde_json::json!({})).is_err());
    }

    #[test]
    fn canonical_bundle_flag_is_opt_in_and_rejects_raw_signature_fallback() {
        let default_cli = Cli::try_parse_from([
            "postern-wallet",
            "verify-bundle",
            "disclosure.json",
        ])
        .unwrap();
        assert!(matches!(
            default_cli.cmd,
            Cmd::VerifyBundle {
                canonical: false,
                ..
            }
        ));
        let strict_cli = Cli::try_parse_from([
            "postern-wallet",
            "verify-bundle",
            "disclosure.json",
            "--canonical",
        ])
        .unwrap();
        assert!(matches!(
            strict_cli.cmd,
            Cmd::VerifyBundle {
                canonical: true,
                ..
            }
        ));
        let default_watch = Cli::try_parse_from([
            "postern-wallet",
            "watch",
            "disclosure.json",
        ])
        .unwrap();
        assert!(matches!(
            default_watch.cmd,
            Cmd::Watch {
                canonical: false,
                ..
            }
        ));
        let strict_watch = Cli::try_parse_from([
            "postern-wallet",
            "watch",
            "disclosure.json",
            "--canonical",
        ])
        .unwrap();
        assert!(matches!(
            strict_watch.cmd,
            Cmd::Watch {
                canonical: true,
                ..
            }
        ));

        let seed = [62u8; 64];
        let mut bundle = (0..8)
            .map(|_| {
                crate::wallet::DisclosureBundle::create(
                    &seed,
                    &[0],
                    Network::Testnet,
                    "wave-62 product policy",
                    "release auditor",
                )
                .unwrap()
            })
            .find(|candidate| {
                let signature = B64.decode(&candidate.entries[0].sig_b64).unwrap();
                !signature[crate::crypto::SUITE_HEADER_LEN..].starts_with(&[0xb1, 0x0c])
            })
            .expect("fixture signature body must not mimic the suite magic");

        assert!(verify_bundle_with_policy(&bundle, false).is_ok());
        assert!(verify_bundle_with_policy(&bundle, true).is_ok());
        let signature = B64.decode(&bundle.entries[0].sig_b64).unwrap();
        bundle.entries[0].sig_b64 = B64.encode(
            &signature[crate::crypto::SUITE_HEADER_LEN..],
        );

        assert!(
            verify_bundle_with_policy(&bundle, false).is_ok(),
            "default CLI policy must preserve historical raw fallback"
        );
        assert!(matches!(
            verify_bundle_with_policy(&bundle, true),
            Err(crate::wallet::DisclosureError::SignatureInvalid { index: 0 })
        ));
    }

    #[test]
    fn canonical_message_flag_routes_genuine_magic_prefixed_fixture() {
        let default_cli = Cli::try_parse_from([
            "postern-wallet",
            "verify-message",
            "00",
            "wave-66-message",
            "00",
        ])
        .unwrap();
        assert!(matches!(
            default_cli.cmd,
            Cmd::VerifyMessage {
                canonical: false,
                ..
            }
        ));
        let strict_cli = Cli::try_parse_from([
            "postern-wallet",
            "verify-message",
            "00",
            "wave-66-message",
            "00",
            "--canonical",
        ])
        .unwrap();
        assert!(matches!(
            strict_cli.cmd,
            Cmd::VerifyMessage {
                canonical: true,
                ..
            }
        ));

        const SEARCH_COUNTER: u64 = 44_970;
        const SIGNING_SEED_HEX: &str =
            "350dedd0a2e98668324887e0a2ee89384f8f4d4e4fba79224f3eba885ac2bd74";
        let (enveloped_pk, enveloped_sk) =
            crate::crypto::generate_keypair_from_seed(&[0x66; 32]).unwrap();
        let mut h = Sha3_256::new();
        h.update(b"bloch/wallet-message/cr10/signing-rng/v1");
        h.update(SEARCH_COUNTER.to_le_bytes());
        let signing_seed: [u8; 32] = h.finalize().into();
        assert_eq!(hex::encode(signing_seed), SIGNING_SEED_HEX);

        let message = b"wave-66-message";
        let digest = crate::crypto::signed_message_digest(message);
        let enveloped_sig = pqcrypto_internals::with_seeded_rng_scope(&signing_seed, || {
            crate::crypto::sign(&enveloped_sk, &digest).unwrap()
        });
        assert!(verify_digest_with_policy(&enveloped_pk, &digest, &enveloped_sig, false));
        assert!(verify_digest_with_policy(&enveloped_pk, &digest, &enveloped_sig, true));

        let raw_pk = &enveloped_pk[crate::crypto::SUITE_HEADER_LEN..];
        let raw_sig = &enveloped_sig[crate::crypto::SUITE_HEADER_LEN..];
        assert_eq!(&raw_sig[..2], &[0xb1, 0x0c], "fixture must hit CR-10");
        assert!(
            !crate::crypto::verify(raw_pk, &digest, raw_sig),
            "generic autodetection must misclassify this genuine raw signature"
        );
        assert!(
            verify_digest_with_policy(raw_pk, &digest, raw_sig, false),
            "compatible wallet policy must use the explicit raw format first"
        );
        assert!(
            !verify_digest_with_policy(raw_pk, &digest, raw_sig, true),
            "canonical product policy must reject legacy raw records"
        );
        // The fixture is a v1 (chain-less) message signature: CRY-8 accepts
        // it only in the explicit legacy mode, in the compatible encoding.
        use crate::wallet::Keypair;
        for (pk, sig) in [(&enveloped_pk[..], &enveloped_sig[..]), (raw_pk, raw_sig)] {
            assert!(!Keypair::verify_message(pk, message, sig));
            assert!(!Keypair::verify_message_canonical(pk, message, sig));
            assert!(Keypair::verify_message_allowing_legacy_v1(None, pk, message, sig));
        }
    }
}

#[cfg(test)]
mod audit_2026_10_cli_tests {
    use super::*;

    /// WAL-7 (residual): https endpoints are spoken over TLS, never
    /// downgraded to plain HTTP; plain endpoints keep working. (Before
    /// HTTPS support this test asserted that https was refused.)
    #[test]
    fn https_endpoints_use_tls_and_plain_endpoints_stay_plain() {
        let e = rpc_endpoint("https://node.example:17210").unwrap();
        assert!(e.tls && e.host == "node.example" && e.port == 17210);
        assert_eq!(rpc_endpoint("https://node.example/").unwrap().port, 443);
        let e = rpc_endpoint("http://127.0.0.1:17210/").unwrap();
        assert!(!e.tls && e.authority() == "127.0.0.1:17210");
        assert!(rpc_endpoint("https://user@node.example").is_err());
        // Nothing listens on port 1: an error, not a plain-HTTP fallback.
        assert!(rpc_call("https://127.0.0.1:1", "getblockcount", serde_json::json!([]))["error"].is_string());
    }

    /// WAL-1/WAL-6/WAL-7: send defaults to the size-aware fee and asks for
    /// confirmation; the guard and confirmation are overridable only explicitly.
    #[test]
    fn send_flags_default_to_auto_fee_guard_and_confirmation() {
        let cli = Cli::try_parse_from(["gnb-wallet", "send", "w.json", "to", "1"]).unwrap();
        match cli.cmd {
            Cmd::Send { fee, max_fee, yes, allow_unverified_inputs, .. } => {
                assert_eq!(fee, "auto");
                assert!(max_fee.is_none() && !yes && !allow_unverified_inputs);
            }
            _ => panic!("expected send"),
        }
        let cli = Cli::try_parse_from(["gnb-wallet", "send", "w.json", "to", "1", "--max-fee", "0.5",
            "--yes", "--allow-unverified-inputs"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Send { yes: true, allow_unverified_inputs: true, .. }));
    }

    /// CRY-7: `send` / `sign` take the stated network from --mainnet /
    /// --testnet (none stated: only a v3 keystore unlocks); both is an error.
    #[test]
    fn spending_network_is_stated_explicitly() {
        let cli = Cli::try_parse_from(["gnb-wallet", "--mainnet", "send", "w.json", "to", "1"]).unwrap();
        assert_eq!(stated_network(cli.testnet, cli.mainnet), Some(crate::address::Network::Mainnet));
        let cli = Cli::try_parse_from(["gnb-wallet", "sign", "w.json", "msg", "--testnet"]).unwrap();
        assert_eq!(stated_network(cli.testnet, cli.mainnet), Some(crate::address::Network::Testnet));
        let cli = Cli::try_parse_from(["gnb-wallet", "sign", "w.json", "msg"]).unwrap();
        assert_eq!(stated_network(cli.testnet, cli.mainnet), None);
        assert!(Cli::try_parse_from(["gnb-wallet", "--mainnet", "--testnet", "sign", "w.json", "m"]).is_err());
    }

    /// WAL-7: `new` is phrase-backed unless --random-key is given.
    #[test]
    fn new_is_phrase_backed_by_default() {
        let cli = Cli::try_parse_from(["gnb-wallet", "new"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::New { random_key: false, .. }));
        let cli = Cli::try_parse_from(["gnb-wallet", "--testnet", "restore"]).unwrap();
        assert!(cli.testnet && matches!(cli.cmd, Cmd::Restore { .. }));
    }

    /// CRY-8: the CLI verifier is chain-bound for v2 signatures, and a v1
    /// signature needs --legacy-v1 (which --canonical excludes).
    #[test]
    fn verify_message_is_network_bound() {
        let kp = crate::wallet::generate_keypair(true);
        let sig = kp.sign_message(b"cli").unwrap();
        assert!(verify_message_on_network(cli_network(true), &kp.public_key, b"cli", &sig, false));
        assert!(!verify_message_on_network(cli_network(false), &kp.public_key, b"cli", &sig, false));
        assert!(verify_message_on_network(cli_network(true), &kp.public_key, b"cli", &sig, true));
        let v1 = kp.sign_message_v1(b"cli").unwrap();
        for canonical in [false, true] {
            assert!(!verify_message_on_network(cli_network(true), &kp.public_key, b"cli", &v1, canonical));
        }
        let cli = Cli::try_parse_from(["gnb-wallet", "verify-message", "00", "m", "00", "--legacy-v1"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::VerifyMessage { legacy_v1: true, canonical: false, .. }));
        assert!(Cli::try_parse_from(["gnb-wallet", "verify-message", "00", "m", "00", "--legacy-v1", "--canonical"]).is_err());
    }
}
