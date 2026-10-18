use gnb_wallet_wasm::handle;
use serde_json::json;

// Public shape fixture accepted by the existing policy predicate; no secret
// key or claim of spendability is associated with these deterministic bytes.
fn key(byte: u8) -> String {
    let bytes = vec![byte; 3745];
    assert!(gnb_crypto::crypto::is_hybrid_public_key(&bytes));
    hex::encode(bytes)
}

#[test]
fn legacy_normalize_control_without_a_session() {
    // ObenBlock core: a GnB string is accepted and shown as obb1q….
    let address =
        gnb_crypto::address::Address::from_hash([0; 20], gnb_crypto::address::Network::Mainnet)
            .to_string();
    assert_eq!(
        handle(&json!({"op":"normalize", "address":address})).unwrap(),
        json!({"address": format!("obb1q{}", &address[5..]), "network": "mainnet"})
    );
}

#[test]
fn public_descriptor_creation_preserves_existing_script_without_a_session() {
    for network in ["mainnet", "testnet"] {
        let public_key = key(7);
        let result = handle(
            &json!({"op":"descriptor", "action":"create", "network":network,
            "body":format!("gnbd1({network},pkh({public_key}))")}),
        );
        assert!(
            result.is_ok(),
            "public descriptor creation failed: {result:?}"
        );
        let result = result.unwrap();
        assert_eq!(result["kind"], "pkh");
        assert_eq!(result["network"], network);
        let net = if network == "mainnet" {
            gnb_crypto::address::Network::Mainnet
        } else {
            gnb_crypto::address::Network::Testnet
        };
        let address =
            gnb_crypto::address::Address::from_pubkey(&hex::decode(public_key).unwrap(), net);
        // The ObenBlock core shows the obb forms of the same script.
        let family = gnb_crypto::address::AddressFamily::ObenBlock;
        assert_eq!(result["address"], address.to_string_in(family));
        assert_eq!(result["script_pubkey"], hex::encode(address.hash()));
        assert_eq!(result["bech32m"], address.to_bech32m_in(family));
        assert_eq!(result["requires_policy_tree_activation"], false);
    }
}

#[test]
fn public_descriptor_pool_restores_public_identities_without_a_session() {
    let result = handle(
        &json!({"op":"descriptor", "action":"pool", "network":"testnet",
        "public_keys":[key(1), key(2)]}),
    );
    assert!(result.is_ok(), "public descriptor pool failed: {result:?}");
    let pool = result.unwrap();
    assert_eq!(pool["count"], 2);
    let restored = handle(&json!({"op":"descriptor", "action":"import", "network":"testnet", "bundle":pool["bundle"]})).unwrap();
    assert_eq!(restored, pool);
}

#[test]
fn raw_public_envelopes_cannot_redirect_or_mutate_a_live_session() {
    use gnb_wallet_wasm::call_bytes;
    use serde_json::Value;
    let opened = handle(&json!({"op":"create", "mnemonic":false})).unwrap();
    let before = handle(&json!({"op":"address"})).unwrap();
    assert_eq!(before["address"], opened["address"]);
    let body = format!(
        "gnbd1(mainnet,pkh({}))",
        opened["public_key"].as_str().unwrap()
    );
    let public = json!({"op":"descriptor","action":"create","network":"mainnet","body":body});
    let response: Value =
        serde_json::from_slice(&call_bytes(&serde_json::to_vec(&public).unwrap())).unwrap();
    assert_eq!(response["ok"]["address"], before["address"]);
    for raw in [
        r#"{"op":"descriptor","op":"wipe","action":"create","network":"mainnet"}"#,
        r#"{"op":"wipe","op":"descriptor","action":"create","network":"mainnet"}"#,
        r#"{"op":"descriptor","\u006fp":"wipe"}"#,
        r#"{"op":"descriptor","action":"wipe","network":"mainnet"}"#,
        r#"{"op":"descriptor","action":"pay","network":"mainnet"}"#,
        r#"{"op":"descriptor","action":"create","network":"mainnet","network":"testnet"}"#,
    ] {
        let response: Value = serde_json::from_slice(&call_bytes(raw.as_bytes())).unwrap();
        assert!(
            response.get("error").is_some(),
            "public envelope unexpectedly accepted"
        );
        assert_eq!(handle(&json!({"op":"address"})).unwrap(), before);
    }
    // Legacy duplicate handling stays last-wins; no descriptor was requested.
    let raw = format!(
        r#"{{"op":"unused","op":"normalize","address":"unused","address":"{}"}}"#,
        opened["address"].as_str().unwrap()
    );
    let legacy: Value = serde_json::from_slice(&call_bytes(raw.as_bytes())).unwrap();
    assert_eq!(legacy, json!({"ok":{"address":opened["address"], "network":"mainnet"}}));
    assert_eq!(handle(&json!({"op":"address"})).unwrap(), before);
    handle(&json!({"op":"wipe"})).unwrap();
}
