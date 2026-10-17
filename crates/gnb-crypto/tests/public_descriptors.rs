use gnb_crypto::address::{Address, Network};
use gnb_crypto::core::policy::{PolicyTree, SpendPolicy};
use gnb_crypto::wallet::descriptor::{
    self, Descriptor, PublicPool, MAX_DESCRIPTOR_BYTES, MAX_POOL_BYTES,
};
use serde_json::{json, Value};

fn key(byte: u8) -> Vec<u8> {
    vec![byte; 3745]
}
fn pkh(byte: u8, network: &str) -> String {
    format!("gnbd1({network},pkh({}))", hex::encode(key(byte)))
}
fn policy(byte: u8, after: u32) -> String {
    format!("policy(1,{after},2,{})", hex::encode(key(byte)))
}
fn create(body: &str) -> Descriptor {
    Descriptor::create(body).unwrap()
}
fn request(action: &str, argument: &str, value: Value) -> Value {
    let mut request = json!({"action":action,"network":"mainnet"});
    request[argument] = value;
    request
}

#[test]
fn bip380_checksum_matches_primary_fixed_vector() {
    assert_eq!(descriptor::checksum("raw(deadbeef)").unwrap(), "89f8spxm");
    assert!(descriptor::checksum("raw(Ü)").is_err());
    assert_ne!(descriptor::checksum("raw(deedbeef)").unwrap(), "89f8spxm");
}

#[test]
fn both_networks_and_all_kinds_preserve_existing_script_identities() {
    for network in [Network::Mainnet, Network::Testnet] {
        let name = descriptor::network_name(network);
        let pkh = create(&pkh(1, name));
        assert_eq!(
            pkh.script_pubkey(),
            Address::from_pubkey(&key(1), network).hash()
        );
        let policy = SpendPolicy::new(1, vec![key(1)], 37, 2).unwrap();
        let parsed = create(&format!("gnbd1({name},{})", self::policy(1, 37)));
        assert_eq!(parsed.script_pubkey(), policy.script_pubkey());
        let tree = PolicyTree::new(vec![
            policy,
            SpendPolicy::new(1, vec![key(2)], 9, 2).unwrap(),
        ])
        .unwrap();
        let parsed_tree = create(&format!(
            "gnbd1({name},tree({},{}))",
            self::policy(1, 37),
            self::policy(2, 9)
        ));
        assert_eq!(parsed_tree.script_pubkey(), tree.script_pubkey());
        for (kind, descriptor) in [("pkh", pkh), ("policy", parsed), ("tree", parsed_tree)] {
            assert_eq!(Descriptor::parse(descriptor.as_str()).unwrap(), descriptor);
            let info = descriptor.info();
            assert_eq!(info["kind"], kind);
            assert_eq!(info["requires_policy_tree_activation"], kind == "tree");
            for field in ["address", "bech32m"] {
                assert_eq!(
                    gnb_crypto::address::destination_script(info[field].as_str().unwrap()).unwrap(),
                    (network, descriptor.script_pubkey())
                );
            }
        }
    }
}

#[test]
fn exact_key_bytes_and_branch_order_are_not_normalized() {
    let raw = key(4);
    let envelope = [vec![0xb1, 0x0c, 0x01, 0x00], raw.clone()].concat();
    let a = create(&format!("gnbd1(mainnet,pkh({}))", hex::encode(&raw)));
    let b = create(&format!("gnbd1(mainnet,pkh({}))", hex::encode(&envelope)));
    assert_ne!(a.script_pubkey(), b.script_pubkey());
    assert_eq!(
        b.script_pubkey(),
        Address::from_pubkey(&envelope, Network::Mainnet).hash()
    );
    // PF-4: the raw key and its envelope are one signer, so one policy may
    // not list both (they used to be accepted as distinct bytes).
    let body = format!(
        "gnbd1(mainnet,policy(2,0,0,{},{}))",
        hex::encode(&raw),
        hex::encode(&envelope)
    );
    assert!(Descriptor::create(&body).is_err(), "twin-encoding policy descriptor");
    assert!(Descriptor::create(&format!(
        "gnbd1(mainnet,tree({},policy(1,0,0,{},{})))",
        policy(1, 0),
        hex::encode(&envelope),
        hex::encode(&raw)
    ))
    .is_err(), "twin-encoding tree branch");
    assert!(SpendPolicy::new(2, vec![raw, envelope], 0, 0).is_err());
    let a = create(&format!(
        "gnbd1(mainnet,tree({},{}))",
        policy(1, 0),
        policy(2, 0)
    ));
    let b = create(&format!(
        "gnbd1(mainnet,tree({},{}))",
        policy(2, 0),
        policy(1, 0)
    ));
    assert_ne!(a.script_pubkey(), b.script_pubkey());
}

/// PF-4 review finding: `create` refuses a policy listing one key in both
/// encodings, but an existing descriptor of that shape (main's tooling
/// created and exported it) is still inspected, exported and imported, with
/// `twin_key_encodings: true` in its info, so a pool holding one restores
/// whole and its owner can find the output to move before the second
/// hardening height. Before the fix inspect and the pool restore failed.
#[test]
fn existing_twin_key_descriptors_restore_flagged() {
    let raw = key(4);
    let envelope = [vec![0xb1, 0x0c, 0x01, 0x00], raw.clone()].concat();
    let twin = format!("policy(2,0,0,{},{})", hex::encode(&raw), hex::encode(&envelope));
    let bodies = [format!("gnbd1(mainnet,{twin})"), format!("gnbd1(mainnet,tree({},{twin}))", policy(1, 0))];
    let mut texts = vec![create(&pkh(1, "mainnet")).as_str().to_string()];
    for body in &bodies {
        assert!(Descriptor::create(body).is_err(), "created: {body:.40}");
        let text = format!("{body}#{}", descriptor::checksum(body).unwrap());
        let parsed = Descriptor::parse(&text).expect("an existing descriptor is restored");
        assert!(parsed.has_twin_key_encodings());
        let info = parsed.info();
        assert_eq!(info["twin_key_encodings"], true);
        let inspected = descriptor::public_request(&request("inspect", "descriptor", json!(text))).unwrap();
        assert_eq!(inspected, info);
        texts.push(text);
    }
    // The twin policy's script is the one consensus decoding gives it.
    let decoded = SpendPolicy::decode(&SpendPolicy { threshold: 2, pubkeys: vec![raw.clone(), envelope.clone()],
        after: 0, older: 0 }.encode()).unwrap();
    assert_eq!(Descriptor::parse(&texts[1]).unwrap().script_pubkey(), decoded.script_pubkey());
    // The whole pool restores (export and import), each entry flagged or not.
    let pool = PublicPool::from_descriptors(Network::Mainnet, &texts).expect("the pool restores");
    let restored = PublicPool::from_bundle(&pool.to_bundle().unwrap(), Network::Mainnet).unwrap();
    let entries = restored.response().unwrap()["entries"].clone();
    let flags: Vec<_> = entries.as_array().unwrap().iter().map(|e| e.get("twin_key_encodings").cloned()).collect();
    assert_eq!(flags, vec![None, Some(json!(true)), Some(json!(true))]);
    // Every other descriptor's info has no such field.
    let honest = create(&format!("gnbd1(mainnet,policy(2,0,0,{},{}))", hex::encode(key(5)), hex::encode(&envelope)));
    assert!(!honest.has_twin_key_encodings());
    assert!(honest.info().get("twin_key_encodings").is_none());
    // Byte-identical keys stay a grammar error on every path.
    let dup = format!("gnbd1(mainnet,policy(1,0,0,{},{}))", hex::encode(&raw), hex::encode(&raw));
    assert!(Descriptor::parse(&format!("{dup}#{}", descriptor::checksum(&dup).unwrap())).is_err());
}

#[test]
fn grammar_rejects_noncanonical_numbers_keys_nesting_and_trailing_data() {
    let key = hex::encode(key(10));
    let invalid = [
        format!("gnbd1(mainnet,pkh({}))", key.to_uppercase()),
        format!("gnbd1(mainnet, pkh({key}))"),
        format!("gnbd1(Mainnet,pkh({key}))"),
        format!("gnbd1(mainnet,policy(01,0,0,{key}))"),
        format!("gnbd1(mainnet,policy(1,00,0,{key}))"),
        format!("gnbd1(mainnet,policy(1,0,+0,{key}))"),
        format!("gnbd1(mainnet,policy(0,0,0,{key}))"),
        format!("gnbd1(mainnet,policy(2,0,0,{key}))"),
        format!("gnbd1(mainnet,policy(1,4294967296,0,{key}))"),
        format!("gnbd1(mainnet,policy(1,0,0,{key},{key}))"),
        format!("gnbd1(mainnet,pkh({key}/*))"),
        format!("gnbd1(mainnet,pkh({key})))"),
        format!("gnbd1(mainnet,pkh({key}))x"),
        format!("gnbd1(mainnet,tree({}))", policy(1, 0)),
        format!(
            "gnbd1(mainnet,tree({},tree({},{})))",
            policy(1, 0),
            policy(1, 0),
            policy(2, 0)
        ),
        "gnbd1(mainnet,pkh(xpub1234))".into(),
        "gnbd1(mainnet,pkh(xprv1234))".into(),
        format!("gnbd1(mainnet,pkh({}))", "00".repeat(6337)),
    ];
    for body in invalid {
        assert!(Descriptor::create(&body).is_err(), "accepted bad grammar");
        if let Ok(checksum) = descriptor::checksum(&body) {
            assert!(
                Descriptor::parse(&format!("{body}#{checksum}")).is_err(),
                "valid checksum bypassed grammar"
            );
        }
    }
    let valid = format!("gnbd1(mainnet,policy(1,4294967295,4294967295,{key}))");
    assert!(Descriptor::create(&valid).is_ok());
}

#[test]
fn checksum_is_mandatory_and_binds_network_and_every_key_byte() {
    let original = create(&pkh(3, "mainnet"));
    let (body, checksum) = original.as_str().split_once('#').unwrap();
    for invalid in [
        body.to_owned(),
        format!("{body}#"),
        format!("{body}#{checksum}x"),
        format!("{body}#{}", &checksum[..7]),
        format!("{body}##{checksum}"),
        original.as_str().replacen("mainnet", "testnet", 1),
        original.as_str().replacen("0303", "0203", 1),
        format!("{} ", original.as_str()),
    ] {
        assert!(Descriptor::parse(&invalid).is_err());
    }
    assert!(Descriptor::create(original.as_str()).is_err());
}

#[test]
fn descriptor_key_and_branch_bounds_are_enforced() {
    assert!(Descriptor::parse(&"a".repeat(MAX_DESCRIPTOR_BYTES + 1)).is_err());
    assert!(Descriptor::create(&"a".repeat(MAX_DESCRIPTOR_BYTES - 8)).is_err());
    let keys = (0..7).map(|i| hex::encode(key(i))).collect::<Vec<_>>();
    let policy7 = format!("policy(7,0,0,{})", keys.join(","));
    let valid = create(&format!(
        "gnbd1(mainnet,tree({policy7},{policy7},{policy7},{policy7}))"
    ));
    assert!(valid.as_str().len() < MAX_DESCRIPTOR_BYTES);
    assert!(Descriptor::create(&format!(
        "gnbd1(mainnet,tree({policy7},{policy7},{policy7},{policy7},{policy7}))"
    ))
    .is_err());
    assert!(Descriptor::create(&format!(
        "gnbd1(mainnet,policy(7,0,0,{},{}))",
        keys.join(","),
        hex::encode(key(8))
    ))
    .is_err());
}

#[test]
fn pool_canonical_order_roundtrip_and_network_are_explicit() {
    let a = create(&pkh(1, "mainnet"));
    let b = create(&format!("gnbd1(mainnet,{})", policy(2, 3)));
    let texts = vec![a.as_str().to_owned(), b.as_str().to_owned()];
    let pool = PublicPool::from_descriptors(Network::Mainnet, &texts).unwrap();
    let bundle = pool.to_bundle().unwrap();
    assert_eq!(bundle, format!("{{\"format\":\"gnb-watch-only-v1\",\"network\":\"mainnet\",\"descriptors\":[\"{}\",\"{}\"]}}", texts[0], texts[1]));
    assert_eq!(
        PublicPool::from_bundle(&bundle, Network::Mainnet)
            .unwrap()
            .response()
            .unwrap(),
        pool.response().unwrap()
    );
    assert!(PublicPool::from_bundle(&bundle, Network::Testnet).is_err());
    assert_eq!(pool.response().unwrap()["entries"][0], a.info());
    assert_eq!(pool.response().unwrap()["entries"][1], b.info());
}

#[test]
fn pool_rejects_duplicate_unknown_fields_trailing_bytes_and_duplicate_scripts() {
    let descriptor = create(&pkh(1, "mainnet"));
    let pool =
        PublicPool::from_descriptors(Network::Mainnet, &[descriptor.as_str().into()]).unwrap();
    let bundle = pool.to_bundle().unwrap();
    for prefix in [
        "\"format\":\"gnb-watch-only-v1\",",
        "\"network\":\"mainnet\",",
        "\"descriptors\":[],",
        "\"extra\":0,",
        "\"netw\\u006frk\":\"mainnet\",",
    ] {
        let malformed = format!("{{{prefix}{}", &bundle[1..]);
        assert!(PublicPool::from_bundle(&malformed, Network::Mainnet).is_err());
    }
    for malformed in [
        format!("{bundle}x"),
        format!("{bundle}{bundle}"),
        bundle.replace("gnb-watch-only-v1", "gnb-watch-only-v2"),
    ] {
        assert!(PublicPool::from_bundle(&malformed, Network::Mainnet).is_err());
    }
    assert!(PublicPool::from_descriptors(
        Network::Mainnet,
        &[descriptor.as_str().into(), descriptor.as_str().into()]
    )
    .is_err());
    assert!(PublicPool::from_descriptors(
        Network::Mainnet,
        &[create(&pkh(1, "testnet")).as_str().into()]
    )
    .is_err());
}

#[test]
fn pool_entry_and_raw_byte_limits_have_positive_controls() {
    let keys = (0..64).map(|i| hex::encode(key(i))).collect::<Vec<_>>();
    let valid = PublicPool::from_public_keys(Network::Mainnet, &keys).unwrap();
    assert_eq!(valid.response().unwrap()["count"], 64);
    let mut too_many = keys.clone();
    too_many.push(hex::encode(key(64)));
    assert!(PublicPool::from_public_keys(Network::Mainnet, &too_many).is_err());
    assert!(PublicPool::from_public_keys(Network::Mainnet, &[]).is_err());
    let mut padded = valid.to_bundle().unwrap();
    padded.push_str(&" ".repeat(MAX_POOL_BYTES - padded.len()));
    assert!(PublicPool::from_bundle(&padded, Network::Mainnet).is_ok());
    padded.push(' ');
    assert!(PublicPool::from_bundle(&padded, Network::Mainnet).is_err());
    let huge = (0..21)
        .map(|after| {
            let keys = (0..7).map(|i| hex::encode(key(i))).collect::<Vec<_>>();
            create(&format!(
                "gnbd1(mainnet,policy(1,{after},0,{}))",
                keys.join(",")
            ))
            .as_str()
            .to_owned()
        })
        .collect::<Vec<_>>();
    assert!(PublicPool::from_descriptors(Network::Mainnet, &huge[..19]).is_ok());
    assert!(PublicPool::from_descriptors(Network::Mainnet, &huge).is_err());
}

#[test]
fn shared_request_rejects_wrong_network_types_fields_and_session_actions() {
    let valid = request("create", "body", json!(pkh(1, "mainnet")));
    assert!(descriptor::public_request(&valid).is_ok());
    for invalid in [Value::Null, json!([]), json!({})] {
        assert!(descriptor::public_request(&invalid).is_err());
    }
    for field in ["action", "network", "body"] {
        for value in [Value::Null, json!(1), json!(true), json!([]), json!({})] {
            let mut bad = valid.clone();
            bad[field] = value;
            assert!(descriptor::public_request(&bad).is_err());
        }
    }
    for action in ["wipe", "create_key", "pay", "pqpsbt_sign"] {
        let mut bad = valid.clone();
        bad["action"] = json!(action);
        assert!(descriptor::public_request(&bad).is_err());
    }
    for op in [json!("wipe"), json!("pay"), Value::Null, json!(1)] {
        let mut bad = valid.clone();
        bad["op"] = op;
        assert!(descriptor::public_request(&bad).is_err());
    }
    let mut bad = valid.clone();
    bad["network"] = json!("testnet");
    assert!(descriptor::public_request(&bad).is_err());
    let mut bad = valid.clone();
    bad["password"] = json!("not a key operation");
    assert!(descriptor::public_request(&bad).is_err());
    let mut bad = valid;
    bad["descriptor"] = json!("unused");
    assert!(descriptor::public_request(&bad).is_err());
}

#[test]
fn raw_request_parser_rejects_duplicates_before_value_can_erase_them() {
    for bytes in [
        br#"{"network":"mainnet","network":"testnet"}"#.as_slice(),
        br#"{"op":"descriptor","op":"wipe"}"#,
        br#"{"op":"wipe","op":"descriptor"}"#,
        br#"{"action":"create","act\u0069on":"inspect"}"#,
        br#"{"unknown":0}"#,
    ] {
        assert!(descriptor::request_from_json(bytes).is_err());
    }
    let valid = request("create", "body", json!(pkh(1, "mainnet")));
    assert_eq!(
        descriptor::request_from_json(&serde_json::to_vec(&valid).unwrap()).unwrap(),
        valid
    );
}
