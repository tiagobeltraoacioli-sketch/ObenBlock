//! Test fixtures: `getblocktemplate` results built from the node's job
//! vectors (`reference/obb_job_vectors.json`). Used by the unit tests and the
//! mock-node integration test; not part of the server.

use serde_json::{json, Value};

use crate::job::EXTRANONCE_LEN;

const VECTORS: &str = include_str!("../../../reference/obb_job_vectors.json");

fn compact(n: u64, out: &mut Vec<u8>) {
    assert!(n < 0xFD);
    out.push(n as u8);
}

/// A `getblocktemplate` result built from vector case `i` of
/// `reference/obb_job_vectors.json`, with a block in the node's wire
/// layout around that case's coinbase (no other transaction, an empty
/// shielded section and a stand-in PoWit section: the server never
/// parses past the coinbase).
pub fn template_from_vector(i: usize) -> Value {
    template_from_vector_at(i, None)
}

/// [`template_from_vector`] with the header time replaced by `time` (and the
/// time window moved with it), for tests that run against the real clock.
pub fn template_from_vector_at(i: usize, time: Option<u32>) -> Value {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    let case = &v["cases"][i];
    let mut job = case["job"].clone();
    if let Some(t) = time {
        job["time"] = json!(t);
    }
    let job = &job;
    let parents: Vec<String> = case["parents"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect();
    let pb: Vec<[u8; 32]> = parents.iter().map(|p| hex::decode(p).unwrap().try_into().unwrap()).collect();
    let commitment = gnb_smh::sha256d::parents_commitment(&pb);
    let mut display = commitment;
    display.reverse();
    let mut hb = hex::decode(case["expect"]["header"].as_str().unwrap()).unwrap();
    if let Some(t) = time {
        hb[68..72].copy_from_slice(&t.to_le_bytes());
    }
    let header = hex::encode(&hb);
    let mut block = Vec::new();
    block.extend_from_slice(&hb[0..4]);
    compact(pb.len() as u64, &mut block);
    for p in &pb {
        block.extend_from_slice(p);
    }
    block.extend_from_slice(&hb[36..68]);
    block.extend_from_slice(&(u32::from_le_bytes(hb[68..72].try_into().unwrap()) as u64).to_le_bytes());
    block.extend_from_slice(&hb[72..76]);
    block.extend_from_slice(&0u64.to_le_bytes());
    block.extend_from_slice(&7u64.to_le_bytes()); // blue score
    block.extend_from_slice(&case["height"].as_u64().unwrap().to_le_bytes());
    let n_tx = 1;
    compact(n_tx, &mut block);
    block.extend(hex::decode(job["coinb1"].as_str().unwrap()).unwrap());
    block.extend(hex::decode(job["extranonce"].as_str().unwrap()).unwrap());
    block.extend(hex::decode(job["coinb2"].as_str().unwrap()).unwrap());
    block.push(0); // no shielded transactions
    block.extend_from_slice(&[0u8; 3]); // PoWit section stand-in
    json!({
        "pow": "sha256d",
        "height": case["height"],
        "parents": parents,
        "parent_time": job["time"].as_u64().unwrap() - 30,
        "coinbase_merkle_branch": job["coinbase_merkle_branch"],
        "stall_relief": {"active": true, "grace_secs": 180, "step_secs": 60, "halflife_secs": 1800},
        "sha256d": {
            "version": job["version"],
            "version_rolling_mask": "1fffe000",
            "parents_commitment": hex::encode(commitment),
            "previousblockhash": hex::encode(display),
            "bits": format!("{:08x}", job["bits"].as_u64().unwrap()),
            "curtime": job["time"],
            "mintime": job["time"].as_u64().unwrap() - 30,
            "merkle_root_rule": job["merkle_root_rule"],
            "shielded_root": job["shielded_root"],
            "powit_root": job["powit_root"],
            "extranonce_bytes": 8,
            "header_job": {
                "header": header,
                "block": hex::encode(&block),
                "merkle_root": case["expect"]["merkle_root"],
                "coinbase_txid": case["expect"]["coinbase_txid"],
                "time": job["time"],
                "coinb1": job["coinb1"],
                "coinb2": job["coinb2"],
                "extranonce": job["extranonce"],
            }
        }
    })
}

pub fn vector_extranonce(i: usize) -> [u8; EXTRANONCE_LEN] {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    hex::decode(v["cases"][i]["job"]["extranonce"].as_str().unwrap()).unwrap().try_into().unwrap()
}

pub fn n_vectors() -> usize {
    let v: Value = serde_json::from_str(VECTORS).unwrap();
    v["cases"].as_array().unwrap().len()
}

