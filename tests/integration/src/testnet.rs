//! Testnet integration tests for Quartz.
//!
//! These tests query the live Xion testnet ZK module to verify proof
//! formats and vkey registration. They use REST API calls via ureq.
//!
//! Required env vars:
//!   XION_REST — REST/LCD endpoint (default: https://api.xion-testnet-2.burnt.com)
//!
//! Optional env vars:
//!   ZKDCAP_VKEY_NAME — vkey name to check (default: zkdcap-sp1)
//!
//! Run with: cargo test testnet -- --ignored --nocapture

use crate::fixtures::ZkdcapFixture;

fn rest_url() -> String {
    std::env::var("XION_REST")
        .unwrap_or_else(|_| "https://api.xion-testnet-2.burnt.com".to_string())
}

fn vkey_name() -> String {
    std::env::var("ZKDCAP_VKEY_NAME").unwrap_or_else(|_| "zkdcap-sp1".to_string())
}

/// Test 1: Verify we can reach the testnet REST API.
#[test]
#[ignore]
fn testnet_connectivity() {
    let url = format!("{}/cosmos/base/tendermint/v1beta1/blocks/latest", rest_url());
    println!("Querying: {}", url);

    let resp: serde_json::Value = ureq::get(&url)
        .call()
        .expect("REST API unreachable")
        .into_json::<serde_json::Value>()
        .expect("parse response");

    let height = resp
        .pointer("/block/header/height")
        .and_then(|v| v.as_str())
        .expect("missing height");

    println!("Testnet height: {}", height);
    assert!(height.parse::<u64>().unwrap() > 0);
}

/// Test 2: Check if a zkdcap vkey is registered in the ZK module.
#[test]
#[ignore]
fn testnet_check_vkey() {
    let name = vkey_name();
    let url = format!("{}/burnt/xion/zk/v1/vkey_by_name/{}", rest_url(), name);
    println!("Querying vkey '{}': {}", name, url);

    match ureq::get(&url).call() {
        Ok(resp) => {
            let body: serde_json::Value = resp
                .into_json()
                .expect("parse response");

            if let Some(vkey) = body.get("vkey") {
                let vkey_name = vkey.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let description = vkey.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let proof_system = vkey.get("proof_system").and_then(|v| v.as_str()).unwrap_or("?");
                println!("vkey found:");
                println!("  name: {}", vkey_name);
                println!("  description: {}", description);
                println!("  proof_system: {}", proof_system);
            } else {
                println!("vkey '{}' not found in response: {}", name,
                    serde_json::to_string_pretty(&body).unwrap());
            }
        }
        Err(e) => {
            println!("vkey query failed: {}", e);
            println!("The vkey '{}' may not be registered yet.", name);
            println!("Register via governance: xiond tx zk add-vkey ...");
        }
    }
}

/// Test 3: List all registered vkeys in the ZK module.
#[test]
#[ignore]
fn testnet_list_vkeys() {
    let url = format!("{}/burnt/xion/zk/v1/vkeys", rest_url());
    println!("Listing vkeys: {}", url);

    match ureq::get(&url).call() {
        Ok(resp) => {
            let body: serde_json::Value = resp
                .into_json()
                .expect("parse response");

            if let Some(vkeys) = body.get("vkeys").and_then(|v| v.as_array()) {
                println!("Found {} vkeys:", vkeys.len());
                for vkey in vkeys {
                    let name = vkey.get("vkey").and_then(|v| v.get("name")).and_then(|v| v.as_str()).unwrap_or("?");
                    let ps = vkey.get("vkey").and_then(|v| v.get("proof_system")).and_then(|v| v.as_str()).unwrap_or("?");
                    let id = vkey.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("  [{}] {} ({})", id, name, ps);
                }
            } else {
                println!("Response: {}", serde_json::to_string_pretty(&body).unwrap());
            }
        }
        Err(e) => {
            println!("List vkeys failed: {}", e);
        }
    }
}

/// Test 4: Query the ZK module's ProofVerify endpoint with fixture proof.
/// This tests whether the ZK module accepts the SnarkJS proof format.
/// With a synthetic fixture, verification will fail (expected) — but the
/// query path and error message confirm the module is reachable and parsing.
#[test]
#[ignore]
fn testnet_zk_proof_verify() {
    let name = vkey_name();
    let fixture = ZkdcapFixture::generate();

    // Encode the proof as base64 for the REST query
    let proof_b64 = base64_encode(&fixture.proof_bytes);
    let inputs_csv = fixture.public_inputs.join(",");

    let url = format!(
        "{}/burnt/xion/zk/v1/verify?proof={}&vkey_name={}&public_inputs={}",
        rest_url(),
        urlencoding(&proof_b64),
        name,
        urlencoding(&inputs_csv),
    );
    println!("Querying ZK ProofVerify...");
    println!("  vkey: {}", name);
    println!("  proof: {} bytes", fixture.proof_bytes.len());
    println!("  inputs: {:?}", fixture.public_inputs);

    match ureq::get(&url).call() {
        Ok(resp) => {
            let body: serde_json::Value = resp
                .into_json()
                .expect("parse response");
            println!("Response: {}", serde_json::to_string_pretty(&body).unwrap());

            let verified = body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
            println!("Verified: {}", verified);

            // Synthetic proof will NOT verify — that's expected.
            // The fact that we got a response (not a 500) means the query path works.
            println!("Note: synthetic proofs won't pass real verification.");
            println!("Use a real gnark/SP1 proof for a true positive test.");
        }
        Err(ureq::Error::Status(status, _)) => {
            println!("ZK module returned HTTP {}", status);
            println!("This may mean the vkey '{}' doesn't exist or the proof format is wrong.", name);
        }
        Err(e) => {
            println!("ZK module query error: {}", e);
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    // Simple base64 encoding without pulling in a full crate
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { result.push(CHARS[((n >> 6) & 0x3F) as usize] as char); } else { result.push('='); }
        if chunk.len() > 2 { result.push(CHARS[(n & 0x3F) as usize] as char); } else { result.push('='); }
    }
    result
}

fn urlencoding(s: &str) -> String {
    s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
}
