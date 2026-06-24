//! zkdcap proof generation and attestation type transformation.
//!
//! The enclave produces a DstackAttestation (raw TDX quote). If a Noir/bb
//! prover is available (`ZKDCAP_PROVER_SOCKET`, or the legacy `GNARK_SOCKET`),
//! this module generates an UltraHonk proof and transforms the attestation into
//! a DstackZkAttestation before submitting to the contract.
//!
//! Without a prover socket, the raw DstackAttestation is submitted as-is.
//!
//! The prover (`quartz/../zkdcap/noir-prove-server`) listens on a unix socket
//! and expects `POST /prove {quote_hex, collateral_json, timestamp}`, returning
//! `{proof, public_inputs}` (both base64). It does NOT fetch Intel collateral
//! itself — the caller must supply `collateral_json` (carried on the enclave's
//! attestation response under `collateral`). There is no separate journal: the
//! packed `public_inputs` ARE the journal.
//!
//! In mock mode, this is a no-op.

use color_eyre::{eyre::eyre, Result};
use serde_json::Value;
use std::io::{Read, Write};
use tracing::{debug, info, warn};

/// If a prover socket is set and the attestation contains a quote, generate an
/// UltraHonk proof and transform the attestation from DstackAttestation (raw
/// quote) to DstackZkAttestation (ZK proof). Otherwise the raw DstackAttestation
/// is left as-is.
pub fn inject_zkdcap_proof(mut response: Value, mock: bool) -> Result<Value> {
    if mock {
        debug!("mock mode: skipping zkdcap proof generation");
        return Ok(response);
    }

    // Prefer the new var; fall back to the legacy GNARK_SOCKET name.
    let socket_path = match std::env::var("ZKDCAP_PROVER_SOCKET")
        .or_else(|_| std::env::var("GNARK_SOCKET"))
    {
        Ok(path) => path,
        Err(_) => {
            warn!("ZKDCAP_PROVER_SOCKET not set, submitting raw DstackAttestation");
            return Ok(response);
        }
    };

    // Navigate to the attestation field in the response JSON.
    let attestation = match response.get_mut("attestation") {
        Some(a) => a,
        None => {
            debug!("No attestation field in response, skipping zkdcap");
            return Ok(response);
        }
    };

    let quote_hex = match attestation.get("quote") {
        Some(Value::String(q)) => q.clone(),
        _ => {
            debug!("No quote in attestation, skipping zkdcap");
            return Ok(response);
        }
    };

    if quote_hex.is_empty() {
        debug!("Empty quote, skipping zkdcap");
        return Ok(response);
    }

    // The Noir prover needs Intel collateral (TCB-Info, QE-Identity, certs, CRLs)
    // for this quote's FMSPC. Unlike the old gnark `/prove-full`, it does not
    // fetch collateral itself; the host/enclave must supply it on the attestation
    // response. Fail loudly on a configured-but-unsatisfiable prover rather than
    // silently dropping to an unverifiable raw quote.
    let collateral_json = match attestation.get("collateral") {
        Some(c) if !c.is_null() => c.clone(),
        _ => {
            return Err(eyre!(
                "prover socket is set but the attestation response carries no `collateral`; \
                 the Noir prover requires Intel collateral (see crate docs)"
            ));
        }
    };

    info!("Generating zkdcap proof via Noir prover...");

    let proof_result = call_noir_prover(&socket_path, &quote_hex, &collateral_json)?;

    // Transform DstackAttestation → DstackZkAttestation:
    // keep user_data and compose_hash, replace quote/event_log with proof fields.
    let user_data = attestation.get("user_data").cloned().unwrap_or(Value::Null);
    let compose_hash = attestation.get("compose_hash").cloned().unwrap_or(Value::Null);

    let zk_attestation = serde_json::json!({
        "user_data": user_data,
        "compose_hash": compose_hash,
        "zkdcap_proof": proof_result.get("proof").cloned().unwrap_or(Value::Null),
        "zkdcap_public_inputs": proof_result.get("public_inputs").cloned().unwrap_or(Value::Null),
    });

    *attestation = zk_attestation;

    info!("zkdcap proof generated, attestation transformed to DstackZkAttestation");
    Ok(response)
}

/// Call the Noir prove server over its unix socket.
///
/// Sends `POST /prove {quote_hex, collateral_json, timestamp}` and returns the
/// parsed `{proof, public_inputs}` JSON (both base64).
fn call_noir_prover(socket_path: &str, quote_hex: &str, collateral_json: &Value) -> Result<Value> {
    use serde_json::json;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| eyre!("system time error: {e}"))?
        .as_secs();

    let request_body = json!({
        "quote_hex": quote_hex,
        "collateral_json": collateral_json,
        "timestamp": now_secs,
    });
    let body_bytes =
        serde_json::to_vec(&request_body).map_err(|e| eyre!("serialize request: {e}"))?;

    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .map_err(|e| eyre!("failed to connect to prover at {}: {}", socket_path, e))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(120)))
        .ok();

    let request = format!(
        "POST /prove HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| eyre!("write request: {e}"))?;
    stream
        .write_all(&body_bytes)
        .map_err(|e| eyre!("write body: {e}"))?;
    stream.flush().map_err(|e| eyre!("flush: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| eyre!("read response: {e}"))?;

    let response_str = String::from_utf8_lossy(&response);
    let body_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let status_line = response_str.lines().next().unwrap_or("");

    if !status_line.contains("200") {
        let body = &response_str[body_start..];
        return Err(eyre!("prover returned {}: {}", status_line, body.trim()));
    }

    let body = &response[body_start..];
    serde_json::from_slice(body).map_err(|e| eyre!("parse prover response: {e}"))
}
