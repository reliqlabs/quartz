//! zkdcap proof injection for attested messages.
//!
//! After the enclave produces an attested message with a TDX quote,
//! the host generates a zkdcap Groth16 proof via the gnark prover
//! server and injects it into the attestation before submitting to
//! the contract.
//!
//! The gnark server communicates over a Unix socket (GNARK_SOCKET env var).
//! At ~5s CPU / <1s GPU, proof generation runs inline during the handshake.
//!
//! In mock mode, this is a no-op.

use color_eyre::{eyre::eyre, Result};
use serde_json::Value;
use std::io::{Read, Write};
use tracing::{debug, info, warn};

/// If GNARK_SOCKET is set and the attestation contains a quote,
/// generate a zkdcap proof via the gnark server and inject it into
/// the response JSON.
pub fn inject_zkdcap_proof(mut response: Value, mock: bool) -> Result<Value> {
    if mock {
        debug!("mock mode: skipping zkdcap proof generation");
        return Ok(response);
    }

    let socket_path = match std::env::var("GNARK_SOCKET") {
        Ok(path) => path,
        Err(_) => {
            warn!("GNARK_SOCKET not set, skipping zkdcap proof generation");
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

    info!("Generating zkdcap proof via gnark server...");

    let proof_result = call_gnark_prover(&socket_path, &quote_hex)?;

    // Inject proof fields into the attestation
    if let Some(proof) = proof_result.get("proof") {
        attestation["zkdcap_proof"] = proof.clone();
    }
    if let Some(inputs) = proof_result.get("public_inputs") {
        attestation["zkdcap_public_inputs"] = inputs.clone();
    }
    if let Some(journal) = proof_result.get("journal") {
        attestation["zkdcap_journal"] = journal.clone();
    }

    info!("zkdcap proof generated and injected");
    Ok(response)
}

/// Call the gnark prover server over Unix socket.
///
/// The gnark server expects HTTP POST /prove with:
///   { "quote_hex": "...", "pre_verified_json": {...}, "timestamp": ... }
///
/// For the initial handshake integration, we send the quote_hex and let
/// the gnark server handle collateral fetching and pre-verification
/// internally. This matches the gnark server's /prove-full endpoint.
fn call_gnark_prover(socket_path: &str, quote_hex: &str) -> Result<Value> {
    use serde_json::json;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| eyre!("system time error: {e}"))?
        .as_secs();

    let request_body = json!({
        "quote_hex": quote_hex,
        "timestamp": now_secs,
    });
    let body_bytes =
        serde_json::to_vec(&request_body).map_err(|e| eyre!("serialize request: {e}"))?;

    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .map_err(|e| eyre!("failed to connect to gnark server at {}: {}", socket_path, e))?;

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(60)))
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
        return Err(eyre!(
            "gnark server returned {}: {}",
            status_line,
            body.trim()
        ));
    }

    let body = &response[body_start..];
    serde_json::from_slice(body).map_err(|e| eyre!("parse gnark response: {e}"))
}
