//! zkdcap proof injection for attested messages.
//!
//! After the enclave produces an attested message with a TDX quote,
//! the host generates a zkdcap Groth16 proof and injects it into the
//! attestation before submitting to the contract.
//!
//! Proof generation is delegated to an external binary (set via
//! ZKDCAP_PROVER env var) to avoid pulling the SP1 SDK into the CLI.
//!
//! In mock-sgx mode, this is a no-op.

use color_eyre::{eyre::eyre, Result};
use serde_json::Value;
use std::process::Command;
use tracing::{debug, info, warn};

/// If ZKDCAP_PROVER is set and the attestation contains a quote,
/// generate a zkdcap proof and inject it into the response JSON.
///
/// The prover binary is called as:
///   $ZKDCAP_PROVER <quote_hex>
/// and must output JSON on stdout:
///   { "proof": "<hex>", "public_inputs": ["..."], "journal": "<hex>" }
pub fn inject_zkdcap_proof(mut response: Value, mock_sgx: bool) -> Result<Value> {
    if mock_sgx {
        debug!("mock-sgx mode: skipping zkdcap proof generation");
        return Ok(response);
    }

    let prover_bin = match std::env::var("ZKDCAP_PROVER") {
        Ok(bin) => bin,
        Err(_) => {
            warn!("ZKDCAP_PROVER not set, skipping proof generation");
            return Ok(response);
        }
    };

    // Navigate to the attestation field in the response JSON.
    // The structure is: { "msg": {...}, "attestation": { "quote": "...", ... } }
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

    info!("Generating zkdcap proof (this may take several minutes)...");

    let output = Command::new(&prover_bin)
        .arg(&quote_hex)
        .output()
        .map_err(|e| eyre!("Failed to run zkdcap prover '{}': {}", prover_bin, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(eyre!(
            "zkdcap prover failed (exit {}): {}",
            output.status,
            stderr
        ));
    }

    let proof_result: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| eyre!("Failed to parse zkdcap prover output: {}", e))?;

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
