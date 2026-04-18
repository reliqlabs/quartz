/// Encrypt a ballot to the enclave's session public key using ECIES.
///
/// The session pubkey is a SEC1-encoded secp256k1 public key (hex string).
/// The ballot is JSON-serialized and encrypted so only the enclave can read it.

import { encrypt } from "eciesjs";

export interface Ballot {
  ranked_choices: string[];
}

/// Encrypt a ballot for the enclave.
/// Returns hex-encoded ciphertext ready for the SubmitBallot message.
export function encryptBallot(
  sessionPubkeyHex: string,
  ballot: Ballot
): string {
  const plaintext = Buffer.from(JSON.stringify(ballot));
  const pubkeyBytes = Buffer.from(sessionPubkeyHex, "hex");
  const ciphertext = encrypt(pubkeyBytes, plaintext);
  return Buffer.from(ciphertext).toString("hex");
}
