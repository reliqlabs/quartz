//! dstack RTMR3 event-log replay: recover and bind the **compose-hash** — the
//! stable, instance-independent app identity — from the per-instance RTMR3.
//!
//! RTMR3 is a one-way SHA-384 extend chain over a sequence of events (dstack
//! emits compose-hash, instance-id, app-id, key-provider into it), so the final
//! register value differs per instance and can't be pinned as a constant. The
//! fix is to replay the event log: fold `SHA384(prev ‖ entry_digest)` and check
//! the result equals the quote's RTMR3, then read the compose-hash event's
//! payload. This is sound when the caller passes the **proof-bound** RTMR3 as
//! the anchor — a forged log can't replay to the same value.
//!
//! Format + replay mirror dstack's `cc-eventlog` crate (`TdxEvent` +
//! `replay_events`): for dstack runtime events (`event_type ==
//! DSTACK_RUNTIME_EVENT_TYPE`) the extended digest is recomputed from
//! `SHA384(event_type_le ‖ ":" ‖ event ‖ ":" ‖ event_payload)` (binding the
//! payload); other entries extend their stored `digest`.

use serde::Deserialize;
use sha2::{Digest, Sha384};

/// dstack runtime event type (cc-eventlog `DSTACK_RUNTIME_EVENT_TYPE`).
pub const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;
/// RTMR3 is IMR index 3.
pub const RTMR3_IMR: u32 = 3;
/// The dstack event name carrying the app compose-hash.
pub const COMPOSE_HASH_EVENT: &str = "compose-hash";

fn de_hex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
}

/// One confidential-computing event-log entry, matching dstack `cc-eventlog`'s
/// `TdxEvent`. `digest` and `event_payload` are hex strings in the JSON.
#[derive(Clone, Debug, Deserialize)]
pub struct TdxEvent {
    pub imr: u32,
    pub event_type: u32,
    #[serde(default, deserialize_with = "de_hex")]
    pub digest: Vec<u8>,
    pub event: String,
    #[serde(deserialize_with = "de_hex")]
    pub event_payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLogError {
    /// Replayed RTMR3 does not equal the proof-bound RTMR3 (forged/altered log).
    Rtmr3Mismatch,
    /// No `compose-hash` event in RTMR3.
    ComposeHashAbsent,
    /// The compose-hash event payload does not equal the expected value.
    ComposeHashMismatch,
}

fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    let mut h = Sha384::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The digest that was extended into the RTMR for this entry. For dstack runtime
/// events it is recomputed from the (event_type, event, payload) so the payload
/// is cryptographically bound by the replay; otherwise the stored digest.
fn entry_digest(e: &TdxEvent) -> Vec<u8> {
    if e.event_type == DSTACK_RUNTIME_EVENT_TYPE {
        sha384(&[
            &e.event_type.to_le_bytes(),
            b":",
            e.event.as_bytes(),
            b":",
            &e.event_payload,
        ])
        .to_vec()
    } else {
        e.digest.clone()
    }
}

/// Replay RTMR3: fold `SHA384(prev ‖ entry_digest)` over the `imr == 3` entries
/// in order, starting from 48 zero bytes (dstack `replay_events`).
pub fn replay_rtmr3(events: &[TdxEvent]) -> [u8; 48] {
    let mut mr = [0u8; 48];
    for e in events.iter().filter(|e| e.imr == RTMR3_IMR) {
        mr = sha384(&[&mr, &entry_digest(e)]);
    }
    mr
}

/// Replay the event log against the proof-bound `rtmr3`, then bind the
/// compose-hash event's payload to `expected`. Returns Ok iff the log is
/// authentic (replays to `rtmr3`) AND its compose-hash equals `expected`.
pub fn verify_compose_hash(
    events: &[TdxEvent],
    rtmr3: &[u8; 48],
    expected: &[u8],
) -> Result<(), EventLogError> {
    if &replay_rtmr3(events) != rtmr3 {
        return Err(EventLogError::Rtmr3Mismatch);
    }
    // SECURITY: only a dstack RUNTIME event's payload is cryptographically bound
    // into RTMR3 (entry_digest recomputes its digest from the payload). A
    // non-runtime event extends its host-supplied `digest` verbatim, with the
    // `event`/`event_payload` fields NOT covered by that digest. So we must
    // require `event_type == DSTACK_RUNTIME_EVENT_TYPE` here: otherwise a host
    // could replace the genuine runtime compose-hash event with a non-runtime
    // one carrying the SAME stored digest (replay still matches rtmr3) but an
    // arbitrary `event_payload`, forging the bound compose-hash. Matching only
    // runtime events guarantees the payload we compare is the one the replay
    // actually hashed.
    let ch = events
        .iter()
        .find(|e| {
            e.imr == RTMR3_IMR
                && e.event_type == DSTACK_RUNTIME_EVENT_TYPE
                && e.event == COMPOSE_HASH_EVENT
        })
        .ok_or(EventLogError::ComposeHashAbsent)?;
    if ch.event_payload.as_slice() != expected {
        return Err(EventLogError::ComposeHashMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(event: &str, payload: &[u8]) -> TdxEvent {
        TdxEvent {
            imr: RTMR3_IMR,
            event_type: DSTACK_RUNTIME_EVENT_TYPE,
            digest: vec![],
            event: event.to_string(),
            event_payload: payload.to_vec(),
        }
    }

    fn sample_log(compose: &[u8]) -> Vec<TdxEvent> {
        vec![
            rt("compose-hash", compose),
            rt("instance-id", b"instance-xyz"),
            rt("app-id", b"app-123"),
            rt("key-provider", b"kms"),
            // a non-RTMR3 entry (must be ignored by the RTMR3 replay)
            TdxEvent {
                imr: 1,
                event_type: 0,
                digest: vec![9u8; 48],
                event: "kernel".into(),
                event_payload: vec![],
            },
        ]
    }

    #[test]
    fn replay_then_bind_compose_hash() {
        let compose = [0xABu8; 32];
        let log = sample_log(&compose);
        let rtmr3 = replay_rtmr3(&log);
        assert!(verify_compose_hash(&log, &rtmr3, &compose).is_ok());
    }

    #[test]
    fn wrong_expected_compose_hash_rejected() {
        let compose = [0xABu8; 32];
        let log = sample_log(&compose);
        let rtmr3 = replay_rtmr3(&log);
        assert_eq!(
            verify_compose_hash(&log, &rtmr3, &[0xCDu8; 32]),
            Err(EventLogError::ComposeHashMismatch)
        );
    }

    #[test]
    fn tampered_payload_breaks_replay() {
        // An attacker swaps the compose-hash payload but keeps the old rtmr3:
        // the recomputed digest changes, so the replay no longer matches.
        let log_good = sample_log(&[0xABu8; 32]);
        let rtmr3 = replay_rtmr3(&log_good);
        let log_bad = sample_log(&[0x11u8; 32]);
        assert_eq!(
            verify_compose_hash(&log_bad, &rtmr3, &[0x11u8; 32]),
            Err(EventLogError::Rtmr3Mismatch)
        );
    }

    #[test]
    fn forged_non_runtime_compose_hash_rejected() {
        // Attack: a host with a genuine proof for image C_evil replaces the
        // genuine RUNTIME compose-hash event with a NON-runtime event carrying
        // the same stored digest (so the RTMR3 replay is unchanged and still
        // matches the proof-bound rtmr3) but event="compose-hash" and a forged
        // payload (the victim's expected compose-hash). The fix must reject this.
        let c_evil = [0xEEu8; 32];
        let genuine = sample_log(&c_evil);
        let rtmr3 = replay_rtmr3(&genuine); // proof-bound rtmr3 reflects C_evil
        let preserved_digest = entry_digest(&genuine[0]); // runtime compose-hash digest

        let c_forged = [0x11u8; 32];
        let mut forged = genuine.clone();
        forged[0] = TdxEvent {
            imr: RTMR3_IMR,
            event_type: 0, // NON-runtime: digest used verbatim, payload unbound
            digest: preserved_digest,
            event: "compose-hash".into(),
            event_payload: c_forged.to_vec(),
        };

        // Replay still matches (the stored digest preserves the chain) ...
        assert_eq!(replay_rtmr3(&forged), rtmr3);
        // ... but binding the forged compose-hash is rejected: no RUNTIME
        // compose-hash event remains, so the lookup finds nothing.
        assert_eq!(
            verify_compose_hash(&forged, &rtmr3, &c_forged),
            Err(EventLogError::ComposeHashAbsent)
        );
    }

    #[test]
    fn absent_compose_hash() {
        let log = vec![rt("app-id", b"app-123")];
        let rtmr3 = replay_rtmr3(&log);
        assert_eq!(
            verify_compose_hash(&log, &rtmr3, b"whatever"),
            Err(EventLogError::ComposeHashAbsent)
        );
    }

    #[test]
    fn rtmr3_replay_ignores_other_imrs() {
        // Adding/removing a non-imr3 entry must not change the RTMR3 replay.
        let compose = [0x55u8; 32];
        let mut log = sample_log(&compose);
        let rtmr3_a = replay_rtmr3(&log);
        log.push(TdxEvent {
            imr: 0,
            event_type: 0,
            digest: vec![7u8; 48],
            event: "fw".into(),
            event_payload: vec![],
        });
        let rtmr3_b = replay_rtmr3(&log);
        assert_eq!(rtmr3_a, rtmr3_b);
    }

    #[test]
    fn parses_dstack_json_shape() {
        let json = r#"[
          {"imr":3,"event_type":134217729,"digest":"","event":"compose-hash","event_payload":"abcd"},
          {"imr":3,"event_type":134217729,"digest":"","event":"app-id","event_payload":"0011"}
        ]"#;
        let events: Vec<TdxEvent> = serde_json::from_str(json).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event, "compose-hash");
        assert_eq!(events[0].event_payload, vec![0xAB, 0xCD]);
        assert_eq!(events[0].event_type, DSTACK_RUNTIME_EVENT_TYPE);
    }
}
