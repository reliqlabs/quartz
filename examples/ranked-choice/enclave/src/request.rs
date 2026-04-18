//! Ranked Choice Voting (Instant-Runoff) tally logic.
//!
//! The enclave receives encrypted ballots from the chain, decrypts them,
//! and runs the instant-runoff algorithm:
//!
//! 1. Count each voter's top remaining choice
//! 2. If any candidate has a majority (>50%), they win
//! 3. Otherwise, eliminate the candidate with the fewest votes
//! 4. Redistribute eliminated candidate's votes to voters' next choices
//! 5. Repeat until a winner is found or one candidate remains
//!
//! Individual ballots are never revealed. Only the round-by-round tallies
//! and the final winner are published.

use cosmwasm_std::{Addr, HexBinary};
use k256::ecdsa::SigningKey;
use ranked_choice_contract::msg::{Ballot, TallyMsg};
use ranked_choice_contract::state::TallyRound;
use std::collections::{HashMap, HashSet};
use tonic::Status;

fn decrypt_ballot(sk: &SigningKey, ciphertext: &HexBinary) -> Result<Ballot, Status> {
    let plaintext =
        ecies::decrypt(&sk.to_bytes(), ciphertext).map_err(|e| Status::internal(e.to_string()))?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| Status::internal(format!("malformed ballot: {e}")))
}

/// Run instant-runoff voting on decrypted ballots.
pub fn tally_election(
    sk: &SigningKey,
    election_id: u64,
    candidates: &[String],
    encrypted_ballots: Vec<(Addr, HexBinary)>,
) -> Result<TallyMsg, Status> {
    // Decrypt all ballots, skip malformed ones
    let mut ballots: Vec<Vec<String>> = Vec::new();
    for (_addr, ciphertext) in &encrypted_ballots {
        match decrypt_ballot(sk, ciphertext) {
            Ok(ballot) => {
                // Filter to only registered candidates, preserving order
                let valid: Vec<String> = ballot
                    .ranked_choices
                    .into_iter()
                    .filter(|c| candidates.contains(c))
                    .collect();
                if !valid.is_empty() {
                    ballots.push(valid);
                }
            }
            Err(_) => {} // skip malformed
        }
    }

    let total_ballots = encrypted_ballots.len() as u32;

    if ballots.is_empty() {
        return Ok(TallyMsg {
            election_id,
            winner: String::new(),
            rounds: vec![],
            total_ballots,
        });
    }

    let mut eliminated: HashSet<String> = HashSet::new();
    let mut rounds: Vec<TallyRound> = Vec::new();
    let mut round_num = 0u32;

    loop {
        round_num += 1;

        // Count first remaining choice for each ballot
        let mut counts: HashMap<String, u32> = HashMap::new();
        for candidate in candidates {
            if !eliminated.contains(candidate) {
                counts.insert(candidate.clone(), 0);
            }
        }

        for ballot in &ballots {
            // Find the voter's top choice among non-eliminated candidates
            if let Some(choice) = ballot.iter().find(|c| !eliminated.contains(c.as_str())) {
                *counts.get_mut(choice).unwrap() += 1;
            }
        }

        let active_count: u32 = counts.values().sum();
        let majority = active_count / 2 + 1;

        // Sort for deterministic output
        let mut count_vec: Vec<(String, u32)> = counts.into_iter().collect();
        count_vec.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        // Check for majority winner
        let has_majority = count_vec
            .first()
            .map(|(_, v)| *v >= majority)
            .unwrap_or(false);

        if has_majority {
            let winner = count_vec[0].0.clone();
            rounds.push(TallyRound {
                round: round_num,
                counts: count_vec,
                eliminated: None,
            });
            return Ok(TallyMsg {
                election_id,
                winner,
                rounds,
                total_ballots,
            });
        }

        // Check if only one candidate remains
        if count_vec.len() <= 1 {
            let winner = count_vec
                .first()
                .map(|(c, _)| c.clone())
                .unwrap_or_default();
            rounds.push(TallyRound {
                round: round_num,
                counts: count_vec,
                eliminated: None,
            });
            return Ok(TallyMsg {
                election_id,
                winner,
                rounds,
                total_ballots,
            });
        }

        // Find the candidate with fewest votes (tiebreak: alphabetical)
        let min_votes = count_vec.last().unwrap().1;
        let loser = count_vec
            .iter()
            .rev()
            .find(|(_, v)| *v == min_votes)
            .unwrap()
            .0
            .clone();

        rounds.push(TallyRound {
            round: round_num,
            counts: count_vec,
            eliminated: Some(loser.clone()),
        });

        eliminated.insert(loser);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::VerifyingKey;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    fn encrypt_ballot(vk: &VerifyingKey, choices: &[&str]) -> HexBinary {
        let ballot = Ballot {
            ranked_choices: choices.iter().map(|s| s.to_string()).collect(),
        };
        let plaintext = serde_json::to_vec(&ballot).unwrap();
        let ciphertext = ecies::encrypt(&vk.to_sec1_bytes(), &plaintext).unwrap();
        ciphertext.into()
    }

    #[test]
    fn test_clear_majority_first_round() {
        let (sk, vk) = keypair();
        let candidates = vec!["Alice".into(), "Bob".into(), "Carol".into()];

        // 3 votes Alice, 1 Bob, 1 Carol → Alice wins round 1
        let ballots = vec![
            (Addr::unchecked("v1"), encrypt_ballot(&vk, &["Alice", "Bob"])),
            (Addr::unchecked("v2"), encrypt_ballot(&vk, &["Alice", "Carol"])),
            (Addr::unchecked("v3"), encrypt_ballot(&vk, &["Alice"])),
            (Addr::unchecked("v4"), encrypt_ballot(&vk, &["Bob", "Alice"])),
            (Addr::unchecked("v5"), encrypt_ballot(&vk, &["Carol", "Bob"])),
        ];

        let result = tally_election(&sk, 1, &candidates, ballots).unwrap();
        assert_eq!(result.winner, "Alice");
        assert_eq!(result.rounds.len(), 1);
    }

    #[test]
    fn test_instant_runoff() {
        let (sk, vk) = keypair();
        let candidates = vec!["Alice".into(), "Bob".into(), "Carol".into()];

        // Round 1: Alice=2, Bob=2, Carol=1 → eliminate Carol
        // Round 2: Carol's voter goes to Bob → Bob=3, Alice=2 → Bob wins
        let ballots = vec![
            (Addr::unchecked("v1"), encrypt_ballot(&vk, &["Alice", "Bob"])),
            (Addr::unchecked("v2"), encrypt_ballot(&vk, &["Alice", "Carol"])),
            (Addr::unchecked("v3"), encrypt_ballot(&vk, &["Bob", "Alice"])),
            (Addr::unchecked("v4"), encrypt_ballot(&vk, &["Bob", "Carol"])),
            (Addr::unchecked("v5"), encrypt_ballot(&vk, &["Carol", "Bob"])),
        ];

        let result = tally_election(&sk, 1, &candidates, ballots).unwrap();
        assert_eq!(result.winner, "Bob");
        assert_eq!(result.rounds.len(), 2);
        assert_eq!(result.rounds[0].eliminated, Some("Carol".to_string()));
    }

    #[test]
    fn test_three_rounds() {
        let (sk, vk) = keypair();
        let candidates = vec!["A".into(), "B".into(), "C".into(), "D".into()];

        // Round 1: A=3, B=2, C=2, D=1 → eliminate D
        // Round 2: D's voter → C: A=3, B=2, C=3 → eliminate B
        // Round 3: B's voters → A: A=5, C=3 → A wins
        let ballots = vec![
            (Addr::unchecked("v1"), encrypt_ballot(&vk, &["A", "B"])),
            (Addr::unchecked("v2"), encrypt_ballot(&vk, &["A", "C"])),
            (Addr::unchecked("v3"), encrypt_ballot(&vk, &["A", "D"])),
            (Addr::unchecked("v4"), encrypt_ballot(&vk, &["B", "A"])),
            (Addr::unchecked("v5"), encrypt_ballot(&vk, &["B", "A"])),
            (Addr::unchecked("v6"), encrypt_ballot(&vk, &["C", "B"])),
            (Addr::unchecked("v7"), encrypt_ballot(&vk, &["C", "A"])),
            (Addr::unchecked("v8"), encrypt_ballot(&vk, &["D", "C"])),
        ];

        let result = tally_election(&sk, 1, &candidates, ballots).unwrap();
        assert_eq!(result.winner, "A");
        assert_eq!(result.rounds.len(), 3);
    }

    #[test]
    fn test_unanimous() {
        let (sk, vk) = keypair();
        let candidates = vec!["Alice".into(), "Bob".into()];

        let ballots = vec![
            (Addr::unchecked("v1"), encrypt_ballot(&vk, &["Alice"])),
            (Addr::unchecked("v2"), encrypt_ballot(&vk, &["Alice"])),
            (Addr::unchecked("v3"), encrypt_ballot(&vk, &["Alice"])),
        ];

        let result = tally_election(&sk, 1, &candidates, ballots).unwrap();
        assert_eq!(result.winner, "Alice");
        assert_eq!(result.rounds.len(), 1);
        assert_eq!(result.rounds[0].counts[0], ("Alice".to_string(), 3));
        assert_eq!(result.rounds[0].counts[1], ("Bob".to_string(), 0));
    }

    #[test]
    fn test_no_ballots() {
        let (sk, _) = keypair();
        let candidates = vec!["Alice".into(), "Bob".into()];
        let result = tally_election(&sk, 1, &candidates, vec![]).unwrap();
        assert_eq!(result.winner, "");
        assert_eq!(result.rounds.len(), 0);
    }

    #[test]
    fn test_invalid_candidates_filtered() {
        let (sk, vk) = keypair();
        let candidates = vec!["Alice".into(), "Bob".into()];

        // Ballot includes "Eve" who isn't a candidate — filtered out
        let ballots = vec![
            (Addr::unchecked("v1"), encrypt_ballot(&vk, &["Eve", "Alice"])),
            (Addr::unchecked("v2"), encrypt_ballot(&vk, &["Bob"])),
            (Addr::unchecked("v3"), encrypt_ballot(&vk, &["Alice"])),
        ];

        let result = tally_election(&sk, 1, &candidates, ballots).unwrap();
        assert_eq!(result.winner, "Alice");
    }

    #[test]
    fn test_malformed_ballot_skipped() {
        let (sk, vk) = keypair();
        let candidates = vec!["Alice".into(), "Bob".into()];

        let ballots = vec![
            (Addr::unchecked("v1"), encrypt_ballot(&vk, &["Alice"])),
            (Addr::unchecked("v2"), HexBinary::from(vec![0xDE, 0xAD])), // garbage
            (Addr::unchecked("v3"), encrypt_ballot(&vk, &["Alice"])),
        ];

        let result = tally_election(&sk, 1, &candidates, ballots).unwrap();
        assert_eq!(result.winner, "Alice");
        assert_eq!(result.total_ballots, 3); // all 3 submitted
    }
}
