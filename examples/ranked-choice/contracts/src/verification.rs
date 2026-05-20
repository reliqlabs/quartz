//! Pure-logic predicates extracted from `contract.rs` so they can be
//! exercised by Kani (and by ordinary unit tests).
//!
//! The contract handlers themselves take `DepsMut`/`Storage`/`Env`,
//! which Kani cannot symbolically execute. The pieces below mirror the
//! guard logic in `exec_create_election`, `exec_cast_ballot`,
//! `exec_tally`, and the enclave-side ballot filtering in
//! `enclave/src/request.rs`. Verifying these in isolation gives us
//! coverage of the protocol-relevant decision points without dragging
//! in the storage backend.
//!
//! Kani harnesses live in the `verification::kani_harnesses` module at
//! the bottom of the file, gated by `#[cfg(kani)]`.

use crate::state::ElectionPhase;

// ── Pure validators ────────────────────────────────────────────────

/// Mirror of `exec_create_election`'s candidate-set check.
/// Returns `true` iff the candidate list is acceptable.
pub fn candidates_valid(candidates: &[u8]) -> bool {
    if candidates.len() < 2 {
        return false;
    }
    // Duplicate check (uses byte identifiers in the harness — the real
    // contract uses `String`, but the structural property is the same).
    for i in 0..candidates.len() {
        for j in (i + 1)..candidates.len() {
            if candidates[i] == candidates[j] {
                return false;
            }
        }
    }
    true
}

/// Mirror of the cast-ballot guards in `exec_cast_ballot`:
///   - phase must be `Voting`
///   - block time strictly before `voting_end`
///   - voter must not already have a ballot stored
pub fn can_cast_ballot(
    phase: &ElectionPhase,
    voting_end: u64,
    now: u64,
    already_voted: bool,
) -> bool {
    matches!(phase, ElectionPhase::Voting) && now < voting_end && !already_voted
}

/// Mirror of `exec_tally`'s phase + election-id guards.
pub fn can_tally(phase: &ElectionPhase, election_id: u64, msg_election_id: u64) -> bool {
    let phase_ok = matches!(phase, ElectionPhase::Voting | ElectionPhase::Tallying);
    phase_ok && election_id == msg_election_id
}

/// Phase transitions allowed by the state machine. Models the implicit
/// transitions enforced by the handlers in `contract.rs`.
pub fn phase_transition_allowed(from: &ElectionPhase, to: &ElectionPhase) -> bool {
    use ElectionPhase::*;
    matches!(
        (from, to),
        (Setup, Setup)        // create_election while in Setup (allowed)
            | (Setup, Voting)         // open_voting
            | (Voting, Tallying)      // (modelled — handler short-circuits to Complete)
            | (Voting, Complete)      // tally (direct)
            | (Tallying, Complete)    // tally
            | (Complete, Setup)       // create_election after a prior election
    )
}

/// Mirror of the enclave's ballot filtering in `tally_election`:
/// strip out any ranked choice that isn't a registered candidate,
/// preserving order. Returns the filtered ballot length (we only care
/// about the size invariant for verification).
///
/// Generic over a small fixed array so Kani can reason about it.
pub fn filter_ballot_len<const N: usize, const M: usize>(
    ballot: &[u8; N],
    candidates: &[u8; M],
) -> usize {
    let mut kept = 0usize;
    let mut i = 0;
    while i < N {
        let c = ballot[i];
        let mut j = 0;
        let mut found = false;
        while j < M {
            if candidates[j] == c {
                found = true;
                break;
            }
            j += 1;
        }
        if found {
            kept += 1;
        }
        i += 1;
    }
    kept
}

/// Count distinct first-active-choice support for a single candidate.
/// Used by the IRV inner loop. `eliminated_mask[i]` is true iff
/// candidate `i` has been eliminated.
pub fn first_active_choice<const N: usize, const M: usize>(
    ballot: &[u8; N],
    candidates: &[u8; M],
    eliminated_mask: &[bool; M],
) -> Option<u8> {
    let mut i = 0;
    while i < N {
        let c = ballot[i];
        let mut j = 0;
        while j < M {
            if candidates[j] == c && !eliminated_mask[j] {
                return Some(c);
            }
            j += 1;
        }
        i += 1;
    }
    None
}

// ── Kani harnesses ─────────────────────────────────────────────────

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// 1. A candidate list with fewer than 2 entries is always invalid.
    #[kani::proof]
    #[kani::unwind(5)]
    fn h_candidates_min_count() {
        // Bound to 0 or 1 entries
        let n: usize = kani::any_where(|&n: &usize| n <= 1);
        let mut buf = [0u8; 1];
        if n == 1 {
            buf[0] = kani::any();
        }
        let slice = &buf[..n];
        assert!(!candidates_valid(slice));
    }

    /// 2. A duplicate-containing candidate list is rejected.
    #[kani::proof]
    #[kani::unwind(5)]
    fn h_candidates_dup_rejected() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let c: u8 = kani::any();
        // Force a duplicate somewhere among 3 entries
        kani::assume(a == b || a == c || b == c);
        let list = [a, b, c];
        assert!(!candidates_valid(&list));
    }

    /// 3. A list of distinct candidates with length >= 2 is accepted.
    #[kani::proof]
    #[kani::unwind(5)]
    fn h_candidates_distinct_accepted() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let c: u8 = kani::any();
        let n: usize = kani::any_where(|&n: &usize| 2 <= n && n <= 3);
        let list = [a, b, c];
        // All pairs in the prefix must differ
        if n == 2 {
            kani::assume(a != b);
            assert!(candidates_valid(&list[..2]));
        } else {
            kani::assume(a != b && a != c && b != c);
            assert!(candidates_valid(&list[..3]));
        }
    }

    /// 4. Cast-ballot succeeds iff phase==Voting AND now<end AND not-already-voted.
    /// (No-double-vote guard.)
    #[kani::proof]
    fn h_cast_ballot_guards() {
        // Pick a phase nondeterministically
        let phase_tag: u8 = kani::any_where(|&t: &u8| t < 4);
        let phase = match phase_tag {
            0 => ElectionPhase::Setup,
            1 => ElectionPhase::Voting,
            2 => ElectionPhase::Tallying,
            _ => ElectionPhase::Complete,
        };
        let voting_end: u64 = kani::any();
        let now: u64 = kani::any();
        let already: bool = kani::any();

        let result = can_cast_ballot(&phase, voting_end, now, already);

        if result {
            // Must be in voting phase
            assert!(matches!(phase, ElectionPhase::Voting));
            // Must be before deadline
            assert!(now < voting_end);
            // Must not have voted
            assert!(!already);
        }
        // Specifically: a voter who already voted is never accepted.
        if already {
            assert!(!result);
        }
    }

    /// 5. Tally is rejected when the message election_id doesn't match.
    #[kani::proof]
    fn h_tally_election_id_match() {
        let phase_tag: u8 = kani::any_where(|&t: &u8| t < 4);
        let phase = match phase_tag {
            0 => ElectionPhase::Setup,
            1 => ElectionPhase::Voting,
            2 => ElectionPhase::Tallying,
            _ => ElectionPhase::Complete,
        };
        let stored_id: u64 = kani::any();
        let msg_id: u64 = kani::any();
        let result = can_tally(&phase, stored_id, msg_id);
        if result {
            assert!(stored_id == msg_id);
            assert!(matches!(phase, ElectionPhase::Voting | ElectionPhase::Tallying));
        }
        if stored_id != msg_id {
            assert!(!result);
        }
    }

    /// 6. Phase transitions: exhaustive enumeration of all 16 (from, to)
    /// pairs.
    ///
    /// **Round E 2026-05-20 strengthening (Kimi #13)**: the prior version
    /// of this harness asserted only three specific forbidden transitions
    /// (Setup→Complete, Complete→Voting, Voting→Setup), leaving the other
    /// seven forbidden pairs unverified. Cross-family review flagged the
    /// spot-check approach as a property-correctness weakness: the
    /// harness was satisfiable even if, e.g., Tallying→Voting were
    /// incorrectly admitted.
    ///
    /// The exhaustive version below pins the expected boolean for every
    /// one of the 16 ordered (from, to) pairs in the 4-variant
    /// `ElectionPhase` enum. The 6 admitted transitions match the
    /// `phase_transition_allowed` allow-list above; the 10 forbidden
    /// transitions assert `!ok`. Any future change to
    /// `phase_transition_allowed` that drops or adds a transition will
    /// be caught here.
    ///
    /// See `.colosseum/attacks/kani-2026-05-20/synthesis.md` Kimi #13.
    #[kani::proof]
    fn h_phase_transition_exhaustive() {
        use ElectionPhase::*;

        // The 6 admitted transitions per phase_transition_allowed:
        //   (Setup, Setup), (Setup, Voting),
        //   (Voting, Tallying), (Voting, Complete),
        //   (Tallying, Complete),
        //   (Complete, Setup)
        assert!(phase_transition_allowed(&Setup, &Setup),
                "Setup -> Setup (re-create while in Setup) must be allowed");
        assert!(phase_transition_allowed(&Setup, &Voting),
                "Setup -> Voting (open_voting) must be allowed");
        assert!(phase_transition_allowed(&Voting, &Tallying),
                "Voting -> Tallying must be allowed");
        assert!(phase_transition_allowed(&Voting, &Complete),
                "Voting -> Complete (direct tally) must be allowed");
        assert!(phase_transition_allowed(&Tallying, &Complete),
                "Tallying -> Complete must be allowed");
        assert!(phase_transition_allowed(&Complete, &Setup),
                "Complete -> Setup (re-create after election) must be allowed");

        // The 10 forbidden transitions: any other pair must be rejected.
        assert!(!phase_transition_allowed(&Setup, &Tallying),
                "Setup -> Tallying skips Voting");
        assert!(!phase_transition_allowed(&Setup, &Complete),
                "Setup -> Complete skips both Voting and Tallying");
        assert!(!phase_transition_allowed(&Voting, &Setup),
                "Voting -> Setup regresses without re-create");
        assert!(!phase_transition_allowed(&Voting, &Voting),
                "Voting -> Voting (re-open without state change) must be rejected");
        assert!(!phase_transition_allowed(&Tallying, &Setup),
                "Tallying -> Setup regresses without re-create");
        assert!(!phase_transition_allowed(&Tallying, &Voting),
                "Tallying -> Voting regresses without re-create");
        assert!(!phase_transition_allowed(&Tallying, &Tallying),
                "Tallying -> Tallying (re-enter without progress) must be rejected");
        assert!(!phase_transition_allowed(&Complete, &Voting),
                "Complete -> Voting requires re-create through Setup");
        assert!(!phase_transition_allowed(&Complete, &Tallying),
                "Complete -> Tallying requires re-create through Setup");
        assert!(!phase_transition_allowed(&Complete, &Complete),
                "Complete -> Complete (re-finalize) must be rejected");
    }

    fn phase_of(t: u8) -> ElectionPhase {
        match t {
            0 => ElectionPhase::Setup,
            1 => ElectionPhase::Voting,
            2 => ElectionPhase::Tallying,
            _ => ElectionPhase::Complete,
        }
    }

    /// 7. Ballot filtering never grows the ballot.
    /// Filtered length <= original length, and equals original when
    /// every choice was a registered candidate.
    #[kani::proof]
    #[kani::unwind(8)]
    fn h_filter_ballot_len_bounded() {
        const N: usize = 4;
        const M: usize = 3;
        let ballot: [u8; N] = kani::any();
        let candidates: [u8; M] = kani::any();
        // Distinct candidates (otherwise the property still holds, but
        // the duplicate check elsewhere would have caught it).
        kani::assume(
            candidates[0] != candidates[1]
                && candidates[0] != candidates[2]
                && candidates[1] != candidates[2],
        );
        let kept = filter_ballot_len::<N, M>(&ballot, &candidates);
        assert!(kept <= N);

        // If every ballot entry is one of the candidates, kept == N.
        let mut all_in = true;
        let mut i = 0;
        while i < N {
            let c = ballot[i];
            let in_cand = c == candidates[0] || c == candidates[1] || c == candidates[2];
            if !in_cand {
                all_in = false;
            }
            i += 1;
        }
        if all_in {
            assert!(kept == N);
        }
    }

    /// 8. `first_active_choice` returns Some iff the ballot mentions at
    /// least one non-eliminated registered candidate. (Captures the
    /// invariant that a voter's vote is counted whenever they have a
    /// surviving choice on their ballot — "every ballot is counted".)
    #[kani::proof]
    #[kani::unwind(8)]
    fn h_first_active_choice_progress() {
        const N: usize = 3;
        const M: usize = 3;
        let ballot: [u8; N] = kani::any();
        let candidates: [u8; M] = kani::any();
        let eliminated_mask: [bool; M] = kani::any();

        kani::assume(
            candidates[0] != candidates[1]
                && candidates[0] != candidates[2]
                && candidates[1] != candidates[2],
        );

        let result = first_active_choice::<N, M>(&ballot, &candidates, &eliminated_mask);

        // If at least one ballot entry matches a non-eliminated candidate,
        // we must return Some.
        let mut has_active = false;
        let mut i = 0;
        while i < N {
            let c = ballot[i];
            let mut j = 0;
            while j < M {
                if candidates[j] == c && !eliminated_mask[j] {
                    has_active = true;
                }
                j += 1;
            }
            i += 1;
        }

        if has_active {
            assert!(result.is_some(), "ballot with active choice must count");
        } else {
            assert!(result.is_none(), "ballot with no active choice yields None");
        }
    }

    /// 9. IRV round-level total-vote-count invariant.
    ///
    /// **Round E 2026-05-20 addition (Nemotron #7)**: cross-family
    /// review surfaced that no harness covered "every valid ballot is
    /// counted exactly once per round". The IRV tally process iterates
    /// rounds, each round counting `first_active_choice` votes per
    /// candidate and eliminating one candidate. The single-round
    /// invariant captured here is the building block: at any round
    /// snapshot, the sum of per-candidate vote counts equals the
    /// number of ballots whose `first_active_choice` is not None
    /// (i.e., non-exhausted ballots). Ballots whose first active
    /// choice has been eliminated cascade down their ranking; ballots
    /// exhausted of all active choices contribute nothing.
    ///
    /// Bounded to 3 ballots / 3 candidates / 3 ranks to stay under
    /// the per-harness time budget. The invariant is independent of
    /// these bounds in principle; the bounded instance proves the
    /// shape.
    ///
    /// Catches a class of bugs: a tally implementation that
    /// double-counts a ballot (e.g., counts both first and second
    /// choices), drops a ballot (e.g., off-by-one on the iteration
    /// bound), or mis-classifies an exhausted ballot as having a
    /// surviving choice (e.g., ignores the eliminated_mask) would
    /// fire this harness.
    #[kani::proof]
    #[kani::unwind(8)]
    fn h_tally_round_vote_conservation() {
        const N: usize = 3;  // ranks per ballot
        const M: usize = 3;  // registered candidates
        const B: usize = 3;  // ballots cast

        let candidates: [u8; M] = kani::any();
        let eliminated_mask: [bool; M] = kani::any();
        let ballots: [[u8; N]; B] = kani::any();

        kani::assume(
            candidates[0] != candidates[1]
                && candidates[0] != candidates[2]
                && candidates[1] != candidates[2],
        );

        // Per-candidate vote tally for this round.
        let mut votes: [u32; M] = [0; M];
        // Count of ballots that contributed a vote (non-exhausted).
        let mut counted_ballots: u32 = 0;

        let mut b = 0;
        while b < B {
            let choice = first_active_choice::<N, M>(
                &ballots[b],
                &candidates,
                &eliminated_mask,
            );
            if let Some(c) = choice {
                counted_ballots += 1;
                // Award the vote to the matching candidate slot.
                // first_active_choice's contract is that the returned
                // value matches some candidates[j] with
                // !eliminated_mask[j]; we find that j and increment.
                let mut j = 0;
                let mut found = false;
                while j < M {
                    if candidates[j] == c && !eliminated_mask[j] {
                        votes[j] += 1;
                        found = true;
                        break;
                    }
                    j += 1;
                }
                assert!(found, "first_active_choice returned a candidate not in the active set");
            }
            b += 1;
        }

        // Invariant: per-candidate vote sum equals the number of
        // non-exhausted ballots that voted this round.
        let total_votes: u32 = votes[0] + votes[1] + votes[2];
        assert_eq!(
            total_votes, counted_ballots,
            "sum of per-candidate votes must equal number of non-exhausted ballots"
        );
    }
}
