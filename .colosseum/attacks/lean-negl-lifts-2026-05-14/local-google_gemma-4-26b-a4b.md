# Adversarial review of 8 Lean `_negl` lifts — local-model arm

- Spec under review: Quartz Protocol-layer VCV-io Lifts (Steps 6.0–6.3)
- Intent doc: `CLAUDE.md` / `.colosseum/ledger.md`
- Date: 2026-05-14
- Round: A.local
- Adversary: google/gemma-4-26b-a4b

VERDICT: WEAKENS

The 8 lifted theorems are technically sound within the provided Lean formalization, but they suffer from a systemic "semantic decoupling." The prover confirms that *if* the cryptographic assumptions hold, the protocol is secure. However, the lifts fail to bridge the gap between these parametric hypotheses and the actual concrete carriers, effectively smuggling mathematical impossibilities and unbounded adversaries into the formal proof surface.

---

## 1. The `IsPPT` Placeholder Loophole (Unbounded Adversary Smuggling)

- **Category**: (d-vacuous-hypothesis)
- **Severity**: critical
- **Scenario**: An adversary with super-polynomial computational resources (e.g., a quantum computer or an exhaustive searcher) finds a collision in the SHA-256 hash used for `commitHashE` or breaks the BN254 discrete log problem to forge a Groth16 proof.
- **Why it succeeds**: In `ProtocolVCVio.lean` (lines 175-180), the predicate `IsPPT` is defined as `True`. While the intent doc (`CLAUDE.md`) acknowledges this as a "placeholder," the lifted theorems (e.g., `cross_component_session_bind_negl` in `ProtocolVCVioQuad.lean`) use this predicate to satisfy the requirements of the VCV-io `SecurityGame`. Because `IsPPT` is vacuously satisfied by *every* adversary, the theorems are technically proven for computationally unbounded adversaries. The "security" being claimed is purely a logical implication of the hypothesis, not a guarantee against real-world attackers.
- **Suggested defense**: Replace the `IsPPT := True` placeholder with a concrete, non-vacuous predicate based on VCV-io's `PolyQueries` as soon as the adversary types are refined to include oracle access.

## 2. Carrier-Refinement Smuggling (The "Parametric Advantage" Trap)

- **Category**: Carrier-refinement smuggling
- **Severity**: serious
- **Scenario**: An auditor reviews `cross_component_session_bind_negl` and concludes the protocol is secure. However, the "advantage" functions (`groth16KSAdv`, `tdxAdv`, etc.) are entirely opaque and parametric.
- **Why it succeeds**: The lifts sidestep the fact that the carriers (e.g., `TdxQuote`, `UserData`) lack `[Fintype]` instances by parameterizing the theorems over an arbitrary advantage function `adv`. The prover confirms that `protocolFailAdv ≤ adv`, but it never proves that for the *actual* concrete carriers, `adv` is actually negligible. The "negligibility" is a precondition provided by the user, not a property derived from the formalization of the carriers. This allows the system to claim "security" even if the underlying carrier types are so small (e.g., a 1-bit `UserData` type) that no negligible advantage could possibly exist.
- **Suggested defense**: Prioritize the "Carrier Refinement" queue in the ledger. The lifts must eventually move from being parametric over an opaque `adv` to being computed from first principles using concrete, finite carrier types.

## 3. Bifurcated Truth (Classical-Negligible Mismatch)

- **Category**: `_classical` re-export honesty
- **Severity**: advisory
- **Scenario**: An engineering team uses the `*_classical` corollaries (e.g., `handshake_binds_ecies_key_classical` in `ProtocolVCVioTriple.lean`) to drive application logic, assuming the mathematical properties of the embeddings are sound.
- **Why it succeeds**: The `_negl` lifts are "honest" because they use collision-resistance hypotheses to bypass the pigeonhole impossibility. However, the `_classical` re-exports (which are explicitly provided for "convenience") rely on the original bundled axioms like `commitHashE : UserDataCommit ↪ UserData`. As noted in the ledger, this axiom is mathematically impossible. This creates a bifurcated formalization where the "security" layer (`_negl`) is truthful, but the "functional" layer (`_classical`) is a mathematical fiction.
- **Suggested defense**: Explicitly mark all `*_classical` corollaries as `noncomputable` or `idealized`, and add a documentation requirement that they cannot be used to derive bounds on real-world collision probabilities.

## 4. Hypothesis Correlation (Summand Dependency)

- **Category**: Hypothesis correlation
- **Severity**: serious
- **Scenario**: An attacker targets the underlying SHA-256 implementation used for both `commitHashE` (Step 2) and `commitHashBytesE` (Step 3).
- **Why it succeeds**: The terminal lift `cross_component_session_bind_negl` (in `ProtocolVCVioQuad.lean`) uses a five-summand union bound. It treats the collision resistance of `hashE` and `hashB` as independent summands in the budget. In practice, if both hashes are derived from the same primitive/hardware, their advantages are highly correlated. While the union bound remains mathematically valid as an upper bound, it masks the fact that the security of the entire terminal lift is bottlenecked by a single cryptographic assumption, potentially leading to an overestimation of the "diversity" of the security surface.
- **Suggested defense**: In the union bound decomposition, explicitly group summands that share a common cryptographic primitive to reflect the true attack surface.

## 5. Intermediate Disjunction Collapse (Visibility Gap)

- **Category**: (d-disjunction-vs-decomposition) collapse at terminal lift
- **Severity**: advisory
- **Scenario**: An auditor performs a partial review, focusing only on the triple-bundle theorems in `ProtocolVCVioTriple.lean`.
- **Why it succeeds**: The "doubled-negligibility" of the Groth16 verifier (KS $\lor$ Circuit Eq) is only expanded at the terminal quadruple-bundle lift (`ProtocolVCVioQuad.lean`). In all intermediate triple-bundle lifts, the disjunction is collapsed into a monolithic `Groth16SoundAdv`. This means the specific software-verification risk (Circuit Eq) is "invisible" to any analysis that does not reach the terminal lift, even though the risk exists at all levels where Groth16 is present.
- **Suggested defense**: Decompose the `groth16Verifier` into its constituent summands (`KS` and `CircuitEq`) in all intermediate lifts, even if the union bound becomes more complex. This ensures the full threat model is visible at every level of composition.