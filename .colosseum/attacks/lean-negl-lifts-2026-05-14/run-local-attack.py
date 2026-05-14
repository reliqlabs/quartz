#!/usr/bin/env python3
"""
Local-model arm of the adversarial-review of the 8 Lean _negl lifts.

Posts to LM Studio's OpenAI-compatible API on localhost:1234 with
google/gemma-4-26b-a4b, matching the prior multimodel attack pattern.

Output: local-google_gemma-4-26b-a4b.md alongside this script.
"""

import json
import sys
import urllib.request
from pathlib import Path

REPO = Path("/Users/mvid/Development/reliq/quartz")
OUT_DIR = REPO / ".colosseum/attacks/lean-negl-lifts-2026-05-14"
MODEL = "google/gemma-4-26b-a4b"
OUT_FILE = OUT_DIR / f"local-{MODEL.replace('/', '_')}.md"
URL = "http://localhost:1234/v1/chat/completions"

# Files to inline into the prompt
FILES = [
    # Intent + methodology
    ("Intent (CLAUDE.md)", "CLAUDE.md"),
    # Prior attack format reference (cut to header + first 2 findings for brevity)
    (
        "Format reference (prior attack, abridged)",
        ".colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/claude.md",
    ),
    # The 8 lifts
    ("ProtocolVCVio.lean (foundations + 1 lift)", "proofs/lean/Specs/Quartz/Protocol/ProtocolVCVio.lean"),
    ("ProtocolVCVioDual.lean (1 lift)", "proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioDual.lean"),
    ("ProtocolVCVioTriple.lean (5 lifts)", "proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioTriple.lean"),
    ("ProtocolVCVioQuad.lean (1 terminal lift)", "proofs/lean/Specs/Quartz/Protocol/ProtocolVCVioQuad.lean"),
    # Classical chain (lifts shadow these)
    ("Handshake.lean (classical)", "proofs/lean/Specs/Quartz/Protocol/Handshake.lean"),
    ("Confidentiality.lean (classical)", "proofs/lean/Specs/Quartz/Protocol/Confidentiality.lean"),
    ("Conservation.lean (classical)", "proofs/lean/Specs/Quartz/Protocol/Conservation.lean"),
    ("AuctionDeterminism.lean (classical)", "proofs/lean/Specs/Quartz/Protocol/AuctionDeterminism.lean"),
    ("CrossComponent.lean (classical terminal)", "proofs/lean/Specs/Quartz/Protocol/CrossComponent.lean"),
    # Carrier-side companions
    ("EciesVCVio.lean", "proofs/lean/Specs/Quartz/Crypto/EciesVCVio.lean"),
    ("UserDataCommitVCVio.lean", "proofs/lean/Specs/Quartz/Crypto/UserDataCommitVCVio.lean"),
    ("RawMessagesVCVio.lean", "proofs/lean/Specs/Quartz/Crypto/RawMessagesVCVio.lean"),
    ("DstackVCVio.lean", "proofs/lean/Specs/Quartz/Attestation/DstackVCVio.lean"),
    ("ZkdcapVCVio.lean", "proofs/lean/Specs/Quartz/Attestation/ZkdcapVCVio.lean"),
    # Ledger (bucket classifications + methodology asks live here)
    ("Ledger (full)", ".colosseum/ledger.md"),
]


def read(path):
    return (REPO / path).read_text(encoding="utf-8", errors="replace")


def build_prompt():
    parts = ["# Adversarial review of 8 Lean `_negl` lifts — local-model arm\n"]
    parts.append(
        "You are the LOCAL-MODEL arm of a multi-model adversarial review of 8 lifted "
        "theorems in a Lean 4 / Mathlib + VCVio formalization of a TEE-mediated CosmWasm "
        "contract framework called Quartz. Your job is to find structural problems in the "
        "8 `_negl` lifts that the prover did NOT catch — cases where the lifted theorem "
        "is technically proven but does not express the property the system actually needs. "
        "A Claude arm is running in parallel; a synthesis pass will compare findings later. "
        "Diversification of attack angles between models is the point of this exercise — "
        "do not assume Claude will have caught what you see.\n"
    )

    parts.append("\n## Output format\n")
    parts.append(
        "Write a single markdown document. Header block (spec under review, intent doc, "
        "date 2026-05-14, round = A.local, adversary = " + MODEL + "). Then a single-line "
        "`VERDICT: <BREAKS|WEAKENS|HOLDS WITH CAVEATS|HOLDS>`. Then numbered attacks, "
        "each with `**Category**`, `**Severity**` (advisory/serious/critical), "
        "`**Scenario**`, `**Why it succeeds**`, `**Suggested defense**`. See the format "
        "reference below.\n"
    )

    parts.append("\n## Required calibration\n")
    parts.append(
        "The prior Quint adversarial review (also shown below) found 6 attacks on a single "
        "60-line spec, 4 of them serious or critical. Eight Lean lifts spanning ~100KB of "
        "source should produce roughly 8-16 attacks at minimum. Aim for depth over breadth. "
        "Reference exact line numbers and definition names.\n"
    )

    parts.append("\n## Attack angles to consider\n")
    parts.append(
        "- **(d-vacuous-hypothesis)**: classical theorem was vacuously satisfied "
        "(e.g. injectivity of a fixed-codomain hash, impossible by pigeonhole). "
        "The lift was supposed to upgrade the hypothesis to a non-vacuous cryptographic "
        "statement. Is the upgrade correct? Could a different, weaker hypothesis fit "
        "the lift while failing to capture real-world threat?\n"
        "- **(d-disjunction-vs-decomposition) collapse at terminal lift**: `groth16Verifier` "
        "carries a disjunction `Groth16-KS ∨ circuit-equivalence`. At the terminal lift "
        "(`cross_component_session_bind_negl`) both disjuncts must be surfaced as parametric "
        "hypotheses. Is anything still collapsed?\n"
        "- **Union-bound tightness**: the terminal lift carries a 5-summand union bound. "
        "Is any summand a loose over-approximation masking a real attack path?\n"
        "- **Hypothesis correlation**: lifts assume negligibility budgets are independent. "
        "Are any correlated in practice (e.g. derived from the same SHA-256 instance)?\n"
        "- **Carrier-refinement smuggling**: 14 abstract carriers sidestepped via parametric "
        "`[Fintype X]`. Could a degenerate `Fintype` instance (e.g. 1-element type) satisfy "
        "the lift while subverting the real claim?\n"
        "- **`IsPPT := True` placeholder**: known gap. Does any lift load-bear on PPT-bounded "
        "adversaries when the predicate is vacuous?\n"
        "- **`_classical` re-export honesty**: do they truly preserve the original classical "
        "theorem, or accidentally weaken / strengthen it?\n"
        "- **Composition-step axiom leakage**: per the ledger all 8 lifts should hide bundle "
        "axioms from their closures uniformly. Does any secretly drag in a bundle axiom?\n"
    )

    parts.append("\n## Material\n")
    for label, path in FILES:
        try:
            content = read(path)
        except FileNotFoundError:
            content = f"[FILE NOT FOUND: {path}]"
        parts.append(f"\n---\n\n### {label}  —  `{path}`\n\n```\n{content}\n```\n")

    parts.append(
        "\n---\n\n"
        "Now write the adversarial-review markdown. Output ONLY the markdown — no "
        "preamble, no closing remarks. Begin with the header block.\n"
    )
    return "".join(parts)


def main():
    prompt = build_prompt()
    print(f"[runner] prompt size: {len(prompt):,} chars (~{len(prompt)//4:,} tokens est.)", file=sys.stderr)
    print(f"[runner] target model: {MODEL}", file=sys.stderr)
    print(f"[runner] writing to:   {OUT_FILE}", file=sys.stderr)

    body = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.6,
        "stream": False,
        "max_tokens": 16000,
    }

    req = urllib.request.Request(
        URL,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=1800) as resp:
        payload = json.loads(resp.read().decode("utf-8"))

    text = payload["choices"][0]["message"]["content"]
    OUT_FILE.write_text(text, encoding="utf-8")
    usage = payload.get("usage", {})
    print(
        f"[runner] done. output {len(text):,} chars. "
        f"usage: prompt={usage.get('prompt_tokens', '?')}, "
        f"completion={usage.get('completion_tokens', '?')}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
