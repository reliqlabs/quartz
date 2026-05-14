#!/usr/bin/env python3
"""
Local-model arm of Round B: adversarial review of 2 recently-revised Quint specs
(examples/sealed-auction/specs/auction.qnt and examples/ranked-choice/specs/ranked-choice.qnt).

Posts to LM Studio's OpenAI-compatible API on localhost:1234 with
google/gemma-4-26b-a4b, matching the prior multimodel attack pattern.

Output: local-google_gemma-4-26b-a4b.md alongside this script.
"""

import json
import sys
import urllib.request
from pathlib import Path

REPO = Path("/Users/mvid/Development/reliq/quartz")
OUT_DIR = REPO / ".colosseum/attacks/quint-recently-revised-2026-05-14"
MODEL = "google/gemma-4-26b-a4b"
OUT_FILE = OUT_DIR / f"local-{MODEL.replace('/', '_')}.md"
URL = "http://localhost:1234/v1/chat/completions"

# Files to inline into the prompt
FILES = [
    # Intent + format reference
    ("Intent (CLAUDE.md)", "CLAUDE.md"),
    (
        "Format reference 1 — prior Quint attack (claude.md)",
        ".colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/claude.md",
    ),
    (
        "Format reference 2 — prior Quint synthesis (for the kind of finding to look for)",
        ".colosseum/attacks/temporal_zk_accept_requires_vkey-multimodel-2026-05-12T16-38-48Z/synthesis.md",
    ),
    # The two specs
    ("Sealed-auction spec (under review)", "examples/sealed-auction/specs/auction.qnt"),
    ("Ranked-choice spec (under review)", "examples/ranked-choice/specs/ranked-choice.qnt"),
    # Implementations the specs are supposed to model
    ("Sealed-auction contract state", "examples/sealed-auction/contracts/src/state.rs"),
    ("Sealed-auction enclave request", "examples/sealed-auction/enclave/src/request.rs"),
    ("Ranked-choice contract state", "examples/ranked-choice/contracts/src/state.rs"),
    ("Ranked-choice enclave request", "examples/ranked-choice/enclave/src/request.rs"),
]


def read(path):
    return (REPO / path).read_text(encoding="utf-8", errors="replace")


def build_prompt():
    parts = ["# Adversarial review of 2 recently-revised Quint specs — local-model arm (Round B)\n"]
    parts.append(
        "You are the LOCAL-MODEL arm of a multi-model adversarial review of two recently-revised "
        "Quint specs in the Quartz project. Your job is to find structural problems in the specs "
        "that the typechecker / Apalache BMC did NOT catch — properties that are technically "
        "satisfied but do not capture the system's intent, action guards that should be tighter, "
        "invariants that are dormant, refactor hazards, or coverage gaps. A Claude arm is running "
        "in parallel with file access; diversification of attack angles between models is the "
        "point of this exercise — do not assume Claude will have caught what you see.\n"
    )

    parts.append("\n## Specs under review\n")
    parts.append(
        "1. **`examples/sealed-auction/specs/auction.qnt`** — recently revised (~490 lines, "
        "14 invariants). The revision wired in the `Resolving` phase to match the contract's "
        "`AuctionPhase::Resolving` and added 1 invariant governing the transition.\n"
        "2. **`examples/ranked-choice/specs/ranked-choice.qnt`** — recently revised (~473 lines, "
        "10 invariants, 3 state vars). State-space slimmed for Apalache tractability (dropped "
        "`ballot_history`, `last_action`, `last_voter`, `election_id`; flattened `EnclaveState`; "
        "ballot universe 15→9; voter universe 4→2). `inv_ballot_integrity` was structurally "
        "rephrased as a consequence of the dropping; the spec author claims this is equivalent.\n"
        "\nThe recent revisions are the most likely place for structural issues to have crept in. "
        "Focus there.\n"
    )

    parts.append("\n## Output format\n")
    parts.append(
        "Write a single markdown document. Header block (specs under review, intent doc, "
        "date 2026-05-14, round = B.local, adversary = " + MODEL + "). Then "
        "**PER-SPEC verdict lines** of the form `VERDICT (auction.qnt): <BREAKS|WEAKENS|HOLDS WITH CAVEATS|HOLDS>` "
        "and similarly for `ranked-choice.qnt`. Then numbered attacks (each labelled with which spec "
        "it targets), each with `**Category**`, `**Severity**` (advisory/serious/critical), "
        "`**Scenario**`, `**Why it succeeds**`, `**Suggested defense**`. See the format reference "
        "files below.\n"
    )

    parts.append("\n## Attack angles to consider\n")
    parts.append(
        "- **Spec-vs-implementation drift**: does the Quint spec actually model what the Rust "
        "contract+enclave do? Specifically, were any behaviors *abstracted away* during the "
        "state-space slimming that materially affect the property class?\n"
        "- **Equivalence-claim verification**: ranked-choice's `inv_ballot_integrity` was "
        "rephrased after dropping `ballot_history`. Is the new form actually equivalent to the "
        "old one in all reachable states?\n"
        "- **Dormant invariants**: invariants only nontrivial in a small subset of reachable states.\n"
        "- **Tie-break / deterministic-choice correctness**: ranked-choice's tie-break is "
        "'lexicographically smallest'; sealed-auction has Vickrey. Does the spec match the "
        "Rust code's tie-break?\n"
        "- **Action-tag refactor hazard**: state-only guards brittle to new actions.\n"
        "- **Phase-machine completeness**: sealed-auction now has `Resolving`. Are all "
        "transitions into and out of it modeled correctly?\n"
        "- **Bounded-universe accuracy**: ranked-choice slimmed ballot universe to 9, voter "
        "universe to 2. Does the slim universe admit all failure modes the full universe would "
        "have admitted?\n"
        "- **Quint-vs-Apalache encoding gaps**: failure modes past tested BMC depth (10 for "
        "auction, 7 for ranked-choice).\n"
        "- **Observer/visibility model**: sealed-auction has observer-flag reset semantics. "
        "Is the spec aligned with the enclave's actual disclosure pattern?\n"
    )

    parts.append("\n## Calibration\n")
    parts.append(
        "The prior Quint review found 6 attacks on a single 60-line spec, 4 serious or "
        "critical. Two specs at ~470 and ~490 lines should produce 8-15 attacks across both. "
        "Per-spec verdicts. Reference exact line numbers and definition names. Depth over "
        "breadth — one well-substantiated critical finding beats five vague ones.\n"
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
        "preamble, no closing remarks. Begin with the header block, then both per-spec "
        "verdict lines, then the numbered attacks.\n"
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
