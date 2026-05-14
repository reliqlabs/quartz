#!/usr/bin/env python3
"""
Local-model arm of Round C: adversarial review of 4 previously-unattacked Quint specs.

Targets:
  - specs/handshake.qnt              (framework spec, 835 lines, never attacked)
  - specs/attestation.qnt            (framework spec, 492 lines; only the temporal
                                      property was attacked in Round 1, not the full spec)
  - examples/pingpong/specs/pingpong.qnt   (example, 452 lines, never attacked)
  - examples/transfers/specs/transfers.qnt (example, 487 lines, never attacked)

Posts to LM Studio's OpenAI-compatible API on localhost:1234 with
google/gemma-4-26b-a4b, matching the prior multimodel attack pattern (Round A on
Lean lifts, Round B on auction+ranked-choice).

Output: local-google_gemma-4-26b-a4b.md alongside this script.
"""

import json
import sys
import urllib.request
from pathlib import Path

REPO = Path("/Users/mvid/Development/reliq/quartz")
OUT_DIR = REPO / ".colosseum/attacks/quint-unattacked-2026-05-14"
MODEL = "google/gemma-4-26b-a4b"
OUT_FILE = OUT_DIR / f"local-{MODEL.replace('/', '_')}.md"
URL = "http://localhost:1234/v1/chat/completions"

FILES = [
    # Intent + format reference
    ("Intent (CLAUDE.md)", "CLAUDE.md"),
    (
        "Format reference 1 — Round A on Lean lifts (claude.md)",
        ".colosseum/attacks/lean-negl-lifts-2026-05-14/claude.md",
    ),
    (
        "Format reference 2 — Round B on revised Quint specs (synthesis.md)",
        ".colosseum/attacks/quint-recently-revised-2026-05-14/synthesis.md",
    ),
    (
        "Format reference 3 — Round 1 prior Quint attack (synthesis)",
        ".colosseum/attacks/temporal_zk_accept_requires_vkey-2026-05-12-synthesis.md",
    ),
    # The 4 specs
    ("Handshake framework spec (under review)", "specs/handshake.qnt"),
    ("Attestation framework spec (under review)", "specs/attestation.qnt"),
    ("Pingpong example spec (under review)", "examples/pingpong/specs/pingpong.qnt"),
    ("Transfers example spec (under review)", "examples/transfers/specs/transfers.qnt"),
    # Rust intent for handshake & attestation (framework layer)
    (
        "Framework session state (Rust intent for handshake.qnt)",
        "crates/contracts/core/src/state.rs",
    ),
    (
        "session_create handler",
        "crates/contracts/core/src/handler/execute/session_create.rs",
    ),
    (
        "session_set_pub_key handler",
        "crates/contracts/core/src/handler/execute/session_set_pub_key.rs",
    ),
    (
        "attested handler (DstackAttestation / zkdcap verify)",
        "crates/contracts/core/src/handler/execute/attested.rs",
    ),
    ("DstackAttestor / MockAttestor", "crates/enclave/core/src/attestor.rs"),
    # Rust intent for pingpong example
    ("Pingpong contract state", "examples/pingpong/contracts/src/state.rs"),
    ("Pingpong contract entrypoints", "examples/pingpong/contracts/src/contract.rs"),
    ("Pingpong enclave request handler", "examples/pingpong/enclave/src/request.rs"),
    # Rust intent for transfers example
    ("Transfers contract state", "examples/transfers/contracts/src/state.rs"),
    ("Transfers contract entrypoints", "examples/transfers/contracts/src/contract.rs"),
    ("Transfers enclave request handler", "examples/transfers/enclave/src/request.rs"),
]


def read(path):
    return (REPO / path).read_text(encoding="utf-8", errors="replace")


def build_prompt():
    parts = [
        "# Adversarial review of 4 previously-unattacked Quint specs — "
        "local-model arm (Round C)\n"
    ]
    parts.append(
        "You are the LOCAL-MODEL arm of a multi-model adversarial review of four "
        "Quint specs in the Quartz project that have NOT yet been adversarially "
        "reviewed (or have only had a single sub-property attacked previously). "
        "Your job is to find structural problems the typechecker / Apalache BMC "
        "did NOT catch — properties technically satisfied but not capturing the "
        "system's intent, action guards that should be tighter, invariants that "
        "are dormant, refactor hazards, coverage gaps, or spec-vs-implementation "
        "drift. A Claude arm is running in parallel with file access; "
        "diversification of attack angles between models is the point of this "
        "exercise — do not assume Claude will have caught what you see.\n"
    )

    parts.append("\n## Specs under review\n")
    parts.append(
        "1. **`specs/handshake.qnt`** (835 lines) — the *main framework* Quint "
        "spec. Models the dstack handshake / session-lifecycle protocol that "
        "every Quartz contract instance rides on. Never adversarially reviewed.\n"
        "2. **`specs/attestation.qnt`** (492 lines) — the *main framework* "
        "attestation spec. Only one sub-property (`temporal_zk_accept_requires_vkey`) "
        "was reviewed in Round 1 (May 12); the rest of the spec — including "
        "the actions, the state machine, and the other invariants — has not "
        "been adversarially reviewed.\n"
        "3. **`examples/pingpong/specs/pingpong.qnt`** (452 lines) — the canonical "
        "Quartz example: an enclave that XOR-encrypts a message and round-trips "
        "it. Never adversarially reviewed.\n"
        "4. **`examples/transfers/specs/transfers.qnt`** (487 lines) — a private-balance "
        "transfers spec (Quartz's analog of a private ERC-20). Never adversarially "
        "reviewed.\n"
        "\nThe four specs are independent. Per-spec verdicts.\n"
    )

    parts.append("\n## Output format\n")
    parts.append(
        "Write a single markdown document. Header block (specs under review, "
        "intent doc, date 2026-05-14, round = C.local, adversary = " + MODEL +
        "). Then **PER-SPEC verdict lines** of the form "
        "`VERDICT (handshake.qnt): <BREAKS|WEAKENS|HOLDS WITH CAVEATS|HOLDS>` "
        "for each of the four specs. Then numbered attacks (each labelled with "
        "which spec it targets, e.g. `## 1. [handshake] ...`), each with "
        "`**Category**`, `**Severity**` (advisory/serious/critical), "
        "`**Scenario**`, `**Why it succeeds**`, `**Suggested defense**`. "
        "See the format reference files below.\n"
    )

    parts.append("\n## Attack angles to consider\n")
    parts.append(
        "- **Spec-vs-implementation drift**: does the Quint spec actually model "
        "what the Rust contract+enclave do? The handshake.qnt and attestation.qnt "
        "specs are the framework-layer specs that the example specs lean on — "
        "any drift here propagates.\n"
        "- **Dormant invariants**: invariants only nontrivial in a small subset "
        "of reachable states, or invariants that hold trivially because no "
        "action can falsify them. The Round-1 S1 pattern is a known carrier.\n"
        "- **Phase-machine completeness**: does the spec model all phases the "
        "Rust enum holds, with correct entry/exit transitions?\n"
        "- **Tie-break / deterministic-choice correctness**: any place the spec "
        "must pick deterministically from multiple options is a hazard.\n"
        "- **Action-tag refactor hazard**: state-only guards brittle to new "
        "actions; Round-1 S1 settled this with `last_action == ActVerifyZk`.\n"
        "- **Bounded-universe accuracy**: does the bounded universe admit all "
        "failure modes the full universe would have admitted?\n"
        "- **Quint-vs-Apalache encoding gaps**: failure modes past tested BMC "
        "depth, or properties Apalache cannot encode.\n"
        "- **Observer/visibility model**: privacy claims that are stronger than "
        "what the actual implementation enforces (e.g. bidder-identity "
        "disclosure that's never modeled).\n"
        "- **Authorization / sender modeling**: is admin / role-based access "
        "control modeled? Quint has no implicit caller — explicit modeling "
        "required.\n"
        "- **Session lifecycle**: handshake.qnt is the SOURCE of the "
        "`session_active` predicate that the example specs depend on. Edge "
        "cases (session_expires, key_rotation, session_recreate) are common "
        "hazards.\n"
        "- **Cross-spec composition**: pingpong.qnt and transfers.qnt presumably "
        "embed handshake-spec assumptions; are those assumptions consistent?\n"
        "- **Vacuous temporal properties**: temporal properties that hold "
        "trivially in the action set (Round-1 S1 finding 3 pattern).\n"
        "- **Privacy / disclosure invariants**: transfers.qnt should have "
        "balance-privacy properties; pingpong.qnt's XOR-encryption is a known "
        "weak primitive — does the spec model it as if it were strong?\n"
    )

    parts.append("\n## Calibration\n")
    parts.append(
        "Round A (Lean lifts, 4 files / ~2000 lines) produced 11 attacks. "
        "Round B (2 Quint specs / ~960 lines) produced 12 attacks. Round C "
        "(4 Quint specs / ~2266 lines) should produce 12-20 attacks total "
        "across the four specs. Per-spec verdicts. Reference exact line "
        "numbers and definition names. Depth over breadth — one well-"
        "substantiated critical finding beats five vague ones.\n"
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
        "preamble, no closing remarks. Begin with the header block, then four "
        "per-spec verdict lines, then the numbered attacks.\n"
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
    with urllib.request.urlopen(req, timeout=3600) as resp:
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
