#!/usr/bin/env python3
"""
Local-model arm of Round C — BATCH 1 (framework specs only).

Framework specs (handshake.qnt + attestation.qnt) are the most important
targets since example specs lean on them. Two-batch split is required because
the full 4-spec prompt exceeds the model's loaded context window.

Output: local-google_gemma-4-26b-a4b-framework.md
"""

import json
import sys
import urllib.request
from pathlib import Path

REPO = Path("/Users/mvid/Development/reliq/quartz")
OUT_DIR = REPO / ".colosseum/attacks/quint-unattacked-2026-05-14"
MODEL = "google/gemma-4-26b-a4b"
OUT_FILE = OUT_DIR / f"local-{MODEL.replace('/', '_')}-framework.md"
URL = "http://localhost:1234/v1/chat/completions"

FILES = [
    ("Intent (CLAUDE.md)", "CLAUDE.md"),
    (
        "Format reference — Round B synthesis (single doc, terse)",
        ".colosseum/attacks/quint-recently-revised-2026-05-14/synthesis.md",
    ),
    ("Handshake framework spec (under review)", "specs/handshake.qnt"),
    ("Attestation framework spec (under review)", "specs/attestation.qnt"),
    (
        "Framework session state (Rust intent)",
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
]


def read(path):
    return (REPO / path).read_text(encoding="utf-8", errors="replace")


def build_prompt():
    parts = [
        "# Adversarial review of 2 framework Quint specs — "
        "local-model arm (Round C, batch 1)\n"
    ]
    parts.append(
        "You are the LOCAL-MODEL arm of a multi-model adversarial review. "
        "Your job is to find structural problems in two Quartz framework "
        "Quint specs that the typechecker / Apalache BMC did not catch. "
        "A Claude arm is running in parallel with file access; diversification "
        "between models is the point.\n"
    )

    parts.append("\n## Specs under review\n")
    parts.append(
        "1. **`specs/handshake.qnt`** (835 lines) — main framework session-"
        "lifecycle spec. Never adversarially reviewed.\n"
        "2. **`specs/attestation.qnt`** (492 lines) — framework attestation "
        "spec. Only `temporal_zk_accept_requires_vkey` was reviewed in Round 1; "
        "the rest has not been.\n"
    )

    parts.append("\n## Output format\n")
    parts.append(
        "Single markdown document. Header block (date 2026-05-14, "
        "round = C.local.framework, adversary = " + MODEL + "). "
        "**Per-spec verdict lines**: "
        "`VERDICT (handshake.qnt): <BREAKS|WEAKENS|HOLDS WITH CAVEATS|HOLDS>` "
        "and similarly for `attestation.qnt`. Then numbered attacks (e.g. "
        "`## 1. [handshake] ...`), each with `**Category**`, `**Severity**` "
        "(advisory/serious/critical), `**Scenario**`, `**Why it succeeds**`, "
        "`**Suggested defense**`. End with a META section.\n"
    )

    parts.append("\n## Attack angles\n")
    parts.append(
        "- Spec-vs-implementation drift (compare Quint vs Rust intent).\n"
        "- Dormant invariants (only nontrivial in narrow reachable states).\n"
        "- Phase-machine completeness (Rust enum states vs Quint phases).\n"
        "- Action-tag refactor hazard (state-only guards brittle to new actions).\n"
        "- Session lifecycle: session_expires, key_rotation, session_recreate.\n"
        "- Authorization modeling (Quint has no implicit caller).\n"
        "- Bounded-universe accuracy.\n"
        "- Vacuous temporal properties.\n"
        "- Mock-mode disclosure paths (enable_mock branches).\n"
    )

    parts.append("\n## Calibration\n")
    parts.append(
        "Round B produced 12 attacks on 2 Quint specs (~960 lines). Two "
        "framework specs at ~1327 lines should produce 8-14 attacks. Reference "
        "exact line numbers and definition names. Depth over breadth.\n"
    )

    parts.append("\n## Material\n")
    for label, path in FILES:
        try:
            content = read(path)
        except FileNotFoundError:
            content = f"[FILE NOT FOUND: {path}]"
        parts.append(f"\n---\n\n### {label}  —  `{path}`\n\n```\n{content}\n```\n")

    parts.append(
        "\n---\n\nNow write the adversarial-review markdown. Output ONLY the "
        "markdown — no preamble, no closing remarks. Begin with the header "
        "block, then both per-spec verdict lines, then numbered attacks, then META.\n"
    )
    return "".join(parts)


def main():
    prompt = build_prompt()
    print(f"[runner] prompt size: {len(prompt):,} chars (~{len(prompt)//4:,} tokens est.)", file=sys.stderr)
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
