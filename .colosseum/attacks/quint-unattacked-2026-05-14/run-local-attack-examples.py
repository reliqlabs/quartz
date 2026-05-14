#!/usr/bin/env python3
"""
Local-model arm of Round C — BATCH 2 (example specs only).

Output: local-google_gemma-4-26b-a4b-examples.md
"""

import json
import sys
import urllib.request
from pathlib import Path

REPO = Path("/Users/mvid/Development/reliq/quartz")
OUT_DIR = REPO / ".colosseum/attacks/quint-unattacked-2026-05-14"
MODEL = "google/gemma-4-26b-a4b"
OUT_FILE = OUT_DIR / f"local-{MODEL.replace('/', '_')}-examples.md"
URL = "http://localhost:1234/v1/chat/completions"

FILES = [
    ("Intent (CLAUDE.md)", "CLAUDE.md"),
    (
        "Format reference — Round B synthesis (single doc, terse)",
        ".colosseum/attacks/quint-recently-revised-2026-05-14/synthesis.md",
    ),
    ("Pingpong example spec (under review)", "examples/pingpong/specs/pingpong.qnt"),
    ("Transfers example spec (under review)", "examples/transfers/specs/transfers.qnt"),
    ("Pingpong contract state", "examples/pingpong/contracts/src/state.rs"),
    ("Pingpong contract entrypoints", "examples/pingpong/contracts/src/contract.rs"),
    ("Pingpong enclave request handler", "examples/pingpong/enclave/src/request.rs"),
    ("Transfers contract state", "examples/transfers/contracts/src/state.rs"),
    ("Transfers contract entrypoints", "examples/transfers/contracts/src/contract.rs"),
    ("Transfers enclave request handler", "examples/transfers/enclave/src/request.rs"),
]


def read(path):
    return (REPO / path).read_text(encoding="utf-8", errors="replace")


def build_prompt():
    parts = [
        "# Adversarial review of 2 example Quint specs — "
        "local-model arm (Round C, batch 2)\n"
    ]
    parts.append(
        "You are the LOCAL-MODEL arm of a multi-model adversarial review. "
        "Find structural problems in two Quartz example Quint specs that "
        "Apalache BMC did not catch.\n"
    )

    parts.append("\n## Specs under review\n")
    parts.append(
        "1. **`examples/pingpong/specs/pingpong.qnt`** (452 lines) — canonical "
        "Quartz example (XOR-encrypted round-trip). Never reviewed.\n"
        "2. **`examples/transfers/specs/transfers.qnt`** (487 lines) — private-"
        "balance transfers spec (Quartz's analog of a private ERC-20). Never reviewed.\n"
    )

    parts.append("\n## Output format\n")
    parts.append(
        "Single markdown document. Header block (date 2026-05-14, "
        "round = C.local.examples, adversary = " + MODEL + "). "
        "Per-spec verdict lines: `VERDICT (pingpong.qnt): <BREAKS|WEAKENS|HOLDS WITH CAVEATS|HOLDS>` "
        "and similarly for `transfers.qnt`. Then numbered attacks (e.g. "
        "`## 1. [pingpong] ...`), each with `**Category**`, `**Severity**` "
        "(advisory/serious/critical), `**Scenario**`, `**Why it succeeds**`, "
        "`**Suggested defense**`. End with a META section.\n"
    )

    parts.append("\n## Attack angles\n")
    parts.append(
        "- Spec-vs-implementation drift (compare Quint vs Rust intent).\n"
        "- Privacy / disclosure invariants: transfers should have balance-"
        "privacy properties; pingpong's XOR-encryption is a known weak "
        "primitive — does the spec model it as if it were strong?\n"
        "- Dormant invariants.\n"
        "- Phase-machine completeness.\n"
        "- Action-tag refactor hazard.\n"
        "- Authorization modeling.\n"
        "- Bounded-universe accuracy.\n"
        "- Replay / nonce hygiene (transfers especially).\n"
        "- Balance-conservation invariants (transfers).\n"
    )

    parts.append("\n## Calibration\n")
    parts.append(
        "Round B produced 12 attacks on 2 Quint specs (~960 lines). Two "
        "example specs at ~940 lines should produce 8-14 attacks. Reference "
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
