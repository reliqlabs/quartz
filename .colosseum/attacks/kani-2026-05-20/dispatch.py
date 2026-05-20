#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Round E adversarial review dispatch: Kani harness surface.

Target: 41 Kani harnesses across 7 files (1666 lines total). The only
spec-class artifact in the verification pyramid that has never been
adversarially reviewed. Per CLAUDE.md two-agent split, the Colosseum
agent owns the verification surface; the Quartz agent owns the
production code these harnesses test.

Cloud-only voice lineup (4 voices via opencode + Claude subagent
dispatched separately). Excluded:
  - burnt/gemini-3-1-flash-lite (returned empty stdout in Round D
    cross-critique; data point still unexplained)
  - burnt/claude-opus-4-7 (gateway Bug 4: Cloudflare 524 at ~127s on
    long-output dispatches)
  - burnt/claude-sonnet-4-6 (Claude voice is already covered by the
    Agent subagent dispatched in parallel; running a second Claude
    voice via gateway adds duplication, not family diversity)

Voices via opencode:
  - openai/gpt-5.5 (OAuth-backed, new family slot)
  - burnt/gpt-oss-120b (variant=high)
  - burnt/kimi-k2-6 (variant=high; output cap ~8K per Bug 3)
  - burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b (variant=high)

Output: per-voice Markdown reports under
  .colosseum/attacks/kani-2026-05-20/<voice-id>.md
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/Users/mvid/Development/reliq/quartz")
OUTDIR = REPO / ".colosseum/attacks/kani-2026-05-20"
OUTDIR.mkdir(parents=True, exist_ok=True)

PER_CALL_TIMEOUT = 1800

VOICES = [
    # (id_slug, opencode_model_id, supports_variant_high)
    ("gpt-5-5",     "openai/gpt-5.5",                                   False),
    ("gpt-oss-120b","burnt/gpt-oss-120b",                               True),
    ("kimi-k2-6",   "burnt/kimi-k2-6",                                  True),
    ("nemotron-3-120b-a12b", "burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b", True),
]


ATTACK_BRIEF = """
Attack-category emphasis for Round E (Kani harness review):

- **Property correctness**: does the asserted property actually capture
  what the function should guarantee? A harness that asserts a weak
  property (e.g., "doesn't panic") instead of the intended functional
  property is a coverage gap masquerading as verification.

- **Tautological harnesses**: harnesses whose `assert!` is trivially
  true given the setup, or that follow a function call without
  asserting anything about its result (e.g., `let _result = f(...)`
  with no subsequent check). The Verus prototype review found
  multiple tautological theorems; the Kani surface may have the same.

- **Coverage gaps from `kani::any_where` bounds**: bounds chosen for
  Kani tractability that exclude real failure modes. Specifically
  look at `pk_len <= 64` bounds, address-prefix bounds, amount bounds,
  list-length bounds. Are the bounds tight enough to exercise the
  property and loose enough to catch attacker-supplied inputs?

- **Bounded `unwind` cutoffs**: `#[kani::unwind(N)]` annotations cut off
  loops at depth N. Does the harness cover the loops the production
  code actually executes, or does it pass because the unwind bound
  prevents Kani from reaching the failure path?

- **Spec-vs-implementation drift**: a harness that asserts what the
  implementation currently does, not what the spec says it should do.
  Compare each harness to the docstring / intent it claims to verify.

- **Missing harnesses for invariants the production code depends on**:
  the production handler chains (instantiate -> session_create ->
  session_set_pub_key -> attested ops) depend on properties that
  may not be covered by any harness in this set. Identify gaps in
  the harness coverage relative to the production handler flow.

- **`unwrap()` patterns**: harnesses that `unwrap()` a Result/Option
  inside the setup but don't constrain the upstream call. A harness
  that says `let session = create(); let s2 = session.with_pub_key(...).unwrap()`
  asserts that with_pub_key returns Some on the given inputs, but if
  the harness is meant to verify properties that hold whenever
  with_pub_key returns Some, the unwrap couples the two.

- **kani_slow vs kani gating**: the production state.rs has two
  `#[cfg(kani_slow)]` harnesses for LightClientOpts because stdlib
  Backtrace unwinding is too deep. Are these harnesses run in CI?
  If not, the property they claim is not actually verified.

- **Mock-mode invisibility**: production has `#[cfg(feature = "mock")]`
  branches. Do the harnesses cover the production (non-mock) build, or
  only the mock build? If the mock build, the verified properties
  don't apply to deployment.

- **Helper-functions-under-test**: harnesses that test private helpers
  rather than the public API the contract handlers actually invoke.
  A bug in the public API not reachable through the private helper
  is invisible to the harness suite.

Findings expected: 10-25 across the 41 harnesses / 7 files. Per-file
verdicts preferred. Per-attack: severity (critical / serious /
advisory), target file + line, scenario, why it succeeds, suggested
defense.
"""


FILES = [
    # Production harness files (the targets under review)
    ("Kani harnesses: framework session_create msg",
     "crates/contracts/core/src/msg/execute/session_create.rs"),
    ("Kani harnesses: framework session_set_pub_key msg",
     "crates/contracts/core/src/msg/execute/session_set_pub_key.rs"),
    ("Kani harnesses: framework state (Session, LightClientOpts)",
     "crates/contracts/core/src/state.rs"),
    ("Kani harnesses: sealed-auction state",
     "examples/sealed-auction/contracts/src/state.rs"),
    ("Kani harnesses: pingpong state",
     "examples/pingpong/contracts/src/state.rs"),
    ("Kani harnesses: transfers state",
     "examples/transfers/contracts/src/state.rs"),
    ("Kani harnesses: ranked-choice verification",
     "examples/ranked-choice/contracts/src/verification.rs"),
    # Intent: handler files these harnesses are meant to corroborate
    ("Handler: framework session_create handler",
     "crates/contracts/core/src/handler/execute/session_create.rs"),
    ("Handler: framework session_set_pub_key handler",
     "crates/contracts/core/src/handler/execute/session_set_pub_key.rs"),
    ("Contract: sealed-auction contract entry points",
     "examples/sealed-auction/contracts/src/contract.rs"),
    ("Contract: pingpong contract entry points",
     "examples/pingpong/contracts/src/contract.rs"),
    ("Contract: transfers contract entry points",
     "examples/transfers/contracts/src/contract.rs"),
    ("Contract: ranked-choice contract entry points",
     "examples/ranked-choice/contracts/src/contract.rs"),
]


def read(path: str) -> str:
    return (REPO / path).read_text(encoding="utf-8", errors="replace")


def build_message() -> str:
    parts = ["# Round E adversarial review: Kani harness surface\n\n"]
    parts.append(
        "Target: 41 Kani harnesses across 7 files (1666 lines total) in "
        "Quartz's `crates/contracts/core/` framework and four example "
        "contracts (sealed-auction, pingpong, transfers, ranked-choice). "
        "This surface has never been adversarially reviewed; Rounds A "
        "through D covered Lean lifts, Quint specs, and Verus prototypes "
        "respectively. Round E closes the Kani coverage gap.\n\n"
        "The Quartz repo's two-agent split (CLAUDE.md:5-12) puts the "
        "Kani harnesses in the Colosseum-agent's verification surface. "
        "Bugs found here that require production-code changes get flagged "
        "as Quartz-agent follow-ups in the synthesis.\n\n"
    )
    parts.append(ATTACK_BRIEF)
    parts.append("\n## Output format\n\n")
    parts.append(
        "Write a single markdown document. Header block (target files, "
        "intent docs, date 2026-05-20, round = E, adversary = your model "
        "id). **Per-file verdict lines**: "
        "`VERDICT (filename): <BREAKS|WEAKENS|HOLDS WITH CAVEATS|HOLDS>` "
        "for each of the 7 Kani files. Then numbered attacks "
        "(e.g. `## 1. [state.rs] ...`), each with `**Target**` (file + "
        "harness name or line range), `**Category**`, `**Severity**` "
        "(critical/serious/advisory), `**Scenario**`, `**Why it succeeds**`, "
        "`**Suggested defense**`. End with a META section: per-file attack "
        "counts, recurring patterns, recommendation.\n\n"
    )
    parts.append("## Material\n")
    for label, path in FILES:
        try:
            content = read(path)
        except FileNotFoundError:
            content = f"[FILE NOT FOUND: {path}]"
        parts.append(f"\n---\n\n### {label}  —  `{path}`\n\n```rust\n{content}\n```\n")
    parts.append(
        "\n---\n\nWrite the adversarial-review markdown now. Output ONLY "
        "the markdown — no preamble, no closing remarks. Begin with the "
        "header block, then seven per-file verdict lines, then numbered "
        "attacks, then META.\n"
    )
    return "".join(parts)


def dispatch_one(voice_id: str, model_id: str, variant_high: bool, message: str) -> dict:
    cmd = ["opencode", "run", "--model", model_id]
    if variant_high:
        cmd.extend(["--variant", "high"])
    cmd.append(message)

    t0 = datetime.now(timezone.utc)
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PER_CALL_TIMEOUT,
        )
        elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
        return {
            "voice_id": voice_id,
            "model_id": model_id,
            "returncode": r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "elapsed_s": elapsed,
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
        return {
            "voice_id": voice_id,
            "model_id": model_id,
            "returncode": -1,
            "stdout": "",
            "stderr": f"TIMEOUT after {elapsed:.1f}s",
            "elapsed_s": elapsed,
        }


def write_result(voice_id: str, model_id: str, result: dict) -> Path:
    out = OUTDIR / f"{voice_id}.md"
    if result["returncode"] != 0:
        body = (
            f"# {model_id} ({voice_id}) — Kani harness review — ERROR\n\n"
            f"- Elapsed: {result['elapsed_s']:.1f}s\n"
            f"- Return code: {result['returncode']}\n\n"
            f"```stderr\n{result['stderr'][:2000]}\n```\n\n"
            f"```stdout\n{result['stdout'][:2000]}\n```\n"
        )
    else:
        body = (
            f"# {model_id} ({voice_id}) — Kani harness adversarial review (Round E)\n\n"
            f"- Elapsed: {result['elapsed_s']:.1f}s\n"
            f"- Model: {model_id}\n\n---\n\n"
            f"{result['stdout']}\n"
        )
    out.write_text(body)
    return out


def main() -> None:
    msg = build_message()
    print(f"Message size: {len(msg):,} chars (~{len(msg)//4:,} tokens est.)")
    print(f"Output dir:   {OUTDIR}")
    print(f"Voices:       {len(VOICES)}\n")

    only_model = sys.argv[1] if len(sys.argv) > 1 else None

    for voice_id, model_id, var_high in VOICES:
        if only_model and voice_id != only_model:
            continue
        print(f"→ {voice_id} ({model_id}, variant_high={var_high}) ...")
        r = dispatch_one(voice_id, model_id, var_high, msg)
        out = write_result(voice_id, model_id, r)
        if r["returncode"] != 0:
            print(f"  ERR ({r['elapsed_s']:.1f}s, rc={r['returncode']}): {r['stderr'][:200]}")
        else:
            print(f"  OK ({r['elapsed_s']:.1f}s, {len(r['stdout']):,} chars) → {out.name}")


if __name__ == "__main__":
    main()
