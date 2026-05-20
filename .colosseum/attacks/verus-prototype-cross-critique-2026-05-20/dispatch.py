#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
Cross-critique dispatch for Round D Criticals 4 and 5.

Both findings were Claude-only in Round D. The v0.4 methodology Ask O
calls for cross-critique as the standard post-fan-out step before
committing to a fix. This script dispatches the two findings to 5 cloud
voices via opencode, each voice voting DEFEND / CONCEDE / THIRD_OPTION
with reasoning. Claude's own voice is dispatched separately via Agent
subagent for file-access.

Cloud voices (no local LM Studio per user request):
  - openai/gpt-5.5                                       (OAuth, newly added)
  - burnt/gpt-oss-120b
  - burnt/kimi-k2-6                                      (Bug 3 8K-cap)
  - burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b
  - burnt/gemini-3-1-flash-lite

Each (voice, finding) is one `opencode run --model <id> --variant high`
call. The variant=high flag (v0.4 Ask T) increases reasoning effort.

Output: per-(voice, finding) Markdown reports under
  .colosseum/attacks/verus-prototype-cross-critique-2026-05-20/
    <voice-id>-critique-of-critical-{4,5}.md
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/Users/mvid/Development/reliq/quartz")
OUTDIR = REPO / ".colosseum/attacks/verus-prototype-cross-critique-2026-05-20"
OUTDIR.mkdir(parents=True, exist_ok=True)

PER_CALL_TIMEOUT = 1800  # 30 min per (voice, finding) call

VOICES = [
    # (id_slug, opencode_model_id, supports_variant_high)
    ("gpt-5-5",     "openai/gpt-5.5", False),   # OpenAI direct, OAuth; no reasoning_effort variant
    ("gpt-oss-120b","burnt/gpt-oss-120b", True),
    ("kimi-k2-6",   "burnt/kimi-k2-6", True),
    ("nemotron-3-120b-a12b", "burnt/cloudflare-100-cf-nvidia-nemotron-3-120b-a12b", True),
    ("gemini-3-1-flash-lite","burnt/gemini-3-1-flash-lite", False),
]


CRITICAL_4_BRIEF = """## Critical 4 — DstackZk handler does not bind `zkdcap_public_inputs` to wrapper's `compose_hash` / `user_data`

**Target files (read with the Read tool to verify each claim):**
- Verus prototype: `crates/contracts/core/verus-prototype/attested.rs` lines 281-359 (the `dstack_zk_handle` function and its `zk_query_verify_succeeded` spec predicate)
- Production: `crates/contracts/core/src/handler/execute/attested.rs` lines 80-124 (the DstackZkAttestation handler)
- Production: `crates/contracts/core/src/handler/execute/attested.rs` lines 167-196 (the `Attested<M, A>::handle` wrapper for context on the user_data / compose_hash checks)

**Original adversary claim (Round D, Claude, severity: critical):**

An attacker submits `Attested<M, DstackZkAttestation>` where:
- `attestation.user_data = expected_user_data` (matches msg.user_data, passes wrapper line 252 check)
- `attestation.compose_hash = config.mr_enclave` (passes wrapper lines 256-264 check)
- `zkdcap_proof` / `zkdcap_public_inputs` are a *valid* Groth16 proof for a *different* enclave instance, one whose actual report_data and compose_hash differ from the wrapper's claimed values.

The ZK module's `ProofVerifyGnark` verifies the proof against the supplied public inputs; it has no knowledge that the wrapper claimed `compose_hash = X` while the proof's public inputs encode `compose_hash = Y`. The Verus spec at attested.rs:314 is `Ok(true) => zk_query_verify_succeeded(proof, public_inputs, vkey_name)`. The spec contract terminates at "the verifier said yes on these inputs." There is no spec clause linking `public_inputs` back to `wrapper.spec_att_user_data()` or the loaded `RawConfig.mr_enclave`. The production handler constructs the protobuf request using `self.zkdcap_proof` and `self.zkdcap_public_inputs` verbatim, with no on-chain equality check that `public_inputs == sha256(report_data || compose_hash || tcb_status)` or any sub-extraction confirming the proof attests to the claimed `compose_hash`. The wrapper's `compose_hash` check (line 184 of production) compares `config.mr_enclave()` to `attestation.mr_enclave() = self.compose_hash` — a *self-declared* field on the attestation, not one extracted from the proof. This is the central security property of the entire zkdcap pipeline ("the proof attests to *this* enclave") and the Verus spec does not encode it.

Claude's suggested defense: add a spec-level uninterpreted predicate `proof_journal_binds(proof, public_inputs, expected_compose_hash, expected_user_data)` and require it on the Ok branch. The production handler must extract or verify-equal these fields against the zkdcap journal/public inputs before accepting the proof.
"""

CRITICAL_5_BRIEF = """## Critical 5 — `pub_key_matches_sk` binding does not survive `Import::import`

**Target files (read with the Read tool to verify each claim):**
- Verus prototype: `crates/enclave/core/verus-prototype/key_manager.rs` lines 122-126, 156-166 (the `pub_key` exec fn and the `pub_key_matches_sk` theorem)
- Verus prototype: `crates/enclave/core/verus-prototype/key_manager.rs` lines 143-146 (the `import_sk` helper)
- Production: `crates/enclave/core/src/key_manager/default.rs` lines 50-57 (the `Import::import` impl that does `self.sk = SigningKey::from_slice(&data)?`)
- Production: `crates/enclave/core/src/key_manager/dstack.rs` lines 36-141 (the production-default DstackKeyManager, also unmodelled by the prototype)

**Original adversary claim (Round D, Claude, severity: critical):**

Theorem 1 at lines 156-166 of the Verus prototype (`pub_key_matches_sk`) proves the binding invariant `verifying_key_spec(km.sk) == pub_key(&km).0` for a *frozen* `DefaultKeyManager` value. Production `impl Import for DefaultKeyManager` (default.rs lines 49-57) does `self.sk = SigningKey::from_slice(&data)?` — mutating the `sk` field in place. After import, any previously-cached or previously-published `PubKey` is **stale**: it no longer corresponds to `km.sk`. The Verus prototype does not model `import` as a mutation at all; lines 143-146 give a pure `import_sk(bytes) -> Result<SigningKey, KmError>` that returns a fresh key without writing it back to a DefaultKeyManager.

The published `pub_key` is a `VerifyingKey` value held by callers — the contract trustfully retains it as "the enclave's identity." After an import, the enclave begins signing/decrypting with a *different* `sk`, but the contract still has the *old* `pub_key`. Subsequent ECIES-to-pub_key messages decrypt with the wrong key (or fail) and signature verification by the contract uses the wrong public key. The Verus invariant `verifying_key_spec(km.sk) == pub_key(&km).0` is a snapshot property; the temporal property "at every point in time, pub_key_currently_held_by_contract == derive(km.sk_currently_held_by_enclave)" is what matters for security, and it is not proved.

Claude's suggested defense: add a `pub_key_published` ghost field to `DefaultKeyManager`. Prove `import` either invalidates `pub_key_published` (sets it to `None`) or atomically updates it. Alternatively, model the "publish" step explicitly and prove `publish(km) ⇒ pub_key_published(km') == verifying_key_spec(km'.sk)`.
"""


CROSS_CRITIQUE_INSTRUCTIONS = """## Your role

You are participating in a v0.4 methodology cross-critique pass. The two findings above were flagged by a single adversary (Claude) in the Round D fan-out against Quartz's Verus prototype tree. The other voices in Round D (Qwen, GPT-OSS, GLM, Kimi, Gemma) did not surface either finding independently — likely because both require cross-file reading of production Rust that the non-file-access voices lacked. Your job is to validate or refute each finding as a *peer reviewer*.

For each finding, you must vote one of:

- **DEFEND** — the finding is valid as stated. Claude's reasoning is grounded in the actual code, the attack scenario is reachable, and the suggested defense is appropriate. State concretely why.
- **CONCEDE** — the finding is invalid or overstated. Claude misread the code, the attack is unreachable, or the suggested defense overcorrects. State concretely what Claude got wrong with file:line citations.
- **THIRD_OPTION** — the finding's core observation is valid but the framing, severity, or suggested defense is wrong. Propose an alternative formulation. State the refined claim concretely.

Ground every claim in a specific file:line reference. Use the Read tool to verify the code you cite. Do not rely solely on Claude's quotations — verify them.

Be paranoid in both directions: paranoid about Claude's claim (could it be wrong?) AND paranoid about hand-waving away the claim (is the suggested defense actually sufficient?).

## Output format

Produce one structured response covering BOTH findings. Use this skeleton:

```
# Cross-critique by <your voice id>

## Critical 4 vote: <DEFEND | CONCEDE | THIRD_OPTION>

<your reasoning, grounded in file:line refs>

## Critical 5 vote: <DEFEND | CONCEDE | THIRD_OPTION>

<your reasoning, grounded in file:line refs>

## Net recommendation

<one paragraph: which fixes should land in the upstream PR, in what shape>
```

End with the net-recommendation paragraph. Do not include any other sections.
"""


def build_message() -> str:
    return f"""You are reviewing two adversarial findings from the Round D multi-voice review of Quartz's Verus prototype tree at /Users/mvid/Development/reliq/quartz. Round D synthesis is at .colosseum/attacks/verus-prototype-2026-05-14/synthesis.md if you want broader context; the two findings under cross-critique are reproduced verbatim below.

Three Round D criticals were closed in commits ec24934, 832fb2e, and a6232c3 (Criticals 1, 2, 3). Criticals 4 and 5 remained open as Claude-only findings worth a peer-review pass before committing to a fix.

{CRITICAL_4_BRIEF}

{CRITICAL_5_BRIEF}

{CROSS_CRITIQUE_INSTRUCTIONS}
"""


def dispatch_one(voice_id: str, model_id: str, variant_high: bool, message: str) -> dict:
    """Invoke opencode for a single voice."""
    cmd = [
        "opencode", "run",
        "--model", model_id,
    ]
    if variant_high:
        # v0.4 Ask T: reasoning-effort variant=high for spec-class adversarial dispatch
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
    out = OUTDIR / f"{voice_id}-cross-critique.md"
    if result["returncode"] != 0:
        body = (
            f"# {model_id} ({voice_id}) — cross-critique — ERROR\n\n"
            f"- Elapsed: {result['elapsed_s']:.1f}s\n"
            f"- Return code: {result['returncode']}\n\n"
            f"```stderr\n{result['stderr'][:2000]}\n```\n\n"
            f"```stdout\n{result['stdout'][:2000]}\n```\n"
        )
    else:
        body = (
            f"# {model_id} ({voice_id}) — verus-prototype Critical 4 + 5 cross-critique\n\n"
            f"- Elapsed: {result['elapsed_s']:.1f}s\n"
            f"- Model: {model_id}\n\n---\n\n"
            f"{result['stdout']}\n"
        )
    out.write_text(body)
    return out


def extract_votes(content: str) -> tuple[str, str]:
    """Extract C4 and C5 vote tokens from the response body."""
    def find(prefix: str) -> str:
        for line in content.splitlines():
            line_norm = line.lower()
            prefix_norm = prefix.lower()
            if prefix_norm in line_norm:
                for token in ("DEFEND", "CONCEDE", "THIRD_OPTION", "THIRD OPTION"):
                    if token.lower() in line_norm:
                        return token.replace(" ", "_")
        return "<not found>"
    return find("critical 4 vote"), find("critical 5 vote")


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
            c4, c5 = extract_votes(r["stdout"])
            print(f"  OK ({r['elapsed_s']:.1f}s, {len(r['stdout']):,} chars) → {out.name}")
            print(f"     C4 vote: {c4}    C5 vote: {c5}")


if __name__ == "__main__":
    main()
