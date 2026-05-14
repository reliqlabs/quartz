#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27.0", "python-dotenv>=1.0.0"]
# ///
"""
Round D — 6-voice adversarial fan-out against Quartz's Verus prototype
specifications.

Channels:
  Local (via LM Studio):
    1. mistral-small-4-119b-2603        (non-reasoning)
    2. qwen3.6-27b-mlx                  (reasoning)
    3. google/gemma-4-26b-a4b           (reasoning)

  Gateway:
    4. kimi-k2-6                        (max_tokens=8192, Bug-3 cap)
    5. glm-4-7-flash                    (max_tokens=16384)
    6. gpt-oss-120b                     (max_tokens=16384)

Claude voice runs separately via the Agent subagent (file-access enabled);
this script handles only the non-Claude voices, per the colosseum agent
methodology note on Bug 4 (Anthropic gateway 524 at ~127s).

Each voice attacks the 6 Verus prototype files plus their production Rust
counterparts. The central question: does the Verus prototype's verified
property hold over the production code under reasonable interpretation of
the stubbed primitives?

Output: <channel>-<model-id>.md alongside this script.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from dotenv import load_dotenv

REPO = Path("/Users/mvid/Development/reliq/quartz")
COLOSSEUM = Path("/Users/mvid/Development/reliq/colosseum")
ENV = REPO / ".env"
SPEC_ADV = COLOSSEUM / "agents" / "colosseum-spec-adversary.md"

OUTDIR = REPO / ".colosseum" / "attacks" / "verus-prototype-2026-05-14"
OUTDIR.mkdir(parents=True, exist_ok=True)

LOCAL_ENDPOINT = "http://localhost:1234/v1/chat/completions"
TIMEOUT = 1800.0

load_dotenv(ENV)
GATEWAY_URL = os.environ["COLOSSEUM_GATEWAY_BASE_URL"]
GATEWAY_KEY = os.environ["COLOSSEUM_GATEWAY_API_KEY"]


def strip_frontmatter(text: str) -> str:
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            return text[end + 5:]
    return text


def build_system_prompt() -> str:
    try:
        spec = strip_frontmatter(SPEC_ADV.read_text())
    except FileNotFoundError:
        spec = ""
    base = (
        "You are a hostile spec reviewer in the Colosseum methodology. "
        "Your job is to find ways the Verus prototype under review is "
        "WRONG, WEAK, or MISLEADING relative to its production Rust intent. "
        "Be paranoid; ground every attack in specific text. Do NOT invent "
        "attacks; do NOT soften findings.\n\n"
    )
    return base + spec


FILES = [
    # Production Rust (the intent the Verus prototype is supposed to verify)
    ("Production: state.rs (RawConfig + CONFIG storage)", "crates/contracts/core/src/state.rs"),
    ("Production: handler/execute/attested.rs (6 Handler impls)", "crates/contracts/core/src/handler/execute/attested.rs"),
    ("Production: handler/execute/session_create.rs", "crates/contracts/core/src/handler/execute/session_create.rs"),
    ("Production: handler/execute/session_set_pub_key.rs", "crates/contracts/core/src/handler/execute/session_set_pub_key.rs"),
    ("Production: handler/instantiate.rs", "crates/contracts/core/src/handler/instantiate.rs"),
    ("Production: enclave/core/encryption.rs (ECIES)", "crates/enclave/core/src/encryption.rs"),
    ("Production: enclave/core/key_manager/default.rs", "crates/enclave/core/src/key_manager/default.rs"),
    # Verus prototypes (under review)
    ("Verus: contracts/core/verus-prototype/instantiate.rs", "crates/contracts/core/verus-prototype/instantiate.rs"),
    ("Verus: contracts/core/verus-prototype/attested.rs", "crates/contracts/core/verus-prototype/attested.rs"),
    ("Verus: contracts/core/verus-prototype/session_create.rs", "crates/contracts/core/verus-prototype/session_create.rs"),
    ("Verus: contracts/core/verus-prototype/session_set_pub_key.rs", "crates/contracts/core/verus-prototype/session_set_pub_key.rs"),
    ("Verus: enclave/core/verus-prototype/encryption.rs", "crates/enclave/core/verus-prototype/encryption.rs"),
    ("Verus: enclave/core/verus-prototype/key_manager.rs", "crates/enclave/core/verus-prototype/key_manager.rs"),
]


ATTACK_BRIEF = """
Attack-category emphasis for Round D (Verus prototype review):

- **Stubbing drift**: the prototype monomorphises Verus-unfriendly generics
  (Attested<M,A> → ConcreteMsg/ConcreteAtt), stubs `UserData` as `u64`
  ("opaque 64-byte buffer in production"), and stubs `zkdcap_vkey` as
  `u64` (0 ⇒ empty). Where does the abstraction LOSE a real attack path?

- **external_body holes**: any `#[verifier::external_body]` block is a
  trust boundary — the Verus proof is over the *spec* of the body, not
  the body itself. Where do the production Rust bodies do MORE than the
  spec attests? Concrete suspects: cosmwasm-std `Storage::save/load`,
  ECIES key construction, gRPC `query_grpc`, prost encode/decode.

- **Inner-handler error propagation (Attested<M,A>)**: the prototype
  comment line 43 admits "we lose the ability to prove that an
  inner-handler error propagates to the wrapper" and uses a single
  `external_body` fallible variant as compensation. Is this honest?

- **Missing CONFIG.may_load semantics at instantiate**: the production
  `Attested<M,A>::handle` (line 183) conditionally skips the mr_enclave
  check via `if let Some(config) = CONFIG.may_load(...)`. Does the
  Verus prototype model this conditional? If not, what does it claim?

- **Cosmwasm-std stub mismatch**: the prototypes are "standalone — not
  integrated into production build" (per STATUS.md) and stub
  `cw_storage_plus` + `cosmwasm-std`. Find a specific cosmwasm-std
  behavior the stub misrepresents.

- **Bool/Prop and Option/Result discipline**: any place a spec function
  returns `Option<T>` but the production function returns `Result<T, E>`,
  or vice versa, is a class of unmodeled failure.

- **Mock-mode vs production divergence**: production has `#[cfg(feature
  = "mock")]` Handler impls. Verus prototype proves over which variant?
  Does the verified property survive the cfg switch?

- **ECIES roundtrip / key_manager**: encryption.rs's verified ECIES
  roundtrip — does it actually constrain the production code or is it
  proved over a stub that throws away the cryptographic content?
  key_manager.rs — the "stored sk matches published pk" binding —
  what happens if the stored sk is updated without re-publishing?

- **Sequence number / replay protection**: session_create + session_set_pub_key
  prototypes — do they model the SEQUENCE_NUM bookkeeping that the
  production handlers depend on for replay protection?

Findings expected: 8-20 across the 6 Verus files. Per-file verdicts
preferred. Per-attack: severity (critical / serious / advisory),
target file + line, scenario, why it succeeds, suggested defense.
"""


def read(path):
    return (REPO / path).read_text(encoding="utf-8", errors="replace")


def build_user_prompt() -> str:
    parts = [
        "# Round D — adversarial review of Quartz's Verus prototype specs\n\n"
    ]
    parts.append(
        "**Target**: 6 Verus prototype files at "
        "`crates/{contracts,enclave}/core/verus-prototype/*.rs` (1431 lines "
        "total), plus their production Rust counterparts. "
        "STATUS.md flags these as **standalone — not integrated into "
        "production build**, **`cw_storage_plus` + `cosmwasm-std` stubbed "
        "via `external_body`**, and **proved property is the *spec* of "
        "each external_body block**.\n\n"
        "**Your job**: find places where the Verus-verified property does "
        "NOT actually constrain the production behavior — drift between "
        "the prototype's stubs and the real Rust code, or stubbing choices "
        "that hide a real failure path.\n\n"
        "**Output format**:\n"
        "1. Per-file verdict line: `VERDICT (instantiate.rs): "
        "<BREAKS|WEAKENS|HOLDS WITH CAVEATS|HOLDS>` for each Verus file.\n"
        "2. Numbered attacks. For each: `**Target**`, `**Category**`, "
        "`**Severity**` (critical/serious/advisory), `**Scenario**`, "
        "`**Why it succeeds**`, `**Suggested defense**`. Cite specific "
        "line numbers from the files inlined below.\n"
        "3. META section: per-file counts + recurring patterns.\n\n"
    )
    parts.append(ATTACK_BRIEF)
    parts.append("\n## Material\n")
    for label, path in FILES:
        try:
            content = read(path)
        except FileNotFoundError:
            content = f"[FILE NOT FOUND: {path}]"
        parts.append(f"\n---\n\n### {label}  —  `{path}`\n\n```\n{content}\n```\n")
    parts.append(
        "\n---\n\nNow write the adversarial-review markdown. Output ONLY the "
        "markdown — no preamble, no closing remarks. Begin with the six "
        "per-file verdict lines, then numbered attacks, then META.\n"
    )
    return "".join(parts)


_NO_TEMPERATURE_MODELS = {"claude-opus-4-7"}


async def call_endpoint(
    client: httpx.AsyncClient,
    endpoint: str,
    auth_header: dict[str, str],
    model: str,
    system: str,
    user: str,
    max_tokens: int = 8192,
) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
    }
    if model not in _NO_TEMPERATURE_MODELS:
        payload["temperature"] = 0.3
    t0 = datetime.now(timezone.utc)
    try:
        r = await client.post(endpoint, json=payload, headers=auth_header, timeout=TIMEOUT)
        elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
        if r.status_code != 200:
            return {"model": model, "error": f"HTTP {r.status_code}: {r.text[:500]}", "elapsed_s": elapsed}
        data = r.json()
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {})
        content = msg.get("content") or msg.get("reasoning_content") or ""
        return {
            "model": model,
            "content": content,
            "finish_reason": choice.get("finish_reason"),
            "usage": data.get("usage", {}),
            "elapsed_s": elapsed,
        }
    except Exception as e:
        elapsed = (datetime.now(timezone.utc) - t0).total_seconds()
        return {"model": model, "error": f"{type(e).__name__}: {e}", "elapsed_s": elapsed}


def write_result(channel: str, model: str, result: dict) -> Path:
    slug = model.replace("/", "-").replace(":", "-")
    outpath = OUTDIR / f"{channel}-{slug}.md"
    if "error" in result:
        outpath.write_text(
            f"# {model} ({channel}) — ERROR\n\n"
            f"- Elapsed: {result['elapsed_s']:.1f}s\n\n"
            f"```\n{result['error']}\n```\n"
        )
    else:
        header = (
            f"# {model} ({channel}) — verus-prototype Round D\n\n"
            f"- **Elapsed**: {result['elapsed_s']:.1f}s\n"
            f"- **Finish reason**: {result['finish_reason']}\n"
            f"- **Usage**: {json.dumps(result['usage'])}\n\n---\n\n"
        )
        outpath.write_text(header + result["content"])
    return outpath


def lms_load(model: str) -> bool:
    print(f"  ... `lms load {model}` ...")
    r = subprocess.run(
        ["lms", "load", model, "--gpu", "max"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    ok = r.returncode == 0 and "loaded successfully" in (r.stdout + r.stderr).lower()
    if not ok:
        print(f"  ... lms load FAILED ({r.returncode}): {r.stderr[:300] or r.stdout[:300]}")
    return ok


def extract_verdict(content: str) -> str:
    for line in reversed(content.splitlines()):
        line = line.strip()
        if "VERDICT" in line.upper():
            return line[:240]
    return "<no verdict line found>"


async def main() -> None:
    system = build_system_prompt()
    user = build_user_prompt()

    print(f"System prompt: {len(system):,} chars")
    print(f"User prompt:   {len(user):,} chars (~{len(user)//4:,} tokens est.)")
    print(f"Output dir:    {OUTDIR}")

    REASONING_MAX = 32768
    NON_REASONING_MAX = 16384

    LOCAL_VOICES = [
        ("mistral-small-4-119b-2603", NON_REASONING_MAX),
        ("qwen3.6-27b-mlx", REASONING_MAX),
        ("google/gemma-4-26b-a4b", REASONING_MAX),
    ]
    GATEWAY_VOICES = [
        ("kimi-k2-6", 8192),
        ("glm-4-7-flash", 16384),
        ("gpt-oss-120b", 16384),
    ]

    only_model = sys.argv[1] if len(sys.argv) > 1 else None

    async with httpx.AsyncClient() as client:
        for model, max_tok in LOCAL_VOICES:
            if only_model and model != only_model:
                continue
            print(f"\n→ local/{model} (max_tokens={max_tok}) ...")
            r = None
            for attempt in range(3):
                lms_load(model)
                r = await call_endpoint(client, LOCAL_ENDPOINT, {}, model, system, user, max_tokens=max_tok)
                err_text = r.get("error", "")
                if "Model unloaded" not in err_text and "has not started loading" not in err_text:
                    break
                print(f"  ... attempt {attempt+1} got unload error; retrying after reload")
            out = write_result("local", model, r)
            if "error" in r:
                print(f"  ERR ({r['elapsed_s']:.1f}s): {r['error'][:200]}")
            else:
                print(f"  OK ({r['elapsed_s']:.1f}s, {len(r['content']):,} chars, finish={r['finish_reason']}) → {out.name}")
                print(f"  {extract_verdict(r['content'])}")

        for model, max_tok in GATEWAY_VOICES:
            if only_model and model != only_model:
                continue
            print(f"\n→ gateway/{model} (max_tokens={max_tok}) ...")
            r = await call_endpoint(
                client,
                f"{GATEWAY_URL}/chat/completions",
                {"Authorization": f"Bearer {GATEWAY_KEY}"},
                model,
                system,
                user,
                max_tokens=max_tok,
            )
            out = write_result("gateway", model, r)
            if "error" in r:
                print(f"  ERR ({r['elapsed_s']:.1f}s): {r['error'][:200]}")
            else:
                print(f"  OK ({r['elapsed_s']:.1f}s, {len(r['content']):,} chars, finish={r['finish_reason']}) → {out.name}")
                print(f"  {extract_verdict(r['content'])}")


if __name__ == "__main__":
    asyncio.run(main())
