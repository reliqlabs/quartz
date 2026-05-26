/-
  Byte-unpacking helpers for the DCAP verifier (cycle 7.19.b).

  This file isolates the Mathlib-tactic and `List` lemma dependencies
  needed to prove `extractBitVec_take` (the "extraction is local to
  its requested window" property). Carved out of `DcapVerifier.lean`
  in cycle 7.19.b because the proof requires `set` + `List.take_take`
  / `List.drop_take` from Mathlib, and adding those imports to
  `DcapVerifier.lean` directly would cascade through the no-VCVio
  discipline in `Dstack.lean` / `DstackCarriers.lean`.

  Layer invariant: this file imports only Mathlib; it does NOT import
  any `Specs.Quartz.Attestation.*` module. `DcapVerifier.lean` is the
  only consumer, and it imports only the bare def + theorem.
-/

import Mathlib.Data.List.Basic
import Mathlib.Tactic

namespace Specs.Quartz.Attestation.ByteUnpacking

/-- **Helper definition (cycle 7.19.b)**: extract a `BitVec width`
    from a `RawBytes` (= `List UInt8`) buffer at byte offset `offset`
    via little-endian byte unpacking.

    Algorithm: take `⌈width / 8⌉` bytes starting at `offset`, then
    fold them right-to-left such that byte `i` contributes
    `byte_i * 256^i` to the natural-number value.

    Previously declared `opaque` in `DcapVerifier.lean` (cycles
    7.7-7.19); the cycle 7.19.b carve-out gives it a concrete body
    so `extractBitVec_take` can be proved rather than asserted. -/
def extractBitVec (raw : List UInt8) (offset width : Nat) : BitVec width :=
  let bytes := (raw.drop offset).take ((width + 7) / 8)
  BitVec.ofNat width
    (bytes.foldr (fun (b : UInt8) (acc : Nat) => b.toNat + 256 * acc) 0)

/-- **Structural property (cycle 7.19.b, proven theorem)**: extracting
    a `BitVec` from a prefix of `raw` equals extracting from the full
    `raw` when the requested window `[offset, offset + ⌈width/8⌉)`
    lies entirely within the prefix `[0, k)`.

    Previously an axiom in `DcapVerifier.lean` (cycle 7.13); cycle
    7.19.b proves it from `List.drop_take` + `List.take_take`. -/
theorem extractBitVec_take (raw : List UInt8) (offset width k : Nat) :
    offset + (width + 7) / 8 ≤ k →
    extractBitVec raw offset width = extractBitVec (raw.take k) offset width := by
  intro h
  set m := (width + 7) / 8 with hm_def
  have h_le : m ≤ k - offset := Nat.le_sub_of_add_le (by linarith)
  have h_slice :
      (raw.drop offset).take m = ((raw.take k).drop offset).take m := by
    rw [List.drop_take, List.take_take, Nat.min_eq_left h_le]
  show BitVec.ofNat width
        (List.foldr (fun b acc => b.toNat + 256 * acc) 0
          ((raw.drop offset).take m)) =
       BitVec.ofNat width
        (List.foldr (fun b acc => b.toNat + 256 * acc) 0
          (((raw.take k).drop offset).take m))
  rw [h_slice]

end Specs.Quartz.Attestation.ByteUnpacking
