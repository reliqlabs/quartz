/-
  VCV-io integration for the Ecies primitive.

  Companion module to `Specs/Quartz/Crypto/Ecies.lean`. Exposes the
  spec-level ECIES algorithm as a VCV-io `AsymmEncAlg Id` record so that
  future probabilistic refinements (IND-CPA security games, KEM
  composition, etc.) can plug directly into VCV-io's `CryptoFoundations`
  framework.

  Kept in a separate module so that the core `Ecies.lean` (used by the
  downstream protocol theorems and by `UserDataCommit.lean`) remains
  free of VCVio's transitive instance load. The VCVio transitive imports
  bloat type-class search enough to push `Decidable (∃ c, …)` synthesis
  in `UserDataCommit.lean` past the default heartbeat budget.

  Notes:

  * VCV-io's `AsymmEncAlg` carries a `keygen : m (PK × SK)` field;
    our spec only models `keyOf`, not full key generation. We provide
    a `keygen` placeholder under an `Inhabited PrivKey` assumption;
    it is included for API conformance only and is **not** used by
    the protocol theorems.

  * The `m` parameter is `Id` (deterministic); the protocol theorems
    do not need probabilistic semantics for the roundtrip.

  * Downstream probabilistic theorems (e.g. IND-CPA reductions to DDH)
    would instantiate this with `ProbComp` and a randomised `encrypt`.
-/

import VCVio.CryptoFoundations.AsymmEncAlg.Defs
import Specs.Quartz.Crypto.Ecies

namespace Specs.Quartz.Crypto.Ecies

/-- The ECIES algorithm as a VCV-io `AsymmEncAlg` record over the `Id`
    monad. Fields:

    * `keygen` — placeholder using `default` under `Inhabited PrivKey`.
      The protocol theorems do not invoke this field.
    * `encrypt`, `decrypt` — direct lifts of the pure functions in
      `Ecies.lean`. -/
noncomputable def eciesAlg [Inhabited PrivKey] :
    AsymmEncAlg Id Plaintext PubKey PrivKey Ciphertext where
  keygen := pure (keyOf default, default)
  encrypt pk pt := pure (encrypt pk pt)
  decrypt sk ct := pure (decrypt sk ct)

end Specs.Quartz.Crypto.Ecies
