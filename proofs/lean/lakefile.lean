import Lake
open Lake DSL

package quartzSpecs where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

-- VCVio (Verified-zkEVM/VCV-io) provides the OracleComp framework used to demote
-- cryptographic axioms (ECIES roundtrip, hash injectivity, etc.) to theorems about
-- oracle handlers. Pinned to v4.29.0 (matches our Lean toolchain).
--
-- VCV-io's lakefile transitively pulls Hax, Loom2, PolyFun, and several C FFI builds
-- (mlkem-native, mldsa-native, c-fn-dsa). We only import `VCVio.OracleComp.*`, so the
-- C builds run but their outputs are not linked into our `Specs` library.
require VCVio from git
  "https://github.com/Verified-zkEVM/VCV-io.git" @ "v4.29.0"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "v4.29.0"

@[default_target]
lean_lib Specs where
  srcDir := "."
