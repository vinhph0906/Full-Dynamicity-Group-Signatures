# NIZK Module – Stern-like Protocol (Math + Code)

This folder implements the Stern-like NIZK used in the lattice-based group signature. It documents both the mathematics and where each piece lives in code.

Contents
- Math overview and notation
- Witness layout and extensions
- Unified equation M·z = u (all blocks)
- Permutations Γ_η and φ(η) encoding
- Commitments (C1/C2/C3) and FS transcript
- VALID set checks and verifier-side constraints
- Code map (functions and files)

Math Overview
- Parameters (from `lattice.PublicParameters`): n, q, k=⌈log₂q⌉, NK=n·k, m=2·NK, m_E=2·(n+ℓ)·k, ℓ=log₂(MaxUsers).
- Matrices: A=[A0|A1] ∈ Z_q^{n×2·NK}, G ∈ Z_q^{n×NK}, tracing matrices B ∈ Z_q^{n×m_E}, P1,P2 ∈ Z_q^{ℓ×m_E}.
- Merkle hash h_A(u0,u1) := bin(A0·u0 + A1·u1 mod q).

Witness Layout and Extensions
- Raw witness ζ = (x, p, bin(j), w_1,…,w_ℓ, r_1, r_2).
- Extensions (Stern sets B^N_t):
  - x* ∈ B^{2m}_m via pairing (1−x_i, x_i).
  - p* ∈ B^{2·NK−1}_{NK} as [p || (1−p)[:-1]] (proves p≠0).
  - p̂ ∈ {0,1}^{4nk-2} = ext(j_ℓ, p*) (CRITICAL: must be in witness structure).
  - j*_i ∈ {0,1}^2 as (1−j_i, j_i).
  - v*_i, w*_i ∈ B^{2·NK}_{NK} (Merkle internal nodes and path elements).
  - v̂_i = ext(b_i, v*_i), ŵ_i = ext(1−b_i, w*_i) with b_i from path direction; ext places second-of-pair entries into either A0 or A1 half.
  - r*_1, r*_2 ∈ B^{2·m_E}_{m_E}.
- Concatenation z = [x* | p* | p̂ | j* | v* | w* | v̂ | ŵ | r*_1 | r*_2].

### Critical Implementation Note (Nov 2025 Fix)
The verifier's dummy witness template MUST include the PHatExt (p̂) component to match the prover's witness structure. Without this, witness segmentation mismatches cause verification failures in challenges 2 and 3. See `nizk/verifier_full.go:createDummyWitness()`.

Unified Equation M·z = u (mod q)
- Root (n rows): A*·v̂_1 + A*·ŵ_1 = G·u_τ, where A* = [A0|0|A1|0] and we select second-of-pair columns (2j+1) inside each half.
- Internal (for i=2..ℓ, n rows): A*·v̂_i + A*·ŵ_i − G·sel(v*_{i−1}) = 0, with sel picking 2j+1 of v*.
- SIS (n rows): A·sel(x*) − G·p = 0, sel picks 2j+1 of x*; p taken from first NK coords of p*.
- LWE-1: B·sel(r*_1) = c1_u (n rows), P1·sel(r*_1) + ⌈q/2⌉·bin(j) = c1_v (ℓ rows).
- LWE-2: B·sel(r*_2) = c2_u (n rows), P2·sel(r*_2) + ⌈q/2⌉·bin(j) = c2_v (ℓ rows).
- u stacks [G·u_τ | 0^{(ℓ−1)·n} | 0^n | c1_u | c1_v | c2_u | c2_v].

Permutations Γ_η and φ(η)
- Γ_η permutes each extended block. For v*, w* permutations are pair-preserving over NK pairs; v̂, ŵ permutations preserve half boundaries and pair order.
- φ(η) encoding (paper-style ext-based bits):
  - For size-2t vectors (x*, v*, w*, r*): mark images of indices (2j+1) ⇒ a vector in B^{2t}_t.
  - For p* of size 2·NK−1: mark images of the first NK indices.
  - For j* of size 2: mark image of index 1.
  - For hat vectors (4·NK): mark second-of-pair images in both halves.
  - We pack φ(η) bits to bytes (MSB-first) before commitment.

Commitments and Transcript
- Commitment scheme: StringCommitment(msg, rnd) (hash-based stand-in for the paper’s string commitment from [22]).
- C1 = StringCommitment( pack(φ(η)) || M·r_z ; pack(ρ1) ).
- C2 = StringCommitment( serialize(Γ_η(r_z)); pack(ρ2) ).
- C3 = StringCommitment( serialize(Γ_η(z+r_z)); pack(ρ3) ).
- Fiat–Shamir transcript binds: message, ciphertexts (c1_u,c1_v,c2_u,c2_v), Merkle root u_τ, a compact M-identifier digest (SHAKE256 over A, G, B, P1, P2), and all commitments.

VALID Set (Verifier Structural Checks)
- Sizes: z length equals expected sum of block sizes.
- Hamming weights: x*, v*_i, w*_i, r*_1, r*_2 exact; each j*_i has weight 1; p* uses nonzero structure check.
- ext-consistency: v̂_i equals ext(b_i, v*_i) and ŵ_i equals ext(1−b_i, w*_i), enforcing zeros in inactive halves.
- Permutations: Bv/Bw must be pair-preserving over NK pairs; BvHat/BwHat preserve half boundaries and pair order.

Code Map (Math → Code)
- Witness and statement: `nizk/proof.go`
- Extension helpers: `nizk/stern.go` (extendToB, extendP, ext, ext2).
- Permutations and Γ_η: `nizk/stern.go` (applyFullPermutation).
- φ(η) encoding (ext-based bits): `nizk/encoding.go` (encodePermutationBits, packBinaryVector).
- Prover (full): `nizk/prover_full.go` (prepareExtendedWitness, buildUnifiedEquation, commitToSyndrome, commitGamma, buildFullTranscript).
- Verifier (full): `nizk/verifier_full.go` (buildPublicEquation, VerifierFull, verifyPermutation + pair-preserving checks, commitGammaVerifier).
- Configuration toggles: `nizk/config.go` (Debug, StrictPExtStructure).

Usage (Full Protocol)
```go
proof, err := nizk.ProverFull(witness, statement)
err = nizk.VerifierFull(proof, statement, expectedRoot)
```

Toggles
- `Debug` (default false): enable diagnostic prints.
- `StrictPExtStructure` (default false): optional post-permutation p* structure warning.

Notes
- Our StringCommitment is a simple hash-based construction standing in for [22]. Swap to the exact scheme if strict adherence is required.
- φ(η) includes v̂/ŵ parts; these can be omitted to reduce size if you prefer (requires consistent changes on both sides).
