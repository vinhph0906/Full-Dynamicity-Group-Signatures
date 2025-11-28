## Current Status (November 2025)

### ✅ Completed
- Witness extensions, permutations, and Γ_η follow Section A.1 exactly
- Unified equation M·z = u correctly implements Merkle, SIS, and LWE constraints
- PHatExt (p̂) component properly included in verifier's dummy witness (CRITICAL FIX)
- Stern permutations Γ_η verified to be linear (Γ_η(z + r_z) = Γ_η(z) + Γ_η(r_z))
- φ(η) encoding uses ext-based bit encoding
- C1/C2/C3 use StringCommitment (hash-based stand-in for [22])
- VALID checks enforce sizes, weights, and ext structure
- Fiat-Shamir transcript binds message, ciphertexts, Merkle root, and matrix digest
- All three challenge types (1, 2, 3) verify correctly
- E2E tests pass consistently

### 🔧 Outstanding / Optional
- Replace hash-based StringCommitment with the exact scheme from [22] if strict compliance required
- Strict p* validation (post-permutation structure check) remains optional (flag: false)
- Add comprehensive unit tests (M·z = u verification, ext consistency, permutation properties)
- Consider trimming φ(η) encoding (omit hat sections) to reduce proof size if needed

### 🐛 Recent Fixes (November 2025)
**Critical Bug Fixed**: createDummyWitness was missing PHatExt component, causing witness segmentation mismatch between prover and verifier. This caused verification failures in challenges 2 and 3. Fixed by adding:
```go
sw.PHatExt = lattice.NewVector(4*params.NK-2, params.Q)
```

### Test Results
✅ Challenge 1 verification: PASS  
✅ Challenge 2 verification: PASS  
✅ Challenge 3 verification: PASS  
✅ Full e2e test suite: PASS  
✅ Permutation linearity: VERIFIED

Unified Equation M·z = u

Build Merkle constraints:
Add root row: A*·v̂_1 + A*·ŵ_1 = G·u_τ. Use extendMatrix(A) and extendGadgetMatrix(G). nizk/stern.go:518, 547
Add intermediate rows for i=2..ℓ: A*·v̂_i + A*·ŵ_i − G*·v*_{i−1} = 0.
Use v̂_i = ext(j_i, v_i), ŵ_i = ext(1−j_i, w_i). nizk/stern.go:488
Fix LWE rows sizing:
Use n rows for B·r_i blocks; use ℓ rows for P_i·r_i + ⌈q/2⌉·bin(j). Ensure totalRows sums n + (ℓ−1)·n + n + [n + ℓ] + [n + ℓ]. nizk/verifier_full.go:221, 340–377
Align u to include: G·u_τ, zeros for internal Merkle rows, zeros for SIS, then c1_u, c1_v, c2_u, c2_v in correct row sizes. nizk/verifier_full.go:340–370
SIS row:
Use A·x − G·p = 0 on extended columns via A*/G* mapping or explicit selection matrices instead of “odd position” heuristic. nizk/verifier_full.go:268–281
Actually use merkleRoot in u (G·u_τ). nizk/verifier_full.go:212, 340–377
Commitments and permutation encoding

Encode φ(η) as per paper using ext-based binary encodings, not raw integer indices; make it a fixed-length binary vector agreed by both parties.
Replace ad-hoc “compress-to-NK-then-COM” with a paper-faithful string commitment:
Planned: swap C1 to lattice.StringCommitment with fixed-length φ(η) encoding shared by prover and verifier. Currently C1 still uses COM over NK-packed (φ(η)||M·r_z) to keep e2e stable while unifying encoding. lattice/crypto.go:65–120; nizk/prover_full.go:772–940
Option B: Commit blockwise with COM to each NK-sized block and include all in transcript (paper variant often uses a string commitment; keep it consistent).
Ensure COM randomness r ∈ {0,1}^{2·NK} and message u ∈ {0,1}^NK for the COM version used; if a true string commitment is used, keep dimensions consistent with the paper’s definition.
Permutations and VALID

Complete block permutations (π_x, π_p, π_w) and integrate them where the paper requires; currently placeholders. nizk/prover_full.go:555–572
Finalize isInVALID to enforce all structural constraints including p* format and no debug prints. nizk/stern.go:340–409
Fiat–Shamir transcript

Bind to M deterministically (e.g., hash a compact encoding or commitment to M or to public params that fix M such as A, G, B, P1, P2, and the expected Merkle root). nizk/prover_full.go:452–479
Confirm domain separation and ordering are stable across prover/verifier.
Response formats

Make response encodings match paper’s exact layouts for all three challenges (sizes, ordering, and bit encodings).
Update decodePermutation to parse the paper’s φ(η) encoding, not raw indices. nizk/verifier_full.go:428–460
Parameter and dimension sanity

Reconcile all row/column dimensions for M with actual matrix sizes of A (n×2NK), G (n×NK), B (n×m_E), P_i (ℓ×m_E).
Add unit tests for each sub-constraint block to catch dimension mismatches.
Merkle verification

Either integrate Merkle constraints into M (preferred per paper) or explicitly run verifyMerklePath using the public path and expected root; current full verifier doesn’t verify it. nizk/verifier_full.go:259–260; nizk/verifier.go:67
Cleanup and tests

Remove debug prints from VALID checks; add assertions instead. nizk/stern.go:340–409
Add tests that:
Check M·z = u holds for honest witness.
Detect broken j, r1/r2, or Merkle path.
Round-trip the transcript to ensure FS challenges match.
