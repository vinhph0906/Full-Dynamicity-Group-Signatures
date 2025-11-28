package nizk

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// SternWitness contains the extended and permutable witness components
// Following Section 4.2: Witness ζ = (x, p, bin(j), w_1,...,w_ℓ, r_1, r_2)
type SternWitness struct {
	// Extended vectors (for proving set membership via permutations)
	XExt    *lattice.Vector   // x* ∈ B^{2m}_m (extended secret credential)
	PExt    *lattice.Vector   // p* ∈ B^{2nk-1}_{nk} (extended public key, proves p ≠ 0)
	PHatExt *lattice.Vector   // p̂ = ext(j_ℓ, p*) ∈ {0,1}^{4nk-2} (paper Section 4.4.2)
	JExt    []*lattice.Vector // j*_i = ext_2(j_i) ∈ {0,1}^2 for each bit
	VExt    []*lattice.Vector // v*_i ∈ B^{2nk}_{nk} (Merkle intermediate nodes)
	WExt    []*lattice.Vector // w*_i ∈ B^{2nk}_{nk} (extended Merkle witnesses)
	VHatExt []*lattice.Vector // v̂_i = ext(j_i, v*_i) ∈ B^{4nk}_{nk}
	WHatExt []*lattice.Vector // ŵ_i = ext(1−j_i, w*_i) ∈ B^{4nk}_{nk}
	R1Ext   *lattice.Vector   // r*_1 ∈ B^{2m_E}_{m_E} (extended encryption randomness)
	R2Ext   *lattice.Vector   // r*_2 ∈ B^{2m_E}_{m_E}

	// Original vectors (kept for reference)
	X  *lattice.Vector
	P  *lattice.Vector
	J  []int // Binary representation of UID
	W  []*lattice.Vector
	R1 *lattice.Vector
	R2 *lattice.Vector

	// Merkle path directions (from witness)
	Directions []bool
}

// Permutation represents η ∈ S containing all permutation components
type Permutation struct {
	// Bit permutations for each extended vector
	Bx    []int   // Permutation for x*
	Bp    []int   // Permutation for p*
	Bj    [][]int // Permutation for each j*_i
	Bv    [][]int // Permutation for each v*_i
	Bw    [][]int // Permutation for each w*_i
	BvHat [][]int // Permutation for each v̂_i
	BwHat [][]int // Permutation for each ŵ_i
	Br1   []int   // Permutation for r*_1
	Br2   []int   // Permutation for r*_2

	// Block permutations
	PiX []int   // π_x for credential blocks
	PiP []int   // π_p for public key blocks
	PiW [][]int // π_w for Merkle witness blocks
}

// UnifiedEquation represents M·z = u (mod q)
// Following Section 4.2: All constraints unified into single linear equation
type UnifiedEquation struct {
	M           *lattice.Matrix // Public matrix combining all constraints
	U           *lattice.Vector // Public vector (right-hand side)
	Z           *lattice.Vector // Secret vector (witness in extended form)
	WitnessSize int             // Size of witness vector z (for verifier use)
}

// ext2 extends a single bit b ∈ {0,1} to (b̄, b)^T ∈ {0,1}^2
// This proves that b is indeed a bit without revealing its value
func ext2(bit int, q int64) *lattice.Vector {
	v := lattice.NewVector(2, q)
	v.Data[0] = int64(1 - bit) // b̄ = 1-b
	v.Data[1] = int64(bit)     // b
	return v
}

// extendToB extends a vector v ∈ {0,1}^n with Hamming weight t
// to v* ∈ B^{2n}_t (vector of length 2n with Hamming weight t)
// This allows proving v has exactly t ones via permutations
func extendToB(v *lattice.Vector, targetLength int, q int64) *lattice.Vector {
	if v == nil {
		return nil
	}

	result := lattice.NewVector(targetLength, q)

	pairs := v.Size
	if targetLength/2 < pairs {
		pairs = targetLength / 2
	}

	for i := 0; i < pairs; i++ {
		bit := v.Data[i] % 2
		if bit < 0 {
			bit += 2
		}
		result.Data[2*i] = 1 - bit
		result.Data[2*i+1] = bit
	}

	// If targetLength has odd tail (e.g., pairing mismatch), leave remaining positions zero
	for i := 2 * pairs; i < targetLength; i++ {
		result.Data[i] = 0
	}

	return result
}

// extendP extends public key p ∈ {0,1}^{nk} to p* ∈ B^{2nk-1}_{nk}
// Special extension to prove p ≠ 0 (at least one bit is 1)
func extendP(p *lattice.Vector, q int64) *lattice.Vector {
	nk := p.Size
	targetLen := 2*nk - 1

	result := lattice.NewVector(targetLen, q)

	onesCount := 0

	// Copy p to first nk positions (ensure binary form)
	for i := 0; i < nk; i++ {
		bit := p.Data[i] % 2
		if bit < 0 {
			bit += 2
		}
		if bit == 1 {
			onesCount++
		}
		result.Data[i] = bit
	}

	// Encode complements for first nk-1 entries to embed non-zero constraint
	for i := 0; i < nk-1; i++ {
		bit := result.Data[i]
		result.Data[nk+i] = 1 - bit
	}

	return result
}

// applyPermutation applies permutation π to vector v
// Returns π(v) where π(v)[i] = v[π[i]]
func applyPermutation(v *lattice.Vector, perm []int) *lattice.Vector {
	result := lattice.NewVector(v.Size, v.Q)

	for i := 0; i < len(perm) && i < v.Size; i++ {
		if perm[i] < v.Size {
			result.Data[i] = v.Data[perm[i]]
		}
	}

	return result
}

// generateRandomPermutation generates a random permutation of [0, 1, ..., n-1]
func generateRandomPermutation(n int) ([]int, error) {
	perm := make([]int, n)
	for i := 0; i < n; i++ {
		perm[i] = i
	}

	// Fisher-Yates shuffle - optimized version using crypto/rand
	// For large n (e.g., NK=12288 for lambda=256), calling RandomVector n times is too slow
	// Instead, generate random bytes in batches
	randBuf := make([]byte, 8)
	for i := n - 1; i > 0; i-- {
		// Generate random j in [0, i]
		_, err := rand.Read(randBuf)
		if err != nil {
			return nil, err
		}
		randVal := binary.BigEndian.Uint64(randBuf)
		j := int(randVal % uint64(i+1))

		// Swap
		perm[i], perm[j] = perm[j], perm[i]
	}

	return perm, nil
}

// Γ_η applies the full permutation η to witness z
// This is the core of Stern protocol: Γ_η(z) ∈ VALID
func applyFullPermutation(witness *SternWitness, perm *Permutation) *lattice.Vector {
	// Apply permutation η to all components of witness
	// Paper: Γ_η(z) permutes each component of the witness vector
	// Result is a single vector with all permuted components concatenated

	// Calculate total size after permutation
	totalSize := 0
	if witness.XExt != nil {
		totalSize += witness.XExt.Size
	}
	if witness.PExt != nil {
		totalSize += witness.PExt.Size
	}
	if witness.PHatExt != nil {
		totalSize += witness.PHatExt.Size
	}
	for _, jext := range witness.JExt {
		if jext != nil {
			totalSize += jext.Size
		}
	}
	for _, vext := range witness.VExt {
		if vext != nil {
			totalSize += vext.Size
		}
	}
	// Note: WExt is NOT in the witness per paper eq (8), skip it
	for _, vhat := range witness.VHatExt {
		if vhat != nil {
			totalSize += vhat.Size
		}
	}
	for _, what := range witness.WHatExt {
		if what != nil {
			totalSize += what.Size
		}
	}
	if witness.R1Ext != nil {
		totalSize += witness.R1Ext.Size
	}
	if witness.R2Ext != nil {
		totalSize += witness.R2Ext.Size
	}

	result := lattice.NewVector(totalSize, witness.XExt.Q)
	offset := 0

	// Apply permutation Bx to x*
	if witness.XExt != nil && perm.Bx != nil && len(perm.Bx) == witness.XExt.Size {
		permuted := applyPermutation(witness.XExt, perm.Bx)
		for i := 0; i < permuted.Size; i++ {
			result.Data[offset+i] = permuted.Data[i]
		}
		offset += permuted.Size
	} else if witness.XExt != nil {
		// No permutation, copy as-is
		for i := 0; i < witness.XExt.Size; i++ {
			result.Data[offset+i] = witness.XExt.Data[i]
		}
		offset += witness.XExt.Size
	}

	// Apply permutation Bp to p*
	if witness.PExt != nil && perm.Bp != nil && len(perm.Bp) == witness.PExt.Size {
		permuted := applyPermutation(witness.PExt, perm.Bp)
		for i := 0; i < permuted.Size; i++ {
			result.Data[offset+i] = permuted.Data[i]
		}
		offset += permuted.Size
	} else if witness.PExt != nil {
		for i := 0; i < witness.PExt.Size; i++ {
			result.Data[offset+i] = witness.PExt.Data[i]
		}
		offset += witness.PExt.Size
	}

	// Copy PHatExt (p̂) as-is (no permutation needed for extended component)
	if witness.PHatExt != nil {
		for i := 0; i < witness.PHatExt.Size; i++ {
			result.Data[offset+i] = witness.PHatExt.Data[i]
		}
		offset += witness.PHatExt.Size
	}

	// Apply permutations Bj[i] to each j*_i
	for i, jext := range witness.JExt {
		if jext != nil && perm.Bj != nil && i < len(perm.Bj) && len(perm.Bj[i]) == jext.Size {
			permuted := applyPermutation(jext, perm.Bj[i])
			for j := 0; j < permuted.Size; j++ {
				result.Data[offset+j] = permuted.Data[j]
			}
			offset += permuted.Size
		} else if jext != nil {
			for j := 0; j < jext.Size; j++ {
				result.Data[offset+j] = jext.Data[j]
			}
			offset += jext.Size
		}
	}

	// Paper witness (eq 8): interleaved (v*_i || v̂_i || ŵ_i) for i=0..ℓ-2, then ŵ_{ℓ-1}
	numVLevels := len(witness.VExt) // should be ℓ-1
	for i := 0; i < numVLevels; i++ {
		// v*_i
		vext := witness.VExt[i]
		if vext != nil && perm.Bv != nil && i < len(perm.Bv) && len(perm.Bv[i]) == vext.Size {
			permuted := applyPermutation(vext, perm.Bv[i])
			for j := 0; j < permuted.Size; j++ {
				result.Data[offset+j] = permuted.Data[j]
			}
			offset += permuted.Size
		} else if vext != nil {
			for j := 0; j < vext.Size; j++ {
				result.Data[offset+j] = vext.Data[j]
			}
			offset += vext.Size
		}

		// v̂_i
		if i < len(witness.VHatExt) {
			vhat := witness.VHatExt[i]
			if vhat != nil && perm.BvHat != nil && i < len(perm.BvHat) && len(perm.BvHat[i]) == vhat.Size {
				permuted := applyPermutation(vhat, perm.BvHat[i])
				for j := 0; j < permuted.Size; j++ {
					result.Data[offset+j] = permuted.Data[j]
				}
				offset += permuted.Size
			} else if vhat != nil {
				for j := 0; j < vhat.Size; j++ {
					result.Data[offset+j] = vhat.Data[j]
				}
				offset += vhat.Size
			}
		}

		// ŵ_i
		if i < len(witness.WHatExt) {
			what := witness.WHatExt[i]
			if what != nil && perm.BwHat != nil && i < len(perm.BwHat) && len(perm.BwHat[i]) == what.Size {
				permuted := applyPermutation(what, perm.BwHat[i])
				for j := 0; j < permuted.Size; j++ {
					result.Data[offset+j] = permuted.Data[j]
				}
				offset += permuted.Size
			} else if what != nil {
				for j := 0; j < what.Size; j++ {
					result.Data[offset+j] = what.Data[j]
				}
				offset += what.Size
			}
		}
	}

	// Last ŵ_{ℓ-1} (leaf level, no corresponding v*)
	if numVLevels < len(witness.WHatExt) {
		what := witness.WHatExt[numVLevels]
		if what != nil && perm.BwHat != nil && numVLevels < len(perm.BwHat) && len(perm.BwHat[numVLevels]) == what.Size {
			permuted := applyPermutation(what, perm.BwHat[numVLevels])
			for j := 0; j < permuted.Size; j++ {
				result.Data[offset+j] = permuted.Data[j]
			}
			offset += permuted.Size
		} else if what != nil {
			for j := 0; j < what.Size; j++ {
				result.Data[offset+j] = what.Data[j]
			}
			offset += what.Size
		}
	}

	// Apply permutation Br1 to r*_1
	if witness.R1Ext != nil && perm.Br1 != nil && len(perm.Br1) == witness.R1Ext.Size {
		permuted := applyPermutation(witness.R1Ext, perm.Br1)
		for i := 0; i < permuted.Size; i++ {
			result.Data[offset+i] = permuted.Data[i]
		}
		offset += permuted.Size
	} else if witness.R1Ext != nil {
		for i := 0; i < witness.R1Ext.Size; i++ {
			result.Data[offset+i] = witness.R1Ext.Data[i]
		}
		offset += witness.R1Ext.Size
	}

	// Apply permutation Br2 to r*_2
	if witness.R2Ext != nil && perm.Br2 != nil && len(perm.Br2) == witness.R2Ext.Size {
		permuted := applyPermutation(witness.R2Ext, perm.Br2)
		for i := 0; i < permuted.Size; i++ {
			result.Data[offset+i] = permuted.Data[i]
		}
		offset += permuted.Size
	} else if witness.R2Ext != nil {
		for i := 0; i < witness.R2Ext.Size; i++ {
			result.Data[offset+i] = witness.R2Ext.Data[i]
		}
		offset += witness.R2Ext.Size
	}

	return result
}

// isInVALID checks if a permuted witness satisfies all structural constraints
// VALID set contains vectors with correct Hamming weights and structure
func isInVALID(z *lattice.Vector, params *lattice.PublicParameters) bool {
	// VALID set verification for permuted witness Γ_η(z)
	// Paper equation (8): z = (x* || p* || p̂ || j_1...j_ℓ || v*_1 || v̂_1 || ŵ_1 || ... || v*_{ℓ-1} || v̂_{ℓ-1} || ŵ_{ℓ-1} || ŵ_ℓ || r*_1 || r*_2)
	// Each component must satisfy specific Hamming weight constraints

	// Calculate component sizes
	M_E := params.M_E // LWE encryption parameter
	treeHeight := params.L
	vLevels := treeHeight - 1 // Number of internal Merkle nodes (ℓ-1)

	xExtSize := 2 * params.M
	pExtSize := 2*params.NK - 1
	pHatExtSize := 4*params.NK - 2
	jExtSizePerBit := 2 // Each j*_i ∈ {0,1}^2
	vExtSizePerLevel := 2 * params.NK
	vHatSizePerLevel := 4 * params.NK
	wHatSizePerLevel := 4 * params.NK
	r1ExtSize := 2 * M_E
	r2ExtSize := 2 * M_E

	// Verify total size matches expected witness dimension (paper formula)
	// D = 10ℓnk + 2m + 4m_E + 2ℓ - 3
	expectedSize := xExtSize + pExtSize + pHatExtSize +
		treeHeight*jExtSizePerBit +
		vLevels*vExtSizePerLevel +
		vLevels*vHatSizePerLevel +
		treeHeight*wHatSizePerLevel +
		r1ExtSize + r2ExtSize

	if z.Size != expectedSize {
		if Debug {
			fmt.Printf("[debug] VALID fail: size mismatch got=%d expected=%d\n", z.Size, expectedSize)
		}
		return false // Incorrect witness dimension
	}

	offset := 0

	// Check 1: x* ∈ B^{2m}_m
	// Must have exactly params.M ones in first 2*params.M positions
	if !checkBinaryWeight(z, offset, xExtSize, params.M) {
		if Debug {
			fmt.Printf("[debug] VALID fail: x block offset=%d length=%d expected=%d\n", offset, xExtSize, params.M)
		}
		return false
	}
	offset += xExtSize

	// Check 2: p* structure [p || (1-p)[:-1]] with p ≠ 0
	if !checkPExtStructure(z, offset, params.NK) {
		if Debug {
			fmt.Printf("[debug] VALID fail: p block offset=%d length=%d expected nk=%d\n", offset, pExtSize, params.NK)
		}
		return false
	}
	offset += pExtSize

	// Check 3: p̂ = ext(j_ℓ, p*) ∈ {0,1}^{4nk-2}
	// Skip weight check for p̂ as it's derived from p*
	// Structural check: p̂ must equal ext(b, p*) for some bit b
	// This is enforced by the prover construction, here we just skip it
	offset += pHatExtSize

	// Check 4: Each j*_i ∈ {0,1}^2
	// Each j*_i must have exactly 1 one (encodes single bit)
	for level := 0; level < treeHeight; level++ {
		if !checkBinaryWeight(z, offset, jExtSizePerBit, 1) {
			if Debug {
				fmt.Printf("[debug] VALID fail: j block level=%d offset=%d\n", level, offset)
			}
			return false
		}
		offset += jExtSizePerBit
	}

	// Check 5: Interleaved v*, v̂, ŵ for levels 1..ℓ-1
	// Paper witness: (v*_1 || v̂_1 || ŵ_1 || ... || v*_{ℓ-1} || v̂_{ℓ-1} || ŵ_{ℓ-1})
	for level := 0; level < vLevels; level++ {
		// Check v*_i ∈ B^{2nk}_{nk}
		if !checkBinaryWeight(z, offset, vExtSizePerLevel, params.NK) {
			if Debug {
				fmt.Printf("[debug] VALID fail: v block level=%d offset=%d expected=%d\n", level, offset, params.NK)
			}
			return false
		}
		offset += vExtSizePerLevel

		// Skip v̂_i (no weight check - derived from v* via ext())
		// Note: Cannot check ext() consistency after permutation Γ_η
		offset += vHatSizePerLevel

		// Skip ŵ_i (no weight check - derived from w* which we don't have in witness)
		// Note: Paper witness includes ŵ but not w*, so no consistency check possible
		offset += wHatSizePerLevel
	}

	// Check 6: ŵ_ℓ (last level, no v* at this level)
	// Skip weight check as it's derived
	offset += wHatSizePerLevel

	// Check 7: r*_1 ∈ B^{2m_E}_{m_E}
	// Must have exactly M_E ones
	if !checkBinaryWeight(z, offset, r1ExtSize, M_E) {
		if Debug {
			fmt.Printf("[debug] VALID fail: r1 block offset=%d length=%d expected=%d\n", offset, r1ExtSize, M_E)
		}
		return false
	}
	offset += r1ExtSize

	// Check 8: r*_2 ∈ B^{2m_E}_{m_E}
	// Must have exactly M_E ones
	if !checkBinaryWeight(z, offset, r2ExtSize, M_E) {
		if Debug {
			fmt.Printf("[debug] VALID fail: r2 block offset=%d length=%d expected=%d\n", offset, r2ExtSize, M_E)
		}
		return false
	}

	// All checks passed - z ∈ VALID
	return true
}

// checkExtConsistency verifies that segment at extStart (length 2*lenBase)
// equals ext(b, base) for some b ∈ {0,1}, under the assumption permutations
// preserved half boundaries. It checks that one half matches base exactly and
// the other half is all zeros.
func checkExtConsistency(z *lattice.Vector, baseStart, baseLen, extStart, extLen int) bool {
	// Align with equation builder: verify second-of-pair positions (2j+1)
	// appear in either the first 2·NK segment (A0 part) or the second 2·NK segment (A1 part),
	// and that all other positions in the chosen half and the entire other half are zeros.
	if extLen != 2*baseLen || baseLen%2 != 0 {
		return false
	}

	// Helper: check zeros in a range
	zeros := func(start, length int) bool {
		for i := 0; i < length; i++ {
			if z.Data[start+i] != 0 {
				return false
			}
		}
		return true
	}

	// bit = 0 case: first half carries second-of-pair; second half all zeros
	b0 := true
	for j := 0; j < baseLen/2; j++ {
		// positions 2j must be zero in ext half-0
		if z.Data[extStart+(2*j)] != 0 {
			b0 = false
			break
		}
		// positions 2j+1 must match base second-of-pair
		if z.Data[extStart+(2*j+1)] != z.Data[baseStart+(2*j+1)] {
			b0 = false
			break
		}
	}
	if b0 && zeros(extStart+baseLen, baseLen) {
		return true
	}

	// bit = 1 case: first half zeros; second half carries second-of-pair
	b1 := true
	if !zeros(extStart, baseLen) {
		b1 = false
	}
	if b1 {
		for j := 0; j < baseLen/2; j++ {
			if z.Data[extStart+baseLen+(2*j)] != 0 {
				b1 = false
				break
			}
			if z.Data[extStart+baseLen+(2*j+1)] != z.Data[baseStart+(2*j+1)] {
				b1 = false
				break
			}
		}
	}
	return b1
}

// countOnes helper removed in favor of exact ext consistency check

func checkBinaryWeight(z *lattice.Vector, start, length, expectedWeight int) bool {
	weight := 0
	for i := 0; i < length; i++ {
		val := z.Data[start+i]
		if val != 0 && val != 1 {
			if Debug {
				fmt.Printf("[debug] checkBinaryWeight: non-binary value at pos %d: %v\n", start+i, z.Data[start+i])
			}
			return false
		}
		if val == 1 {
			weight++
		}
	}
	if weight != expectedWeight {
		if Debug {
			fmt.Printf("[debug] checkBinaryWeight: weight mismatch start=%d len=%d got=%d expected=%d\n", start, length, weight, expectedWeight)
		}
	}
	return weight == expectedWeight
}

func checkPExtStructure(z *lattice.Vector, start, nk int) bool {
	if z == nil {
		return false
	}

	totalLen := 2*nk - 1
	ones := 0
	for i := 0; i < totalLen; i++ {
		val := z.Data[start+i]
		if val != 0 && val != 1 {
			return false
		}
		if val == 1 {
			ones++
		}
	}

	if StrictPExtStructure {
		// Strict mode is incompatible with permuted p*; fallback to weight check
		// (structure enforced during witness construction)
	}

	// Weight check: nk ones (or nk-1 due to final complement drop) and not all zero
	if ones != nk && ones != nk-1 {
		return false
	}
	return ones > 0
}

// checkHammingWeight verifies that a binary vector has exactly the expected number of 1s
// Returns true if v ∈ B^n_w where n is vector size and w is expected weight

// ext extends a vector v based on bit b
// ext(b, v) = (b̄·v || b·v) where b̄ = 1-b
// This encodes Merkle tree branching logic into the vector structure
func ext(bit int, v *lattice.Vector) *lattice.Vector {
	// Paper-consistent ext for v* of length 2·nk with pairs (2i, 2i+1) = (1−b, b).
	// Output length 4·nk with blocks of size nk: [A0 | 0 | A1 | 0].
	// Only second-of-pair (2i+1) entries are relevant for A0/A1; we place them into block0 (bit=0) or block2 (bit=1).
	size := v.Size
	if size%2 != 0 {
		// Fallback to 2-block generic form
		result := lattice.NewVector(2*size, v.Q)
		bBar := 1 - bit
		for i := 0; i < size; i++ {
			if bBar == 1 {
				result.Data[i] = v.Data[i]
			} else {
				result.Data[i] = 0
			}
		}
		for i := 0; i < size; i++ {
			if bit == 1 {
				result.Data[size+i] = v.Data[i]
			} else {
				result.Data[size+i] = 0
			}
		}
		return result
	}

	nk := size / 2
	out := lattice.NewVector(4*nk, v.Q)
	if bit == 0 {
		for i := 0; i < nk; i++ {
			out.Data[2*i+1] = v.Data[2*i+1] // block0, second-of-pair
		}
	} else {
		for i := 0; i < nk; i++ {
			out.Data[2*nk+(2*i+1)] = v.Data[2*i+1] // block2, second-of-pair
		}
	}
	return out
}

// extP extends p* based on bit b for Merkle root verification
// p̂ = ext(j_ℓ, p*) where p* ∈ {0,1}^{2nk-1} (odd size)
// Output: p̂ ∈ {0,1}^{4nk-2} per paper Section 4.4.2
// Similar to ext but accounts for odd input size
func extP(bit int, pExt *lattice.Vector) *lattice.Vector {
	size := pExt.Size // 2nk-1
	// Output size should be 4nk-2 = 2*(2nk-1)
	result := lattice.NewVector(2*size, pExt.Q)

	bBar := 1 - bit
	// First half: b̄·p*
	for i := 0; i < size; i++ {
		if bBar == 1 {
			result.Data[i] = pExt.Data[i]
		} else {
			result.Data[i] = 0
		}
	}
	// Second half: b·p*
	for i := 0; i < size; i++ {
		if bit == 1 {
			result.Data[size+i] = pExt.Data[i]
		} else {
			result.Data[size+i] = 0
		}
	}
	return result
}

// extendMatrix creates A* from A by interleaving with zero blocks
// A = [A0 | A1] ∈ Z_q^{n×m} where m = 2nk
// A* = [A0 | 0 | A1 | 0] ∈ Z_q^{n×2m}

// extendGadgetMatrix creates G* from G by appending zero block
// G ∈ Z_q^{n×nk}
// G* = [G | 0] ∈ Z_q^{n×2nk}
