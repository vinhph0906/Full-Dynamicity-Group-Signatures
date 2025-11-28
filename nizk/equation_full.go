package nizk

import (
	"fmt"
	"os"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"github.com/vinhphamhuu/lattice-group-signature/merkle"
)

// computeMerkleIntermediateNodes computes v_i from leaf p up to root.
func computeMerkleIntermediateNodes(witness *Witness, params *lattice.PublicParameters) ([]*lattice.Vector, error) {
	treeHeight := len(witness.MerklePath)
	if treeHeight == 0 {
		return nil, fmt.Errorf("empty Merkle path")
	}
	hashFunc := merkle.NewHashFunction(params.A, params.NK)
	intermediateNodes := make([]*lattice.Vector, treeHeight+1)
	intermediateNodes[treeHeight] = witness.P
	for i := treeHeight - 1; i >= 0; i-- {
		vNext := intermediateNodes[i+1]
		idx := treeHeight - 1 - i
		wNext := witness.MerklePath[idx]
		isLeft := witness.Directions[idx]
		var vi *lattice.Vector
		if isLeft {
			vi = hashFunc.Hash(vNext, wNext)
		} else {
			vi = hashFunc.Hash(wNext, vNext)
		}
		intermediateNodes[i] = vi
	}
	return intermediateNodes, nil
}

// buildUnifiedEquation constructs M·z = u (mod q) using the extended witness blocks.
func buildUnifiedEquation(sw *SternWitness, stmt *Statement, params *lattice.PublicParameters) (*UnifiedEquation, error) {
	originalWitness := &Witness{X: sw.X, P: sw.P, UID: 0, MerklePath: sw.W, Directions: append([]bool(nil), sw.Directions...)}
	for i := 0; i < len(sw.J); i++ {
		originalWitness.UID |= sw.J[i] << i
	}
	intermediateNodes, err := computeMerkleIntermediateNodes(originalWitness, params)
	if err != nil {
		return nil, fmt.Errorf("failed to compute Merkle nodes: %v", err)
	}
	merkleRoot := intermediateNodes[0]
	if os.Getenv("NIZK_PROFILE") == "1" {
		fmt.Printf("[Debug] Computed merkleRoot from intermediate nodes: %v...\n", merkleRoot.Data[0])
	}
	// VExt contains (ℓ-1) intermediate nodes (NOT including root at index 0)
	// intermediateNodes: [0]=root, [1..ℓ-1]=intermediate, [ℓ]=leaf
	// We take [1..ℓ-1] only (skip root and leaf)
	if len(intermediateNodes) > 2 {
		sw.VExt = make([]*lattice.Vector, len(intermediateNodes)-2)
		for i := 1; i < len(intermediateNodes)-1; i++ {
			sw.VExt[i-1] = extendToB(intermediateNodes[i], 2*params.NK, params.Q)
		}
	}
	// VHatExt: (ℓ-1) vectors matching VExt
	if len(sw.VExt) > 0 {
		sw.VHatExt = make([]*lattice.Vector, len(sw.VExt))
		for i := 0; i < len(sw.VExt); i++ {
			if sw.VExt[i] != nil {
				dirIdx := len(sw.Directions) - 1 - i
				isLeft := dirIdx >= 0 && dirIdx < len(sw.Directions) && sw.Directions[dirIdx]
				bit := 1
				if isLeft {
					bit = 0
				}
				sw.VHatExt[i] = ext(bit, sw.VExt[i])
			}
		}
	}
	// WHatExt: Paper unclear if (ℓ-1) or ℓ vectors. Keeping ℓ for now to match WExt.
	if len(sw.WExt) > 0 {
		sw.WHatExt = make([]*lattice.Vector, len(sw.WExt))
		for i := 0; i < len(sw.WExt); i++ {
			if sw.WExt[i] != nil {
				dirIdx := len(sw.Directions) - 1 - i
				isLeft := dirIdx >= 0 && dirIdx < len(sw.Directions) && sw.Directions[dirIdx]
				bit := 0
				if isLeft {
					bit = 1
				}
				sw.WHatExt[i] = ext(bit, sw.WExt[i])
			}
		}
	}

	// Build public equation and inject witness
	treeHeight := params.L
	xExtSize := 2 * params.M
	pExtSize := 2*params.NK - 1
	pHatExtSize := 4*params.NK - 2 // p̂ = ext(j_ℓ, p*) per paper
	jExtSizePerBit := 2
	vExtSizePerLevel := 2 * params.NK
	vHatSizePerLevel := 4 * params.NK
	wHatSizePerLevel := 4 * params.NK
	r1ExtSize := 2 * params.M_E
	r2ExtSize := 2 * params.M_E

	// fmt.Printf("[DEBUG prover sizes] M_E=%d, r1ExtSize=%d, r2ExtSize=%d\n", params.M_E, r1ExtSize, r2ExtSize)

	// VExt and VHatExt have (ℓ-1) vectors; WExt and WHatExt have ℓ vectors
	vLevels := treeHeight - 1
	if vLevels < 0 {
		vLevels = 0
	}

	offsetX := 0
	offsetP := offsetX + xExtSize
	offsetPHat := offsetP + pExtSize
	offsetJ := offsetPHat + pHatExtSize
	baseInterleaved := offsetJ + treeHeight*jExtSizePerBit

	// Paper witness (eq 8): z = (x* || p* || p̂ || j_1...j_ℓ || v*_0 || v̂_0 || ŵ_0 || ... || v*_{ℓ-2} || v̂_{ℓ-2} || ŵ_{ℓ-2} || ŵ_{ℓ-1} || r*_1 || r*_2)
	// Interleaved structure: (ℓ-1) triplets of (v*, v̂, ŵ), then one final ŵ_{ℓ-1}
	offsetR1 := baseInterleaved + vLevels*(vExtSizePerLevel+vHatSizePerLevel+wHatSizePerLevel) + wHatSizePerLevel
	offsetR2 := offsetR1 + r1ExtSize
	totalSize := offsetR2 + r2ExtSize

	// fmt.Printf("[DEBUG prover totalSize] vLevels=%d, baseInterleaved=%d, offsetR1=%d, offsetR2=%d, totalSize=%d\n", vLevels, baseInterleaved, offsetR1, offsetR2, totalSize)

	z := lattice.NewVector(totalSize, params.Q)
	off := 0
	if sw.XExt != nil {
		for i := 0; i < sw.XExt.Size; i++ {
			z.Data[off+i] = sw.XExt.Data[i]
		}
		off += sw.XExt.Size
	}
	if sw.PExt != nil {
		for i := 0; i < sw.PExt.Size; i++ {
			z.Data[off+i] = sw.PExt.Data[i]
		}
		off += sw.PExt.Size
	}
	if sw.PHatExt != nil {
		for i := 0; i < sw.PHatExt.Size; i++ {
			z.Data[off+i] = sw.PHatExt.Data[i]
		}
		off += sw.PHatExt.Size
	}
	for i := 0; i < treeHeight; i++ {
		if sw.JExt[i] != nil {
			for j := 0; j < sw.JExt[i].Size; j++ {
				z.Data[off+j] = sw.JExt[i].Data[j]
			}
			off += sw.JExt[i].Size
		}
	}
	// Paper witness (eq 8): interleaved (v*_i || v̂_i || ŵ_i) for i=0..ℓ-2, then ŵ_{ℓ-1}
	// VExt has (ℓ-1) vectors, VHatExt has (ℓ-1) vectors, WHatExt has ℓ vectors
	numVLevels := len(sw.VExt) // should be ℓ-1
	for i := 0; i < numVLevels; i++ {
		// v*_i
		if sw.VExt[i] != nil {
			for j := 0; j < sw.VExt[i].Size; j++ {
				z.Data[off+j] = sw.VExt[i].Data[j]
			}
			off += sw.VExt[i].Size
		}
		// v̂_i
		if i < len(sw.VHatExt) && sw.VHatExt[i] != nil {
			for j := 0; j < sw.VHatExt[i].Size; j++ {
				z.Data[off+j] = sw.VHatExt[i].Data[j]
			}
			off += sw.VHatExt[i].Size
		}
		// ŵ_i
		if i < len(sw.WHatExt) && sw.WHatExt[i] != nil {
			for j := 0; j < sw.WHatExt[i].Size; j++ {
				z.Data[off+j] = sw.WHatExt[i].Data[j]
			}
			off += sw.WHatExt[i].Size
		}
	}
	// Last ŵ_{ℓ-1} (leaf level, no corresponding v*)
	if numVLevels < len(sw.WHatExt) && sw.WHatExt[numVLevels] != nil {
		for j := 0; j < sw.WHatExt[numVLevels].Size; j++ {
			z.Data[off+j] = sw.WHatExt[numVLevels].Data[j]
		}
		off += sw.WHatExt[numVLevels].Size
	}
	if sw.R1Ext != nil {
		for i := 0; i < sw.R1Ext.Size; i++ {
			z.Data[off+i] = sw.R1Ext.Data[i]
		}
		off += sw.R1Ext.Size
	}
	if sw.R2Ext != nil {
		for i := 0; i < sw.R2Ext.Size; i++ {
			z.Data[off+i] = sw.R2Ext.Data[i]
		}
		off += sw.R2Ext.Size
	}

	// Debug: print actual witness size filled vs allocated
	if os.Getenv("NIZK_PROFILE") == "1" {
		fmt.Printf("[Debug] Witness z: allocated=%d, filled=%d, unused=%d\n",
			totalSize, off, totalSize-off)

		// Detail breakdown
		fmt.Printf("  XExt: %d\n", sw.XExt.Size)
		fmt.Printf("  PExt: %d\n", sw.PExt.Size)
		if sw.PHatExt != nil {
			fmt.Printf("  PHatExt: %d\n", sw.PHatExt.Size)
		} else {
			fmt.Printf("  PHatExt: nil\n")
		}
		fmt.Printf("  JExt: %d bits → %d elements\n", len(sw.J), len(sw.J)*2)

		vExtCount := 0
		vExtSize := 0
		for _, v := range sw.VExt {
			if v != nil {
				vExtCount++
				vExtSize = v.Size
			}
		}
		fmt.Printf("  VExt: %d/%d non-nil × %d = %d total\n", vExtCount, len(sw.VExt), vExtSize, vExtCount*vExtSize)

		wExtCount := 0
		wExtSize := 0
		for _, w := range sw.WExt {
			if w != nil {
				wExtCount++
				wExtSize = w.Size
			}
		}
		fmt.Printf("  WExt: %d/%d non-nil × %d = %d total\n", wExtCount, len(sw.WExt), wExtSize, wExtCount*wExtSize)

		vHatCount := 0
		vHatSize := 0
		for _, v := range sw.VHatExt {
			if v != nil {
				vHatCount++
				vHatSize = v.Size
			}
		}
		fmt.Printf("  VHatExt: %d/%d non-nil × %d = %d total\n", vHatCount, len(sw.VHatExt), vHatSize, vHatCount*vHatSize)

		wHatCount := 0
		wHatSize := 0
		for _, w := range sw.WHatExt {
			if w != nil {
				wHatCount++
				wHatSize = w.Size
			}
		}
		fmt.Printf("  WHatExt: %d/%d non-nil × %d = %d total\n", wHatCount, len(sw.WHatExt), wHatSize, wHatCount*wHatSize)

		fmt.Printf("  R1Ext: %d\n", sw.R1Ext.Size)
		fmt.Printf("  R2Ext: %d\n", sw.R2Ext.Size)
	}

	// Use computed merkleRoot (don't override with stmt.MerkleRoot)
	// The prover computes the correct root from witness
	rootForEquation := merkleRoot
	if os.Getenv("NIZK_PROFILE") == "1" {
		fmt.Printf("[Debug] Using computed merkleRoot: %v...\n", merkleRoot.Data[0])
	}
	publicEquation, err := buildPublicEquation(stmt, rootForEquation, params)
	if err != nil {
		return nil, fmt.Errorf("failed to build public equation: %v", err)
	}
	if publicEquation == nil || publicEquation.M == nil || publicEquation.U == nil {
		return nil, fmt.Errorf("invalid public equation state")
	}
	if publicEquation.WitnessSize != totalSize {
		return nil, fmt.Errorf("witness size mismatch: prover=%d verifier=%d", totalSize, publicEquation.WitnessSize)
	}
	publicEquation.Z = z
	check := publicEquation.M.Mul(z)
	if !vectorsEqualMod(check, publicEquation.U, params.Q) {
		if os.Getenv("NIZK_PROFILE") == "1" {
			fmt.Printf("[ERROR] M·z != u\n")
			fmt.Printf("  M: %d × %d\n", publicEquation.M.Rows, publicEquation.M.Cols)
			fmt.Printf("  z: %d\n", z.Size)
			fmt.Printf("  u: %d\n", publicEquation.U.Size)
			fmt.Printf("  M·z: %d\n", check.Size)

			// Count and show mismatches by row range
			mismatchCount := 0
			firstMismatch := -1
			for i := 0; i < check.Size; i++ {
				if check.Data[i] != publicEquation.U.Data[i] {
					if firstMismatch == -1 {
						firstMismatch = i
					}
					mismatchCount++
				}
			}
			fmt.Printf("  Total mismatches: %d out of %d rows\n", mismatchCount, check.Size)
			if firstMismatch >= 0 {
				fmt.Printf("  First mismatch at row %d\n", firstMismatch)

				// Show row ranges (based on typical structure: Merkle root (n), Merkle internal ((ℓ-1)*n), SIS (n), LWE1 (n+ℓ), LWE2 (n+ℓ))
				n := params.N
				L := params.L
				merkleRootEnd := n
				merkleInternalEnd := merkleRootEnd
				if L > 1 {
					merkleInternalEnd += (L - 1) * n
				}
				sisEnd := merkleInternalEnd + n
				lwe1End := sisEnd + n + L
				lwe2End := lwe1End + n + L

				if firstMismatch < merkleRootEnd {
					fmt.Printf("  Mismatch in: Merkle root equation (rows 0-%d)\n", merkleRootEnd-1)
				} else if firstMismatch < merkleInternalEnd {
					fmt.Printf("  Mismatch in: Merkle internal equations (rows %d-%d)\n", merkleRootEnd, merkleInternalEnd-1)
				} else if firstMismatch < sisEnd {
					fmt.Printf("  Mismatch in: SIS binding equation (rows %d-%d)\n", merkleInternalEnd, sisEnd-1)
				} else if firstMismatch < lwe1End {
					fmt.Printf("  Mismatch in: LWE1 equations (rows %d-%d)\n", sisEnd, lwe1End-1)
				} else if firstMismatch < lwe2End {
					fmt.Printf("  Mismatch in: LWE2 equations (rows %d-%d)\n", lwe1End, lwe2End-1)
				}

				// Show actual values for first mismatch
				fmt.Printf("  Row %d: M·z=%d, u=%d\n", firstMismatch, check.Data[firstMismatch], publicEquation.U.Data[firstMismatch])
			}
		}
		return nil, fmt.Errorf("unified equation mismatch: M·z != u")
	}
	return publicEquation, nil
}
