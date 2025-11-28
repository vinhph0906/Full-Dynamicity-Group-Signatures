package nizk

import (
	"fmt"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// generateFullPermutation samples all block permutations used in Γ_η.
func generateFullPermutation(sw *SternWitness, params *lattice.PublicParameters) (*Permutation, error) {
	perm := &Permutation{}
	var err error

	if sw.XExt != nil {
		if perm.Bx, err = generateRandomPermutation(sw.XExt.Size); err != nil {
			return nil, fmt.Errorf("failed to generate Bx: %v", err)
		}
	}
	if sw.PExt != nil {
		if perm.Bp, err = generateRandomPermutation(sw.PExt.Size); err != nil {
			return nil, fmt.Errorf("failed to generate Bp: %v", err)
		}
	}

	perm.Bj = make([][]int, len(sw.JExt))
	for i := 0; i < len(sw.JExt); i++ {
		if sw.JExt[i] != nil {
			if perm.Bj[i], err = generateRandomPermutation(sw.JExt[i].Size); err != nil {
				return nil, fmt.Errorf("failed to generate Bj[%d]: %v", i, err)
			}
		}
	}

	perm.Bv = make([][]int, len(sw.VExt))
	for i := 0; i < len(sw.VExt); i++ {
		if sw.VExt[i] != nil {
			pairPerm, err := generateRandomPermutation(params.NK)
			if err != nil {
				return nil, fmt.Errorf("failed to gen pair perm for Bv[%d]: %v", i, err)
			}
			perm.Bv[i] = make([]int, 2*params.NK)
			for j := 0; j < params.NK; j++ {
				dest := pairPerm[j]
				perm.Bv[i][2*j] = 2 * dest
				perm.Bv[i][2*j+1] = 2*dest + 1
			}
		}
	}

	perm.Bw = make([][]int, len(sw.WExt))
	for i := 0; i < len(sw.WExt); i++ {
		if sw.WExt[i] != nil {
			pairPerm, err := generateRandomPermutation(params.NK)
			if err != nil {
				return nil, fmt.Errorf("failed to gen pair perm for Bw[%d]: %v", i, err)
			}
			perm.Bw[i] = make([]int, 2*params.NK)
			for j := 0; j < params.NK; j++ {
				dest := pairPerm[j]
				perm.Bw[i][2*j] = 2 * dest
				perm.Bw[i][2*j+1] = 2*dest + 1
			}
		}
	}

	perm.BvHat = make([][]int, len(sw.VHatExt))
	for level := 0; level < len(sw.VHatExt); level++ {
		if sw.VHatExt[level] == nil {
			continue
		}
		size := sw.VHatExt[level].Size
		perm.BvHat[level] = make([]int, size)
		for k := 0; k < size; k++ {
			perm.BvHat[level][k] = k
		}
		// Generate half-preserving permutation
		// First half and second half each need their own independent pair permutation
		if size == 4*params.NK {
			// Generate random pair permutation for first half [0, 2nk)
			pairPerm1, err := generateRandomPermutation(params.NK)
			if err != nil {
				return nil, fmt.Errorf("failed to generate BvHat pair permutation 1: %v", err)
			}
			for j := 0; j < params.NK; j++ {
				dest := pairPerm1[j]
				perm.BvHat[level][2*j] = 2 * dest
				perm.BvHat[level][2*j+1] = 2*dest + 1
			}

			// Generate random pair permutation for second half [2nk, 4nk)
			pairPerm2, err := generateRandomPermutation(params.NK)
			if err != nil {
				return nil, fmt.Errorf("failed to generate BvHat pair permutation 2: %v", err)
			}
			base := 2 * params.NK
			for j := 0; j < params.NK; j++ {
				dest := pairPerm2[j]
				perm.BvHat[level][base+2*j] = base + 2*dest
				perm.BvHat[level][base+2*j+1] = base + 2*dest + 1
			}
		}
	}

	perm.BwHat = make([][]int, len(sw.WHatExt))
	for level := 0; level < len(sw.WHatExt); level++ {
		if sw.WHatExt[level] == nil {
			continue
		}
		size := sw.WHatExt[level].Size
		// fmt.Printf("[DEBUG BwHat] level=%d, size=%d, 4*NK=%d, condition=%v\n", level, size, 4*params.NK, size == 4*params.NK)
		perm.BwHat[level] = make([]int, size)
		for k := 0; k < size; k++ {
			perm.BwHat[level][k] = k
		}
		// Generate half-preserving permutation
		// First half and second half each need their own independent pair permutation
		if size == 4*params.NK {
			// Generate random pair permutation for first half [0, 2nk)
			pairPerm1, err := generateRandomPermutation(params.NK)
			if err != nil {
				return nil, fmt.Errorf("failed to generate BwHat pair permutation 1: %v", err)
			}
			for j := 0; j < params.NK; j++ {
				dest := pairPerm1[j]
				perm.BwHat[level][2*j] = 2 * dest
				perm.BwHat[level][2*j+1] = 2*dest + 1
			}
			// Debug: check for duplicates in first half
			seen := make(map[int]bool)
			for i := 0; i < 2*params.NK; i++ {
				if seen[perm.BwHat[level][i]] {
					fmt.Printf("[DEBUG BwHat] level=%d, DUPLICATE in first half at i=%d, value=%d\n", level, i, perm.BwHat[level][i])
				}
				seen[perm.BwHat[level][i]] = true
			}

			// Generate random pair permutation for second half [2nk, 4nk)
			pairPerm2, err := generateRandomPermutation(params.NK)
			if err != nil {
				return nil, fmt.Errorf("failed to generate BwHat pair permutation 2: %v", err)
			}
			base := 2 * params.NK
			// fmt.Printf("[DEBUG BwHat] level=%d, base=%d, setting second half\n", level, base)
			for j := 0; j < params.NK; j++ {
				dest := pairPerm2[j]
				perm.BwHat[level][base+2*j] = base + 2*dest
				perm.BwHat[level][base+2*j+1] = base + 2*dest + 1
			}
			// Debug: check for duplicates in whole array
			seen2 := make(map[int]bool)
			for i := 0; i < size; i++ {
				if seen2[perm.BwHat[level][i]] {
					fmt.Printf("[DEBUG BwHat] level=%d, DUPLICATE in full array at i=%d, value=%d\n", level, i, perm.BwHat[level][i])
				}
				seen2[perm.BwHat[level][i]] = true
			}
			// fmt.Printf("[DEBUG BwHat] level=%d, perm[%d]=%d, perm[%d]=%d\n", level, base, perm.BwHat[level][base], base+1, perm.BwHat[level][base+1])
		}
	}

	if sw.R1Ext != nil {
		if perm.Br1, err = generateRandomPermutation(sw.R1Ext.Size); err != nil {
			return nil, fmt.Errorf("failed to generate Br1: %v", err)
		}
	}
	if sw.R2Ext != nil {
		if perm.Br2, err = generateRandomPermutation(sw.R2Ext.Size); err != nil {
			return nil, fmt.Errorf("failed to generate Br2: %v", err)
		}
	}

	perm.PiX = make([]int, 0)
	perm.PiP = make([]int, 0)
	perm.PiW = make([][]int, len(sw.WExt))
	for i := range perm.PiW {
		perm.PiW[i] = make([]int, 0)
	}

	return perm, nil
}
