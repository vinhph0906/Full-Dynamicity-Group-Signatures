package nizk

import (
	"fmt"
	"sync"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

var permutationPool = sync.Pool{New: func() any { return &Permutation{} }}

// generateFullPermutation samples all block permutations used in Γ_η.
func generateFullPermutation(sw *SternWitness, params *lattice.PublicParameters) (*Permutation, error) {
	perm := permutationPool.Get().(*Permutation)
	if err := populatePermutation(perm, sw, params); err != nil {
		releasePermutation(perm)
		return nil, err
	}
	return perm, nil
}

func populatePermutation(perm *Permutation, sw *SternWitness, params *lattice.PublicParameters) error {
	var err error
	tempPair := make([]int, params.NK)

	if sw.XExt != nil {
		perm.Bx = ensurePermSlice(perm.Bx, sw.XExt.Size)
		if err = fillRandomPermutation(perm.Bx); err != nil {
			return fmt.Errorf("failed to generate Bx: %w", err)
		}
	} else {
		perm.Bx = nil
	}
	if sw.PExt != nil {
		perm.Bp = ensurePermSlice(perm.Bp, sw.PExt.Size)
		if err = fillRandomPermutation(perm.Bp); err != nil {
			return fmt.Errorf("failed to generate Bp: %w", err)
		}
	} else {
		perm.Bp = nil
	}

	perm.Bj = ensurePermMatrix(perm.Bj, len(sw.JExt))
	for i := 0; i < len(sw.JExt); i++ {
		if sw.JExt[i] == nil {
			perm.Bj[i] = nil
			continue
		}
		perm.Bj[i] = ensurePermSlice(perm.Bj[i], sw.JExt[i].Size)
		if err = fillRandomPermutation(perm.Bj[i]); err != nil {
			return fmt.Errorf("failed to generate Bj[%d]: %w", i, err)
		}
	}

	perm.Bv = ensurePermMatrix(perm.Bv, len(sw.VExt))
	for i := 0; i < len(sw.VExt); i++ {
		if sw.VExt[i] == nil {
			perm.Bv[i] = nil
			continue
		}
		perm.Bv[i] = ensurePermSlice(perm.Bv[i], 2*params.NK)
		if err = fillRandomPermutation(tempPair); err != nil {
			return fmt.Errorf("failed to gen pair perm for Bv[%d]: %w", i, err)
		}
		for j := 0; j < params.NK; j++ {
			dest := tempPair[j]
			perm.Bv[i][2*j] = 2 * dest
			perm.Bv[i][2*j+1] = 2*dest + 1
		}
	}

	perm.Bw = ensurePermMatrix(perm.Bw, len(sw.WExt))
	for i := 0; i < len(sw.WExt); i++ {
		if sw.WExt[i] == nil {
			perm.Bw[i] = nil
			continue
		}
		perm.Bw[i] = ensurePermSlice(perm.Bw[i], 2*params.NK)
		if err = fillRandomPermutation(tempPair); err != nil {
			return fmt.Errorf("failed to gen pair perm for Bw[%d]: %w", i, err)
		}
		for j := 0; j < params.NK; j++ {
			dest := tempPair[j]
			perm.Bw[i][2*j] = 2 * dest
			perm.Bw[i][2*j+1] = 2*dest + 1
		}
	}

	perm.BvHat = ensurePermMatrix(perm.BvHat, len(sw.VHatExt))
	for level := 0; level < len(sw.VHatExt); level++ {
		if sw.VHatExt[level] == nil {
			perm.BvHat[level] = nil
			continue
		}
		size := sw.VHatExt[level].Size
		perm.BvHat[level] = ensurePermSlice(perm.BvHat[level], size)
		for k := 0; k < size; k++ {
			perm.BvHat[level][k] = k
		}
		if size == 4*params.NK {
			if err = fillRandomPermutation(tempPair); err != nil {
				return fmt.Errorf("failed to generate BvHat pair permutation 1: %w", err)
			}
			for j := 0; j < params.NK; j++ {
				dest := tempPair[j]
				perm.BvHat[level][2*j] = 2 * dest
				perm.BvHat[level][2*j+1] = 2*dest + 1
			}
			if err = fillRandomPermutation(tempPair); err != nil {
				return fmt.Errorf("failed to generate BvHat pair permutation 2: %w", err)
			}
			base := 2 * params.NK
			for j := 0; j < params.NK; j++ {
				dest := tempPair[j]
				perm.BvHat[level][base+2*j] = base + 2*dest
				perm.BvHat[level][base+2*j+1] = base + 2*dest + 1
			}
		}
	}

	perm.BwHat = ensurePermMatrix(perm.BwHat, len(sw.WHatExt))
	for level := 0; level < len(sw.WHatExt); level++ {
		if sw.WHatExt[level] == nil {
			perm.BwHat[level] = nil
			continue
		}
		size := sw.WHatExt[level].Size
		perm.BwHat[level] = ensurePermSlice(perm.BwHat[level], size)
		for k := 0; k < size; k++ {
			perm.BwHat[level][k] = k
		}
		if size == 4*params.NK {
			if err = fillRandomPermutation(tempPair); err != nil {
				return fmt.Errorf("failed to generate BwHat pair permutation 1: %w", err)
			}
			for j := 0; j < params.NK; j++ {
				dest := tempPair[j]
				perm.BwHat[level][2*j] = 2 * dest
				perm.BwHat[level][2*j+1] = 2*dest + 1
			}
			if err = fillRandomPermutation(tempPair); err != nil {
				return fmt.Errorf("failed to generate BwHat pair permutation 2: %w", err)
			}
			base := 2 * params.NK
			for j := 0; j < params.NK; j++ {
				dest := tempPair[j]
				perm.BwHat[level][base+2*j] = base + 2*dest
				perm.BwHat[level][base+2*j+1] = base + 2*dest + 1
			}
		}
	}

	if sw.R1Ext != nil {
		perm.Br1 = ensurePermSlice(perm.Br1, sw.R1Ext.Size)
		if err = fillRandomPermutation(perm.Br1); err != nil {
			return fmt.Errorf("failed to generate Br1: %w", err)
		}
	} else {
		perm.Br1 = nil
	}
	if sw.R2Ext != nil {
		perm.Br2 = ensurePermSlice(perm.Br2, sw.R2Ext.Size)
		if err = fillRandomPermutation(perm.Br2); err != nil {
			return fmt.Errorf("failed to generate Br2: %w", err)
		}
	} else {
		perm.Br2 = nil
	}

	perm.PiX = nil
	perm.PiP = nil
	perm.PiW = ensurePermMatrix(perm.PiW, len(sw.WExt))
	for i := range perm.PiW {
		perm.PiW[i] = nil
	}

	return nil
}

func releasePermutation(perm *Permutation) {
	if perm == nil {
		return
	}
	permutationPool.Put(perm)
}

func ensurePermSlice(buf []int, size int) []int {
	if size <= 0 {
		return nil
	}
	if cap(buf) < size {
		buf = make([]int, size)
	} else {
		buf = buf[:size]
	}
	return buf
}

func ensurePermMatrix(buf [][]int, length int) [][]int {
	if cap(buf) < length {
		buf = make([][]int, length)
	} else {
		buf = buf[:length]
	}
	return buf
}
