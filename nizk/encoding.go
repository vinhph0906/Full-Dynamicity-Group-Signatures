package nizk

import (
	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// packBinaryVector packs a binary vector into bytes (MSB-first per byte).
func packBinaryVector(v *lattice.Vector) []byte {
	if v == nil || v.Size == 0 {
		return nil
	}
	nbytes := (v.Size + 7) / 8
	out := make([]byte, nbytes)
	for i := 0; i < v.Size; i++ {
		if v.Data[i] != 0 {
			byteIdx := i / 8
			bitIdx := 7 - (i % 8)
			out[byteIdx] |= (1 << uint(bitIdx))
		}
	}
	return out
}

// encodePermutationBits builds a binary vector φ(η) using ext-style templates:
//   - For size-2t vectors (x*, v*, w*, r*), we mark the images of all second-of-pair indices (2j+1)
//     producing a vector in B^{2t}_t.
//   - For size-(2nk-1) vector (p*), we mark the images of the first nk indices, producing B^{2nk-1}_{nk}.
//   - For size-2 vectors (each j*), we mark the image of index 1.
//   - For hat permutations (length 4·nk), we mark the second-of-pair positions in each half, resulting in 2·nk ones.
func encodePermutationBits(eta *Permutation, params *lattice.PublicParameters) *lattice.Vector {
	// compute total length
	total := 0
	total += 2 * params.M               // Bx
	total += 2*params.NK - 1            // Bp
	total += 2 * params.L               // Bj
	total += params.L * (2 * params.NK) // Bv
	total += params.L * (2 * params.NK) // Bw
	total += params.L * (4 * params.NK) // BvHat
	total += params.L * (4 * params.NK) // BwHat
	total += 2 * params.M_E             // Br1
	total += 2 * params.M_E             // Br2

	phi := lattice.NewVector(total, params.Q)
	// Vector is initialized with zeros

	off := 0

	// Bx: mark images of all odd indices (2j+1)
	if eta.Bx != nil && len(eta.Bx) == 2*params.M {
		for j := 0; j < params.M; j++ {
			idx := eta.Bx[2*j+1]
			if idx >= 0 && idx < 2*params.M {
				phi.Data[off+idx] = 1
			}
		}
	}
	off += 2 * params.M

	// Bp: length 2*NK-1; mark images of first NK indices
	if eta.Bp != nil && len(eta.Bp) == 2*params.NK-1 {
		for j := 0; j < params.NK; j++ {
			idx := eta.Bp[j]
			if idx >= 0 && idx < 2*params.NK-1 {
				phi.Data[off+idx] = 1
			}
		}
	}
	off += 2*params.NK - 1

	// Bj: for each level, size 2; mark image of index 1
	for lvl := 0; lvl < params.L; lvl++ {
		if eta.Bj != nil && lvl < len(eta.Bj) && len(eta.Bj[lvl]) == 2 {
			idx := eta.Bj[lvl][1]
			if idx >= 0 && idx < 2 {
				phi.Data[off+idx] = 1
			}
		}
		off += 2
	}

	// Bv: for each level, size 2*NK; mark images of (2j+1)
	for lvl := 0; lvl < params.L; lvl++ {
		if eta.Bv != nil && lvl < len(eta.Bv) && len(eta.Bv[lvl]) == 2*params.NK {
			for j := 0; j < params.NK; j++ {
				idx := eta.Bv[lvl][2*j+1]
				if idx >= 0 && idx < 2*params.NK {
					phi.Data[off+idx] = 1
				}
			}
		}
		off += 2 * params.NK
	}

	// Bw: same as Bv
	for lvl := 0; lvl < params.L; lvl++ {
		if eta.Bw != nil && lvl < len(eta.Bw) && len(eta.Bw[lvl]) == 2*params.NK {
			for j := 0; j < params.NK; j++ {
				idx := eta.Bw[lvl][2*j+1]
				if idx >= 0 && idx < 2*params.NK {
					phi.Data[off+idx] = 1
				}
			}
		}
		off += 2 * params.NK
	}

	// BvHat: for each level, size 4*NK; mark second-of-pair in both halves
	for lvl := 0; lvl < params.L; lvl++ {
		if eta.BvHat != nil && lvl < len(eta.BvHat) && len(eta.BvHat[lvl]) == 4*params.NK {
			// first half [0,2*NK)
			for j := 0; j < params.NK; j++ {
				idx := eta.BvHat[lvl][2*j+1]
				if idx >= 0 && idx < 4*params.NK {
					phi.Data[off+idx] = 1
				}
			}
			// second half [2*NK,4*NK)
			for j := 0; j < params.NK; j++ {
				idx := eta.BvHat[lvl][2*params.NK+(2*j+1)]
				if idx >= 0 && idx < 4*params.NK {
					phi.Data[off+idx] = 1
				}
			}
		}
		off += 4 * params.NK
	}

	// BwHat: similar
	for lvl := 0; lvl < params.L; lvl++ {
		if eta.BwHat != nil && lvl < len(eta.BwHat) && len(eta.BwHat[lvl]) == 4*params.NK {
			for j := 0; j < params.NK; j++ {
				idx := eta.BwHat[lvl][2*j+1]
				if idx >= 0 && idx < 4*params.NK {
					phi.Data[off+idx] = 1
				}
			}
			for j := 0; j < params.NK; j++ {
				idx := eta.BwHat[lvl][2*params.NK+(2*j+1)]
				if idx >= 0 && idx < 4*params.NK {
					phi.Data[off+idx] = 1
				}
			}
		}
		off += 4 * params.NK
	}

	// Br1: mark images of (2j+1)
	if eta.Br1 != nil && len(eta.Br1) == 2*params.M_E {
		for j := 0; j < params.M_E; j++ {
			idx := eta.Br1[2*j+1]
			if idx >= 0 && idx < 2*params.M_E {
				phi.Data[off+idx] = 1
			}
		}
	}
	off += 2 * params.M_E

	// Br2: mark images of (2j+1)
	if eta.Br2 != nil && len(eta.Br2) == 2*params.M_E {
		for j := 0; j < params.M_E; j++ {
			idx := eta.Br2[2*j+1]
			if idx >= 0 && idx < 2*params.M_E {
				phi.Data[off+idx] = 1
			}
		}
	}
	// off += 2 * params.M_E

	return phi
}
