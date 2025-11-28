package nizk

import (
	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// prepareExtendedWitness builds the extended witness blocks used in the full Stern protocol.
func prepareExtendedWitness(w *Witness, params *lattice.PublicParameters) (*SternWitness, error) {
	sw := &SternWitness{
		X:          w.X,
		P:          w.P,
		W:          w.MerklePath,
		R1:         w.R1,
		R2:         w.R2,
		Directions: w.Directions,
	}

	sw.XExt = extendToB(w.X, 2*params.M, params.Q)
	sw.PExt = extendP(w.P, params.Q)

	sw.J = make([]int, params.L)
	sw.JExt = make([]*lattice.Vector, params.L)
	for i := 0; i < params.L; i++ {
		bit := (w.UID >> i) & 1
		sw.J[i] = bit
		sw.JExt[i] = ext2(bit, params.Q)
	}

	// p̂ = ext(j_ℓ, p*) where j_ℓ is the last bit of UID
	// Paper: p̂ ∈ {0,1}^{4nk-2}
	if params.L > 0 {
		lastBit := sw.J[params.L-1]
		sw.PHatExt = extP(lastBit, sw.PExt)
	}

	sw.WExt = make([]*lattice.Vector, len(w.MerklePath))
	for i, wi := range w.MerklePath {
		sw.WExt[i] = extendToB(wi, 2*params.NK, params.Q)
	}
	for i := 0; i < len(sw.WExt)/2; i++ {
		j := len(sw.WExt) - 1 - i
		sw.WExt[i], sw.WExt[j] = sw.WExt[j], sw.WExt[i]
	}

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

	if w.R1 != nil {
		sw.R1Ext = extendToB(w.R1, 2*params.M_E, params.Q)
	}
	if w.R2 != nil {
		sw.R2Ext = extendToB(w.R2, 2*params.M_E, params.Q)
	}

	return sw, nil
}
