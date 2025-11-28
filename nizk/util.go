package nizk

import (
	"math/big"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// bigIntToFixedBytes serializes a big.Int to a fixed-length byte array
// determined by modulus q (length = len(q.Bytes())).
func bigIntToFixedBytes(val *big.Int, q *big.Int) []byte {
	qBytes := len(q.Bytes())
	normalized := new(big.Int).Mod(val, q)
	if normalized.Sign() < 0 {
		normalized.Add(normalized, q)
	}
	vBytes := normalized.Bytes()
	out := make([]byte, qBytes)
	copy(out[qBytes-len(vBytes):], vBytes)
	return out
}

// createWitnessFromVector maps a flat vector onto a SternWitness layout.
func createWitnessFromVector(v *lattice.Vector, template *SternWitness) *SternWitness {
	if v == nil || template == nil {
		return nil
	}
	copySegment := func(length int, offset *int) *lattice.Vector {
		if length == 0 {
			return nil
		}
		seg := lattice.NewVector(length, v.Q)
		for i := 0; i < length && *offset+i < v.Size; i++ {
			seg.Data[i] = v.Data[*offset+i]
		}
		*offset += length
		return seg
	}
	sw := &SternWitness{}
	off := 0
	if template.XExt != nil {
		sw.XExt = copySegment(template.XExt.Size, &off)
	}
	if template.PExt != nil {
		sw.PExt = copySegment(template.PExt.Size, &off)
	}
	if template.PHatExt != nil {
		sw.PHatExt = copySegment(template.PHatExt.Size, &off)
	}
	if len(template.JExt) > 0 {
		sw.JExt = make([]*lattice.Vector, len(template.JExt))
		for i, jext := range template.JExt {
			ln := 0
			if jext != nil {
				ln = jext.Size
			}
			sw.JExt[i] = copySegment(ln, &off)
		}
	}
	// Paper witness (eq 8): interleaved (v*_i || v̂_i || ŵ_i) for i=0..ℓ-2, then ŵ_{ℓ-1}
	if len(template.VExt) > 0 {
		sw.VExt = make([]*lattice.Vector, len(template.VExt))
		sw.VHatExt = make([]*lattice.Vector, len(template.VHatExt))
		sw.WHatExt = make([]*lattice.Vector, len(template.WHatExt))

		numVLevels := len(template.VExt) // should be ℓ-1
		for i := 0; i < numVLevels; i++ {
			// v*_i
			if template.VExt[i] != nil {
				sw.VExt[i] = copySegment(template.VExt[i].Size, &off)
			}
			// v̂_i
			if i < len(template.VHatExt) && template.VHatExt[i] != nil {
				sw.VHatExt[i] = copySegment(template.VHatExt[i].Size, &off)
			}
			// ŵ_i
			if i < len(template.WHatExt) && template.WHatExt[i] != nil {
				sw.WHatExt[i] = copySegment(template.WHatExt[i].Size, &off)
			}
		}
		// Last ŵ_{ℓ-1}
		if numVLevels < len(template.WHatExt) && template.WHatExt[numVLevels] != nil {
			sw.WHatExt[numVLevels] = copySegment(template.WHatExt[numVLevels].Size, &off)
		}
	}
	if template.R1Ext != nil {
		sw.R1Ext = copySegment(template.R1Ext.Size, &off)
	}
	if template.R2Ext != nil {
		sw.R2Ext = copySegment(template.R2Ext.Size, &off)
	}
	return sw
}
