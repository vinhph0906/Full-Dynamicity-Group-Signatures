package nizk

import (
	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// packResponse1 packs (tz, tr, rho2, rho3) for challenge 1
func packResponse1(tz, tr, rho2, rho3 *lattice.Vector, params *lattice.PublicParameters) *lattice.Vector {
	totalSize := tz.Size + tr.Size + rho2.Size + rho3.Size
	result := lattice.NewVector(totalSize, params.Q)
	offset := 0
	for i := 0; i < tz.Size; i++ {
		result.Data[offset+i] = tz.Data[i]
	}
	offset += tz.Size
	for i := 0; i < tr.Size; i++ {
		result.Data[offset+i] = tr.Data[i]
	}
	offset += tr.Size
	for i := 0; i < rho2.Size; i++ {
		result.Data[offset+i] = rho2.Data[i]
	}
	offset += rho2.Size
	for i := 0; i < rho3.Size; i++ {
		result.Data[offset+i] = rho3.Data[i]
	}
	return result
}

// packResponse2 packs raw permutation arrays (η), then z2, rho1, rho3
func packResponse2(eta *Permutation, z2, rho1, rho3 *lattice.Vector, params *lattice.PublicParameters) *lattice.Vector {
	// Compute total length of permutation encoding
	phiSize := 0
	if eta.Bx != nil {
		phiSize += len(eta.Bx)
	}
	if eta.Bp != nil {
		phiSize += len(eta.Bp)
	}
	if eta.Bj != nil {
		for _, bj := range eta.Bj {
			phiSize += len(bj)
		}
	}
	if eta.Bv != nil {
		for _, bv := range eta.Bv {
			phiSize += len(bv)
		}
	}
	if eta.Bw != nil {
		for _, bw := range eta.Bw {
			// if i == 0 {
			// 	fmt.Printf("[DEBUG packResponse2] Bw phiSize before Bw=%d, %d levels × %d size\n", phiSize, len(eta.Bw), len(bw))
			// }
			phiSize += len(bw)
		}
	}
	if eta.BvHat != nil {
		for _, b := range eta.BvHat {
			// if i == 0 {
			// 	fmt.Printf("[DEBUG packResponse2] BvHat phiSize before BvHat=%d\n", phiSize)
			// }
			// fmt.Printf("[DEBUG packResponse2] BvHat[%d] len=%d\n", i, len(b))
			phiSize += len(b)
		}
	}
	if eta.BwHat != nil {
		for _, b := range eta.BwHat {
			// if i == 0 {
			// 	fmt.Printf("[DEBUG packResponse2] BwHat phiSize before BwHat=%d\n", phiSize)
			// }
			// fmt.Printf("[DEBUG packResponse2] BwHat[%d] len=%d\n", i, len(b))
			phiSize += len(b)
		}
	}
	if eta.Br1 != nil {
		phiSize += len(eta.Br1)
	}
	if eta.Br2 != nil {
		phiSize += len(eta.Br2)
	}

	totalSize := phiSize + z2.Size + rho1.Size + rho3.Size
	result := lattice.NewVector(totalSize, params.Q)

	// Write all permutation arrays as ints
	offset := 0
	write := func(arr []int) {
		for _, v := range arr {
			result.Data[offset] = int64(v)
			offset++
		}
	}
	if eta.Bx != nil {
		write(eta.Bx)
	}
	if eta.Bp != nil {
		write(eta.Bp)
	}
	if eta.Bj != nil {
		for _, bj := range eta.Bj {
			write(bj)
		}
	}
	if eta.Bv != nil {
		for _, bv := range eta.Bv {
			write(bv)
		}
	}
	if eta.Bw != nil {
		for _, bw := range eta.Bw {
			write(bw)
		}
	}
	if eta.BvHat != nil {
		for _, b := range eta.BvHat {
			// fmt.Printf("[DEBUG packResponse2] Writing BvHat[%d] at offset=%d\n", i, offset)
			write(b)
		}
	}
	if eta.BwHat != nil {
		for _, b := range eta.BwHat {
			// fmt.Printf("[DEBUG packResponse2] Writing BwHat[%d] at offset=%d, b[1088]=%d\n", i, offset, b[1088])
			write(b)
		}
	}
	if eta.Br1 != nil {
		write(eta.Br1)
	}
	if eta.Br2 != nil {
		write(eta.Br2)
	}

	// Append z2, rho1, rho3
	for i := 0; i < z2.Size; i++ {
		result.Data[offset+i] = z2.Data[i]
	}
	offset += z2.Size
	for i := 0; i < rho1.Size; i++ {
		result.Data[offset+i] = rho1.Data[i]
	}
	offset += rho1.Size
	for i := 0; i < rho3.Size; i++ {
		result.Data[offset+i] = rho3.Data[i]
	}
	return result
}

// packResponse3 packs raw permutation arrays (η), then z3, rho1, rho2
func packResponse3(eta *Permutation, z3, rho1, rho2 *lattice.Vector, params *lattice.PublicParameters) *lattice.Vector {
	phiSize := 0
	if eta.Bx != nil {
		phiSize += len(eta.Bx)
	}
	if eta.Bp != nil {
		phiSize += len(eta.Bp)
	}
	if eta.Bj != nil {
		for _, bj := range eta.Bj {
			phiSize += len(bj)
		}
	}
	if eta.Bv != nil {
		for _, bv := range eta.Bv {
			phiSize += len(bv)
		}
	}
	if eta.Bw != nil {
		for _, bw := range eta.Bw {
			phiSize += len(bw)
		}
	}
	if eta.BvHat != nil {
		for _, b := range eta.BvHat {
			phiSize += len(b)
		}
	}
	if eta.BwHat != nil {
		for _, b := range eta.BwHat {
			phiSize += len(b)
		}
	}
	if eta.Br1 != nil {
		phiSize += len(eta.Br1)
	}
	if eta.Br2 != nil {
		phiSize += len(eta.Br2)
	}

	totalSize := phiSize + z3.Size + rho1.Size + rho2.Size
	result := lattice.NewVector(totalSize, params.Q)
	offset := 0
	write := func(arr []int) {
		for _, v := range arr {
			result.Data[offset] = int64(v)
			offset++
		}
	}
	if eta.Bx != nil {
		write(eta.Bx)
	}
	if eta.Bp != nil {
		write(eta.Bp)
	}
	if eta.Bj != nil {
		for _, bj := range eta.Bj {
			write(bj)
		}
	}
	if eta.Bv != nil {
		for _, bv := range eta.Bv {
			write(bv)
		}
	}
	if eta.Bw != nil {
		for _, bw := range eta.Bw {
			write(bw)
		}
	}
	if eta.BvHat != nil {
		for _, b := range eta.BvHat {
			write(b)
		}
	}
	if eta.BwHat != nil {
		for _, b := range eta.BwHat {
			write(b)
		}
	}
	if eta.Br1 != nil {
		write(eta.Br1)
	}
	if eta.Br2 != nil {
		write(eta.Br2)
	}

	for i := 0; i < z3.Size; i++ {
		result.Data[offset+i] = z3.Data[i]
	}
	offset += z3.Size
	for i := 0; i < rho1.Size; i++ {
		result.Data[offset+i] = rho1.Data[i]
	}
	offset += rho1.Size
	for i := 0; i < rho2.Size; i++ {
		result.Data[offset+i] = rho2.Data[i]
	}
	return result
}
