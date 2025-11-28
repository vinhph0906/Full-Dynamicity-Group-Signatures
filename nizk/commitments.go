package nizk

import (
	"encoding/binary"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// commitGamma commits Γ_η(·) using the string commitment scheme.
func commitGamma(data *lattice.Vector, rho *lattice.Vector, params *lattice.PublicParameters) *lattice.Vector {
	var msg []byte
	var buf [8]byte
	for i := 0; i < data.Size; i++ {
		binary.BigEndian.PutUint64(buf[:], uint64(data.Data[i]))
		msg = append(msg, buf[:]...)
	}
	return lattice.StringCommitment(msg, rho, params)
}

// commitToSyndrome commits to (φ(η) || syndrome) using the string commitment.
func commitToSyndrome(eta *Permutation, syndrome *lattice.Vector, rho *lattice.Vector, params *lattice.PublicParameters) *lattice.Vector {
	phiBits := encodePermutationBits(eta, params)
	phiPacked := packBinaryVector(phiBits)
	var synBytes []byte
	var buf [8]byte
	for i := 0; i < syndrome.Size; i++ {
		binary.BigEndian.PutUint64(buf[:], uint64(syndrome.Data[i]))
		synBytes = append(synBytes, buf[:]...)
	}
	msg := append(phiPacked, synBytes...)
	return lattice.StringCommitment(msg, rho, params)
}
