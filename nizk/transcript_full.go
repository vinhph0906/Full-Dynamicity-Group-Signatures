package nizk

import (
	"encoding/binary"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"golang.org/x/crypto/sha3"
)

// buildFullTranscript assembles the Fiat–Shamir transcript inputs.
func buildFullTranscript(stmt *Statement, commitments []*CommitmentTriple) []byte {
	builder := newTranscriptBuilder(stmt.Params.Q)

	builder.appendBytes(stmt.Message)
	if stmt != nil && stmt.Ciphertext != nil {
		c1u, c1v, c2u, c2v := stmt.Ciphertext.GetComponents()
		builder.appendVector(c1u)
		builder.appendVector(c1v)
		builder.appendVector(c2u)
		builder.appendVector(c2v)
	}
	if stmt != nil && stmt.MerkleRoot != nil {
		builder.appendVector(stmt.MerkleRoot)
	}
	if stmt != nil && stmt.Params != nil && stmt.TPK != nil {
		shake := sha3.NewShake256()
		var buf [8]byte
		appendMatrix := func(M *lattice.Matrix) {
			if M == nil {
				return
			}
			for i := 0; i < M.Rows; i++ {
				for j := 0; j < M.Cols; j++ {
					binary.BigEndian.PutUint64(buf[:], uint64(M.Data[i][j]))
					_, _ = shake.Write(buf[:])
				}
			}
		}
		appendMatrix(stmt.Params.A)
		appendMatrix(stmt.Params.G)
		if B, P1, P2 := stmt.TPK.GetMatrices(); B != nil && P1 != nil && P2 != nil {
			appendMatrix(B)
			appendMatrix(P1)
			appendMatrix(P2)
		}
		digest := make([]byte, 32)
		_, _ = shake.Read(digest)
		builder.appendBytes(digest)
	}
	for _, triple := range commitments {
		if triple == nil {
			continue
		}
		builder.appendVector(triple.C1)
		builder.appendVector(triple.C2)
		builder.appendVector(triple.C3)
	}
	return builder.bytes()
}
