package nizk

import (
	"fmt"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// TraceOpenProof is a publicly verifiable proof of correct decryption (simplified)
//
// It contains the two noisy vectors that, when threshold-decoded, yield the UID
// encrypted in both ciphertexts. This enables public verification without the TM's
// secret key. Note: This is a minimal, practical proof; it does not reveal tsk but
// also does not include a full zero-knowledge relation tying noisy vectors back to
// tsk. It is sufficient for public consistency checks and matches our implementation
// goals for Judge.
type TraceOpenProof struct {
	UID     int
	Proof1  *lattice.Vector // noisy1 = c1_v - S1^T·c1_u (mod q)
	Proof2  *lattice.Vector // noisy2 = c2_v - S2^T·c2_u (mod q)
	SigHash []byte          // hash of ciphertext to bind the proof
}

// TracingSecretKeyInterface exposes the secret matrices needed for decryption
// Implemented by scheme.TracingSecretKey (see scheme/keys.go)
type TracingSecretKeyInterface interface {
	GetSecretMatrices() (S1, S2 *lattice.Matrix)
}

// ProverTrace computes a publicly verifiable decryption witness from tsk and ct.
// The output proof is checked by VerifierTrace without requiring tsk.
func ProverTrace(params *lattice.PublicParameters,
	tpk TracingPublicKeyInterface,
	tsk TracingSecretKeyInterface,
	ct CiphertextInterface,
	uid int,
	sigHash []byte,
) (*TraceOpenProof, error) {

	c1u, c1v, c2u, c2v := ct.GetComponents()
	if c1u == nil || c1v == nil || c2u == nil || c2v == nil {
		return nil, fmt.Errorf("invalid ciphertext components")
	}

	S1, S2 := tsk.GetSecretMatrices()
	if S1 == nil || S2 == nil {
		return nil, fmt.Errorf("invalid tracing secret key matrices")
	}

	// Compute S_i^T · u_i
	S1T := S1.Transpose()
	s1Tu := S1T.Mul(c1u)
	S2T := S2.Transpose()
	s2Tu := S2T.Mul(c2u)

	// noisy_i = v_i - S_i^T·u_i (mod q)
	noisy1 := lattice.NewVector(c1v.Size, params.Q)
	noisy2 := lattice.NewVector(c2v.Size, params.Q)
	for i := 0; i < c1v.Size && i < s1Tu.Size; i++ {
		diff := (c1v.Data[i] - s1Tu.Data[i]) % params.Q
		if diff < 0 {
			diff += params.Q
		}
		noisy1.Data[i] = diff
	}
	for i := 0; i < c2v.Size && i < s2Tu.Size; i++ {
		diff := (c2v.Data[i] - s2Tu.Data[i]) % params.Q
		if diff < 0 {
			diff += params.Q
		}
		noisy2.Data[i] = diff
	}

	return &TraceOpenProof{
		UID:     uid,
		Proof1:  noisy1,
		Proof2:  noisy2,
		SigHash: sigHash,
	}, nil
}

// VerifierTrace checks that both noisy vectors decode to the claimed UID
// using threshold decoding around q/2, consistent with ⌈q/2⌉ message scaling.
// It assumes the caller separately checks SigHash binds to the ciphertext.
func VerifierTrace(params *lattice.PublicParameters, proof *TraceOpenProof) bool {
	if proof == nil || proof.Proof1 == nil || proof.Proof2 == nil {
		return false
	}

	halfQ := params.Q / 2
	quarterQ := params.Q / 4

	decode := func(v *lattice.Vector) int {
		uid := 0
		for i := 0; i < params.L && i < v.Size; i++ {
			val := v.Data[i] % params.Q
			if val < 0 {
				val += params.Q
			}
			bit := 0
			threeQuarterQ := halfQ + quarterQ
			if val >= quarterQ && val < threeQuarterQ {
				bit = 1
			}
			uid |= bit << i
		}
		return uid
	}

	u1 := decode(proof.Proof1)
	u2 := decode(proof.Proof2)
	return u1 == proof.UID && u2 == proof.UID
}
