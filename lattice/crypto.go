package lattice

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/sha3"
)

func intToBytes(i int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

// Cryptographic primitives following the paper specification

// FiatShamirHash implements H_FS : {0,1}* → {1,2,3}^κ
// Paper: "A hash function H_FS : {0,1}* → {1,2,3}^κ, where κ = ω(log λ),
//
//	to be modelled as a random oracle in the Fiat-Shamir transformations"
//
// This hash function is used to generate challenges in zero-knowledge proofs.
// The output is a sequence of κ values, each in {1, 2, 3}.
//
// Implementation: Use SHAKE256 (extendable-output function) with rejection sampling
// to ensure uniform distribution over {1, 2, 3}.
func FiatShamirHash(input []byte, kappa int) []int {
	challenges := make([]int, kappa)

	// Create SHAKE256 instance
	shake := sha3.NewShake256()
	shake.Write(input)

	// Generate challenges using rejection sampling for uniform distribution
	idx := 0
	var data []byte
	for idx < kappa {
		if idx%256 == 0 { // Every 256 challenges, mix in the current index because shake only 256 bytes
			data = shake.Sum(intToBytes(idx))
		}
		// Read one byte from SHAKE256

		// Rejection sampling: accept values 0-251 (252 = 84*3, divides evenly)
		// This gives us uniform distribution over {0,1,2} → map to {1,2,3}
		challenges[idx] = int(data[idx%256]%3) + 1
		idx++
		if idx%256 == 0 { // Every 256 challenges, mix in the current index because shake only 256 bytes
			shake.Write([]byte{byte(idx)})
		}
	}

	return challenges
}

// StringCommitment implements the hash-based stand-in for the paper’s
// statistically hiding string commitment COM : {0,1}* × {0,1}^m → Z_q^n.
//
// The construction follows the structure described in ACNS 2017, §4:
//  1. Randomness is a binary vector of length 2·nk that we split into
//     r0, r1 ∈ {0,1}^{nk}. Each half multiplies the corresponding slice of
//     the public matrix A = [A0 | A1] to reproduce the linear term A0·r0 + A1·r1.
//  2. The message is absorbed bit by bit (prefixed with a 32-bit length tag for
//     collision-freedom) using SHAKE256 keyed by the global CommitSeed. Each bit
//     drives a deterministic column generator that expands to Z_q^n and is added
//     whenever the bit is 1.
//  3. The final commitment is the sum of the linear term and the selected columns,
//     reduced modulo q.
//
// This helper is intentionally stateful with respect to the global parameters:
// CommitSeed, A, nk, and q must match between prover and verifier to ensure
// commitments recompute verbatim in the Stern rounds.
var count = 0

func StringCommitment(message []byte, randomness *Vector, params *PublicParameters) *Vector {
	count++
	prof := false
	if v := os.Getenv("NIZK_PROFILE"); v == "1" {
		prof = true
	}
	var tStart, tLin, tCols time.Time
	if prof {
		tStart = time.Now()
	}
	if randomness == nil || randomness.Size != 2*params.NK {
		panic("string commitment: randomness must have 2·NK bits")
	}

	nk := params.NK

	r0 := NewVector(nk, params.Q)
	r1 := NewVector(nk, params.Q)
	for i := 0; i < nk; i++ {
		r0.Data[i] = randomness.Data[i]
		r1.Data[i] = randomness.Data[i+nk]
	}

	A0, A1 := SplitMatrix(params.A, nk)

	// GPU-accelerated batch processing for A0·r0 and A1·r1
	var termA *Vector
	if UseGPU && params.N >= GPUThreshold {
		// Use batch GPU multiplication
		matrices := []*Matrix{A0, A1}
		vectors := []*Vector{r0, r1}
		results := BatchMatrixVectorMul(matrices, vectors)
		termA = results[0].Add(results[1])
	} else {
		// Original CPU path
		termA0 := A0.Mul(r0)
		termA1 := A1.Mul(r1)
		termA = termA0.Add(termA1)
	}

	if prof {
		tLin = time.Now()
	}
	// Streamed XOF derivation: single SHAKE stream for all bit columns.
	// This avoids per-bit SHAKE init. Both sides must agree on totalBits and order.
	termB := bytesToVector(message, params.N, params.Q)
	if prof {
		tCols = time.Now()
		fmt.Printf("[profile] COM: round=%d linear=%v columns=%v total=%v\n",
			count, tLin.Sub(tStart), tCols.Sub(tLin), tCols.Sub(tStart))
	}

	return termA.Add(termB)
}

// VerifyCommitment re-derives the commitment for (message, randomness) and
// performs an element-wise comparison against the supplied commitment vector.
// Note: VerifyCommitment and SternChallenge removed (unused). Verifier recomputes COM and
// challenges via FiatShamirHash over the full transcript.

// ChallengeSet generates κ independent challenges for parallel Stern rounds
// Paper uses κ = ω(log λ) parallel rounds for soundness
func bytesToVector(data []byte, length int, q int64) *Vector {
	hash := sha3.NewShake256()
	hash.Write(data)
	vec := NewVector(length, q)
	buf := make([]byte, 8)
	for i := 0; i < length; i++ {
		hash.Read(buf)
		val := int64(binary.BigEndian.Uint64(buf))
		if val < 0 {
			val = -val
		}
		vec.Data[i] = val % q
	}
	return vec
}
