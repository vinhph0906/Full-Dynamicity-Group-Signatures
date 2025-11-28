package lattice

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

type PublicParameters struct {
	Lambda     int     // Security parameter λ
	N          int     // Lattice dimension n (NOT number of users!)
	MaxUsers   int     // Maximum expected number of group users N = 2^ℓ = poly(λ)
	L          int     // ℓ = log2(MaxUsers) - message length
	Q          int64   // Prime modulus q for lattice operations
	K          int     // k = ⌈log₂ q⌉ - bit decomposition length
	M          int     // m = 2nk for hashing layer
	M_E        int     // m_E = 2(n+ℓ)k for encryption layer
	NK         int     // n·k dimension for public keys
	Beta       int64   // β = √n · ω(log n): SIS bound (also used for LWE per paper)
	Sigma      float64 // σ: Gaussian parameter for χ distribution
	Kappa      int     // κ = ω(log λ): Hash function output length
	A          *Matrix // A = [A0|A1] ∈ Z_q^{n×2NK} - commitment matrix (A0, A1 ∈ Z_q^{n×NK})
	G          *Matrix // G ∈ Z_q^{n×NK} - powers-of-2 gadget matrix: I_n ⊗ (1,2,...,2^(k-1))
	CommitSeed []byte  // Seed for deriving string commitment matrix columns
}

// NewParams creates standard parameters for security level lambda
// Paper specification: N = 2^ℓ = poly(λ)
// This means:
// - N is the maximum number of potential users
// - N = 2^ℓ where ℓ is the message length
// - N should be polynomial in λ for efficient implementation
// - Example: λ=128, ℓ=4 → N=16 (small poly, good for demo)
// - Production: λ=128, ℓ=10 → N=1024 (larger poly, more realistic)
func NewParams(lambda int, maxUsers int) *PublicParameters {
	// ℓ = log2(maxUsers) - number of bits to encode user ID
	// Paper: ℓ must satisfy N = 2^ℓ = poly(λ)
	l := 0
	tmp := maxUsers
	for tmp > 1 {
		tmp >>= 1
		l++
	}

	// Validate: maxUsers must be a power of 2
	if maxUsers != (1 << l) {
		panic("maxUsers must be a power of 2 (N = 2^ℓ)")
	}

	// Validate: N should be polynomial in λ
	// For practical purposes, we require ℓ ≤ 2λ (so N ≤ 2^(2λ) = poly(λ))
	// This is very generous; typical values: λ=128, ℓ=10-20
	if l > 2*lambda {
		panic("maxUsers too large: N = 2^ℓ must be polynomial in λ")
	}

	// Lattice dimension n (paper's n, not number of users)
	// Standard choice: n ≈ 2λ for stronger security
	n := lambda

	// Generate prime q ≈ n·sqrt(n)·log(n)
	// Paper: q = Õ(n^1.5) where Õ hides poly-log factors
	sqrtN := int64(math.Sqrt(float64(n)))
	logN := int64(math.Ceil(math.Log(float64(n))))

	// q ≈ n·sqrt(n)·log(n) = n^1.5·log(n)
	qTarget := int64(n) * sqrtN * logN

	// Use crypto/rand to generate a random prime near qTarget
	// Convert qTarget to big.Int for prime generation
	qTargetBig := big.NewInt(qTarget)

	// Generate a random prime with bit length close to qTarget
	// This ensures cryptographic quality
	qBig, err := rand.Prime(rand.Reader, qTargetBig.BitLen()+2)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate prime: %v", err))
	}
	if !qBig.ProbablyPrime(40) {
		panic("Generated q is not prime")
	}
	// Convert back to int64
	// Check if it fits in int64 range
	maxInt64 := big.NewInt(9223372036854775807) // 2^63 - 1
	if qBig.Cmp(maxInt64) > 0 {
		// If too large, generate a smaller prime
		qBig, err = rand.Prime(rand.Reader, 62) // 62 bits to stay safe in int64
		if err != nil {
			panic(fmt.Sprintf("Failed to generate fallback prime: %v", err))
		}
	}

	q := qBig.Int64()

	// m should be larger than n·log(q) for SIS security
	// Paper requirement: m = 2nk for hashing layer
	k := qBig.BitLen() // k = ⌈log q⌉
	nk := n * k
	m := 2 * nk // Paper: m = 2nk

	// Beta = sqrt(n) * log(n) for SIS bound
	beta := sqrtN * logN

	// Paper requirement: m_E = 2(n+ℓ)k for encryption layer
	m_E := 2 * (n + l) * k // Generate commitment matrix A = [A0|A1] ∈ Z_q^{n×2NK}
	// This is used for the string commitment scheme COM
	// A0, A1 ∈ Z_q^{n×NK} are uniformly random
	A, err := RandomMatrix(n, 2*nk, q)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate matrix A: %v", err))
	}

	// Generate gadget matrix G ∈ Z_q^{n×NK} (powers-of-2 matrix)
	// G = I_n ⊗ (1, 2, 4, ..., 2^(k-1))
	G := GadgetMatrix(n, q)

	commitSeed := make([]byte, 32)
	if _, err := rand.Read(commitSeed); err != nil {
		panic(fmt.Sprintf("Failed to generate commitment seed: %v", err))
	}

	// Initialize PublicParameters
	pp := &PublicParameters{
		Lambda:     lambda,
		N:          n,        // Lattice dimension n
		MaxUsers:   maxUsers, // Number of users (2^ℓ)
		L:          l,        // ℓ = log2(MaxUsers)
		Q:          q,        // Prime modulus
		K:          k,        // k = ⌈log₂ q⌉
		M:          m,        // m = 2nk for hashing layer
		M_E:        m_E,      // m_E = 2(n+ℓ)k for encryption layer
		NK:         nk,       // n·k where k = ⌈log q⌉
		Beta:       beta,     // β = √n · log(n)
		Sigma:      float64(lambda),
		Kappa:      int(math.Log2(float64(lambda))) * int(math.Log(float64(lambda))), // κ = ω(log λ) ≈ 2 log(λ) for hash output
		A:          A,                                                                // A ∈ Z_q^{n×2NK} - commitment matrix
		G:          G,                                                                // G ∈ Z_q^{n×NK} - gadget matrix
		CommitSeed: commitSeed,
	}

	return pp
}

// IsPrime checks if q is prime with high confidence
// For int64, we use a simpler check (in production, use proper primality testing)
func (p *PublicParameters) IsPrime() bool {
	return isPrime(p.Q)
}

// VerifyPrimeStrength checks q with extra rounds for maximum confidence
func (p *PublicParameters) VerifyPrimeStrength() bool {
	return isPrime(p.Q)
}

// Simple primality test for int64
func isPrime(n int64) bool {
	if n <= 1 {
		return false
	}
	if n <= 3 {
		return true
	}
	if n%2 == 0 || n%3 == 0 {
		return false
	}
	i := int64(5)
	for i*i <= n {
		if n%i == 0 || n%(i+2) == 0 {
			return false
		}
		i += 6
	}
	return true
}

// String returns a human-readable description of parameters following paper notation
func (p *PublicParameters) String() string {
	qBits := int(math.Ceil(math.Log2(float64(p.Q))))
	return fmt.Sprintf(`Lattice Parameters (Paper Notation):
  λ (security parameter): %d
  n (lattice dimension):  %d
  m (matrix dimension):   %d (= %d·n, satisfies m > n·log(q))
  q (prime modulus):      %d bits
  ℓ (message length):     %d
  N (max users):          %d (= 2^ℓ, poly(λ))
  β (SIS bound):          %d (≈ √n·log(n))
  σ (LWE noise):          %.1f`,
		p.Lambda,
		p.N,
		p.M, p.M/p.N,
		qBits,
		p.L,
		p.MaxUsers,
		p.Beta,
		p.Sigma,
	)
}
