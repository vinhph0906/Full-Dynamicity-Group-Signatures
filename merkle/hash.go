package merkle

import (
	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// HashFunction represents the hash function family H from Definition 4
// Paper: H = {h_A | A ∈ Z_q^{n×m}}, where for A = [A₀|A₁]
// h_A(u₀, u₁) = bin(A₀ · u₀ + A₁ · u₁ mod q) ∈ {0,1}^{nk}
type HashFunction struct {
	A0 *lattice.Matrix // A₀ ∈ Z_q^{n×nk} - first half of A
	A1 *lattice.Matrix // A₁ ∈ Z_q^{n×nk} - second half of A
	Q  int64           // Prime modulus q
	NK int             // n·k dimension for output
}

// NewHashFunction creates a new hash function h_A from matrix A
// Paper: A ∈ Z_q^{n×m} where m = 2nk, split as A = [A₀|A₁]
func NewHashFunction(A *lattice.Matrix, nk int) *HashFunction {
	A0, A1 := lattice.SplitMatrix(A, nk)
	return &HashFunction{
		A0: A0,
		A1: A1,
		Q:  A.Q,
		NK: nk,
	}
}

// Hash computes h_A(u₀, u₁) = bin(A₀ · u₀ + A₁ · u₁ mod q)
// Paper: For any (u₀, u₁) ∈ {0,1}^{nk} × {0,1}^{nk}, output ∈ {0,1}^{nk}
// Property: h_A(u₀, u₁) = u ⟺ A₀ · u₀ + A₁ · u₁ = G · u mod q
func (h *HashFunction) Hash(u0, u1 *lattice.Vector) *lattice.Vector {
	// Compute A₀ · u₀
	t0 := h.A0.Mul(u0)

	// Compute A₁ · u₁
	t1 := h.A1.Mul(u1)

	// Compute A₀ · u₀ + A₁ · u₁ mod q
	sum := t0.Add(t1)

	// Apply binary decomposition: bin(sum) ∈ {0,1}^{nk}
	result := lattice.ToBinaryVector(sum, h.NK, h.Q)

	return result
}
