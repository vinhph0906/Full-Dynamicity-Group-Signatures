package nizk

import (
	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// ZKProof represents the zero-knowledge proof (Stern-like protocol)
type ZKProof struct {
	// Only store actual responses (not 3κ, just κ)
	Responses []*lattice.Vector

	// Commitment triples (C1, C2, C3) for each round of the protocol
	Commitments []*CommitmentTriple
}

// CommitmentTriple captures the three commitments produced in each round.
type CommitmentTriple struct {
	C1 *lattice.Vector
	C2 *lattice.Vector
	C3 *lattice.Vector
}

// Witness contains all secret information needed to generate a ZK proof
type Witness struct {
	X          *lattice.Vector   // Secret credential
	P          *lattice.Vector   // Public key = bin(A·x)
	UID        int               // User ID
	MerklePath []*lattice.Vector // Merkle authentication path
	Directions []bool            // Merkle path directions
	R1         *lattice.Vector   // LWE encryption randomness for first ciphertext
	R2         *lattice.Vector   // LWE encryption randomness for second ciphertext
}

// CiphertextInterface provides access to ciphertext components
type CiphertextInterface interface {
	GetComponents() (c1u, c1v, c2u, c2v *lattice.Vector)
}

// TracingPublicKeyInterface provides access to LWE encryption matrices
type TracingPublicKeyInterface interface {
	GetMatrices() (B, P1, P2 *lattice.Matrix)
}

// Statement contains the public information being proven
type Statement struct {
	Message    []byte                    // Message being signed
	Ciphertext CiphertextInterface       // Encrypted identity
	Params     *lattice.PublicParameters // System parameters
	TPK        TracingPublicKeyInterface // Tracing public key (for LWE constraints)

	// Optional: If provided, verifier will explicitly check Merkle path to expected root
	// These are PUBLIC inputs only when explicit Merkle verification is desired.
	// In the standard Stern construction, Merkle constraints are embedded in M·z = u instead.
	MerklePath []*lattice.Vector // Optional Merkle authentication path (public)
	Directions []bool            // Optional path directions (public)
	Leaf       *lattice.Vector   // Optional leaf value p = bin(A·x) (public)

	// Public Merkle root u_τ to use in the unified equation (preferred over recomputing)
	MerkleRoot *lattice.Vector
}
