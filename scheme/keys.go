package scheme

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"github.com/vinhphamhuu/lattice-group-signature/merkle"
)

// GroupPublicKey contains the group's public key
type GroupPublicKey struct {
	PP  *lattice.PublicParameters
	MPK *ManagerPublicKey
	TPK *TracingPublicKey
}

// ManagerPublicKey is the group manager's public key
type ManagerPublicKey struct {
	PK *lattice.Vector
}

// ManagerSecretKey is the group manager's secret key
type ManagerSecretKey struct {
	SK *lattice.Vector
}

// TracingPublicKey is the tracing manager's public key
// Paper: tpk = (B, P₁, P₂)
type TracingPublicKey struct {
	B  *lattice.Matrix // B ∈ Z_q^{n×m_E}
	P1 *lattice.Matrix // P₁ ∈ Z_q^{ℓ×m_E}
	P2 *lattice.Matrix // P₂ ∈ Z_q^{ℓ×m_E}
	// TODO: Remove these legacy fields once signature.go and trace.go are updated
	PK1 *lattice.Vector // Legacy: for backward compatibility
	PK2 *lattice.Vector // Legacy: for backward compatibility
}

// GetMatrices implements nizk.TracingPublicKeyInterface
func (tpk *TracingPublicKey) GetMatrices() (B, P1, P2 *lattice.Matrix) {
	return tpk.B, tpk.P1, tpk.P2
}

// TracingSecretKey is the tracing manager's secret key
// Paper: tsk = (S₁, E₁)
type TracingSecretKey struct {
	S1 *lattice.Matrix // S₁ ∈ Z_q^{n×ℓ}
	E1 *lattice.Matrix // E₁ ∈ Z_q^{ℓ×m_E}
	// TODO: Remove this legacy field once signature.go and trace.go are updated
	SK *lattice.Vector // Legacy: for backward compatibility
	// Second encryption secrets for stronger tracing proof
	S2          *lattice.Matrix // S₂ ∈ Z_q^{n×ℓ}
	E2          *lattice.Matrix // E₂ ∈ Z_q^{ℓ×m_E}
	s1Transpose *lattice.Matrix
}

// GetSecretMatrices provides access to secret matrices needed by π_trace prover
// Implements the nizk.TracingSecretKeyInterface without importing nizk to avoid cycles
func (tsk *TracingSecretKey) GetSecretMatrices() (S1, S2 *lattice.Matrix) {
	return tsk.S1, tsk.S2
}

func (tsk *TracingSecretKey) ensureS1Transpose() *lattice.Matrix {
	if tsk == nil {
		return nil
	}
	if tsk.s1Transpose != nil {
		return tsk.s1Transpose
	}
	if tsk.S1 == nil {
		return nil
	}
	tsk.s1Transpose = tsk.S1.Transpose()
	return tsk.s1Transpose
}

// UserPublicKey is a user's public key
type UserPublicKey struct {
	PK *lattice.Vector
}

// UserSecretKey is a user's secret key
type UserSecretKey struct {
	SK *lattice.Vector
}

// GroupSigningKey is a user's group signing key
type GroupSigningKey struct {
	UID int
	USK *UserSecretKey
	UPK *UserPublicKey
	X   *lattice.Vector // Secret credential
	PI  *lattice.Vector // Public credential
}

// GroupInfo contains the current group information for an epoch
type GroupInfo struct {
	Epoch           int
	Tree            *merkle.Tree //TODO: remove
	RootHash        *lattice.Vector
	ActiveUIDs      map[int]bool            //TODO: remove
	HistoricalRoots map[int]*lattice.Vector // epoch → Merkle root
}

// RegistrationTable stores registration information
// Paper: reg := (reg[0][1], reg[0][2], ..., reg[N-1][1], reg[N-1][2])
type RegistrationTable struct {
	Records map[int]*RegistrationRecord
}

// RegistrationRecord stores user registration data
// Paper: For each i ∈ [0, N-1]:
//   - reg[i][1] = public key of registered user (0^{n·k} if not registered)
//   - reg[i][2] = epoch at which the user joins (0 if not registered)
type RegistrationRecord struct {
	UPK   *lattice.Vector // reg[i][1]: Public key (0^{n·k} initially)
	Epoch int             // reg[i][2]: Epoch at which user joins (0 initially)
}

// GSetup generates public parameters
// Paper: GSetup(λ) outputs pp = {λ, N, n, q, k, m, m_E, ℓ, β, χ, κ, H_FS, COM, A}
func GSetup(lambda int, maxUsers int) *lattice.PublicParameters {
	return lattice.NewParams(lambda, maxUsers)
}

// GKgenGM generates the group manager's key pair
// Paper: msk ←$ {0,1}^m and mpk = A · msk mod q
func GKgenGM(pp *lattice.PublicParameters) (*ManagerPublicKey, *ManagerSecretKey, error) {
	// Generate secret key: msk ←$ {0,1}^m (binary vector)
	// Paper specifies binary vector, not small vector
	msk, err := lattice.BinaryVector(pp.M, pp.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate manager SK: %v", err)
	}

	// Generate public key: mpk = A · msk mod q
	// A is n×m, msk is m×1, result mpk is n×1
	mpk := pp.A.Mul(msk)

	return &ManagerPublicKey{PK: mpk}, &ManagerSecretKey{SK: msk}, nil
}

// GKgenTM generates the tracing manager's key pair
// Paper: Naor-Yung double-encryption with ℓ-bit Regev encryption
// B ←$ Z_q^{n×m_E}, for i∈{1,2}: S_i ←$ χ^{n×ℓ}, E_i ←$ χ^{ℓ×m_E}
// P_i = S_i^T · B + E_i ∈ Z_q^{ℓ×m_E}
// tsk = (S₁, E₁), tpk = (B, P₁, P₂)
func GKgenTM(pp *lattice.PublicParameters) (*TracingPublicKey, *TracingSecretKey, error) {
	// Choose B ←$ Z_q^{n×m_E}
	B, err := lattice.RandomMatrix(pp.N, pp.M_E, pp.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate matrix B: %v", err)
	}

	// For i = 1: Sample S₁ ←$ χ^{n×ℓ}
	S1, err := lattice.GaussianMatrix(pp.N, pp.L, pp.Beta, pp.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate S1: %v", err)
	}

	// Sample E₁ ←$ χ^{ℓ×m_E}
	E1, err := lattice.GaussianMatrix(pp.L, pp.M_E, pp.Beta, pp.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate E1: %v", err)
	}

	// Compute P₁ = S₁^T · B + E₁ ∈ Z_q^{ℓ×m_E}
	S1T := S1.Transpose()
	P1 := S1T.MatMul(B).Add(E1)

	// For i = 2: Sample S₂ ←$ χ^{n×ℓ}
	S2, err := lattice.GaussianMatrix(pp.N, pp.L, pp.Beta, pp.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate S2: %v", err)
	}

	// Sample E₂ ←$ χ^{ℓ×m_E}
	E2, err := lattice.GaussianMatrix(pp.L, pp.M_E, pp.Beta, pp.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate E2: %v", err)
	}

	// Compute P₂ = S₂^T · B + E₂ ∈ Z_q^{ℓ×m_E}
	S2T := S2.Transpose()
	P2 := S2T.MatMul(B).Add(E2)

	// tsk = (S₁, E₁), tpk = (B, P₁, P₂)
	tsk := &TracingSecretKey{
		S1:          S1,
		E1:          E1,
		S2:          S2,
		E2:          E2,
		SK:          lattice.NewVector(pp.M_E, pp.Q), // Legacy field - TODO: update signature.go
		s1Transpose: S1T,
	}
	tpk := &TracingPublicKey{
		B:   B,
		P1:  P1,
		P2:  P2,
		PK1: lattice.NewVector(pp.N, pp.Q), // Legacy field - TODO: update signature.go
		PK2: lattice.NewVector(pp.N, pp.Q), // Legacy field - TODO: update signature.go
	}

	return tpk, tsk, nil
}

// UKgen generates a user's key pair
// Paper: usk = x ← {0,1}^m, upk = p = bin(A · x) mod q ∈ {0,1}^(n·k)
// Note: The relationship A · x = G · p mod q holds by definition of bin(),
// where G is the gadget matrix and p is the binary decomposition.
func UKgen(pp *lattice.PublicParameters) (*UserPublicKey, *UserSecretKey, error) {
	// Generate secret key: x ← {0,1}^m (binary vector of length m)
	sk, err := lattice.BinaryVector(pp.M, pp.Q)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate user SK: %v", err)
	}

	// Generate public key: p = bin(A · x) mod q
	// Step 1: Compute t = A · x mod q (where A is n×m, x is m×1, result t is n×1)
	// Use A from params
	t := pp.A.Mul(sk)

	// Step 2: Convert to binary representation p = bin(t) ∈ {0,1}^(n·k)
	// This ensures upk ∈ {0,1}^(n·k) as specified in paper
	// The binary decomposition guarantees: G · p = t = A · x mod q
	pkBinary := lattice.ToBinaryVector(t, pp.NK, pp.Q)

	// Verify correctness: G · p should equal A · x mod q
	// Note: Disabled for now as it may cause issues during key generation
	// The mathematical relationship G·p = A·x is guaranteed by ToBinaryVector construction
	if !lattice.VerifyBinaryDecomposition(t, pkBinary, pp) {
		return nil, nil, fmt.Errorf("binary decomposition verification failed")
	}

	return &UserPublicKey{PK: pkBinary}, &UserSecretKey{SK: sk}, nil
}

// InitializeGroup initializes the group with empty Merkle tree
// Paper: The Merkle tree T is built on top of reg[0][1], ..., reg[N-1][1]
// Note: T is an all-zero tree at this stage (since all reg[i][1] = 0^{n·k})
func InitializeGroup(pp *lattice.PublicParameters, reg *RegistrationTable) *GroupInfo {
	tree := merkle.NewTree(pp)

	// Build Merkle tree from registration table
	// Paper: Tree is built on reg[0][1], ..., reg[N-1][1]
	// Initially all are 0^{n·k}, so tree is all-zero
	for i := 0; i < pp.MaxUsers; i++ {
		if record, exists := reg.Records[i]; exists {
			tree.Leaves[i] = &merkle.Node{
				Data:  record.UPK,
				Left:  nil,
				Right: nil,
			}
		}
	}
	tree.BuildTree(tree.Leaves)

	rootHash := tree.GetRoot()

	return &GroupInfo{
		Epoch:           0,
		Tree:            tree,
		RootHash:        rootHash,
		ActiveUIDs:      make(map[int]bool),
		HistoricalRoots: map[int]*lattice.Vector{0: rootHash}, // Store epoch 0 root
	}
}

// InitializeRegistry initializes the registration table
// Paper: reg[i][1] = 0^{n·k} and reg[i][2] = 0 for all i ∈ [0, N-1]
func InitializeRegistry(pp *lattice.PublicParameters) *RegistrationTable {
	reg := &RegistrationTable{
		Records: make(map[int]*RegistrationRecord),
	}

	// Initialize all N slots with zero values

	for i := 0; i < pp.MaxUsers; i++ {
		reg.Records[i] = &RegistrationRecord{
			UPK:   lattice.NewVector(pp.NK, pp.Q),
			Epoch: 0, // User hasn't joined yet
		}
	}

	return reg
}

// Join is the user's part of the Join/Issue protocol
func Join(info *GroupInfo, gpk *GroupPublicKey, upk *UserPublicKey, usk *UserSecretKey) (*GroupSigningKey, error) {
	// Use the binary UKgen secret as credential for Stern proof compatibility
	x := usk.SK
	if x == nil {
		return nil, fmt.Errorf("user secret key is nil")
	}

	// pi: public credential = A * x (use A from params)
	pi := gpk.PP.A.Mul(x)

	// Find available UID (in practice, coordinated with GM)
	uid := len(info.ActiveUIDs)

	return &GroupSigningKey{
		UID: uid,
		USK: usk,
		UPK: upk,
		X:   x,
		PI:  pi,
	}, nil
}

// Issue is the group manager's part of the Join/Issue protocol
// Paper: Store user's public key in reg[uid][1] and current epoch in reg[uid][2]
func Issue(info *GroupInfo, msk *ManagerSecretKey, upk *UserPublicKey, pi *lattice.Vector, uid int, reg *RegistrationTable) error {
	if uid < 0 || uid >= info.Tree.Size {
		return fmt.Errorf("invalid UID: %d", uid)
	}

	// Store the current epoch's root BEFORE making changes
	// This preserves the root for signatures created in this epoch
	if info.RootHash != nil {
		info.HistoricalRoots[info.Epoch] = info.RootHash
	}

	// Increment epoch (every tree change creates new epoch)
	info.Epoch++

	// Store registration record with current epoch
	// Paper: reg[i][1] = upk (user's public key), reg[i][2] = current epoch
	reg.Records[uid] = &RegistrationRecord{
		UPK:   upk.PK,     // reg[uid][1]: user's public key
		Epoch: info.Epoch, // reg[uid][2]: epoch at which user joins
	}
	err := info.Tree.SetActive(uid, upk.PK)
	if err != nil {
		return fmt.Errorf("failed to activate user in tree: %v", err)
	}

	// Mark user as active
	info.ActiveUIDs[uid] = true
	info.RootHash = info.Tree.GetRoot()

	return nil
} // GUpdate updates the group information (handles revocations)
func GUpdate(gpk *GroupPublicKey, msk *ManagerSecretKey, info *GroupInfo, revokeUIDs []int, reg *RegistrationTable) (*GroupInfo, error) {
	if len(revokeUIDs) == 0 {
		return nil, nil // No changes
	}

	// Store the current epoch's root before moving to new epoch
	// This preserves the root that signatures from this epoch should verify against
	info.HistoricalRoots[info.Epoch] = info.RootHash

	// Create new epoch
	newInfo := &GroupInfo{
		Epoch:           info.Epoch + 1,
		Tree:            info.Tree,
		ActiveUIDs:      make(map[int]bool),
		HistoricalRoots: info.HistoricalRoots, // Copy historical roots
	}

	// Copy active users
	for uid := range info.ActiveUIDs {
		newInfo.ActiveUIDs[uid] = true
	}

	// Revoke users by setting their leaves to 0
	for _, uid := range revokeUIDs {
		err := newInfo.Tree.SetInactive(uid)
		if err != nil {
			return nil, fmt.Errorf("failed to revoke user %d: %v", uid, err)
		}
		delete(newInfo.ActiveUIDs, uid)
	}

	newInfo.RootHash = newInfo.Tree.GetRoot()

	return newInfo, nil
}

// GenerateChallenge generates a random challenge for zero-knowledge proof
func GenerateChallenge(q *big.Int) (*big.Int, error) {
	return rand.Int(rand.Reader, q)
}
