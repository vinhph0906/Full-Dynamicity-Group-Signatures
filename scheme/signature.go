package scheme

import (
	"fmt"
	"os"
	"time"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"github.com/vinhphamhuu/lattice-group-signature/nizk"
)

// Signature represents a group signature
type Signature struct {
	Epoch      int
	Ciphertext *Ciphertext
	Proof      *nizk.ZKProof
	Message    []byte
}

// Ciphertext represents the encrypted identity (Naor-Yung double encryption)
// Following paper: each encryption c_i = (u_i, v_i) where:
// - u_i = random vector (sampled fresh for each encryption)
// - v_i = tpk_i^T · u_i + ⌈q/2⌋ · bin(j)
type Ciphertext struct {
	// First encryption (c1 = (u1, v1))
	C1_U *lattice.Vector // u1 - random vector
	C1_V *lattice.Vector // v1 = PK1^T · u1 + ⌈q/2⌋ · bin(j)

	// Second encryption (c2 = (u2, v2)) for CCA security
	C2_U *lattice.Vector // u2 - random vector
	C2_V *lattice.Vector // v2 = PK2^T · u2 + ⌈q/2⌋ · bin(j)
}

// GetComponents implements nizk.CiphertextInterface
func (ct *Ciphertext) GetComponents() (c1u, c1v, c2u, c2v *lattice.Vector) {
	return ct.C1_U, ct.C1_V, ct.C2_U, ct.C2_V
}

// Sign generates a group signature on a message
// Implements the full Stern protocol with extended vectors and permutations
func Sign(gpk *GroupPublicKey, gsk *GroupSigningKey, info *GroupInfo, message []byte) (*Signature, error) {
	prof := os.Getenv("NIZK_PROFILE") == "1"
	tAll := time.Now()

	// Check that public key is non-zero (key requirement for full dynamicity)
	if gsk.UPK.PK.IsZero() {
		return nil, fmt.Errorf("user public key cannot be zero")
	}

	// Validate credential integrity (prevent zero credential attacks)
	if gsk.PI == nil || isZeroVector(gsk.PI) {
		return nil, fmt.Errorf("user credential cannot be zero or nil")
	}

	// 1. Encrypt the identity using Naor-Yung double encryption
	tEnc := time.Now()
	ciphertext, r1, r2, err := encryptIdentity(gpk, gsk.UID)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt identity: %v", err)
	}
	if prof {
		fmt.Fprintf(os.Stderr, "[profile] encryptIdentity: %v\n", time.Since(tEnc))
	}

	// 2. Get Merkle proof for the user's public key
	tMerkle := time.Now()
	merklePath, directions, err := info.Tree.GetProof(gsk.UID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Merkle proof: %v", err)
	}
	if prof {
		fmt.Fprintf(os.Stderr, "[profile] merkle GetProof: %v\n", time.Since(tMerkle))
	}

	// 3. Generate zero-knowledge proof using full Stern protocol
	witness := &nizk.Witness{
		X:          gsk.X,
		P:          gsk.UPK.PK,
		UID:        gsk.UID,
		MerklePath: merklePath,
		Directions: directions,
		R1:         r1, // LWE encryption randomness for first ciphertext
		R2:         r2, // LWE encryption randomness for second ciphertext
	}

	statement := &nizk.Statement{
		Message:    message,
		Ciphertext: ciphertext,
		Params:     gpk.PP,
		TPK:        gpk.TPK, // Add tracing public key for LWE constraints
		MerkleRoot: info.RootHash,
	}

	tProof := time.Now()
	proof, err := nizk.Prove(witness, statement)
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %v", err)
	}
	if prof {
		fmt.Fprintf(os.Stderr, "[profile] Prove: %v\n", time.Since(tProof))
	}
	if prof {
		fmt.Fprintf(os.Stderr, "[profile] Sign total: %v\n", time.Since(tAll))
	}

	return &Signature{
		Epoch:      info.Epoch,
		Ciphertext: ciphertext,
		Proof:      proof,
		Message:    message,
	}, nil
}

// Verify verifies a group signature using the full Stern protocol
// Returns error with details if verification fails, nil if successful
func Verify(gpk *GroupPublicKey, info *GroupInfo, sig *Signature) error {
	// 1. Check epoch validity - allow signatures from past epochs
	// This allows old signatures to remain valid even after group changes
	// Trade-off: Revoked users can reuse old credentials to create "new" signatures
	// that verify against their revocation epoch's root
	if sig.Epoch > info.Epoch {
		return fmt.Errorf("invalid epoch: signature from future")
	}

	// 2. Validate ciphertext integrity (prevent zero ciphertext attacks)
	if sig.Ciphertext == nil {
		return fmt.Errorf("ciphertext is nil")
	}
	if !validateCiphertext(sig.Ciphertext) {
		return fmt.Errorf("invalid ciphertext")
	}

	// 3. Verify zero-knowledge proof using full Stern protocol
	// Select the appropriate root based on signature epoch
	var expectedRoot *lattice.Vector
	if sig.Epoch == info.Epoch {
		expectedRoot = info.RootHash
	} else {
		if info.HistoricalRoots == nil {
			return fmt.Errorf("no historical roots available")
		}
		historicalRoot, exists := info.HistoricalRoots[sig.Epoch]
		if !exists {
			return fmt.Errorf("historical root not found for epoch %d", sig.Epoch)
		}
		expectedRoot = historicalRoot
	}

	statement := &nizk.Statement{
		Message:    sig.Message,
		Ciphertext: sig.Ciphertext,
		Params:     gpk.PP,
		TPK:        gpk.TPK, // Add tracing public key for LWE verification
	}

	return nizk.Verify(sig.Proof, statement, expectedRoot)
}

// validateCiphertext checks ciphertext components are non-zero and well-formed
func validateCiphertext(ct *Ciphertext) bool {
	// Check all ciphertext components exist and are non-zero
	if ct.C1_U == nil || ct.C1_V == nil || ct.C2_U == nil || ct.C2_V == nil {
		return false
	}

	// Check C1_U is non-zero
	if isZeroVector(ct.C1_U) {
		return false
	}

	// Check C1_V is non-zero
	if isZeroVector(ct.C1_V) {
		return false
	}

	// Check C2_U is non-zero
	if isZeroVector(ct.C2_U) {
		return false
	}

	// Check C2_V is non-zero
	if isZeroVector(ct.C2_V) {
		return false
	}

	return true
}

// isZeroVector checks if a vector is all zeros
func isZeroVector(v *lattice.Vector) bool {
	if v == nil || len(v.Data) == 0 {
		return true
	}

	for _, val := range v.Data {
		if val != 0 {
			return false
		}
	}
	return true
}

// verifyMerkleRootConsistency verifies that the Merkle path in the proof
// leads to the expected root in group info
// encryptIdentity encrypts the user's identity using Naor-Yung double encryption
// Paper specification: For i ∈ {1,2}, sample r_i ←$ {0,1}^{m_E} and compute
//
//	c_i = (c_{i,1}, c_{i,2})
//	    = (B·r_i mod q, P_i·r_i + ⌈q/2⌉·bin(j) mod q) ∈ Z_q^n × Z_q^ℓ
func encryptIdentity(gpk *GroupPublicKey, uid int) (*Ciphertext, *lattice.Vector, *lattice.Vector, error) {
	params := gpk.PP

	// 1. Sample binary random vectors r1, r2 ←$ {0,1}^{m_E}
	r1, err := lattice.BinaryVector(params.M_E, params.Q)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate r1: %v", err)
	}

	r2, err := lattice.BinaryVector(params.M_E, params.Q)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate r2: %v", err)
	}

	// 2. Encode UID as binary vector bin(j) ∈ {0,1}^ℓ
	binJ := lattice.NewVector(params.L, params.Q)
	for i := 0; i < params.L; i++ {
		bit := (uid >> i) & 1
		binJ.Data[i] = int64(bit)
	}

	// 3. Message scaling: ⌈q/2⌉ for robust decryption
	halfQ := params.Q / 2

	// Scale message: ⌈q/2⌉ · bin(j)
	scaledMsg := lattice.NewVector(params.L, params.Q)
	for i := 0; i < params.L; i++ {
		scaledMsg.Data[i] = (halfQ * binJ.Data[i]) % params.Q
	} // 4. First encryption: c_1 = (c_{1,1}, c_{1,2})
	//    c_{1,1} = B·r_1 mod q ∈ Z_q^n
	//    c_{1,2} = P_1·r_1 + ⌈q/2⌉·bin(j) mod q ∈ Z_q^ℓ

	c1_1 := gpk.TPK.B.Mul(r1)    // B·r_1 (n-dimensional)
	temp1 := gpk.TPK.P1.Mul(r1)  // P_1·r_1 (ℓ-dimensional)
	c1_2 := temp1.Add(scaledMsg) // P_1·r_1 + ⌈q/2⌉·bin(j)

	// 5. Second encryption: c_2 = (c_{2,1}, c_{2,2})
	//    c_{2,1} = B·r_2 mod q ∈ Z_q^n
	//    c_{2,2} = P_2·r_2 + ⌈q/2⌉·bin(j) mod q ∈ Z_q^ℓ

	c2_1 := gpk.TPK.B.Mul(r2)    // B·r_2 (n-dimensional)
	temp2 := gpk.TPK.P2.Mul(r2)  // P_2·r_2 (ℓ-dimensional)
	c2_2 := temp2.Add(scaledMsg) // P_2·r_2 + ⌈q/2⌉·bin(j)

	ciphertext := &Ciphertext{
		C1_U: c1_1, // c_{1,1} = B·r_1
		C1_V: c1_2, // c_{1,2} = P_1·r_1 + ⌈q/2⌉·bin(j)
		C2_U: c2_1, // c_{2,1} = B·r_2
		C2_V: c2_2, // c_{2,2} = P_2·r_2 + ⌈q/2⌉·bin(j)
	}

	// Return ciphertext along with the randomness r1, r2 (needed for ZK proof)
	return ciphertext, r1, r2, nil
}
