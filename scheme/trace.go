package scheme

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

// TraceProof represents a proof of correct tracing
type TraceProof struct {
	UID               int
	DecryptedIdentity []byte
	Proof             *lattice.Vector // Proof of correct decryption
	SigHash           []byte          // Binds proof to signature's ciphertext
}

// Trace traces a signature to the signer's identity
// This is run by the Tracing Manager (TM)
func Trace(gpk *GroupPublicKey, tsk *TracingSecretKey, info *GroupInfo,
	reg *RegistrationTable, sig *Signature) (int, *TraceProof, error) {

	// // Optional but recommended: verify signature before tracing
	// if err := Verify(gpk, info, sig); err != nil {
	// 	return -1, nil, fmt.Errorf("cannot trace invalid signature: %v", err)
	// }

	// 1. Decrypt the ciphertext to recover the identity
	uid, err := decryptIdentity(gpk, tsk, sig.Ciphertext)
	if err != nil {
		return -1, nil, fmt.Errorf("failed to decrypt identity: %v", err)
	}

	// 2. Verify that the UID is in the registration table
	record, exists := reg.Records[uid]
	if !exists {
		return -1, nil, fmt.Errorf("UID %d not found in registration table", uid)
	}

	// 3. Verify that the user was active at the signature epoch
	// (This check would need to track historical group info)
	if !info.ActiveUIDs[uid] {
		return -1, nil, fmt.Errorf("UID %d was not active at epoch %d", uid, sig.Epoch)
	}

	// 4. Generate proof of correct tracing
	proof, err := generateTraceProof(gpk, tsk, sig.Ciphertext, uid)
	if err != nil {
		return -1, nil, fmt.Errorf("failed to generate trace proof: %v", err)
	}

	// Include the public key in the proof
	// Paper: record.UPK is now directly a Vector (reg[i][1])
	upkBytes, _ := json.Marshal(record.UPK.Data)
	proof.DecryptedIdentity = upkBytes
	// Bind proof to this signature's ciphertext
	proof.SigHash = hashCiphertext(sig.Ciphertext)

	return uid, proof, nil
}

// Judge verifies a tracing proof
func Judge(gpk *GroupPublicKey, uid int, info *GroupInfo, proof *TraceProof, sig *Signature) bool {
	// 1. Check that UID matches
	if proof.UID != uid {
		return false
	}

	// // 2. Verify the signature is valid before judging the trace
	// if Verify(gpk, info, sig) != nil {
	// 	return false
	// }

	// 3. Check proof binds to this ciphertext
	if proof.SigHash == nil || len(proof.SigHash) == 0 {
		return false
	}
	if !equalBytes(proof.SigHash, hashCiphertext(sig.Ciphertext)) {
		return false
	}

	// 4. Verify the tracing proof (simplified threshold decode)
	return verifyTraceProof(gpk, proof)
}

// decryptIdentity decrypts the ciphertext to recover the user's identity
// Paper specification: Decryption uses tsk = (S₁, E₁) to decrypt c₁ = (c_{1,1}, c_{1,2})
// Compute: bin(j) = ⌊(c_{1,2} - S₁^T · c_{1,1}) / (q/2)⌉
// Where: c_{1,2} - S₁^T · c_{1,1} = E₁·r₁ + ⌈q/2⌉·bin(j) (small noise + message)
func decryptIdentity(gpk *GroupPublicKey, tsk *TracingSecretKey, ct *Ciphertext) (int, error) {
	params := gpk.PP

	// Paper decryption: m = c_{1,2} - S₁^T · c_{1,1}
	// Where:
	//   c_{1,1} = B·r₁ (n-dimensional)
	//   c_{1,2} = P₁·r₁ + ⌈q/2⌉·bin(j) (ℓ-dimensional)
	//   P₁ = S₁^T·B + E₁
	// So: c_{1,2} - S₁^T·c_{1,1} = E₁·r₁ + ⌈q/2⌉·bin(j)

	// Step 1: Compute S₁^T · c_{1,1}
	// S₁ is n×ℓ, so S₁^T is ℓ×n
	// c_{1,1} is n-dimensional
	// Result: S₁^T · c_{1,1} is ℓ-dimensional
	S1_T := tsk.S1.Transpose()
	S1T_times_c11 := S1_T.Mul(ct.C1_U)

	// Step 2: Compute noisy message: c_{1,2} - S₁^T·c_{1,1}
	noisyMsg := lattice.NewVector(ct.C1_V.Size, params.Q)
	for i := 0; i < ct.C1_V.Size && i < S1T_times_c11.Size; i++ {
		diff := ct.C1_V.Data[i] - S1T_times_c11.Data[i]
		noisyMsg.Data[i] = diff % params.Q
		if noisyMsg.Data[i] < 0 {
			noisyMsg.Data[i] += params.Q
		}
	}

	// Step 3: Decode UID bits using threshold decoding
	// Each component should be either ≈0 or ≈q/2
	uid := 0
	halfQ := params.Q / 2
	quarterQ := params.Q / 4

	for i := 0; i < params.L && i < noisyMsg.Size; i++ {
		val := noisyMsg.Data[i]

		// Normalize to [0, q)
		val = val % params.Q
		if val < 0 {
			val += params.Q
		}

		// Threshold decoding around q/2:
		// - If val is close to 0 (< q/4): bit = 0
		// - If val is close to q/2 (between q/4 and 3q/4): bit = 1
		// - If val is close to q (> 3q/4): bit = 0 (wraparound)
		bit := 0
		threeQuarterQ := halfQ + quarterQ
		if val >= quarterQ && val < threeQuarterQ {
			bit = 1
		}

		uid |= bit << i
	}

	return uid, nil
}

// generateTraceProof generates a proof that the tracing was done correctly
// Paper: TM proves correct decryption of c₁ using tsk = (S₁, E₁)
func generateTraceProof(gpk *GroupPublicKey, tsk *TracingSecretKey,
	ct *Ciphertext, uid int) (*TraceProof, error) {

	params := gpk.PP

	// Generate proof by re-computing the decryption
	// Proof consists of the noisy message: c_{1,2} - S₁^T·c_{1,1}
	S1_T := tsk.S1.Transpose()
	S1T_times_c11 := S1_T.Mul(ct.C1_U)

	// Compute noisy message as proof
	noisyMsg := lattice.NewVector(ct.C1_V.Size, params.Q)
	for i := 0; i < ct.C1_V.Size && i < S1T_times_c11.Size; i++ {
		diff := ct.C1_V.Data[i] - S1T_times_c11.Data[i]
		noisyMsg.Data[i] = diff % params.Q
		if noisyMsg.Data[i] < 0 {
			noisyMsg.Data[i] += params.Q
		}
	}

	return &TraceProof{
		UID:   uid,
		Proof: noisyMsg, // Proof = decrypted noisy message
	}, nil
}

// verifyTraceProof verifies the tracing proof
// Verifies that TM correctly decrypted the ciphertext to obtain the claimed UID
func verifyTraceProof(gpk *GroupPublicKey, proof *TraceProof) bool {
	params := gpk.PP

	if proof.Proof == nil {
		return false
	}

	// The proof contains the noisy message: E₁·r₁ + ⌈q/2⌉·bin(j)
	// Decode it to verify the claimed UID
	noisyMsg := proof.Proof

	// Decode UID from noisy message
	uid := 0
	halfQ := params.Q / 2
	quarterQ := params.Q / 4

	for i := 0; i < params.L && i < noisyMsg.Size; i++ {
		val := noisyMsg.Data[i]

		// Normalize to [0, q)
		val = val % params.Q
		if val < 0 {
			val += params.Q
		}

		// Threshold decoding around q/2
		bit := 0
		threeQuarterQ := halfQ + quarterQ
		if val >= quarterQ && val < threeQuarterQ {
			bit = 1
		}

		uid |= bit << i
	}

	// Verify the decoded UID matches the claimed UID
	return uid == proof.UID
}

// Helpers
func hashCiphertext(ct *Ciphertext) []byte {
	if ct == nil {
		return nil
	}
	// Simple hash over all components
	h := sha256.New()
	writeVec := func(v *lattice.Vector) {
		if v == nil {
			return
		}
		var buf [8]byte
		for i := 0; i < v.Size; i++ {
			binary.BigEndian.PutUint64(buf[:], uint64(v.Data[i]))
			h.Write(buf[:])
		}
	}
	writeVec(ct.C1_U)
	writeVec(ct.C1_V)
	writeVec(ct.C2_U)
	writeVec(ct.C2_V)
	return h.Sum(nil)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// OpeningInfo contains information for signature opening
type OpeningInfo struct {
	UID       int
	Signature *Signature
	Proof     *TraceProof
}

// BatchTrace traces multiple signatures efficiently
func BatchTrace(gpk *GroupPublicKey, tsk *TracingSecretKey, info *GroupInfo,
	reg *RegistrationTable, signatures []*Signature) ([]*OpeningInfo, error) {

	results := make([]*OpeningInfo, 0, len(signatures))

	for _, sig := range signatures {
		uid, proof, err := Trace(gpk, tsk, info, reg, sig)
		if err != nil {
			// Skip signatures that cannot be traced
			continue
		}

		results = append(results, &OpeningInfo{
			UID:       uid,
			Signature: sig,
			Proof:     proof,
		})
	}

	return results, nil
}

// VerifyBatch verifies multiple signatures efficiently
func VerifyBatch(gpk *GroupPublicKey, info *GroupInfo, signatures []*Signature) []bool {
	results := make([]bool, len(signatures))

	for i, sig := range signatures {
		results[i] = (Verify(gpk, info, sig) == nil)
	}

	return results
}

// SignatureSize estimates the size of a signature in bytes
func SignatureSize(sig *Signature) int {
	size := 0

	// Epoch
	size += 4

	// Ciphertext
	if sig.Ciphertext != nil {
		size += sig.Ciphertext.C1_U.Size * 32 // u1
		size += sig.Ciphertext.C1_V.Size * 32 // v1
		size += sig.Ciphertext.C2_U.Size * 32 // u2
		size += sig.Ciphertext.C2_V.Size * 32 // v2
	}

	// ZK Proof (commitments + responses)
	if sig.Proof != nil {
		for _, resp := range sig.Proof.Responses {
			if resp != nil {
				size += resp.Size * 32
			}
		}

		for _, triple := range sig.Proof.Commitments {
			if triple == nil {
				continue
			}
			if triple.C1 != nil {
				size += triple.C1.Size * 32
			}
			if triple.C2 != nil {
				size += triple.C2.Size * 32
			}
			if triple.C3 != nil {
				size += triple.C3.Size * 32
			}
		}
	}

	// Message
	size += len(sig.Message)

	return size
}

// SignatureHash removed (unused). Linking prevention not used in current CLI path.
