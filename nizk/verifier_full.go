package nizk

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"golang.org/x/crypto/sha3"
)

// VerifierFull implements the full Stern protocol verification
// Following Section 4.2 of the paper
//
// Verification checks for each challenge type:
// - Ch=1: Check Γ_η(z) ∈ VALID and commitment consistency
// - Ch=2: Check M·(z+r_z) = M·r_z + u and commitment consistency
// - Ch=3: Check M·r_z matches committed value and commitment consistency
func VerifierFull(proof *ZKProof, statement *Statement, expectedRoot *lattice.Vector) error {
	params := statement.Params

	if params == nil {
		return fmt.Errorf("nil public parameters")
	}

	if len(proof.Responses) != params.Kappa {
		return fmt.Errorf("expected %d responses, got %d", params.Kappa, len(proof.Responses))
	}

	if len(proof.Commitments) != params.Kappa {
		return fmt.Errorf("expected %d commitment triples, got %d", params.Kappa, len(proof.Commitments))
	}

	var (
		equation *UnifiedEquation
		err      error
	)
	if key, ok := buildEquationCacheKey(params, expectedRoot); ok {
		if cached, hit := verifierEquationCache.Get(key); hit {
			equation = cached
		} else {
			equation, err = buildPublicEquation(statement, expectedRoot, params)
			if err != nil {
				return fmt.Errorf("failed to build public equation: %v", err)
			}
			verifierEquationCache.Add(key, equation)
		}
	} else {
		equation, err = buildPublicEquation(statement, expectedRoot, params)
		if err != nil {
			return fmt.Errorf("failed to build public equation: %v", err)
		}
	}

	// Ensure the Merkle root is bound in the transcript as part of the public instance
	if statement != nil {
		statement.MerkleRoot = expectedRoot
	}
	transcript := buildFullTranscript(statement, proof.Commitments)
	// Debug: print short digest of transcript to ensure prover/verifier alignment
	if Debug {
		shake := sha3.NewShake256()
		_, _ = shake.Write(transcript)
		buf := make([]byte, 16)
		_, _ = shake.Read(buf)
		fmt.Printf("[debug] FS transcript digest (veri) = %x\n", buf)
	}
	expectedChallenges := lattice.FiatShamirHash(transcript, params.Kappa)

	// Derive challenges via Fiat–Shamir; ignore stored challenges to avoid serialization drift

	dummyWitness := getDummyWitnessTemplate(params)
	if dummyWitness == nil {
		return fmt.Errorf("failed to build witness template")
	}
	witnessSize := equation.WitnessSize
	rhoSize := 2 * params.NK

	if params.Kappa == 0 {
		return nil
	}

	verifyRound := func(round int) error {
		if Debug {
			fmt.Printf("[debug] round %d challenge=%d\n", round, expectedChallenges[round])
		}
		stored := proof.Commitments[round]
		if stored == nil {
			return fmt.Errorf("round %d: missing commitments", round)
		}

		response := proof.Responses[round]
		if response == nil {
			return fmt.Errorf("round %d: missing response", round)
		}

		switch expectedChallenges[round] {
		case 1:
			expectedSize := 2*witnessSize + 2*rhoSize
			if response.Size != expectedSize {
				if os.Getenv("NIZK_PROFILE") == "1" {
					fmt.Printf("[DEBUG] Challenge 1 size mismatch: expected=%d (2*%d + 2*%d), got=%d\n",
						expectedSize, witnessSize, rhoSize, response.Size)
				}
				return fmt.Errorf("round %d: invalid response size for challenge 1", round)
			}

			tz := lattice.NewVector(witnessSize, params.Q)
			tr := lattice.NewVector(witnessSize, params.Q)
			rho2Resp := lattice.NewVector(rhoSize, params.Q)
			rho3Resp := lattice.NewVector(rhoSize, params.Q)

			for i := 0; i < witnessSize; i++ {
				tz.Data[i] = response.Data[i]
				tr.Data[i] = response.Data[witnessSize+i]
			}

			offset := 2 * witnessSize
			for i := 0; i < rhoSize; i++ {
				rho2Resp.Data[i] = response.Data[offset+i]
			}
			offset += rhoSize
			for i := 0; i < rhoSize; i++ {
				rho3Resp.Data[i] = response.Data[offset+i]
			}

			if !isInVALID(tz, params) {
				return fmt.Errorf("round %d: t_z not in VALID", round)
			}
			if !isBinaryVectorMod(rho2Resp) || !isBinaryVectorMod(rho3Resp) {
				return fmt.Errorf("round %d: randomness not binary for challenge 1", round)
			}
			computed := commitGammaVerifier(tr, rho2Resp, params)
			if !vectorsEqualMod(computed, stored.C2, params.Q) {
				return fmt.Errorf("round %d: commitment C2 mismatch", round)
			}
			tzPlusTr := tz.Add(tr)
			if !vectorsEqualMod(commitGammaVerifier(tzPlusTr, rho3Resp, params), stored.C3, params.Q) {
				fmt.Printf("[DEBUG C3] tzPlusTr.Size=%d, rho3Resp.Size=%d\n", tzPlusTr.Size, rho3Resp.Size)
				computed := commitGammaVerifier(tzPlusTr, rho3Resp, params)
				fmt.Printf("[DEBUG C3] computed[0]=%v, stored[0]=%v\n", computed.Data[0], stored.C3.Data[0])
				return fmt.Errorf("round %d: commitment C3 mismatch", round)
			}

		case 2:
			eta, remaining, err := decodePermutation(response, params)
			if err != nil {
				return fmt.Errorf("round %d: failed to decode permutation: %v", round, err)
			}
			if err := verifyPermutation(eta, params); err != nil {
				return fmt.Errorf("round %d: invalid permutation: %v", round, err)
			}

			expectedRemaining := witnessSize + 2*rhoSize
			if remaining.Size != expectedRemaining {
				return fmt.Errorf("round %d: unexpected response size for challenge 2", round)
			}

			z2 := lattice.NewVector(witnessSize, params.Q)
			for i := 0; i < witnessSize; i++ {
				z2.Data[i] = remaining.Data[i]
			}

			offset := witnessSize
			rho1Resp := lattice.NewVector(rhoSize, params.Q)
			for i := 0; i < rhoSize; i++ {
				rho1Resp.Data[i] = remaining.Data[offset+i]
			}
			offset += rhoSize
			rho3Resp := lattice.NewVector(rhoSize, params.Q)
			for i := 0; i < rhoSize; i++ {
				rho3Resp.Data[i] = remaining.Data[offset+i]
			}

			syndrome := subtractVectorsMod(equation.M.Mul(z2), equation.U, params.Q)
			if syndrome == nil {
				return fmt.Errorf("round %d: failed to compute linear relation", round)
			}

			if !isBinaryVectorMod(rho1Resp) || !isBinaryVectorMod(rho3Resp) {
				return fmt.Errorf("round %d: randomness not binary for challenge 2", round)
			}

			{
				recomputed := commitToSyndrome(eta, syndrome, rho1Resp, params)
				if !vectorsEqualMod(recomputed, stored.C1, params.Q) {
					if Debug {
						show := 5
						if show > recomputed.Size {
							show = recomputed.Size
						}
						fmt.Printf("[debug] C1 recomputed[0:%d]=", show)
						for i := 0; i < show; i++ {
							fmt.Printf("%d ", recomputed.Data[i])
						}
						fmt.Println()
						fmt.Printf("[debug] C1 stored   [0:%d]=", show)
						for i := 0; i < show; i++ {
							fmt.Printf("%d ", stored.C1.Data[i])
						}
						fmt.Println()
					}
					return fmt.Errorf("round %d: commitment C1 mismatch", round)
				}
			}

			witnessZ2 := createWitnessViewFromVector(z2, dummyWitness)
			if witnessZ2 == nil {
				return fmt.Errorf("round %d: failed to reconstruct witness for z2", round)
			}

			gammaZ2 := applyFullPermutation(witnessZ2, eta)
			if !vectorsEqualMod(commitGammaVerifier(gammaZ2, rho3Resp, params), stored.C3, params.Q) {
				return fmt.Errorf("round %d: commitment C3 mismatch", round)
			}

		case 3:
			eta, remaining, err := decodePermutation(response, params)
			if err != nil {
				return fmt.Errorf("round %d: failed to decode permutation: %v", round, err)
			}
			if err := verifyPermutation(eta, params); err != nil {
				return fmt.Errorf("round %d: invalid permutation: %v", round, err)
			}

			expectedRemaining := witnessSize + 2*rhoSize
			if remaining.Size != expectedRemaining {
				return fmt.Errorf("round %d: unexpected response size for challenge 3", round)
			}

			rz := lattice.NewVector(witnessSize, params.Q)
			for i := 0; i < witnessSize; i++ {
				rz.Data[i] = remaining.Data[i]
			}

			offset := witnessSize
			rho1Resp := lattice.NewVector(rhoSize, params.Q)
			for i := 0; i < rhoSize; i++ {
				rho1Resp.Data[i] = remaining.Data[offset+i]
			}
			offset += rhoSize
			rho2Resp := lattice.NewVector(rhoSize, params.Q)
			for i := 0; i < rhoSize; i++ {
				rho2Resp.Data[i] = remaining.Data[offset+i]
			}

			syndrome := equation.M.Mul(rz)
			{
				recomputed := commitToSyndrome(eta, syndrome, rho1Resp, params)
				if !vectorsEqualMod(recomputed, stored.C1, params.Q) {
					if Debug {
						show := 5
						if show > recomputed.Size {
							show = recomputed.Size
						}
						fmt.Printf("[debug] C1 recomputed[0:%d]=", show)
						for i := 0; i < show; i++ {
							fmt.Printf("%d ", recomputed.Data[i])
						}
						fmt.Println()
						fmt.Printf("[debug] C1 stored   [0:%d]=", show)
						for i := 0; i < show; i++ {
							fmt.Printf("%d ", stored.C1.Data[i])
						}
						fmt.Println()
					}
					return fmt.Errorf("round %d: commitment C1 mismatch", round)
				}
			}

			if !isBinaryVectorMod(rho1Resp) || !isBinaryVectorMod(rho2Resp) {
				return fmt.Errorf("round %d: randomness not binary for challenge 3", round)
			}

			witnessRz := createWitnessViewFromVector(rz, dummyWitness)
			if witnessRz == nil {
				return fmt.Errorf("round %d: failed to reconstruct witness for r_z", round)
			}

			gammaRz := applyFullPermutation(witnessRz, eta)
			if !vectorsEqualMod(commitGammaVerifier(gammaRz, rho2Resp, params), stored.C2, params.Q) {
				return fmt.Errorf("round %d: commitment C2 mismatch", round)
			}

		default:
			return fmt.Errorf("round %d: unknown challenge value %d", round, expectedChallenges[round])
		}

		return nil
	}

	workerCount := lattice.MaxWorkers
	if workerCount <= 0 {
		workerCount = 1
	}
	if workerCount > params.Kappa {
		workerCount = params.Kappa
	}

	var abort atomic.Bool
	errCh := make(chan error, 1)
	jobs := make(chan int, params.Kappa)
	var wg sync.WaitGroup
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := range jobs {
				if abort.Load() {
					continue
				}
				if err := verifyRound(round); err != nil {
					if !abort.Load() {
						abort.Store(true)
						select {
						case errCh <- err:
						default:
						}
					}
				}
			}
		}()
	}

	for round := 0; round < params.Kappa; round++ {
		jobs <- round
	}
	close(jobs)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
	}

	// Explicit Merkle verification removed; constraints are enforced via M·z = u.

	return nil
}

func buildPublicEquation(stmt *Statement, merkleRoot *lattice.Vector, params *lattice.PublicParameters) (*UnifiedEquation, error) {
	// Build M and u from public information (without knowing witness z)
	// Paper Section 4.2: Verifier reconstructs M·z = u equation
	// This builder includes Merkle, SIS and LWE linear constraints as per paper.

	treeHeight := params.L

	// Extended dimensions for witness components (must match prover)
	xExtSize := 2 * params.M
	pExtSize := 2*params.NK - 1
	pHatExtSize := 4*params.NK - 2 // p̂ = ext(j_ℓ, p*) per paper
	jExtSizePerLevel := 2
	vExtSizePerLevel := 2 * params.NK
	vHatSizePerLevel := 4 * params.NK
	wHatSizePerLevel := 4 * params.NK
	r1ExtSize := 2 * params.M_E
	r2ExtSize := 2 * params.M_E

	// VExt and VHatExt have (ℓ-1) vectors; WExt and WHatExt have ℓ vectors
	vLevels := treeHeight - 1
	if vLevels < 0 {
		vLevels = 0
	}

	// Column offsets inside witness vector z
	// Paper witness (eq 8): interleaved structure
	// z = (x* || p* || p̂ || j_1...j_ℓ || v*_0 || v̂_0 || ŵ_0 || ... || v*_{ℓ-2} || v̂_{ℓ-2} || ŵ_{ℓ-2} || ŵ_{ℓ-1} || r*_1 || r*_2)
	offsetX := 0
	offsetP := offsetX + xExtSize
	offsetPHat := offsetP + pExtSize
	offsetJ := offsetPHat + pHatExtSize
	baseInterleaved := offsetJ + treeHeight*jExtSizePerLevel

	// Helper functions to get offsets in interleaved structure
	offsetVStar := func(level int) int {
		// v*_level position
		if level < 0 || level >= vLevels {
			return -1
		}
		return baseInterleaved + level*(vExtSizePerLevel+vHatSizePerLevel+wHatSizePerLevel)
	}
	offsetVHat := func(level int) int {
		// v̂_level position
		if level < 0 || level >= vLevels {
			return -1
		}
		return baseInterleaved + level*(vExtSizePerLevel+vHatSizePerLevel+wHatSizePerLevel) + vExtSizePerLevel
	}
	offsetWHat := func(level int) int {
		// ŵ_level position (works for all ℓ levels)
		if level < 0 || level >= treeHeight {
			return -1
		}
		if level < vLevels {
			// Interleaved: after v*_level and v̂_level
			return baseInterleaved + level*(vExtSizePerLevel+vHatSizePerLevel+wHatSizePerLevel) + vExtSizePerLevel + vHatSizePerLevel
		} else {
			// Last ŵ_{ℓ-1}: after all interleaved triplets
			return baseInterleaved + vLevels*(vExtSizePerLevel+vHatSizePerLevel+wHatSizePerLevel)
		}
	}

	offsetR1 := baseInterleaved + vLevels*(vExtSizePerLevel+vHatSizePerLevel+wHatSizePerLevel) + wHatSizePerLevel
	offsetR2 := offsetR1 + r1ExtSize
	totalCols := offsetR2 + r2ExtSize

	if params.A == nil || params.G == nil {
		return nil, fmt.Errorf("missing public matrices")
	}

	if stmt.TPK == nil {
		return nil, fmt.Errorf("missing tracing public key")
	}
	B, P1, P2 := stmt.TPK.GetMatrices()
	if B == nil || P1 == nil || P2 == nil {
		return nil, fmt.Errorf("incomplete tracing matrices")
	}

	// Total rows: Merkle root (n) + Merkle internal ((ℓ-1)-1)*n + SIS (n) + LWE1 (n + ℓ) + LWE2 (n + ℓ)
	// Merkle internal: for levels 2 to ℓ-1 (not including root or leaf)
	// For L=2: vLevels=1, internal levels = vLevels-1 = 0
	// For L=3: vLevels=2, internal levels = vLevels-1 = 1 (level 2)
	totalRows := 0
	totalRows += params.N // Merkle root
	if vLevels > 1 {
		totalRows += (vLevels - 1) * params.N // Merkle internal (only if ℓ-1 > 1, i.e., ℓ > 2)
	}
	totalRows += params.N              // SIS
	totalRows += params.N + treeHeight // LWE 1
	totalRows += params.N + treeHeight // LWE 2

	M := lattice.NewMatrix(totalRows, totalCols, params.Q)

	rowOffset := 0

	// Merkle root equation: A0·sel(v̂_0) + A1·sel(v̂_0) + A0·sel(ŵ_0) + A1·sel(ŵ_0) = G·u_τ
	// Level 0 refers to the first internal node above the leaf
	A0, A1 := lattice.SplitMatrix(params.A, params.NK)
	for i := 0; i < params.N; i++ {
		for j := 0; j < params.NK; j++ {
			// v̂_0 contributions (select 2*j+1 inside each 2·nk half)
			vHat0Offset := offsetVHat(0)
			colV0 := vHat0Offset + (2*j + 1)               // A0 part
			colV1 := vHat0Offset + 2*params.NK + (2*j + 1) // A1 part
			M.Data[rowOffset+i][colV0] = A0.Data[i][j]
			M.Data[rowOffset+i][colV1] = A1.Data[i][j]
			// ŵ_0 contributions
			wHat0Offset := offsetWHat(0)
			colW0 := wHat0Offset + (2*j + 1)
			colW1 := wHat0Offset + 2*params.NK + (2*j + 1)
			// accumulate
			M.Data[rowOffset+i][colW0] = (M.Data[rowOffset+i][colW0] + A0.Data[i][j]) % params.Q
			M.Data[rowOffset+i][colW1] = (M.Data[rowOffset+i][colW1] + A1.Data[i][j]) % params.Q
		}
	}
	rowOffset += params.N

	// Merkle internal levels: for level=1..ℓ-2, A*·v̂_level + A*·ŵ_level − G·sel(v*_{level-1}) = 0
	// VHatExt has (ℓ-1) elements: [v̂_0, ..., v̂_{ℓ-2}]
	// For L=2: vLevels=1, no internal-to-internal constraints (loop doesn't run)
	// For L=4: vLevels=3, loop runs for level=1,2 (linking v*_0→(v̂_1,ŵ_1) and v*_1→(v̂_2,ŵ_2))
	for level := 1; level < vLevels; level++ {
		vHatOffset_level := offsetVHat(level)
		wHatOffset_level := offsetWHat(level)
		vStarOffset_prev := offsetVStar(level - 1)

		for i := 0; i < params.N; i++ {
			for j := 0; j < params.NK; j++ {
				// v̂_level
				colV0 := vHatOffset_level + (2*j + 1)
				colV1 := vHatOffset_level + 2*params.NK + (2*j + 1)
				M.Data[rowOffset+i][colV0] = A0.Data[i][j]
				M.Data[rowOffset+i][colV1] = A1.Data[i][j]
				// ŵ_level
				colW0 := wHatOffset_level + (2*j + 1)
				colW1 := wHatOffset_level + 2*params.NK + (2*j + 1)
				M.Data[rowOffset+i][colW0] = (M.Data[rowOffset+i][colW0] + A0.Data[i][j]) % params.Q
				M.Data[rowOffset+i][colW1] = (M.Data[rowOffset+i][colW1] + A1.Data[i][j]) % params.Q
				// − G · sel(v*_{level-1}) i.e., pick second elements of pairs
				colVsel := vStarOffset_prev + (2*j + 1)
				neg := (-params.G.Data[i][j]) % params.Q
				if neg < 0 {
					neg += params.Q
				}
				M.Data[rowOffset+i][colVsel] = neg
			}
		}
		rowOffset += params.N
	}

	// SIS binding equation: A·x - G·p = 0 (n rows)
	for i := 0; i < params.N; i++ {
		// x* selection: take the second bit of each (1−x_i, x_i) pair → column 2*j+1
		for j := 0; j < params.M; j++ {
			col := offsetX + 2*j + 1
			if col < totalCols {
				M.Data[rowOffset+i][col] = params.A.Data[i][j]
			}
		}
		// p* selection: first NK entries hold p; complements follow and are ignored
		for j := 0; j < params.G.Cols; j++ {
			col := offsetP + j
			if col < totalCols {
				neg := (-params.G.Data[i][j]) % params.Q
				if neg < 0 {
					neg += params.Q
				}
				M.Data[rowOffset+i][col] = neg
			}
		}
	}
	rowOffset += params.N

	// LWE equations for ciphertext 1: B·r1 (n rows)
	for i := 0; i < params.N; i++ {
		for j := 0; j < B.Cols; j++ {
			col := offsetR1 + 2*j + 1 // select r1 bits
			if col < totalCols {
				M.Data[rowOffset+i][col] = B.Data[i][j]
			}
		}
	}
	rowOffset += params.N

	// LWE equations for ciphertext 1: P1·r1 + ⌈q/2⌉·bin(j) (ℓ rows)
	halfQ := params.Q / 2
	for i := 0; i < treeHeight; i++ {
		// P1 · r1
		for j := 0; j < P1.Cols; j++ {
			col := offsetR1 + 2*j + 1
			if col < totalCols {
				M.Data[rowOffset+i][col] = P1.Data[i][j]
			}
		}
		// + ⌈q/2⌉ · j_i where j_i is the second entry in j*_i
		jBitCol := offsetJ + i*jExtSizePerLevel + 1
		if jBitCol < totalCols {
			M.Data[rowOffset+i][jBitCol] = halfQ
		}
	}
	rowOffset += treeHeight

	// LWE equations for ciphertext 2: B·r2 (n rows)
	for i := 0; i < params.N; i++ {
		for j := 0; j < B.Cols; j++ {
			col := offsetR2 + 2*j + 1 // select r2 bits
			if col < totalCols {
				M.Data[rowOffset+i][col] = B.Data[i][j]
			}
		}
	}
	rowOffset += params.N

	// LWE equations for ciphertext 2: P2·r2 + ⌈q/2⌉·bin(j) (ℓ rows)
	for i := 0; i < treeHeight; i++ {
		// P2 · r2
		for j := 0; j < P2.Cols; j++ {
			col := offsetR2 + 2*j + 1
			if col < totalCols {
				M.Data[rowOffset+i][col] = P2.Data[i][j]
			}
		}
		// + ⌈q/2⌉ · j_i
		jBitCol := offsetJ + i*jExtSizePerLevel + 1
		if jBitCol < totalCols {
			// Accumulate with existing entry if any (should be zero here)
			M.Data[rowOffset+i][jBitCol] = halfQ
		}
	}

	// Build u vector aligned with blocks: [G·u_τ (n) | 0^{(ℓ-1)·n} | 0^n | c1_u (n) | c1_v (ℓ) | c2_u (n) | c2_v (ℓ)]
	u := lattice.NewVector(totalRows, params.Q)
	uOffset := 0

	// Merkle root RHS = G·u_τ
	if merkleRoot != nil {
		rootTerm := params.G.Mul(merkleRoot)
		for i := 0; i < params.N && i < rootTerm.Size; i++ {
			u.Data[uOffset+i] = rootTerm.Data[i]
		}
	}
	uOffset += params.N

	// Merkle internal rows RHS = 0^{(vLevels-1)·n} (only if vLevels > 1)
	if vLevels > 1 {
		uOffset += (vLevels - 1) * params.N
	}

	// SIS RHS = 0^n
	uOffset += params.N

	if stmt.Ciphertext != nil {
		c1u, c1v, c2u, c2v := stmt.Ciphertext.GetComponents()

		// c1_u (n rows)
		for i := 0; i < params.N && i < c1u.Size; i++ {
			u.Data[uOffset+i] = c1u.Data[i]
		}
		uOffset += params.N

		// c1_v (ℓ rows)
		for i := 0; i < treeHeight && i < c1v.Size; i++ {
			u.Data[uOffset+i] = c1v.Data[i]
		}
		uOffset += treeHeight

		// c2_u (n rows)
		for i := 0; i < params.N && i < c2u.Size; i++ {
			u.Data[uOffset+i] = c2u.Data[i]
		}
		uOffset += params.N

		// c2_v (ℓ rows)
		for i := 0; i < treeHeight && i < c2v.Size; i++ {
			u.Data[uOffset+i] = c2v.Data[i]
		}
		// uOffset += treeHeight // not used further
	}

	return &UnifiedEquation{
		M:           M,
		U:           u,
		Z:           nil,
		WitnessSize: totalCols,
	}, nil
}

func vectorsEqualMod(a, b *lattice.Vector, q int64) bool {
	if a.Size != b.Size {
		return false
	}

	for i := 0; i < a.Size; i++ {
		aMod := a.Data[i] % q
		if aMod < 0 {
			aMod += q
		}
		bMod := b.Data[i] % q
		if bMod < 0 {
			bMod += q
		}
		if aMod != bMod {
			return false
		}
	}

	return true
}

func subtractVectorsMod(a, b *lattice.Vector, q int64) *lattice.Vector {
	if a == nil || b == nil || a.Size != b.Size {
		return nil
	}

	result := lattice.NewVector(a.Size, q)
	for i := 0; i < a.Size; i++ {
		diff := (a.Data[i] - b.Data[i]) % q
		if diff < 0 {
			diff += q
		}
		result.Data[i] = diff
	}
	return result
}

func isBinaryVectorMod(v *lattice.Vector) bool {
	if v == nil {
		return false
	}

	for i := 0; i < v.Size; i++ {
		val := v.Data[i] % v.Q
		if val < 0 {
			val += v.Q
		}
		if val != 0 && val != 1 {
			return false
		}
	}

	return true
}

// commitGammaVerifier mirrors commitGamma in the prover for C2/C3 verification.
func commitGammaVerifier(data *lattice.Vector, rho *lattice.Vector, params *lattice.PublicParameters) *lattice.Vector {
	var msg []byte
	var buf [8]byte
	for i := 0; i < data.Size; i++ {
		binary.BigEndian.PutUint64(buf[:], uint64(data.Data[i]))
		msg = append(msg, buf[:]...)
	}
	return lattice.StringCommitment(msg, rho, params)
}

// decodePermutation extracts permutation η from response vector
// Returns (eta, remainingResponse, error)
func decodePermutation(response *lattice.Vector, params *lattice.PublicParameters) (*Permutation, *lattice.Vector, error) {
	// Calculate expected permutation sizes
	M_E := params.M_E
	treeHeight := params.L

	xExtSize := 2 * params.M
	pExtSize := 2*params.NK - 1
	jExtSizePerBit := 2
	vExtSizePerLevel := 2 * params.NK
	wExtSizePerLevel := 2 * params.NK
	vHatSizePerLevel := 4 * params.NK
	wHatSizePerLevel := 4 * params.NK
	r1ExtSize := 2 * M_E
	r2ExtSize := 2 * M_E

	// Total permutation encoding size
	// NOTE: Bv has (ℓ-1) levels, Bw has ℓ levels
	// NOTE: BvHat has (ℓ-1) levels, BwHat has ℓ levels
	phiSize := xExtSize + pExtSize +
		treeHeight*jExtSizePerBit +
		(treeHeight-1)*vExtSizePerLevel + // Bv: ℓ-1 levels
		treeHeight*wExtSizePerLevel + // Bw: ℓ levels
		(treeHeight-1)*vHatSizePerLevel + // BvHat: ℓ-1 levels
		treeHeight*wHatSizePerLevel + // BwHat: ℓ levels
		r1ExtSize + r2ExtSize

	if response.Size < phiSize {
		return nil, nil, fmt.Errorf("response too small to contain permutation")
	}

	eta := &Permutation{}
	offset := 0

	// Decode Bx
	eta.Bx = make([]int, xExtSize)
	for i := 0; i < xExtSize; i++ {
		eta.Bx[i] = int(response.Data[offset+i])
	}
	offset += xExtSize

	// Decode Bp
	eta.Bp = make([]int, pExtSize)
	for i := 0; i < pExtSize; i++ {
		eta.Bp[i] = int(response.Data[offset+i])
	}
	offset += pExtSize

	// Decode Bj[]
	eta.Bj = make([][]int, treeHeight)
	for level := 0; level < treeHeight; level++ {
		eta.Bj[level] = make([]int, jExtSizePerBit)
		for i := 0; i < jExtSizePerBit; i++ {
			eta.Bj[level][i] = int(response.Data[offset+i])
		}
		offset += jExtSizePerBit
	}

	// Decode Bv[] - NOTE: Only ℓ-1 levels (matches VExt)
	eta.Bv = make([][]int, treeHeight-1)
	for level := 0; level < treeHeight-1; level++ {
		eta.Bv[level] = make([]int, vExtSizePerLevel)
		for i := 0; i < vExtSizePerLevel; i++ {
			eta.Bv[level][i] = int(response.Data[offset+i])
		}
		offset += vExtSizePerLevel
	}

	// Decode Bw[]
	eta.Bw = make([][]int, treeHeight)
	for level := 0; level < treeHeight; level++ {
		eta.Bw[level] = make([]int, wExtSizePerLevel)
		for i := 0; i < wExtSizePerLevel; i++ {
			eta.Bw[level][i] = int(response.Data[offset+i])
		}
		offset += wExtSizePerLevel
	}

	// Decode BvHat[] - NOTE: Only ℓ-1 levels (one less than tree height)
	eta.BvHat = make([][]int, treeHeight-1)
	// fmt.Printf("[DEBUG decode] BvHat offset=%d, expected %d levels × %d size = %d total\n", offset, treeHeight-1, vHatSizePerLevel, (treeHeight-1)*vHatSizePerLevel)
	for level := 0; level < treeHeight-1; level++ {
		eta.BvHat[level] = make([]int, vHatSizePerLevel)
		for i := 0; i < vHatSizePerLevel; i++ {
			eta.BvHat[level][i] = int(response.Data[offset+i])
		}
		offset += vHatSizePerLevel
	}

	// Decode BwHat[] - NOTE: Full ℓ levels
	eta.BwHat = make([][]int, treeHeight)
	// fmt.Printf("[DEBUG decode] BwHat offset=%d, expected %d levels × %d size = %d total\n", offset, treeHeight, wHatSizePerLevel, treeHeight*wHatSizePerLevel)
	for level := 0; level < treeHeight; level++ {
		eta.BwHat[level] = make([]int, wHatSizePerLevel)
		for i := 0; i < wHatSizePerLevel; i++ {
			eta.BwHat[level][i] = int(response.Data[offset+i])
		}
		// fmt.Printf("[DEBUG decode] BwHat[%d][1088]=%d, BwHat[%d][1089]=%d\n", level, eta.BwHat[level][1088], level, eta.BwHat[level][1089])
		offset += wHatSizePerLevel
	}

	// Decode Br1
	eta.Br1 = make([]int, r1ExtSize)
	for i := 0; i < r1ExtSize; i++ {
		eta.Br1[i] = int(response.Data[offset+i])
	}
	offset += r1ExtSize

	// Decode Br2
	eta.Br2 = make([]int, r2ExtSize)
	for i := 0; i < r2ExtSize; i++ {
		eta.Br2[i] = int(response.Data[offset+i])
	}
	offset += r2ExtSize

	// Extract remaining response (z and randomness)
	remainingSize := response.Size - phiSize
	remaining := lattice.NewVector(remainingSize, params.Q)
	for i := 0; i < remainingSize; i++ {
		remaining.Data[i] = response.Data[phiSize+i]
	}

	return eta, remaining, nil
}

// verifyPermutation checks if η is a valid permutation
// Verifies that each component is a bijection (valid permutation of indices)
func verifyPermutation(eta *Permutation, params *lattice.PublicParameters) error {
	if eta == nil {
		return fmt.Errorf("nil permutation")
	}

	M_E := params.M_E
	treeHeight := params.L

	xExtSize := 2 * params.M
	pExtSize := 2*params.NK - 1
	jExtSizePerBit := 2
	vExtSizePerLevel := 2 * params.NK
	wExtSizePerLevel := 2 * params.NK
	vHatSizePerLevel := 4 * params.NK
	wHatSizePerLevel := 4 * params.NK
	r1ExtSize := 2 * M_E
	r2ExtSize := 2 * M_E

	// Verify Bx is a valid permutation of [0..xExtSize-1]
	if err := isValidPermutation(eta.Bx, xExtSize); err != nil {
		return fmt.Errorf("invalid Bx: %v", err)
	}

	// Verify Bp is a valid permutation of [0..pExtSize-1]
	if err := isValidPermutation(eta.Bp, pExtSize); err != nil {
		return fmt.Errorf("invalid Bp: %v", err)
	}

	// Verify each Bj[i] is a valid permutation
	if len(eta.Bj) != treeHeight {
		return fmt.Errorf("wrong number of Bj permutations: got %d, expected %d", len(eta.Bj), treeHeight)
	}
	for i, bj := range eta.Bj {
		if err := isValidPermutation(bj, jExtSizePerBit); err != nil {
			return fmt.Errorf("invalid Bj[%d]: %v", i, err)
		}
	}

	// Verify each Bv[i] is a valid, pair-preserving permutation over 2·NK
	// Validate Bv permutations (ℓ-1 levels)
	if len(eta.Bv) != treeHeight-1 {
		return fmt.Errorf("wrong number of Bv permutations: got %d, expected %d", len(eta.Bv), treeHeight-1)
	}
	for i, bv := range eta.Bv {
		if err := isValidPermutation(bv, vExtSizePerLevel); err != nil {
			return fmt.Errorf("invalid Bv[%d]: %v", i, err)
		}
		if !isPairPreserving(bv, params.NK) {
			return fmt.Errorf("bv[%d] not pair-preserving", i)
		}
	}

	// Verify each Bw[i] is a valid permutation
	if len(eta.Bw) != treeHeight {
		return fmt.Errorf("wrong number of Bw permutations: got %d, expected %d", len(eta.Bw), treeHeight)
	}

	// Verify each BvHat[i] is a valid permutation - NOTE: Only ℓ-1 levels
	if len(eta.BvHat) != treeHeight-1 {
		return fmt.Errorf("wrong number of BvHat permutations: got %d, expected %d", len(eta.BvHat), treeHeight-1)
	}
	for i, bvh := range eta.BvHat {
		if err := isValidPermutation(bvh, vHatSizePerLevel); err != nil {
			return fmt.Errorf("invalid BvHat[%d]: %v", i, err)
		}
	}

	// Verify each BwHat[i] is a valid permutation and preserves half boundaries and pairs
	if len(eta.BwHat) != treeHeight {
		return fmt.Errorf("wrong number of BwHat permutations: got %d, expected %d", len(eta.BwHat), treeHeight)
	}
	for i, bwh := range eta.BwHat {
		if err := isValidPermutation(bwh, wHatSizePerLevel); err != nil {
			return fmt.Errorf("invalid BwHat[%d]: %v", i, err)
		}
		if !isHatPairPreserving(bwh, params.NK) {
			// Debug: print first few values to see what's wrong
			sample := ""
			for j := 0; j < 10 && j < len(bwh); j++ {
				sample += fmt.Sprintf("%d,", bwh[j])
			}
			half := 2 * params.NK
			sampleSecondHalf := ""
			for j := half; j < half+10 && j < len(bwh); j++ {
				sampleSecondHalf += fmt.Sprintf("[%d]=%d,", j, bwh[j])
			}
			return fmt.Errorf("bwHat[%d] not half/pair-preserving (len=%d, NK=%d, half=%d) first10=%s secondHalf=%s",
				i, len(bwh), params.NK, half, sample, sampleSecondHalf)
		}
	}
	for i, bw := range eta.Bw {
		if err := isValidPermutation(bw, wExtSizePerLevel); err != nil {
			return fmt.Errorf("invalid Bw[%d]: %v", i, err)
		}
		if !isPairPreserving(bw, params.NK) {
			return fmt.Errorf("bw[%d] not pair-preserving", i)
		}
	}

	// Verify Br1 is a valid permutation
	if err := isValidPermutation(eta.Br1, r1ExtSize); err != nil {
		return fmt.Errorf("invalid Br1: %v", err)
	}

	// Verify Br2 is a valid permutation
	if err := isValidPermutation(eta.Br2, r2ExtSize); err != nil {
		return fmt.Errorf("invalid Br2: %v", err)
	}

	return nil
}

// isPairPreserving checks that a permutation over 2·pairs maps (2j,2j+1) → (2π(j),2π(j)+1) for some π.
func isPairPreserving(perm []int, pairs int) bool {
	if len(perm) != 2*pairs {
		return false
	}
	// derive mapping from even positions
	for j := 0; j < pairs; j++ {
		a := perm[2*j]
		b := perm[2*j+1]
		if a/2 != b/2 {
			return false
		}
		// positions within new pair must be 2*dest and 2*dest+1 in some order, but we enforce order preservation
		if b != a+1 || a%2 != 0 {
			return false
		}
	}
	return true
}

// isHatPairPreserving checks that a permutation over 4·nk preserves half boundaries and pair order within each half.
func isHatPairPreserving(perm []int, nk int) bool {
	if len(perm) != 4*nk {
		fmt.Printf("[DEBUG isHatPairPreserving] Wrong length: got %d, expected %d\n", len(perm), 4*nk)
		return false
	}
	half := 2 * nk
	// Check first half block [0,2·nk) maps within [0,2·nk) and preserves pairs
	if !checkHalfPairPreserving(perm[:half], nk) {
		fmt.Printf("[DEBUG isHatPairPreserving] First half check failed\n")
		return false
	}
	// Check second half block [2·nk,4·nk) maps within [2·nk,4·nk)
	// Extract the images of indices in [2·nk,4·nk) and normalize by subtracting 2·nk
	part := make([]int, half)
	for i := 0; i < half; i++ {
		v := perm[half+i] - half
		if v < 0 || v >= half {
			fmt.Printf("[DEBUG isHatPairPreserving] Second half boundary violation at i=%d: perm[%d]=%d, v=%d (should be in [%d,%d))\n",
				i, half+i, perm[half+i], v, half, 2*half)
			return false
		}
		part[i] = v
	}
	if !checkHalfPairPreserving(part, nk) {
		fmt.Printf("[DEBUG isHatPairPreserving] Second half check failed\n")
		return false
	}
	return true
}

func checkHalfPairPreserving(perm []int, nk int) bool {
	if len(perm) != 2*nk {
		return false
	}
	for j := 0; j < nk; j++ {
		a := perm[2*j]
		b := perm[2*j+1]
		// Check that a and b come from the same pair (indices that differ by 1)
		if a/2 != b/2 {
			fmt.Printf("[DEBUG] Pair check failed at j=%d: a=%d, b=%d, a/2=%d, b/2=%d\n", j, a, b, a/2, b/2)
			return false
		}
		// Allow pairs in either order: (even, odd) or (odd, even)
		if !(b == a+1 || a == b+1) {
			fmt.Printf("[DEBUG] Consecutive check failed at j=%d: a=%d, b=%d\n", j, a, b)
			return false
		}
	}
	return true
}

// isValidPermutation checks if perm is a valid permutation of [0..n-1]
// A valid permutation is a bijection - each index appears exactly once
func isValidPermutation(perm []int, n int) error {
	if len(perm) != n {
		return fmt.Errorf("wrong size: got %d, expected %d", len(perm), n)
	}

	// Check each element is in range and appears exactly once
	seen := make([]bool, n)
	for i, val := range perm {
		if val < 0 || val >= n {
			return fmt.Errorf("element %d out of range [0,%d): %d", i, n, val)
		}
		if seen[val] {
			return fmt.Errorf("duplicate element: %d", val)
		}
		seen[val] = true
	}

	// Verify all indices were seen (completeness)
	for i, s := range seen {
		if !s {
			return fmt.Errorf("missing element: %d", i)
		}
	}

	return nil
}

// createDummyWitness creates a witness structure with correct sizes for permutation derivation
// The verifier doesn't have the actual witness, but needs the structure to derive the same permutation
var sternWitnessTemplateCache sync.Map

func getDummyWitnessTemplate(params *lattice.PublicParameters) *SternWitness {
	if params == nil {
		return nil
	}
	key := paramsFingerprint(params)
	if cached, ok := sternWitnessTemplateCache.Load(key); ok {
		if sw, ok := cached.(*SternWitness); ok {
			return sw
		}
	}
	templ := createDummyWitness(params)
	if templ == nil {
		return nil
	}
	sternWitnessTemplateCache.Store(key, templ)
	return templ
}

func createDummyWitness(params *lattice.PublicParameters) *SternWitness {
	sw := &SternWitness{}

	// XExt: B^{2m}_m
	sw.XExt = lattice.NewVector(2*params.M, params.Q)

	// PExt: B^{2nk-1}_{nk}
	sw.PExt = lattice.NewVector(2*params.NK-1, params.Q)

	// PHatExt: p̂ = ext(j_ℓ, p*) ∈ {0,1}^{4nk-2}
	sw.PHatExt = lattice.NewVector(4*params.NK-2, params.Q)

	// JExt: ℓ vectors of size 2
	sw.JExt = make([]*lattice.Vector, params.L)
	for i := 0; i < params.L; i++ {
		sw.JExt[i] = lattice.NewVector(2, params.Q)
	}

	// VExt: (ℓ-1) vectors of size 2*nk (intermediate nodes, excluding root and leaf)
	sw.VExt = make([]*lattice.Vector, params.L-1)
	for i := 0; i < params.L-1; i++ {
		sw.VExt[i] = lattice.NewVector(2*params.NK, params.Q)
	}

	// WExt: ℓ vectors of size 2*nk
	sw.WExt = make([]*lattice.Vector, params.L)
	for i := 0; i < params.L; i++ {
		sw.WExt[i] = lattice.NewVector(2*params.NK, params.Q)
	}

	// VHatExt: (ℓ-1) vectors of size 4*nk
	sw.VHatExt = make([]*lattice.Vector, params.L-1)
	for i := 0; i < params.L-1; i++ {
		sw.VHatExt[i] = lattice.NewVector(4*params.NK, params.Q)
	}

	// WHatExt: ℓ vectors of size 4*nk
	sw.WHatExt = make([]*lattice.Vector, params.L)
	for i := 0; i < params.L; i++ {
		sw.WHatExt[i] = lattice.NewVector(4*params.NK, params.Q)
	}

	// R1Ext, R2Ext: B^{2m_E}_{m_E}
	sw.R1Ext = lattice.NewVector(2*params.M_E, params.Q)
	sw.R2Ext = lattice.NewVector(2*params.M_E, params.Q)

	return sw
}
