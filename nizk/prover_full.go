package nizk

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vinhphamhuu/lattice-group-signature/lattice"
	"golang.org/x/crypto/sha3"
)

// bigIntToFixedBytes moved to util.go

// ProverFull implements the full Stern protocol with permutations
// Following Section 4.2 of the paper: Full NIZKAoK construction
//
// Protocol Overview:
// 1. Build unified equation M·z = u (mod q)
// 2. For κ rounds:
//   - Generate random mask r_z and permutation η
//   - Compute 3 commitments: C1 = StringCommitment(φ(η)||M·r_z), C2 = StringCommitment(Γ_η(r_z)), C3 = StringCommitment(Γ_η(z+r_z))
//   - Add commitments to transcript
//
// 3. Generate challenges via Fiat-Shamir: CH = H_FS(transcript)
// 4. For each round, compute response based on challenge:
//   - Ch=1: Reveal Γ_η(z), Γ_η(r_z) to check structure
//   - Ch=2: Reveal η, z+r_z to check equation M·(z+r_z) = M·r_z + u
//   - Ch=3: Reveal η, r_z to check equation M·r_z
func ProverFull(witness *Witness, statement *Statement) (*ZKProof, error) {
	params := statement.Params
	prof := os.Getenv("NIZK_PROFILE") == "1"
	tStart := time.Now()

	// Helper function to print memory stats
	printMemStats := func(label string) {
		if !prof {
			return
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Printf("[Memory] %s: Alloc=%d MB, TotalAlloc=%d MB, Sys=%d MB, NumGC=%d [%s]\n",
			label,
			m.Alloc/1024/1024,
			m.TotalAlloc/1024/1024,
			m.Sys/1024/1024,
			m.NumGC,
			time.Now().Format("15:04:05"))
	}

	printMemStats("Start")

	// Step 1: Prepare extended witness
	if prof {
		fmt.Printf("[ProverFull] Step 1: Preparing extended witness...\n")
	}
	t1 := time.Now()
	sternWitness, err := prepareExtendedWitness(witness, params)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare extended witness: %v", err)
	}
	if prof {
		fmt.Printf("[ProverFull] Step 1 completed in %v\n", time.Since(t1))
	}

	// Step 2: Build unified equation M·z = u (mod q)
	if prof {
		fmt.Printf("[ProverFull] Step 2: Building unified equation M·z = u...\n")
	}
	t2 := time.Now()
	equation, err := buildUnifiedEquation(sternWitness, statement, params)
	if err != nil {
		return nil, fmt.Errorf("failed to build unified equation: %v", err)
	}
	if prof {
		fmt.Printf("[ProverFull] Step 2 completed in %v (M: %dx%d, witness_size: %d)\n",
			time.Since(t2), equation.M.Rows, equation.M.Cols, equation.Z.Size)
	}

	// Always log dimensions for experiments (even without NIZK_PROFILE)
	fmt.Printf("[Dimensions] M: %d×%d, z: %d\n", equation.M.Rows, equation.M.Cols, equation.Z.Size)
	//check m cols is euqal to  D= 10nkℓ+ 2m+ 4mE + 2ℓ−3
	if equation.M.Cols != 10*params.NK*params.L+2*params.M+4*params.M_E+2*params.L-3 {
		return nil, fmt.Errorf("[debug] M·z != u on honest witness (sanity check failed)")
	}
	// Debug assertion: verify M·z == u for honest witness
	if Debug {
		lhs := equation.M.Mul(equation.Z)
		ok := true
		for i := 0; i < lhs.Size && i < equation.U.Size; i++ {
			lhsMod := lhs.Data[i] % params.Q
			if lhsMod < 0 {
				lhsMod += params.Q
			}
			uMod := equation.U.Data[i] % params.Q
			if uMod < 0 {
				uMod += params.Q
			}
			if lhsMod != uMod {
				ok = false
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("[debug] M·z != u on honest witness (sanity check failed)")
		}
	}

	proof := &ZKProof{
		Responses:   make([]*lattice.Vector, params.Kappa),
		Commitments: make([]*CommitmentTriple, params.Kappa),
	}

	type roundSecret struct {
		mask        *lattice.Vector
		permutation *Permutation
		rho1        *lattice.Vector
		rho2        *lattice.Vector
		rho3        *lattice.Vector
	}

	secrets := make([]roundSecret, params.Kappa)

	workerCount := lattice.MaxWorkers
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > params.Kappa {
		workerCount = params.Kappa
	}
	if workerCount == 0 {
		workerCount = 1
	}

	jobCh := make(chan int, workerCount)
	var wg sync.WaitGroup
	errCh := make(chan error, 1)
	var abort atomic.Bool

	worker := func() {
		defer wg.Done()
		syndromeBuffer := acquireSyndromeBuffer(equation.M.Rows, params.Q)
		defer releaseSyndromeBuffer(syndromeBuffer)

		for round := range jobCh {
			if abort.Load() {
				return
			}
			tRound := time.Now()
			if prof && round%5 == 0 {
				fmt.Printf("[ProverFull] Commitment round %d/%d [%s]...\n",
					round+1, params.Kappa, time.Now().Format("15:04:05"))
				printMemStats(fmt.Sprintf("Round %d", round+1))
			}

			tMask := time.Now()
			rz, err := acquireMaskVector(equation.Z.Size, params.Q)
			if err != nil {
				recordWorkerError(&abort, errCh, fmt.Errorf("failed to sample mask vector: %w", err))
				return
			}
			if prof {
				fmt.Printf("  [Round %d] Mask generation: %v\n", round+1, time.Since(tMask))
			}

			tPerm := time.Now()
			eta, err := generateFullPermutation(sternWitness, params)
			if err != nil {
				releaseMaskVector(rz)
				recordWorkerError(&abort, errCh, fmt.Errorf("failed to sample permutation: %w", err))
				return
			}
			if prof {
				fmt.Printf("  [Round %d] Permutation generation: %v\n", round+1, time.Since(tPerm))
			}

			tRho := time.Now()
			rho1, err := lattice.BinaryVector(2*params.NK, params.Q)
			if err != nil {
				releaseMaskVector(rz)
				releasePermutation(eta)
				recordWorkerError(&abort, errCh, fmt.Errorf("failed to sample rho1: %w", err))
				return
			}
			rho2, err := lattice.BinaryVector(2*params.NK, params.Q)
			if err != nil {
				releaseMaskVector(rz)
				releasePermutation(eta)
				recordWorkerError(&abort, errCh, fmt.Errorf("failed to sample rho2: %w", err))
				return
			}
			rho3, err := lattice.BinaryVector(2*params.NK, params.Q)
			if err != nil {
				releaseMaskVector(rz)
				releasePermutation(eta)
				recordWorkerError(&abort, errCh, fmt.Errorf("failed to sample rho3: %w", err))
				return
			}
			if prof && round%5 == 0 {
				fmt.Printf("  [Round %d] Rho sampling: %v\n", round+1, time.Since(tRho))
			}

			// Compute commitments following Stern protocol
			tCommit := time.Now()
			equation.M.MulInto(rz, syndromeBuffer)
			c1 := commitToSyndrome(eta, syndromeBuffer, rho1, params)

			maskWitness := createWitnessViewFromVector(rz, sternWitness)
			if maskWitness == nil {
				releaseMaskVector(rz)
				releasePermutation(eta)
				recordWorkerError(&abort, errCh, fmt.Errorf("failed to map mask to witness structure"))
				return
			}
			gammaRz := applyFullPermutation(maskWitness, eta)
			c2 := commitGamma(gammaRz, rho2, params)

			gammaZ := applyFullPermutation(sternWitness, eta)
			gammaZPlusRz := gammaZ.Add(gammaRz)
			c3 := commitGamma(gammaZPlusRz, rho3, params)

			proof.Commitments[round] = &CommitmentTriple{C1: c1, C2: c2, C3: c3}
			secrets[round] = roundSecret{
				mask:        rz,
				permutation: eta,
				rho1:        rho1,
				rho2:        rho2,
				rho3:        rho3,
			}
			if prof {
				fmt.Printf("  [Round %d] Commitments: %v\n", round+1, time.Since(tCommit))
				fmt.Printf("  [Round %d] Total round time: %v\n", round+1, time.Since(tRound))
				printMemStats(fmt.Sprintf("After commitment round %d", round+1))
			}
		}
	}

	if prof {
		fmt.Printf("[ProverFull] Step 3: Commitment phase - κ=%d rounds, witness_size=%d [%s]\n",
			params.Kappa, equation.Z.Size, time.Now().Format("15:04:05"))
	}
	printMemStats("Before commitment phase")
	tCommitStart := time.Now()
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		defer close(jobCh)
		for round := 0; round < params.Kappa; round++ {
			if abort.Load() {
				return
			}
			jobCh <- round
		}
	}()

	wg.Wait()
	select {
	case err := <-errCh:
		if err != nil {
			return nil, err
		}
	default:
	}
	if prof {
		fmt.Printf("[ProverFull] Commitment phase completed in %v\n", time.Since(tCommitStart))
	}
	printMemStats("After commitment phase")

	// Build Fiat-Shamir transcript after all commitments are available
	if prof {
		fmt.Printf("[ProverFull] Building Fiat-Shamir transcript...\n")
	}
	transcript := buildFullTranscript(statement, proof.Commitments)

	// Debug: print short digest of transcript to ensure prover/verifier alignment
	if Debug {
		shake := sha3.NewShake256()
		_, _ = shake.Write(transcript)
		buf := make([]byte, 16)
		_, _ = shake.Read(buf)
		fmt.Printf("[debug] FS transcript digest (prov) = %x\n", buf)
	}

	// Step 4: Challenge phase via Fiat-Shamir
	// CH = H_FS(M, {CMT_i}, public_inputs) ∈ {1,2,3}^κ
	if prof {
		fmt.Printf("[ProverFull] Computing Fiat-Shamir challenges...\n")
	}
	challenges := lattice.FiatShamirHash(transcript, params.Kappa)

	// Challenges are recomputed by the verifier; not stored

	// Step 5: Response phase - depends on challenge
	if prof {
		fmt.Printf("[ProverFull] Step 5: Response phase - %d rounds [%s]\n",
			params.Kappa, time.Now().Format("15:04:05"))
	}
	printMemStats("Before response phase")
	tResponseStart := time.Now()
	for round := 0; round < params.Kappa; round++ {
		tRespRound := time.Now()
		if prof {
			fmt.Printf("[ProverFull] Response round %d/%d [%s]...\n",
				round+1, params.Kappa, time.Now().Format("15:04:05"))
		}
		secret := secrets[round]
		rz := secret.mask
		eta := secret.permutation
		rho1 := secret.rho1
		rho2 := secret.rho2
		rho3 := secret.rho3

		var response *lattice.Vector

		switch challenges[round] {
		case 1:
			tz := applyFullPermutation(sternWitness, eta)
			tr := applyFullPermutation(createWitnessViewFromVector(rz, sternWitness), eta)
			response = packResponse1(tz, tr, rho2, rho3, params)

		case 2:
			z2 := equation.Z.Add(rz)
			response = packResponse2(eta, z2, rho1, rho3, params)

		case 3:
			response = packResponse3(eta, rz, rho1, rho2, params)
		}

		// OPTIMIZATION: Store only the actual response for this challenge
		proof.Responses[round] = response
		releasePermutation(eta)
		releaseMaskVector(rz)
		secrets[round] = roundSecret{}
		if prof {
			fmt.Printf("  [Round %d] Response computed in %v\n", round+1, time.Since(tRespRound))
		}
		if prof && round%10 == 9 {
			printMemStats(fmt.Sprintf("After response round %d", round+1))
		}
	}
	if prof {
		fmt.Printf("[ProverFull] Response phase completed in %v\n", time.Since(tResponseStart))
		fmt.Printf("[ProverFull] === TOTAL PROOF GENERATION TIME: %v ===\n", time.Since(tStart))
	}
	printMemStats("End")

	return proof, nil
}

// Helper functions

var (
	maskVectorPool     = sync.Pool{New: func() any { return &lattice.Vector{} }}
	syndromeVectorPool = sync.Pool{New: func() any { return &lattice.Vector{} }}
)

func acquireMaskVector(size int, q int64) (*lattice.Vector, error) {
	vec := acquireVectorFromPool(&maskVectorPool, size, q)
	if err := fillRandomVector(vec, q); err != nil {
		releaseVectorToPool(&maskVectorPool, vec)
		return nil, err
	}
	return vec, nil
}

func releaseMaskVector(v *lattice.Vector) {
	releaseVectorToPool(&maskVectorPool, v)
}

func acquireSyndromeBuffer(size int, q int64) *lattice.Vector {
	return acquireVectorFromPool(&syndromeVectorPool, size, q)
}

func releaseSyndromeBuffer(v *lattice.Vector) {
	releaseVectorToPool(&syndromeVectorPool, v)
}

func acquireVectorFromPool(pool *sync.Pool, size int, q int64) *lattice.Vector {
	if size < 0 {
		size = 0
	}
	val := pool.Get()
	var vec *lattice.Vector
	if val == nil {
		vec = lattice.NewVector(size, q)
	} else {
		vec = val.(*lattice.Vector)
		if cap(vec.Data) < size {
			vec.Data = make([]int64, size)
		} else {
			vec.Data = vec.Data[:size]
		}
		vec.Size = size
		vec.Q = q
	}
	return vec
}

func releaseVectorToPool(pool *sync.Pool, v *lattice.Vector) {
	if v == nil {
		return
	}
	pool.Put(v)
}

func fillRandomVector(v *lattice.Vector, q int64) error {
	if q <= 0 {
		return fmt.Errorf("invalid modulus: %d", q)
	}
	modulus := big.NewInt(q)
	for i := 0; i < v.Size; i++ {
		val, err := rand.Int(rand.Reader, modulus)
		if err != nil {
			return err
		}
		v.Data[i] = val.Int64()
	}
	return nil
}

func recordWorkerError(abort *atomic.Bool, errCh chan<- error, err error) {
	if err == nil {
		return
	}
	if abort.CompareAndSwap(false, true) {
		select {
		case errCh <- err:
		default:
		}
	}
}

// computeMerkleIntermediateNodes computes v_i from leaf p up to root
// Paper: v_ℓ = p (leaf), v_i = h_A(v_{i+1}, w_{i+1}) if j_{i+1}=0, else h_A(w_{i+1}, v_{i+1})
// where h_A(u0, u1) = bin(A0·u0 + A1·u1 mod q)
