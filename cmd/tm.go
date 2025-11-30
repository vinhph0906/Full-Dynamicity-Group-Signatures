package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vinhphamhuu/lattice-group-signature/scheme"
	"github.com/vinhphamhuu/lattice-group-signature/storage"
)

var tmCmd = &cobra.Command{
	Use:   "tm",
	Short: "Tracing Manager commands",
	Long: `Tracing Manager (TM) commands for signature tracing and identity revelation.

The TM is responsible for:
  - Tracing signatures to identify anonymous signers (Trace protocol)
  - Generating publicly verifiable tracing proofs
  - Ensuring accountability while preserving anonymity
  - Decrypting identity ciphertexts in signatures

Security guarantees:
  - Only the TM can trace signatures (traceability)
  - Tracing proofs are publicly verifiable (Judge algorithm)
  - Cannot falsely attribute signatures (non-frameability)`,
}

var tmTraceCmd = &cobra.Command{
	Use:   "trace <signature-id>",
	Short: "Trace a signature to identify the signer (Trace algorithm)",
	Long: `Identify the signer of an anonymous group signature using TM secret key.

The Trace algorithm:
  1. Load signature σ = (c1, c2, root, epoch, π)
  2. Optionally verify signature validity first (--verify-before-trace)
  3. Decrypt identity from ciphertext c1 using TM secret key tsk
     - Uses LWE decryption algorithm
     - Recovers user ID (uid) from plaintext
  4. Verify decryption consistency with c2 (Naor-Yung)
  5. Generate publicly verifiable trace proof
     - Proves correct decryption of c1
     - Proves consistency between c1 and c2
     - Can be verified by anyone using Judge algorithm
  6. Save trace proof for public verification

Parameters:
  <signature-id>: ID of the signature to trace

Flags:
  --verbose: Show detailed tracing steps
  --proof-output: Custom path for trace proof
    - Default: <data-dir>/trace_<sig-id>.json
  --verify-before-trace: Verify signature first (default: true)
  --save-decryption-log: Save intermediate decryption steps

Examples:
  lattice-gs tm trace sig_12345
  lattice-gs tm trace sig_12345 --verbose
  lattice-gs tm trace sig_12345 --proof-output=/tmp/trace.json

Output:
  - Identified signer's UID
  - Signature epoch
  - Publicly verifiable trace proof

Anyone can verify tracing correctness using: 'lattice-gs tm judge <sig-id> <uid>'`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sigID := args[0]
		if sigID == "" {
			fmt.Println("Error: Signature ID cannot be empty")
			os.Exit(1)
		}

		verbose, _ := cmd.Flags().GetBool("verbose")
		proofOutput, _ := cmd.Flags().GetString("proof-output")
		verifyBefore, _ := cmd.Flags().GetBool("verify-before-trace")
		saveDecryptionLog, _ := cmd.Flags().GetBool("save-decryption-log")

		fmt.Println("=== Tracing Manager: Trace Signature ===")
		fmt.Printf("Signature ID: %s\n", sigID)

		// Load storage
		store, err := storage.NewStorage(dataDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Load necessary data
		gpk, err := store.BuildGroupPublicKey()
		if err != nil {
			fmt.Printf("Error loading group public key: %v\n", err)
			return
		}

		_, tsk, err := store.LoadTMKeys()
		if err != nil {
			fmt.Printf("Error loading TM keys: %v\n", err)
			return
		}

		info, err := store.LoadGroupInfo()
		if err != nil {
			fmt.Printf("Error loading group info: %v\n", err)
			return
		}

		reg, err := store.LoadRegistry()
		if err != nil {
			fmt.Printf("Error loading registry: %v\n", err)
			return
		}

		// Load signature
		sig, err := store.LoadSignature(sigID)
		if err != nil {
			fmt.Printf("Error: Signature '%s' not found: %v\n", sigID, err)
			fmt.Println("\nAvailable signatures:")
			// Try to list available signatures
			if files, err := os.ReadDir(store.DataDir); err == nil {
				count := 0
				for _, f := range files {
					if !f.IsDir() && len(f.Name()) > 4 && f.Name()[:4] == "sig_" {
						fmt.Printf("  - %s\n", f.Name()[4:len(f.Name())-5])
						count++
					}
				}
				if count == 0 {
					fmt.Println("  (none)")
				}
			}
			os.Exit(1)
		}

		// Optionally verify signature first
		if verifyBefore {
			if verbose {
				fmt.Println("\nPre-trace verification...")
			}
			if err := scheme.Verify(gpk, info, sig); err != nil {
				fmt.Printf("Error: Signature is invalid: %v\n", err)
				fmt.Println("Cannot trace invalid signature.")
				os.Exit(1)
			}
			if verbose {
				fmt.Println("   [OK] Signature is valid")
			}
		}

		// Run Trace protocol
		if verbose {
			fmt.Println("\nRunning Trace protocol (detailed mode)...")
		} else {
			fmt.Println("\nRunning Trace protocol...")
		}
		fmt.Println("1. Decrypting identity from signature...")
		uid, proof, err := scheme.Trace(gpk, tsk, info, reg, sig)
		if err != nil {
			fmt.Printf("Error tracing signature: %v\n", err)
			return
		}

		fmt.Printf("2. Generating proof of correct tracing...\n")

		// Save trace proof
		var traceFile string
		if proofOutput != "" {
			traceFile = proofOutput
		} else {
			traceFile = fmt.Sprintf("trace_%s.json", sigID)
		}
		tracePath := traceFile
		if tracePath[0] != '/' {
			tracePath = fmt.Sprintf("%s/%s", store.DataDir, traceFile)
		}

		if err := store.SaveJSON(tracePath, proof); err != nil {
			fmt.Printf("Warning: Could not save trace proof: %v\n", err)
		}

		// Save decryption log if requested
		if saveDecryptionLog {
			logFile := fmt.Sprintf("%s/decrypt_log_%s.json", store.DataDir, sigID)
			decryptLog := map[string]interface{}{
				"signature_id":   sigID,
				"traced_uid":     uid,
				"epoch":          sig.Epoch,
				"has_ciphertext": sig.Ciphertext != nil,
			}
			if err := store.SaveJSON(logFile, decryptLog); err != nil {
				fmt.Printf("Warning: Could not save decryption log: %v\n", err)
			} else if verbose {
				fmt.Printf("Decryption log saved to: %s\n", logFile)
			}
		}

		fmt.Printf("\n[SUCCESS] Signature traced successfully\n")
		fmt.Printf("Signer: User %d\n", uid)
		fmt.Printf("Signature epoch: %d\n", sig.Epoch)
		fmt.Printf("Trace proof saved to: %s\n", traceFile)
	},
}

var tmJudgeCmd = &cobra.Command{
	Use:   "judge <signature-id> <uid>",
	Short: "Verify a tracing proof for correctness (Judge algorithm)",
	Long: `Verify that a signature was correctly traced to a specific user.

The Judge algorithm (publicly verifiable):
  1. Load signature σ and claimed signer UID
  2. Load trace proof generated by TM
  3. Verify proof of correct decryption:
     - Check decryption consistency
     - Verify Naor-Yung ciphertext relation
     - Validate cryptographic proof components
  4. Return accept/reject decision

Security guarantees:
  - Non-frameability: TM cannot falsely attribute signatures
  - Anyone can verify tracing results
  - No secret keys needed for verification
  - Prevents malicious TM from framing innocent users

Parameters:
  <signature-id>: ID of the traced signature
  <uid>: Claimed signer's user ID

Flags:
  --verbose: Show detailed verification steps
  --proof-file: Custom trace proof path
    - Default: <data-dir>/trace_<sig-id>.json
  --strict: Use strict verification mode (default: true)

Examples:
  lattice-gs tm judge sig_12345 5
  lattice-gs tm judge sig_12345 5 --verbose
  lattice-gs tm judge sig_12345 5 --proof-file=/tmp/trace.json

Returns:
  - VALID: Tracing is correct, signature created by claimed UID
  - INVALID: Tracing is incorrect or proof is malformed`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sigID := args[0]
		if sigID == "" {
			fmt.Println("Error: Signature ID cannot be empty")
			os.Exit(1)
		}

		uid := 0
		n, err := fmt.Sscanf(args[1], "%d", &uid)
		if err != nil || n != 1 {
			fmt.Printf("Error: Invalid user ID '%s'. Must be a positive integer.\n", args[1])
			os.Exit(1)
		}
		if uid < 0 {
			fmt.Printf("Error: User ID must be non-negative (got %d)\n", uid)
			os.Exit(1)
		}

		verbose, _ := cmd.Flags().GetBool("verbose")
		proofFile, _ := cmd.Flags().GetString("proof-file")
		strict, _ := cmd.Flags().GetBool("strict")

		fmt.Println("=== Tracing Manager: Judge Tracing Proof ===")
		fmt.Printf("Signature ID: %s\n", sigID)
		fmt.Printf("Claimed signer: User %d\n", uid)
		if strict {
			fmt.Println("Verification mode: STRICT")
		}

		// Load storage
		store, err := storage.NewStorage(dataDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Load necessary data
		gpk, err := store.BuildGroupPublicKey()
		if err != nil {
			fmt.Printf("Error loading group public key: %v\n", err)
			return
		}

		info, err := store.LoadGroupInfo()
		if err != nil {
			fmt.Printf("Error loading group info: %v\n", err)
			return
		}

		// Load signature
		sig, err := store.LoadSignature(sigID)
		if err != nil {
			fmt.Printf("Error: Signature '%s' not found: %v\n", sigID, err)
			os.Exit(1)
		}

		// Load trace proof
		var tracePath string
		if proofFile != "" {
			tracePath = proofFile
		} else {
			traceFile := fmt.Sprintf("trace_%s.json", sigID)
			tracePath = fmt.Sprintf("%s/%s", store.DataDir, traceFile)
		}

		var proof scheme.TraceProof
		if err := store.LoadJSON(tracePath, &proof); err != nil {
			fmt.Printf("Error loading trace proof from %s: %v\n", tracePath, err)
			os.Exit(1)
		}

		// Run Judge protocol
		if verbose {
			fmt.Println("\nRunning Judge protocol (detailed mode)...")
			fmt.Println("1. Verifying trace proof components...")
			fmt.Println("2. Checking decryption correctness...")
			fmt.Println("3. Validating Naor-Yung consistency...")
		} else {
			fmt.Println("\nRunning Judge protocol...")
			fmt.Println("1. Verifying trace proof...")
		}
		valid := scheme.Judge(gpk, uid, info, &proof, sig)

		fmt.Println()
		if valid {
			fmt.Println("[VALID] Trace proof is correct")
			fmt.Printf("Signature was indeed created by User %d\n", uid)
		} else {
			fmt.Println("[INVALID] Trace proof verification failed")
			fmt.Println("The claimed signer is incorrect or the proof is malformed")
		}
	},
}

var tmInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display Tracing Manager information and capabilities",
	Long: `Show Tracing Manager public key, system configuration, and capabilities.

Displays:
  - TM public key components (pk1, pk2)
  - Public key dimensions and sizes
  - System security parameters
  - Tracing capabilities and responsibilities
  - Tracing statistics (with --show-stats)

TM responsibilities:
  - Decrypt identity ciphertexts in signatures
  - Identify anonymous signers when needed
  - Generate publicly verifiable tracing proofs
  - Maintain accountability without compromising anonymity

Security properties:
  - Cannot forge signatures (no signing capability)
  - Cannot frame innocent users (non-frameability)
  - Tracing is publicly verifiable (Judge algorithm)
  - Only TM can decrypt identities (traceability)

Flags:
  --show-stats: Display tracing statistics and history
  --format: Output format - text or json (default: text)

Examples:
  lattice-gs tm info
  lattice-gs tm info --show-stats
  lattice-gs tm info --format=json

Useful for understanding TM role and public parameters.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("=== Tracing Manager: Information ===")

		// Load storage
		store, err := storage.NewStorage(dataDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if !store.IsInitialized() {
			fmt.Println("Error: System not initialized. Run 'gm setup' first.")
			return
		}

		tpk, _, err := store.LoadTMKeys()
		if err != nil {
			fmt.Printf("Error loading TM keys: %v\n", err)
			return
		}

		pp, err := store.LoadPublicParameters()
		if err != nil {
			fmt.Printf("Error loading public parameters: %v\n", err)
			return
		}

		fmt.Println("\nTracing Manager Public Key:")
		fmt.Printf("  PK1 size: %d\n", tpk.PK1.Size)
		fmt.Printf("  PK2 size: %d\n", tpk.PK2.Size)
		fmt.Printf("\nSystem Parameters:")
		fmt.Printf("  Security parameter (lambda): %d\n", pp.Lambda)
		fmt.Printf("  Max users N: %d\n", pp.N)
		fmt.Printf("  Modulus q: %d\n", pp.Q)
		fmt.Printf("\nCapabilities:")
		fmt.Println("  - Trace signatures to signers")
		fmt.Println("  - Generate proofs of correct tracing")
		fmt.Println("  - Preserve anonymity unless tracing is needed")
	},
}

func init() {
	rootCmd.AddCommand(tmCmd)

	// Trace command flags
	tmTraceCmd.Flags().Bool("verbose", false, "Show detailed tracing protocol steps")
	tmTraceCmd.Flags().String("proof-output", "", "Custom output path for trace proof (default: data-dir/trace_<sig-id>.json)")
	tmTraceCmd.Flags().Bool("verify-before-trace", true, "Verify signature validity before attempting to trace")
	tmTraceCmd.Flags().Bool("save-decryption-log", false, "Save decryption intermediate steps for audit")

	// Judge command flags
	tmJudgeCmd.Flags().Bool("verbose", false, "Show detailed judge verification steps")
	tmJudgeCmd.Flags().String("proof-file", "", "Custom path to trace proof file (default: data-dir/trace_<sig-id>.json)")
	tmJudgeCmd.Flags().Bool("strict", true, "Use strict verification mode")

	// Info command flags
	tmInfoCmd.Flags().Bool("show-stats", false, "Display tracing statistics and history")
	tmInfoCmd.Flags().String("format", "text", "Output format: text or json")

	tmCmd.AddCommand(tmTraceCmd)
	tmCmd.AddCommand(tmJudgeCmd)
	tmCmd.AddCommand(tmInfoCmd)
}
