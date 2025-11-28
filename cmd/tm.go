package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vinhphamhuu/lattice-group-signature/scheme"
	"github.com/vinhphamhuu/lattice-group-signature/storage"
)

var tmCmd = &cobra.Command{
	Use:   "tm",
	Short: "Tracing Manager commands",
	Long:  "Commands for the Tracing Manager to trace signatures to signers",
}

var tmTraceCmd = &cobra.Command{
	Use:   "trace [signature-id]",
	Short: "Trace a signature to the signer (Trace algorithm)",
	Long: `Runs the Trace algorithm from the paper.
Decrypts the ciphertext in the signature to identify the signer.
Generates a proof of correct tracing that can be verified by anyone.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sigID := args[0]

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
			fmt.Printf("Error: Signature not found: %v\n", err)
			return
		}

		// Run Trace protocol
		fmt.Println("\nRunning Trace protocol...")
		fmt.Println("1. Decrypting identity from signature...")
		uid, proof, err := scheme.Trace(gpk, tsk, info, reg, sig)
		if err != nil {
			fmt.Printf("Error tracing signature: %v\n", err)
			return
		}

		fmt.Printf("2. Generating proof of correct tracing...\n")

		// Save trace proof
		traceFile := fmt.Sprintf("trace_%s.json", sigID)
		tracePath := fmt.Sprintf("%s/%s", store.DataDir, traceFile)
		if err := store.SaveJSON(tracePath, proof); err != nil {
			fmt.Printf("Warning: Could not save trace proof: %v\n", err)
		}

		fmt.Printf("\n✅ Signature traced successfully\n")
		fmt.Printf("Signer: User %d\n", uid)
		fmt.Printf("Signature epoch: %d\n", sig.Epoch)
		fmt.Printf("Trace proof saved to: %s\n", traceFile)
		fmt.Println("\nAnyone can verify this tracing result using 'tm judge' command.")
	},
}

var tmJudgeCmd = &cobra.Command{
	Use:   "judge [signature-id] [uid]",
	Short: "Verify a tracing proof (Judge algorithm)",
	Long: `Runs the Judge algorithm from the paper.
Verifies that the Tracing Manager correctly traced a signature to a specific user.
This ensures tracing soundness - signatures cannot be falsely attributed.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sigID := args[0]
		uid := 0
		fmt.Sscanf(args[1], "%d", &uid)

		fmt.Println("=== Tracing Manager: Judge Tracing Proof ===")
		fmt.Printf("Signature ID: %s\n", sigID)
		fmt.Printf("Claimed signer: User %d\n", uid)

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
			fmt.Printf("Error: Signature not found: %v\n", err)
			return
		}

		// Load trace proof
		traceFile := fmt.Sprintf("trace_%s.json", sigID)
		tracePath := fmt.Sprintf("%s/%s", store.DataDir, traceFile)
		var proof scheme.TraceProof
		if err := store.LoadJSON(tracePath, &proof); err != nil {
			fmt.Printf("Error loading trace proof: %v\n", err)
			return
		}

		// Run Judge protocol
		fmt.Println("\nRunning Judge protocol...")
		fmt.Println("1. Verifying trace proof...")
		valid := scheme.Judge(gpk, uid, info, &proof, sig)

		fmt.Println()
		if valid {
			fmt.Println("✅ VALID: Trace proof is correct")
			fmt.Printf("Signature was indeed created by User %d\n", uid)
		} else {
			fmt.Println("❌ INVALID: Trace proof verification failed")
			fmt.Println("The claimed signer is incorrect or the proof is malformed")
		}
	},
}

var tmInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show TM information",
	Long:  "Displays Tracing Manager public key and system information.",
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
		fmt.Printf("  Security parameter λ: %d\n", pp.Lambda)
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

	tmCmd.AddCommand(tmTraceCmd)
	tmCmd.AddCommand(tmJudgeCmd)
	tmCmd.AddCommand(tmInfoCmd)
}
