package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vinhphamhuu/lattice-group-signature/scheme"
	"github.com/vinhphamhuu/lattice-group-signature/storage"
)

var verifierCmd = &cobra.Command{
	Use:   "verifier",
	Short: "Public verifier commands",
	Long:  "Commands for anyone to verify group signatures",
}

var verifyCmd = &cobra.Command{
	Use:   "verify [signature-id]",
	Short: "Verify a group signature (Verify algorithm)",
	Long: `Runs the Verify algorithm from the paper.
Verifies that a signature is valid for the current group at the signature's epoch.
Checks:
  - Zero-knowledge proof validity
  - Merkle root matches group state
  - Signature is well-formed
  
Anyone can verify signatures - no secret keys needed.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sigID := args[0]

		fmt.Println("=== Verifier: Verify Signature ===")
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

		// Run Verify protocol
		fmt.Println("\nRunning Verify protocol...")
		fmt.Println("1. Checking signature epoch...")
		fmt.Printf("   Signature epoch: %d\n", sig.Epoch)
		fmt.Printf("   Current epoch: %d\n", info.Epoch)

		fmt.Println("2. Verifying zero-knowledge proof...")
		fmt.Println("   - Checking Fiat-Shamir challenges")
		fmt.Println("   - Verifying Stern protocol responses")
		fmt.Println("   - Validating Merkle authentication path")

		fmt.Println("3. Checking signature well-formedness...")

		err = scheme.Verify(gpk, info, sig)

		fmt.Println()
		if err == nil {
			fmt.Println("✅ VALID SIGNATURE")
			fmt.Println("\nThis signature was created by an active group member.")
			fmt.Println("The signer's identity is hidden but can be traced by the TM.")

			fmt.Printf("\nSignature details:\n")
			fmt.Printf("  Message: %s\n", string(sig.Message))
			fmt.Printf("  Epoch: %d\n", sig.Epoch)
			// Report actual file size if available
			if fi, err := os.Stat(fmt.Sprintf("%s/sig_%s.json", dataDir, sigID)); err == nil {
				fmt.Printf("  Size: ~%d bytes\n", fi.Size())
			} else {
				fmt.Printf("  Size: ~%d bytes\n", scheme.SignatureSize(sig))
			}
		} else {
			fmt.Println("❌ INVALID SIGNATURE")
			fmt.Printf("\nReason: %v\n", err)
			fmt.Println("\nPossible reasons:")
			fmt.Println("  - Signature was forged")
			fmt.Println("  - Signer was not active at the signature epoch")
			fmt.Println("  - Signature was tampered with")
			fmt.Println("  - Cryptographic proof verification failed")

			fmt.Printf("\nSignature details:\n")
			fmt.Printf("  Message: %s\n", string(sig.Message))
			fmt.Printf("  Epoch: %d\n", sig.Epoch)
			if fi, err := os.Stat(fmt.Sprintf("%s/sig_%s.json", dataDir, sigID)); err == nil {
				fmt.Printf("  Size: ~%d bytes\n", fi.Size())
			} else {
				fmt.Printf("  Size: ~%d bytes\n", scheme.SignatureSize(sig))
			}

			os.Exit(1)
		}
	},
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show system information",
	Long:  "Displays public system information, parameters, and group state.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("=== System Information ===")

		// Load storage
		store, err := storage.NewStorage(dataDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if !store.IsInitialized() {
			fmt.Println("\nSystem Status: NOT INITIALIZED")
			fmt.Println("Run 'lattice-gs gm setup' to initialize the system.")
			return
		}

		// Load public parameters
		pp, err := store.LoadPublicParameters()
		if err != nil {
			fmt.Printf("Error loading public parameters: %v\n", err)
			return
		}

		// Load group info
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

		fmt.Println("\nSystem Status: INITIALIZED ✓")
		fmt.Println("\n--- Public Parameters ---")
		fmt.Printf("Security parameter λ: %d bits\n", pp.Lambda)
		fmt.Printf("Maximum users N: %d\n", pp.N)
		fmt.Printf("Modulus q: %d\n", pp.Q)
		fmt.Printf("Matrix dimension m: %d\n", pp.M)
		fmt.Printf("SIS bound β: %d\n", pp.Beta)

		fmt.Println("\n--- Group State ---")
		fmt.Printf("Current epoch: %d\n", info.Epoch)
		fmt.Printf("Merkle tree root: %x\n", info.RootHash)
		fmt.Printf("Total registered users: %d\n", len(reg.Records))
		fmt.Printf("Active members: %d\n", len(info.ActiveUIDs))

		fmt.Println("\n--- Security Properties ---")
		fmt.Println("✓ Anonymity: Signatures hide signer identity")
		fmt.Println("✓ Traceability: TM can identify signers")
		fmt.Println("✓ Non-frameability: Cannot forge signatures")
		fmt.Println("✓ Full dynamicity: Users can join/leave")
		fmt.Println("✓ Post-quantum security: Based on lattice assumptions (SIS & LWE)")

		fmt.Println("\n--- Complexity ---")
		fmt.Printf("Signature size: Õ(λ·log N) = Õ(%d·%d) bits\n", pp.Lambda, pp.L)
		fmt.Printf("Group PK size: Õ(λ² + λ·log N) = Õ(%d + %d) bits\n",
			pp.Lambda*pp.Lambda, pp.Lambda*pp.L)
		fmt.Println("Join/Revoke complexity: O(log N)")
		fmt.Println("Sign/Verify complexity: O(log N)")

		fmt.Printf("\nData directory: %s\n", store.DataDir)
	},
}

func init() {
	rootCmd.AddCommand(verifierCmd)

	verifierCmd.AddCommand(verifyCmd)
	verifierCmd.AddCommand(infoCmd)
}
