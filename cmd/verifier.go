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
	Long: `Public Verifier commands for signature verification and system information.

Anyone can verify signatures without secret keys:
  - Verify signature validity (Verify algorithm)
  - Check zero-knowledge proofs
  - Validate Merkle authentication paths
  - Confirm signature epoch and group state
  - View public system information and parameters

Verification checks:
  - Zero-knowledge proof validity (Stern protocol)
  - Merkle root matches group state at signature epoch
  - Signature components are well-formed
  - Cryptographic commitments and challenges are correct

Available commands:
  verify  - Verify a group signature's validity
  info    - Display system information and parameters`,
}

var verifyCmd = &cobra.Command{
	Use:   "verify <signature-id>",
	Short: "Verify a group signature's validity (Verify algorithm)",
	Long: `Verify that a group signature is valid and was created by an active member.

The Verify algorithm checks:
  1. Signature epoch consistency
     - Signature epoch ≤ current epoch
     - Merkle root matches group state at signature epoch
  
  2. Zero-knowledge proof validity (Stern protocol)
     - Fiat-Shamir challenges correctly computed
     - All proof responses satisfy verification equations
     - Commitment scheme soundness
     - Achieves negligible soundness error after k rounds
  
  3. Merkle authentication path validation
     - Path authenticates public credential pi
     - Path leads to claimed Merkle root
     - Path length = log_2(N)
  
  4. Signature well-formedness
     - Ciphertexts c1, c2 properly formed
     - Public credential pi ≠ 0
     - All components in valid ranges

No secret keys required - anyone can verify!

Parameters:
  <signature-id>: ID of the signature to verify

Flags:
  --verbose: Show detailed verification steps
  --show-proof: Display zero-knowledge proof components
  --check-epoch: Verify epoch consistency (default: true)
  --benchmark: Measure and report verification time
  --sig-file: Custom signature file path
    - Default: <data-dir>/sig_<sig-id>.json

Examples:
  lattice-gs verifier verify sig_12345
  lattice-gs verifier verify sig_12345 --verbose
  lattice-gs verifier verify sig_12345 --show-proof --benchmark

Returns:
  - VALID: Signature is correct, created by active member
  - INVALID: Signature is forged, tampered, or signer was inactive`,
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
	Short: "Display public system information and parameters",
	Long: `Show comprehensive system information, parameters, and security properties.

Displays:
  - System initialization status
  - Public parameters (pp):
    * Security parameter λ
    * Max users N and Merkle tree height
    * Lattice dimension m and modulus q
    * SIS bound β and LWE noise parameters
  
  - Group state:
    * Current epoch number
    * Merkle tree root hash
    * Total registered users
    * Active member count
  
  - Security properties:
    * Anonymity (signatures hide identity)
    * Traceability (TM can identify signers)
    * Non-frameability (cannot forge attributions)
    * Full dynamicity (join/revoke at any time)
    * Post-quantum security (lattice-based)
  
  - Complexity analysis:
    * Signature size: Õ(λ·log N)
    * Group public key size: Õ(λ² + λ·log N)
    * Operation complexities

Flags:
  --show-params: Display cryptographic parameters (default: true)
  --show-members: Display membership information (default: true)
  --show-complexity: Show complexity metrics (default: true)
  --format: Output format - text or json (default: text)

Examples:
  lattice-gs verifier info
  lattice-gs verifier info --format=json
  lattice-gs verifier info --show-params=false --show-members

Useful for understanding system configuration and security.`,
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

	// Verify command flags
	verifyCmd.Flags().Bool("verbose", false, "Show detailed verification steps and proof checks")
	verifyCmd.Flags().Bool("show-proof", false, "Display zero-knowledge proof components")
	verifyCmd.Flags().Bool("check-epoch", true, "Verify signature epoch matches current group state")
	verifyCmd.Flags().Bool("benchmark", false, "Measure and report verification time")
	verifyCmd.Flags().String("sig-file", "", "Custom path to signature file (default: data-dir/sig_<sig-id>.json)")

	// Info command flags
	infoCmd.Flags().Bool("show-params", true, "Display public parameters and cryptographic settings")
	infoCmd.Flags().Bool("show-members", true, "Display group membership information")
	infoCmd.Flags().Bool("show-complexity", true, "Show complexity analysis and performance metrics")
	infoCmd.Flags().String("format", "text", "Output format: text or json")

	verifierCmd.AddCommand(verifyCmd)
	verifierCmd.AddCommand(infoCmd)
}
