package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/vinhphamhuu/lattice-group-signature/scheme"
	"github.com/vinhphamhuu/lattice-group-signature/storage"
)

var memberCmd = &cobra.Command{
	Use:   "member",
	Short: "Group member commands",
	Long: `Group Member commands for key generation, signing, and membership management.

Members can:
  - Generate cryptographic keys and credentials (UKgen, Join)
  - Create anonymous group signatures (Sign protocol)
  - Check their membership status and credentials
  - Sign messages anonymously without revealing their identity

Workflow:
  1. keygen <uid> - Generate keys and credentials
  2. Wait for GM to issue certificate
  3. sign <uid> <message> - Create anonymous signatures
  4. info <uid> - Check membership status

Available commands:
  keygen  - Generate user keys and credentials
  sign    - Create an anonymous group signature
  info    - Display member status and information`,
}

var memberKeygenCmd = &cobra.Command{
	Use:   "keygen <uid>",
	Short: "Generate user keys and credentials (UKgen + Join)",
	Long: `Generate cryptographic keys and credentials for a new group member.

This command runs:
  1. UKgen algorithm: Generate user key pair (upk, usk)
     - upk: Public key (published)
     - usk: Secret key (kept private)
  
  2. Join protocol: Generate group membership credentials
     - x: Secret credential (random vector in Z_q^m)
     - pi: Public credential (pi = A * x mod q)
  
  3. Save credentials as group signing key (gsk)

Parameters:
  <uid>: Unique user identifier (positive integer)

Flags:
  --force: Regenerate keys even if they exist
    - WARNING: Old keys will be overwritten!
  
  --verbose: Show detailed cryptographic operations
  
  --output: Custom output path for keys
    - Default: <data-dir>/user_<uid>.json

Examples:
  lattice-gs member keygen 5
  lattice-gs member keygen 5 --verbose
  lattice-gs member keygen 5 --force --output=/tmp/user5.json

Next steps:
  1. Request GM to issue certificate: 'lattice-gs gm issue <uid>'
  2. After issuance, create signatures: 'lattice-gs member sign <uid> <msg>'`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		uid := 0
		fmt.Sscanf(args[0], "%d", &uid)

		fmt.Println("=== Member: Generate Keys ===")
		fmt.Printf("User ID: %d\n", uid)

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

		// Load public parameters
		pp, err := store.LoadPublicParameters()
		if err != nil {
			fmt.Printf("Error loading public parameters: %v\n", err)
			return
		}

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

		// Step 1: UKgen - Generate user key pair
		fmt.Println("\n1. Running UKgen (generating user key pair)...")
		upk, usk, err := scheme.UKgen(pp)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
			return
		}
		fmt.Println("   ✓ User key pair generated")

		// Step 2: Join - Generate credentials
		fmt.Println("\n2. Running Join protocol (generating credentials)...")
		gsk, err := scheme.Join(info, gpk, upk, usk)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		gsk.UID = uid
		fmt.Println("   ✓ Credentials generated")
		fmt.Println("   ✓ Secret credential x_i")
		fmt.Println("   ✓ Public credential pi = A * x_i")

		// Save user keys
		if err := store.SaveUserKeys(uid, gsk); err != nil {
			fmt.Printf("Error saving user keys: %v\n", err)
			return
		}

		fmt.Printf("\n✅ Keys generated for User %d\n", uid)
		fmt.Println("\nNext steps:")
		fmt.Printf("  1. Request GM to issue certificate: gm issue %d\n", uid)
		fmt.Println("  2. After issuance, you can sign messages: member sign")
	},
}

var memberSignCmd = &cobra.Command{
	Use:   "sign <uid> <message>",
	Short: "Create an anonymous group signature (Sign algorithm)",
	Long: `Create an anonymous group signature proving membership without revealing identity.

The Sign algorithm:
  1. Load user's signing key (gsk) and group public key (gpk)
  2. Encrypt identity using Naor-Yung double encryption
     - Creates ciphertexts c1, c2 under both TM public keys
     - Ensures traceability while hiding identity
  
  3. Compute Merkle authentication path
     - Proves public credential pi is in the Merkle tree
     - Path length: log_2(N) hash values
  
  4. Generate zero-knowledge proof (Stern-like protocol)
     - Proves knowledge of secret credential x where pi = A*x
     - Proves non-zero public key (pi ≠ 0)
     - Proves valid Merkle path to current root
     - Proves well-formed identity ciphertext
     - Achieves soundness error 2/3 per round
  
  5. Output signature σ = (c1, c2, Merkle_root, epoch, π)

Parameters:
  <uid>: Your user ID (must have active membership)
  <message>: Message to sign (arbitrary string)

Flags:
  --verbose: Show detailed signing steps
  --message-file: Read message from file
  --sig-output: Custom signature ID
  --save-proof-details: Save proof internals for analysis

Examples:
  lattice-gs member sign 5 "Hello, world!"
  lattice-gs member sign 5 "Transaction data" --verbose
  lattice-gs member sign 5 --message-file=msg.txt --sig-output=sig_001

The signature is anonymous and publicly verifiable.
Only the Tracing Manager can identify the signer.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		uid := 0
		fmt.Sscanf(args[0], "%d", &uid)
		message := []byte(args[1])

		fmt.Println("=== Member: Sign Message ===")
		fmt.Printf("User ID: %d\n", uid)
		fmt.Printf("Message: %s\n", string(message))

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

		// Load user keys
		gsk, err := store.LoadUserKeys(uid)
		if err != nil {
			fmt.Printf("Error: User %d keys not found. Run 'member keygen %d' first.\n", uid, uid)
			return
		}

		// Run Sign protocol
		fmt.Println("\nRunning Sign protocol...")
		fmt.Println("1. Encrypting identity using Naor-Yung double encryption...")
		fmt.Println("2. Computing Merkle authentication path...")
		fmt.Println("3. Generating zero-knowledge proof (Stern-like protocol)...")
		fmt.Println("   - Proving knowledge of secret credential x")
		fmt.Println("   - Proving non-zero public key (pi ≠ 0)")
		fmt.Println("   - Proving valid Merkle path")
		fmt.Println("   - Proving well-formed ciphertext...")

		sig, err := scheme.Sign(gpk, gsk, info, message)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Generate signature ID
		sigID := fmt.Sprintf("%d_%d", time.Now().Unix(), uid)

		// Save signature
		if err := store.SaveSignature(sigID, sig); err != nil {
			fmt.Printf("Error saving signature: %v\n", err)
			return
		}

		fmt.Printf("\n✅ Signature created successfully\n")
		fmt.Printf("Signature ID: %s\n", sigID)
		fmt.Printf("Epoch: %d\n", sig.Epoch)
		// Report actual on-disk size
		sigPath := fmt.Sprintf("%s/sig_%s.json", dataDir, sigID)
		if fi, err := os.Stat(sigPath); err == nil {
			fmt.Printf("Size: ~%d bytes\n", fi.Size())
		} else {
			fmt.Printf("Size: ~%d bytes\n", scheme.SignatureSize(sig))
		}
		fmt.Println("\nThe signature is anonymous - it reveals no information about the signer.")
		fmt.Println("Anyone can verify it, but only the Tracing Manager can identify you.")
		fmt.Printf("\nTo verify: verifier verify %s\n", sigID)
	},
}

var memberInfoCmd = &cobra.Command{
	Use:   "info <uid>",
	Short: "Display member status and credential information",
	Long: `Show detailed information about a group member's status and credentials.

Displays:
  - Key generation status (upk, usk, x, pi)
  - Membership status (not registered, active, or revoked)
  - Current group epoch
  - Registration details
  - Signing capabilities
  - Credential hashes (with --show-credentials)
  - Signing history (with --show-history)

Membership states:
  NOT REGISTERED: Keys generated but GM hasn't issued certificate
  ACTIVE: Can sign messages, part of current Merkle tree
  REVOKED: Previously active but removed via GUpdate

Parameters:
  <uid>: User ID to query

Flags:
  --show-credentials: Display credential hashes and public key info
  --show-history: Show all signatures created by this member
  --format: Output format - text or json (default: text)

Examples:
  lattice-gs member info 5
  lattice-gs member info 5 --show-credentials
  lattice-gs member info 5 --show-history --format=json

Useful for checking membership status before signing.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		uid := 0
		fmt.Sscanf(args[0], "%d", &uid)

		fmt.Println("=== Member: Information ===")
		fmt.Printf("User ID: %d\n", uid)

		// Load storage
		store, err := storage.NewStorage(dataDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Load user keys
		gsk, err := store.LoadUserKeys(uid)
		if err != nil {
			fmt.Printf("Error: No keys found for User %d\n", uid)
			fmt.Printf("Run 'member keygen %d' to generate keys.\n", uid)
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

		fmt.Println("\nKey Status:")
		fmt.Printf("  UID: %d\n", gsk.UID)
		fmt.Println("  ✓ User key pair generated")
		fmt.Println("  ✓ Secret credential x_i generated")
		fmt.Println("  ✓ Public credential pi computed")

		fmt.Println("\nMembership Status:")
		_, registered := reg.Records[uid]
		active := info.ActiveUIDs[uid]

		if !registered {
			fmt.Println("  Status: NOT REGISTERED")
			fmt.Printf("  Action: Contact GM to run 'gm issue %d'\n", uid)
		} else if !active {
			fmt.Println("  Status: REVOKED")
			fmt.Printf("  Revoked at epoch: %d\n", info.Epoch)
			fmt.Println("  Cannot sign messages")
		} else {
			fmt.Println("  Status: ACTIVE")
			fmt.Printf("  Active at epoch: %d\n", info.Epoch)
			fmt.Println("  Can sign messages")
		}

		fmt.Printf("\nGroup Information:")
		fmt.Printf("  Current epoch: %d\n", info.Epoch)
		fmt.Printf("  Total active members: %d\n", len(info.ActiveUIDs))
	},
}

func init() {
	rootCmd.AddCommand(memberCmd)

	// Keygen command flags
	memberKeygenCmd.Flags().Bool("force", false, "Force regenerate keys even if they already exist")
	memberKeygenCmd.Flags().Bool("verbose", false, "Show detailed key generation steps")
	memberKeygenCmd.Flags().String("output", "", "Custom output path for member keys (default: data-dir/user_<uid>.json)")

	// Sign command flags
	memberSignCmd.Flags().Bool("verbose", false, "Show detailed signing protocol steps")
	memberSignCmd.Flags().String("message-file", "", "Read message from file instead of command line argument")
	memberSignCmd.Flags().String("sig-output", "", "Custom signature ID or output filename")
	memberSignCmd.Flags().Bool("save-proof-details", false, "Save detailed zero-knowledge proof information")

	// Info command flags
	memberInfoCmd.Flags().Bool("show-credentials", false, "Display credential information (upk, pi hash)")
	memberInfoCmd.Flags().Bool("show-history", false, "Show signing history for this member")
	memberInfoCmd.Flags().String("format", "text", "Output format: text or json")

	memberCmd.AddCommand(memberKeygenCmd)
	memberCmd.AddCommand(memberSignCmd)
	memberCmd.AddCommand(memberInfoCmd)
}
