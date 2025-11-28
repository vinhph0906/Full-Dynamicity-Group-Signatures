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
	Long:  "Commands for group members to generate keys, join the group, and create signatures",
}

var memberKeygenCmd = &cobra.Command{
	Use:   "keygen [uid]",
	Short: "Generate user keys (UKgen algorithm)",
	Long: `Runs the UKgen algorithm from the paper.
Generates a user's key pair (upk, usk) and credentials (x, pi).
This must be done before joining the group.`,
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
	Use:   "sign [uid] [message]",
	Short: "Create an anonymous group signature (Sign algorithm)",
	Long: `Runs the Sign algorithm from the paper.
Creates an anonymous signature that proves membership without revealing identity.
Uses Stern-like zero-knowledge proof to prove:
  - Knowledge of secret credential x where pi = A*x
  - Valid non-zero public key
  - Valid Merkle authentication path
  - Well-formed ciphertext encrypting identity`,
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
	Use:   "info [uid]",
	Short: "Show member information",
	Long:  "Displays member's status, keys, and group membership information.",
	Args:  cobra.ExactArgs(1),
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

	memberCmd.AddCommand(memberKeygenCmd)
	memberCmd.AddCommand(memberSignCmd)
	memberCmd.AddCommand(memberInfoCmd)
}
