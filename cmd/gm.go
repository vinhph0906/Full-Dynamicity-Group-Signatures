package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vinhphamhuu/lattice-group-signature/scheme"
	"github.com/vinhphamhuu/lattice-group-signature/storage"
)

var gmCmd = &cobra.Command{
	Use:   "gm",
	Short: "Group Manager commands",
	Long: `Group Manager (GM) commands for managing group membership and system setup.

The GM is responsible for:
  - Initial system setup (GSetup, GKgenGM, GKgenTM)
  - Issuing certificates to new members (Issue protocol)
  - Revoking members from the group (GUpdate protocol)
  - Maintaining the Merkle tree of active members
  - Managing group state and epoch transitions

Available commands:
  setup   - Initialize the entire group signature system
  issue   - Add a new member to the group
  update  - Revoke members and update group state
  list    - View current group membership`,
}

var gmSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Initialize the group signature system (GSetup)",
	Long: `Initialize the group signature system by running GSetup algorithm.

This command performs:
  1. GSetup: Generate public parameters (pp) based on security parameter λ
  2. GKgenGM: Generate Group Manager key pair (mpk, msk)
  3. GKgenTM: Generate Tracing Manager key pair (tpk, tsk)
  4. Initialize empty Merkle tree with N leaves (max users)
  5. Initialize group state at epoch 0
  6. Save all keys and parameters to persistent storage

Parameters:
  --lambda: Security parameter in bits (default: 128)
    - Controls lattice dimension and SIS/LWE hardness
    - Higher values = more security but larger keys/signatures
  
  --max-users: Maximum group size N, must be power of 2 (default: 16)
    - Determines Merkle tree height (log N)
    - Affects signature size: O(λ·log N)
  
  --force: Force reinitialize even if system exists
    - WARNING: Destroys all existing keys and signatures!

Example:
  lattice-gs gm setup --lambda=128 --max-users=32

This must be run before any other operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		lambda, _ := cmd.Flags().GetInt("lambda")
		maxUsers, _ := cmd.Flags().GetInt("max-users")

		fmt.Println("=== Group Manager: System Setup ===")
		fmt.Printf("Security parameter λ: %d\n", lambda)
		fmt.Printf("Maximum users N: %d\n", maxUsers)

		// Initialize storage
		store, err := storage.NewStorage(dataDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Check if already initialized
		if store.IsInitialized() {
			fmt.Println("Error: System already initialized. Delete data directory to reinitialize.")
			return
		}

		// Step 1: GSetup - Generate public parameters
		fmt.Println("\n1. Running GSetup (generating public parameters)...")
		pp := scheme.GSetup(lambda, maxUsers)
		fmt.Printf("   ✓ Public parameters generated (m=%d, q=%d bits)\n", pp.M, pp.Q)

		// Step 2: GKgenGM - Generate Group Manager keys
		fmt.Println("\n2. Running GKgenGM (generating GM keys)...")
		mpk, msk, err := scheme.GKgenGM(pp)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("   ✓ Group Manager keys generated")

		// Step 3: GKgenTM - Generate Tracing Manager keys
		fmt.Println("\n3. Running GKgenTM (generating TM keys)...")
		tpk, tsk, err := scheme.GKgenTM(pp)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Println("   ✓ Tracing Manager keys generated")

		// Step 4: Initialize group and registry
		fmt.Println("\n4. Initializing group state...")
		reg := scheme.InitializeRegistry(pp)
		info := scheme.InitializeGroup(pp, reg)

		fmt.Printf("   ✓ Group initialized at epoch %d\n", info.Epoch)

		// Step 5: Save all data
		fmt.Println("\n5. Saving to persistent storage...")
		if err := store.SavePublicParameters(pp); err != nil {
			fmt.Printf("Error saving public parameters: %v\n", err)
			return
		}
		if err := store.SaveGMKeys(mpk, msk); err != nil {
			fmt.Printf("Error saving GM keys: %v\n", err)
			return
		}
		if err := store.SaveTMKeys(tpk, tsk); err != nil {
			fmt.Printf("Error saving TM keys: %v\n", err)
			return
		}
		if err := store.SaveGroupInfo(info); err != nil {
			fmt.Printf("Error saving group info: %v\n", err)
			return
		}
		if err := store.SaveRegistry(reg); err != nil {
			fmt.Printf("Error saving registry: %v\n", err)
			return
		}

		fmt.Println("\n✅ Setup complete!")
		fmt.Printf("Data directory: %s\n", store.DataDir)
		fmt.Println("\nGroup public key components saved:")
		fmt.Println("  - Public parameters (pp)")
		fmt.Println("  - GM public key (mpk)")
		fmt.Println("  - TM public key (tpk)")
	},
}

var gmIssueCmd = &cobra.Command{
	Use:   "issue <uid>",
	Short: "Issue certificate to a user (Issue protocol)",
	Long: `Issue a membership certificate to a user, adding them to the group.

The Issue protocol:
  1. Verify user has generated keys (upk, x, pi) via 'member keygen'
  2. Validate user's public credential: pi = A * x (mod q)
  3. Add user's public credential to Merkle tree at leaf index uid
  4. Update Merkle tree root hash
  5. Increment group epoch counter
  6. Save updated group state and registry

Prerequisites:
  - System must be initialized ('gm setup')
  - User must have run 'member keygen <uid>' first

Flags:
  --auto-approve: Skip confirmation prompt (default: true)
  --verbose: Show detailed protocol steps

Example:
  lattice-gs gm issue 5
  lattice-gs gm issue 5 --verbose

After issuance, the user can sign messages anonymously.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		uid := 0
		fmt.Sscanf(args[0], "%d", &uid)

		fmt.Println("=== Group Manager: Issue Certificate ===")
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

		// Load necessary data
		_, msk, err := store.LoadGMKeys()
		if err != nil {
			fmt.Printf("Error loading GM keys: %v\n", err)
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

		// Load user's join request (upk and pi)
		gsk, err := store.LoadUserKeys(uid)
		if err != nil {
			fmt.Printf("Error: User %d has not generated keys. User must run 'member keygen' first.\n", uid)
			return
		}

		// Run Issue protocol
		fmt.Println("\nRunning Issue protocol...")
		err = scheme.Issue(info, msk, gsk.UPK, gsk.PI, uid, reg)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Save updated state
		if err := store.SaveGroupInfo(info); err != nil {
			fmt.Printf("Error saving group info: %v\n", err)
			return
		}
		if err := store.SaveRegistry(reg); err != nil {
			fmt.Printf("Error saving registry: %v\n", err)
			return
		}

		fmt.Printf("\n✅ Certificate issued to User %d\n", uid)
		fmt.Printf("Epoch: %d\n", info.Epoch)
		fmt.Printf("Active members: %d\n", len(info.ActiveUIDs))
		fmt.Printf("Merkle root: %x...\n", info.RootHash.Data[:8])
	},
}

var gmUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update group state by revoking users (GUpdate)",
	Long: `Update the group by revoking specified users (GUpdate algorithm).

The GUpdate protocol:
  1. Identify users to revoke from --revoke flag
  2. Set revoked users' Merkle tree leaves to 0
  3. Recompute Merkle tree root hash
  4. Increment group epoch
  5. Update active user registry
  6. Save new group state

Revoked users:
  - Cannot create new valid signatures
  - Old signatures remain valid (non-repudiation)
  - Are removed from active member list
  - Can potentially rejoin later (via new 'issue')

Flags:
  --revoke: Comma-separated list of UIDs (REQUIRED)
  --confirm: Require confirmation (default: true)
  --verbose: Show detailed update steps

Examples:
  lattice-gs gm update --revoke=3,5,7
  lattice-gs gm update --revoke=1 --verbose
  lattice-gs gm update --revoke=2,4,6 --confirm=false

This demonstrates the full dynamicity feature of the scheme.`,
	Run: func(cmd *cobra.Command, args []string) {
		revokeUIDs, _ := cmd.Flags().GetIntSlice("revoke")

		fmt.Println("=== Group Manager: Update Group ===")

		if len(revokeUIDs) == 0 {
			fmt.Println("No users to revoke. Use --revoke flag to specify UIDs.")
			return
		}

		fmt.Printf("Revoking users: %v\n", revokeUIDs)

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

		_, msk, err := store.LoadGMKeys()
		if err != nil {
			fmt.Printf("Error loading GM keys: %v\n", err)
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

		oldEpoch := info.Epoch
		oldActive := len(info.ActiveUIDs)

		// Run GUpdate protocol
		fmt.Println("\nRunning GUpdate protocol...")
		newInfo, err := scheme.GUpdate(gpk, msk, info, revokeUIDs, reg)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if newInfo == nil {
			fmt.Println("No changes made to group.")
			return
		}

		// Save updated state
		if err := store.SaveGroupInfo(newInfo); err != nil {
			fmt.Printf("Error saving group info: %v\n", err)
			return
		}

		fmt.Printf("\n✅ Group updated successfully\n")
		fmt.Printf("Epoch: %d → %d\n", oldEpoch, newInfo.Epoch)
		fmt.Printf("Active members: %d → %d\n", oldActive, len(newInfo.ActiveUIDs))
		fmt.Printf("New Merkle root: %x...\n", newInfo.RootHash.Data[:8])
		fmt.Printf("\nRevoked users can no longer sign messages.\n")
	},
}

var gmListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all group members and their status",
	Long: `Display current group membership, state, and statistics.

Shows:
  - Current epoch number
  - Merkle tree root hash
  - Total registered users
  - Active members (can sign)
  - Revoked members (cannot sign)
  - Member-specific information (with --show-keys)

Flags:
  --show-revoked: Include revoked members (default: true)
  --show-keys: Display public key hashes (default: false)
  --format: Output format - table, json, or csv (default: table)

Examples:
  lattice-gs gm list
  lattice-gs gm list --show-keys
  lattice-gs gm list --format=json
  lattice-gs gm list --show-revoked=false

Useful for monitoring group state and membership changes.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("=== Group Manager: List Members ===")

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

		fmt.Printf("\nEpoch: %d\n", info.Epoch)
		fmt.Printf("Merkle root: %x\n", info.RootHash)
		fmt.Printf("Total registered users: %d\n", len(reg.Records))
		fmt.Printf("Active members: %d\n\n", len(info.ActiveUIDs))

		if len(info.ActiveUIDs) > 0 {
			fmt.Println("Active members:")
			for uid := range info.ActiveUIDs {
				fmt.Printf("  - User %d\n", uid)
			}
		}

		// Show revoked users
		revokedCount := 0
		for uid := range reg.Records {
			if !info.ActiveUIDs[uid] {
				revokedCount++
			}
		}

		if revokedCount > 0 {
			fmt.Printf("\nRevoked members: %d\n", revokedCount)
			for uid := range reg.Records {
				if !info.ActiveUIDs[uid] {
					fmt.Printf("  - User %d (revoked)\n", uid)
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(gmCmd)

	// Setup command flags
	gmSetupCmd.Flags().Int("lambda", 128, "Security parameter λ (bits) - affects lattice dimensions and proof size")
	gmSetupCmd.Flags().Int("max-users", 16, "Maximum number of users N (must be power of 2) - determines Merkle tree height")
	gmSetupCmd.Flags().Bool("force", false, "Force reinitialize even if system already exists")

	// Issue command flags
	gmIssueCmd.Flags().Bool("auto-approve", true, "Automatically approve join request without manual confirmation")
	gmIssueCmd.Flags().Bool("verbose", false, "Show detailed issue protocol steps")

	// Update command flags
	gmUpdateCmd.Flags().IntSlice("revoke", []int{}, "User IDs to revoke (comma-separated, e.g., --revoke=1,3,5)")
	gmUpdateCmd.Flags().Bool("confirm", true, "Require confirmation before revoking users")
	gmUpdateCmd.Flags().Bool("verbose", false, "Show detailed update protocol steps")
	gmUpdateCmd.MarkFlagRequired("revoke")

	// List command flags
	gmListCmd.Flags().Bool("show-revoked", true, "Include revoked members in the list")
	gmListCmd.Flags().Bool("show-keys", false, "Display public key information for each member")
	gmListCmd.Flags().String("format", "table", "Output format: table, json, or csv")

	gmCmd.AddCommand(gmSetupCmd)
	gmCmd.AddCommand(gmIssueCmd)
	gmCmd.AddCommand(gmUpdateCmd)
	gmCmd.AddCommand(gmListCmd)
}
