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
	Long:  "Commands for the Group Manager to manage group membership",
}

var gmSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Initialize the group signature system (GSetup)",
	Long: `Runs the GSetup algorithm from the paper.
Generates public parameters and initializes both GM and TM key pairs.
This must be run first before any other operations.`,
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
	Use:   "issue [uid]",
	Short: "Issue certificate to a user (Issue protocol)",
	Long: `Runs the Issue algorithm from the paper.
The GM accepts a user's join request and adds them to the group.
The user must have already generated their keys and credentials.`,
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
	Short: "Update group (revoke users) - GUpdate algorithm",
	Long: `Runs the GUpdate algorithm from the paper.
Revokes specified users from the group by setting their leaves to 0 in the Merkle tree.
This demonstrates the full dynamicity feature.`,
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
	Short: "List group members",
	Long:  "Shows current group state, active members, and epoch information.",
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
	gmSetupCmd.Flags().Int("lambda", 128, "Security parameter")
	gmSetupCmd.Flags().Int("max-users", 16, "Maximum number of users (power of 2)")

	// Update command flags
	gmUpdateCmd.Flags().IntSlice("revoke", []int{}, "User IDs to revoke (comma-separated)")
	gmUpdateCmd.MarkFlagRequired("revoke")

	gmCmd.AddCommand(gmSetupCmd)
	gmCmd.AddCommand(gmIssueCmd)
	gmCmd.AddCommand(gmUpdateCmd)
	gmCmd.AddCommand(gmListCmd)
}
