package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	dataDir string
	rootCmd = &cobra.Command{
		Use:   "lattice-gs",
		Short: "Lattice-Based Fully Dynamic Group Signature",
		Long: `A post-quantum group signature scheme based on lattice assumptions.
Implements the scheme from "Lattice-Based Group Signatures: Achieving Full Dynamicity with Ease" (ACNS 2017).

Supports four roles:
  - Group Manager (gm): Manages group membership
  - Tracing Manager (tm): Traces signatures to signers
  - Member: Creates anonymous signatures
  - Verifier: Verifies signatures`,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "Data directory for keys and state (default: ~/.lattice-gs)")
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
