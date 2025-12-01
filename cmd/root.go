package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vinhphamhuu/lattice-group-signature/lattice"
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
	rootCmd.PersistentFlags().Bool("quiet", false, "Suppress non-essential output")
	rootCmd.PersistentFlags().Bool("debug", false, "Enable debug logging for troubleshooting")
	rootCmd.PersistentFlags().String("log-file", "", "Write logs to file instead of stdout")

	// Performance flags
	rootCmd.PersistentFlags().Bool("use-gpu", false, "Enable GPU acceleration for matrix operations (experimental)")
	rootCmd.PersistentFlags().Int("gpu-threshold", 256, "Minimum matrix size for GPU acceleration")
	rootCmd.PersistentFlags().Int("max-workers", 0, "Maximum concurrent workers for CPU operations (0=auto)")

	// Apply GPU settings on startup
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if useGPU, _ := cmd.Flags().GetBool("use-gpu"); useGPU {
			lattice.SetUseGPU(true)
			if threshold, _ := cmd.Flags().GetInt("gpu-threshold"); threshold > 0 {
				lattice.SetGPUThreshold(threshold)
			}
		}
		if workers, _ := cmd.Flags().GetInt("max-workers"); workers > 0 {
			lattice.SetMaxWorkers(workers)
		}
	}
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
