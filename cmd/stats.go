package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vinhphamhuu/lattice-group-signature/lattice"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Display system performance statistics",
	Long: `Display GPU and CPU usage statistics for matrix operations.

Shows:
  - GPU availability status
  - Number of GPU operations performed
  - Number of CPU operations performed
  - GPU device information (if available)
  - Current GPU configuration settings`,
	Run: func(cmd *cobra.Command, args []string) {
		stats := lattice.GetGPUStats()

		fmt.Println("=== System Performance Statistics ===")
		fmt.Println()

		// GPU Status
		fmt.Println("GPU Configuration:")
		fmt.Printf("  Enabled:    %v\n", stats.GPUEnabled)
		fmt.Printf("  Available:  %v\n", stats.GPUAvailable)
		if stats.GPUEnabled {
			fmt.Printf("  Threshold:  %d (matrices >= %d×%d use GPU)\n",
				lattice.GPUThreshold, lattice.GPUThreshold, lattice.GPUThreshold)
		}
		fmt.Println()

		// Operation Counts
		total := stats.GPUOperations + stats.CPUOperations
		fmt.Println("Matrix Operations:")
		fmt.Printf("  GPU ops:    %d", stats.GPUOperations)
		if total > 0 {
			fmt.Printf(" (%.1f%%)\n", float64(stats.GPUOperations)/float64(total)*100)
		} else {
			fmt.Println()
		}

		fmt.Printf("  CPU ops:    %d", stats.CPUOperations)
		if total > 0 {
			fmt.Printf(" (%.1f%%)\n", float64(stats.CPUOperations)/float64(total)*100)
		} else {
			fmt.Println()
		}

		fmt.Printf("  Total:      %d\n", total)
		fmt.Println()

		// GPU Device Info
		if stats.GPUAvailable {
			fmt.Println("GPU Device:")
			fmt.Printf("  %s\n", lattice.GetGPUInfo())
		} else {
			fmt.Println("GPU Device:")
			fmt.Println("  No GPU detected")
			if stats.GPUEnabled {
				fmt.Println("  Using optimized CPU fallback (16-core simulation)")
			}
		}
		fmt.Println()

		// CPU Configuration
		fmt.Println("CPU Configuration:")
		fmt.Printf("  Max workers: %d\n", lattice.MaxWorkers)
		fmt.Printf("  Threshold:   %d (matrices >= %d rows use concurrency)\n",
			lattice.ConcurrencyThresholdMulVec, lattice.ConcurrencyThresholdMulVec)
		fmt.Println()

		// Recommendations
		if stats.GPUEnabled && !stats.GPUAvailable && total > 100 {
			fmt.Println("Recommendations:")
			fmt.Println("  • GPU enabled but not available - using CPU fallback")
			fmt.Println("  • For real GPU: link OpenCL/CUDA libraries")
			fmt.Println("  • See docs/GPU_ACCELERATION.md for details")
		} else if !stats.GPUEnabled && total > 100 {
			fmt.Println("Recommendations:")
			fmt.Println("  • Enable GPU with --use-gpu for potential speedup")
			fmt.Println("  • Current CPU performance is already optimized")
		}
	},
}

var resetStatsCmd = &cobra.Command{
	Use:   "reset-stats",
	Short: "Reset performance statistics counters",
	Long:  `Reset GPU and CPU operation counters to zero.`,
	Run: func(cmd *cobra.Command, args []string) {
		lattice.ResetGPUStats()
		fmt.Println("[OK] Performance statistics reset")
	},
}

func init() {
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(resetStatsCmd)
}
