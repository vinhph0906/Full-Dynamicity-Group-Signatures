# Concurrent Matrix Operations

The lattice-based group signature implementation uses concurrent matrix multiplication for improved performance with large matrices.

## Configuration

### Max Workers

Configure the maximum number of concurrent goroutines:

```go
import "github.com/vinhphamhuu/lattice-group-signature/lattice"

// Set max workers to 16 (for high-performance systems)
lattice.SetMaxWorkers(16)

// Set max workers to 4 (for resource-constrained environments)
lattice.SetMaxWorkers(4)
```

**Default**: `min(8, NumCPU)`

### Concurrency Thresholds

Adjust when concurrent operations are used:

```go
// Matrix-vector multiplication threshold (default: 100 rows)
lattice.ConcurrencyThresholdMulVec = 200

// Matrix-matrix multiplication threshold (default: 50 rows)
lattice.ConcurrencyThresholdMatMul = 100
```

## Performance Characteristics

### Matrix-Vector Multiplication (`Matrix.Mul`)

- **Sequential**: Used for matrices with `< 100` rows (configurable)
- **Concurrent**: Used for matrices with `≥ 100` rows
- **Parallelization**: Each row computed in a separate goroutine (up to MaxWorkers)

### Matrix-Matrix Multiplication (`Matrix.MatMul`)

- **Sequential**: Used for matrices with `< 50` rows (configurable)
- **Concurrent**: Used for matrices with `≥ 50` rows
- **Parallelization**: Each row computed in a separate goroutine (up to MaxWorkers)

## Usage Examples

### High-Performance Server

```go
package main

import "github.com/vinhphamhuu/lattice-group-signature/lattice"

func main() {
    // Use all available CPUs
    lattice.SetMaxWorkers(runtime.NumCPU())
    
    // Lower thresholds for more concurrency
    lattice.ConcurrencyThresholdMulVec = 50
    lattice.ConcurrencyThresholdMatMul = 25
    
    // Your code here...
}
```

### Resource-Constrained Environment

```go
package main

import "github.com/vinhphamhuu/lattice-group-signature/lattice"

func main() {
    // Limit concurrent goroutines
    lattice.SetMaxWorkers(2)
    
    // Higher thresholds to prefer sequential computation
    lattice.ConcurrencyThresholdMulVec = 500
    lattice.ConcurrencyThresholdMatMul = 200
    
    // Your code here...
}
```

### Disable Concurrency (Sequential Only)

```go
package main

import "github.com/vinhphamhuu/lattice-group-signature/lattice"

func main() {
    // Set very high thresholds to effectively disable concurrency
    lattice.ConcurrencyThresholdMulVec = 1000000
    lattice.ConcurrencyThresholdMatMul = 1000000
    
    // Your code here...
}
```

## Implementation Details

### Semaphore Pattern

The implementation uses a semaphore pattern to limit concurrent goroutines:

```go
semaphore := make(chan struct{}, maxWorkers)
done := make(chan bool, m.Rows)

for i := 0; i < m.Rows; i++ {
    semaphore <- struct{}{}  // Acquire slot
    go func(rowIdx int) {
        defer func() {
            <-semaphore      // Release slot
            done <- true
        }()
        // Compute row...
    }(i)
}

// Wait for all goroutines
for i := 0; i < m.Rows; i++ {
    <-done
}
```

This ensures at most `maxWorkers` goroutines run simultaneously, preventing resource exhaustion.

## Performance Benchmarks

For λ=128 (production security level):

- **Matrix dimensions**: 
  - A: 128×32768 (n×m where m=2nk)
  - B: 128×832 (n×m_E where m_E=2(n+ℓ)k)
  - P₁, P₂: 4×832 (ℓ×m_E)

- **Sequential**: ~40s total for setup + sign
- **Concurrent (8 workers)**: ~20s total for setup + sign
- **Speedup**: ~2x improvement

## Notes

- Concurrency provides the most benefit for large matrices (high security parameters)
- For small security parameters (λ < 64), sequential may be faster due to goroutine overhead
- Adjust MaxWorkers based on your system's CPU count and available memory
- Each goroutine allocates memory for intermediate big.Int values
