package lattice

import (
	"crypto/rand"
	"math"
	"math/big"
	"runtime"
)

// Configuration for concurrent matrix operations
var (
	// MaxWorkers sets the maximum number of concurrent goroutines for matrix operations
	// Default: min(8, NumCPU)
	MaxWorkers = getDefaultMaxWorkers()

	// ConcurrencyThreshold sets the minimum matrix size for using concurrent operations
	// For matrix-vector multiplication: minimum number of rows
	// For matrix-matrix multiplication: minimum number of rows
	ConcurrencyThresholdMulVec = 32
	ConcurrencyThresholdMatMul = 32
)

// getDefaultMaxWorkers returns a reasonable default for max workers
func getDefaultMaxWorkers() int {
	cpus := runtime.NumCPU()
	if cpus > 8 {
		return 8
	}
	return cpus
}

// SetMaxWorkers configures the maximum concurrent goroutines for matrix operations
// Use this to limit resource usage or increase parallelism based on your system
func SetMaxWorkers(workers int) {
	if workers < 1 {
		workers = 1
	}
	MaxWorkers = workers
}

// Matrix represents a matrix over Zq
type Matrix struct {
	Rows int
	Cols int
	Data [][]int64
	Q    int64
}

// NewMatrix creates a new matrix with given dimensions
func NewMatrix(rows, cols int, q int64) *Matrix {
	data := make([][]int64, rows)
	for i := range data {
		data[i] = make([]int64, cols)
	}
	return &Matrix{
		Rows: rows,
		Cols: cols,
		Data: data,
		Q:    q,
	}
}

// RandomMatrix generates a uniformly random matrix over Zq
func RandomMatrix(rows, cols int, q int64) (*Matrix, error) {
	m := NewMatrix(rows, cols, q)
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			val, err := rand.Int(rand.Reader, big.NewInt(q))
			if err != nil {
				return nil, err
			}
			m.Data[i][j] = val.Int64()
		}
	}
	return m, nil
}

// GaussianMatrix generates a matrix with β-bounded noise distribution χ
// Paper: χ is a β-bounded noise distribution where β = √n · ω(log n)
// Each entry is sampled uniformly from [-β, β] and then reduced mod q
func GaussianMatrix(rows, cols int, beta int64, q int64) (*Matrix, error) {
	m := NewMatrix(rows, cols, q)

	// Sample range: [0, 2β]
	twoBeta := 2 * beta

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			// Sample from [0, 2β]
			val, err := rand.Int(rand.Reader, big.NewInt(twoBeta))
			if err != nil {
				return nil, err
			}
			// Shift to [-β, β]
			v := val.Int64() - beta

			// Ensure it's positive mod q
			if v < 0 {
				v += q
			}
			m.Data[i][j] = v % q
		}
	}
	return m, nil
}

// Vector represents a vector over Zq
type Vector struct {
	Size int
	Data []int64
	Q    int64
}

// NewVector creates a new vector with given size
func NewVector(size int, q int64) *Vector {
	data := make([]int64, size)
	return &Vector{
		Size: size,
		Data: data,
		Q:    q,
	}
}

// RandomVector generates a uniformly random vector over Zq
func RandomVector(size int, q int64) (*Vector, error) {
	v := NewVector(size, q)
	for i := 0; i < size; i++ {
		val, err := rand.Int(rand.Reader, big.NewInt(q))
		if err != nil {
			return nil, err
		}
		v.Data[i] = val.Int64()
	}
	return v, nil
}

// BinaryVector creates a random binary vector
func BinaryVector(size int, q int64) (*Vector, error) {
	v := NewVector(size, q)
	for i := 0; i < size; i++ {
		bit, err := rand.Int(rand.Reader, big.NewInt(2))
		if err != nil {
			return nil, err
		}
		v.Data[i] = bit.Int64()
	}
	return v, nil
}

// SmallVector creates a vector with small coefficients (for LWE errors)
func SmallVector(size int, bound int64, q int64) (*Vector, error) {
	v := NewVector(size, q)
	for i := 0; i < size; i++ {
		val, err := rand.Int(rand.Reader, big.NewInt(bound))
		if err != nil {
			return nil, err
		}
		// Center around 0: subtract bound/2
		half := bound / 2
		v.Data[i] = val.Int64() - half
	}
	return v, nil
}

// Mul performs matrix-vector multiplication with optional concurrency
// For large matrices, uses goroutines to parallelize row computations
func (m *Matrix) Mul(v *Vector) *Vector {
	if m.Cols != v.Size {
		panic("incompatible dimensions for matrix-vector multiplication")
	}

	result := NewVector(m.Rows, m.Q)

	// Use concurrent multiplication for larger matrices
	if m.Rows >= ConcurrencyThresholdMulVec {
		return m.mulConcurrent(v)
	}

	// Sequential multiplication for small matrices
	for i := 0; i < m.Rows; i++ {
		var sum int64
		for j := 0; j < m.Cols; j++ {
			sum += m.Data[i][j] * v.Data[j]
		}
		result.Data[i] = sum % m.Q
	}
	return result
}

// MulInto performs matrix-vector multiplication and stores result in dst
// This avoids allocating a new vector, reusing dst instead
func (m *Matrix) MulInto(v *Vector, dst *Vector) {
	if m.Cols != v.Size {
		panic("incompatible dimensions for matrix-vector multiplication")
	}
	if dst.Size != m.Rows {
		panic("destination vector has wrong size")
	}

	// Use concurrent multiplication for larger matrices
	if m.Rows >= ConcurrencyThresholdMulVec {
		m.mulConcurrentInto(v, dst)
		return
	}

	// Sequential multiplication for small matrices
	for i := 0; i < m.Rows; i++ {
		var sum int64
		for j := 0; j < m.Cols; j++ {
			sum += m.Data[i][j] * v.Data[j]
		}
		dst.Data[i] = sum % m.Q
	}
}

// mulConcurrent performs concurrent matrix-vector multiplication
// Spawns goroutines to compute rows in parallel with configurable max workers
func (m *Matrix) mulConcurrent(v *Vector) *Vector {
	result := NewVector(m.Rows, m.Q)

	// Use configured max workers
	maxWorkers := MaxWorkers
	if m.Rows < maxWorkers {
		maxWorkers = m.Rows
	}

	// Channel to limit concurrent goroutines
	semaphore := make(chan struct{}, maxWorkers)
	done := make(chan bool, m.Rows)

	// Compute each row concurrently
	for i := 0; i < m.Rows; i++ {
		semaphore <- struct{}{} // Acquire slot
		go func(rowIdx int) {
			defer func() {
				<-semaphore // Release slot
				done <- true
			}()

			var sum int64
			for j := 0; j < m.Cols; j++ {
				sum += (m.Data[rowIdx][j] * v.Data[j]) % m.Q
				sum %= m.Q
			}
			result.Data[rowIdx] = sum % m.Q
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < m.Rows; i++ {
		<-done
	}

	return result
}

// mulConcurrentInto performs concurrent matrix-vector multiplication into dst
func (m *Matrix) mulConcurrentInto(v *Vector, dst *Vector) {
	// Use configured max workers
	maxWorkers := MaxWorkers
	if m.Rows < maxWorkers {
		maxWorkers = m.Rows
	}

	// Channel to limit concurrent goroutines
	semaphore := make(chan struct{}, maxWorkers)
	done := make(chan bool, m.Rows)

	// Compute each row concurrently
	for i := 0; i < m.Rows; i++ {
		semaphore <- struct{}{} // Acquire slot
		go func(rowIdx int) {
			defer func() {
				<-semaphore // Release slot
				done <- true
			}()

			var sum int64
			for j := 0; j < m.Cols; j++ {
				sum += m.Data[rowIdx][j] * v.Data[j]
			}
			dst.Data[rowIdx] = sum % m.Q
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < m.Rows; i++ {
		<-done
	}
}

// Add performs vector addition modulo q
func (v *Vector) Add(other *Vector) *Vector {
	if v.Size != other.Size {
		panic("incompatible vector sizes for addition")
	}

	result := NewVector(v.Size, v.Q)
	for i := 0; i < v.Size; i++ {
		sum := v.Data[i] + other.Data[i]
		result.Data[i] = sum % v.Q
	}
	return result
}

// IsZero checks if vector is zero
func (v *Vector) IsZero() bool {
	for i := 0; i < v.Size; i++ {
		if v.Data[i] != 0 {
			return false
		}
	}
	return true
}

// Clone creates a deep copy of the vector
func (v *Vector) Clone() *Vector {
	clone := NewVector(v.Size, v.Q)
	copy(clone.Data, v.Data)
	return clone
}

func (v *Vector) IsEqual(other *Vector) bool {
	if v.Size != other.Size {
		return false
	}
	for i := 0; i < v.Size; i++ {
		if v.Data[i] != other.Data[i] {
			return false
		}
	}
	return true
}

// ToBinaryVector converts a vector to binary representation
// Paper: bin(v) extracts binary representation of each coefficient
// For vector v ∈ Z_q^n, outputs binary vector p ∈ {0,1}^(n·k) where k = ⌈log q⌉
//
// Property: If G is the gadget matrix (n×(n·k)), then G·p = v mod q
// This is the standard binary decomposition used in lattice-based cryptography.
func ToBinaryVector(v *Vector, outputSize int, q int64) *Vector {
	result := NewVector(outputSize, q)

	// Calculate k = ⌈log2 q⌉
	k := int(math.Ceil(math.Log2(float64(q))))
	bitIndex := 0

	for i := 0; i < v.Size && bitIndex < outputSize; i++ {
		// Get binary representation of v[i] mod q
		coeff := v.Data[i] % q

		// Extract each bit
		for j := 0; j < k && bitIndex < outputSize; j++ {
			result.Data[bitIndex] = (coeff >> j) & 1
			bitIndex++
		}
	}

	// Remaining bits are already 0 from initialization
	return result
}

// GadgetMatrix generates the gadget matrix G (n × n·k)
// Used to verify: G · p = v, where p = bin(v)
// G has structure: [g | g | ... | g] where g = [1, 2, 4, ..., 2^(k-1)]^T repeated n times
func GadgetMatrix(n int, q int64) *Matrix {
	k := int(math.Ceil(math.Log2(float64(q))))
	cols := n * k
	G := NewMatrix(n, cols, q)

	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			// Set G[i, i*k + j] = 2^j
			power := int64(1) << j
			G.Data[i][i*k+j] = power % q
		}
	}

	return G
}

// VerifyBinaryDecomposition verifies that G · p = v mod q
// Returns true if the binary decomposition is correct
func VerifyBinaryDecomposition(v *Vector, p *Vector, pp *PublicParameters) bool {

	if p.Size != pp.NK {
		return false
	}

	// Compute G · p
	reconstructed := pp.G.Mul(p)

	// Check if G · p = v mod q
	for i := 0; i < v.Size; i++ {
		vMod := v.Data[i] % pp.Q
		rMod := reconstructed.Data[i] % pp.Q
		if vMod != rMod {
			return false
		}
	}

	return true
}

// Transpose returns the transpose of the matrix
func (m *Matrix) Transpose() *Matrix {
	result := NewMatrix(m.Cols, m.Rows, m.Q)
	for i := 0; i < m.Rows; i++ {
		for j := 0; j < m.Cols; j++ {
			result.Data[j][i] = m.Data[i][j]
		}
	}
	return result
}

// MatMul performs matrix-matrix multiplication: (this) × (other)
// Returns a new matrix with dimensions (this.Rows × other.Cols)
// Uses concurrent computation for large matrices
func (m *Matrix) MatMul(other *Matrix) *Matrix {
	if m.Cols != other.Rows {
		panic("incompatible dimensions for matrix-matrix multiplication")
	}

	result := NewMatrix(m.Rows, other.Cols, m.Q)

	// Use concurrent multiplication for larger matrices
	if m.Rows >= ConcurrencyThresholdMatMul {
		return m.matMulConcurrent(other)
	}

	// Sequential multiplication for small matrices
	for i := 0; i < m.Rows; i++ {
		for j := 0; j < other.Cols; j++ {
			var sum int64
			for k := 0; k < m.Cols; k++ {
				sum += m.Data[i][k] * other.Data[k][j]
			}
			result.Data[i][j] = sum % m.Q
		}
	}
	return result
}

// matMulConcurrent performs concurrent matrix-matrix multiplication
// Spawns goroutines to compute rows in parallel
func (m *Matrix) matMulConcurrent(other *Matrix) *Matrix {
	result := NewMatrix(m.Rows, other.Cols, m.Q)

	// Use configured max workers
	maxWorkers := MaxWorkers
	if m.Rows < maxWorkers {
		maxWorkers = m.Rows
	}

	// Channel to limit concurrent goroutines
	semaphore := make(chan struct{}, maxWorkers)
	done := make(chan bool, m.Rows)

	// Compute each row concurrently
	for i := 0; i < m.Rows; i++ {
		semaphore <- struct{}{} // Acquire slot
		go func(rowIdx int) {
			defer func() {
				<-semaphore // Release slot
				done <- true
			}()

			// Compute all columns in this row
			for j := 0; j < other.Cols; j++ {
				var sum int64
				for k := 0; k < m.Cols; k++ {
					sum += m.Data[rowIdx][k] * other.Data[k][j]
				}
				result.Data[rowIdx][j] = sum % m.Q
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < m.Rows; i++ {
		<-done
	}

	return result
} // Add performs matrix addition modulo q
func (m *Matrix) Add(other *Matrix) *Matrix {
	if m.Rows != other.Rows || m.Cols != other.Cols {
		panic("incompatible dimensions for matrix addition")
	}

	result := NewMatrix(m.Rows, m.Cols, m.Q)
	for i := 0; i < m.Rows; i++ {
		for j := 0; j < m.Cols; j++ {
			sum := m.Data[i][j] + other.Data[i][j]
			result.Data[i][j] = sum % m.Q
		}
	}
	return result
}

// SplitMatrix splits matrix A ∈ Z_q^{n×m} into [A₀|A₁] where A₀, A₁ ∈ Z_q^{n×nk}
// This is used for the hash function family H
func SplitMatrix(A *Matrix, nk int) (*Matrix, *Matrix) {
	if A.Cols != 2*nk {
		panic("Matrix A must have 2·nk columns for splitting")
	}

	n := A.Rows
	A0 := NewMatrix(n, nk, A.Q)
	A1 := NewMatrix(n, nk, A.Q)

	// Split: A₀ is first nk columns, A₁ is last nk columns
	for i := 0; i < n; i++ {
		for j := 0; j < nk; j++ {
			A0.Data[i][j] = A.Data[i][j]
			A1.Data[i][j] = A.Data[i][j+nk]
		}
	}

	return A0, A1
}
