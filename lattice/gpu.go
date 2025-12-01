package lattice

import (
	"fmt"
	"sync"
	"unsafe"
)

// #cgo CFLAGS: -x objective-c -fno-objc-arc
// #cgo LDFLAGS: -framework Metal -framework Foundation -framework CoreGraphics
// #import <Metal/Metal.h>
// #import <Foundation/Foundation.h>
//
// typedef struct {
//     void* device;
//     void* commandQueue;
//     void* matvecPipeline;
//     void* matmulPipeline;
//     // Persistent buffers for reuse
//     void* persistentBufferA;
//     void* persistentBufferB;
//     void* persistentBufferC;
//     size_t bufferASize;
//     size_t bufferBSize;
//     size_t bufferCSize;
//     int initialized;
// } MetalContext;
//
// const char* kernelSource =
// "kernel void matvec_mul("
// "    device const long* matrix [[ buffer(0) ]],"
// "    device const long* vector [[ buffer(1) ]],"
// "    device long* result [[ buffer(2) ]],"
// "    constant int& cols [[ buffer(3) ]],"
// "    constant long& modulus [[ buffer(4) ]],"
// "    uint row [[ thread_position_in_grid ]]"
// ") {"
// "    long sum = 0;"
// "    int base = row * cols;"
// "    for (int i = 0; i < cols; i++) {"
// "        sum += matrix[base + i] * vector[i];"
// "    }"
// "    result[row] = sum % modulus;"
// "}\n"
// "\n"
// "kernel void matmat_mul_tiled("
// "    device const long* A [[ buffer(0) ]],"
// "    device const long* B [[ buffer(1) ]],"
// "    device long* C [[ buffer(2) ]],"
// "    constant int& M [[ buffer(3) ]],"
// "    constant int& N [[ buffer(4) ]],"
// "    constant int& K [[ buffer(5) ]],"
// "    constant long& modulus [[ buffer(6) ]],"
// "    uint2 gid [[ thread_position_in_grid ]]"
// ") {"
// "    int row = gid.y;"
// "    int col = gid.x;"
// "    if (row >= M || col >= K) return;"
// "    long sum = 0;"
// "    for (int i = 0; i < N; i++) {"
// "        sum += A[row * N + i] * B[i * K + col];"
// "    }"
// "    C[row * K + col] = sum % modulus;"
// "}";
//
// MetalContext* createMetalContext() {
//     @autoreleasepool {
//         id<MTLDevice> device = MTLCreateSystemDefaultDevice();
//         if (!device) {
//             return NULL;
//         }
//
//         id<MTLCommandQueue> queue = [device newCommandQueue];
//         if (!queue) {
//             return NULL;
//         }
//
//         // Compile Metal shader
//         NSError* error = nil;
//         NSString* source = [NSString stringWithUTF8String:kernelSource];
//         MTLCompileOptions* options = [[MTLCompileOptions alloc] init];
//         id<MTLLibrary> library = [device newLibraryWithSource:source options:options error:&error];
//         if (!library) {
//             return NULL;
//         }
//
//         id<MTLFunction> matvecFunc = [library newFunctionWithName:@"matvec_mul"];
//         id<MTLFunction> matmulFunc = [library newFunctionWithName:@"matmat_mul_tiled"];
//         if (!matvecFunc || !matmulFunc) {
//             return NULL;
//         }
//
//         id<MTLComputePipelineState> matvecPipeline = [device newComputePipelineStateWithFunction:matvecFunc error:&error];
//         id<MTLComputePipelineState> matmulPipeline = [device newComputePipelineStateWithFunction:matmulFunc error:&error];
//         if (!matvecPipeline || !matmulPipeline) {
//             return NULL;
//         }
//
//         MetalContext* ctx = (MetalContext*)malloc(sizeof(MetalContext));
//         ctx->device = (void*)CFBridgingRetain(device);
//         ctx->commandQueue = (void*)CFBridgingRetain(queue);
//         ctx->matvecPipeline = (void*)CFBridgingRetain(matvecPipeline);
//         ctx->matmulPipeline = (void*)CFBridgingRetain(matmulPipeline);
//         ctx->persistentBufferA = NULL;
//         ctx->persistentBufferB = NULL;
//         ctx->persistentBufferC = NULL;
//         ctx->bufferASize = 0;
//         ctx->bufferBSize = 0;
//         ctx->bufferCSize = 0;
//         ctx->initialized = 1;
//         return ctx;
//     }
// }
//
// void releaseMetalContext(MetalContext* ctx) {
//     if (ctx) {
//         if (ctx->persistentBufferC) CFRelease(ctx->persistentBufferC);
//         if (ctx->persistentBufferB) CFRelease(ctx->persistentBufferB);
//         if (ctx->persistentBufferA) CFRelease(ctx->persistentBufferA);
//         if (ctx->matmulPipeline) CFRelease(ctx->matmulPipeline);
//         if (ctx->matvecPipeline) CFRelease(ctx->matvecPipeline);
//         if (ctx->commandQueue) CFRelease(ctx->commandQueue);
//         if (ctx->device) CFRelease(ctx->device);
//         free(ctx);
//     }
// }
//
// // Helper to get or create buffer with required size
// // (DISABLED: causes SIGBUS crashes)
// // id<MTLBuffer> getOrCreateBuffer(MetalContext* ctx, void** bufferPtr, size_t* currentSize,
// //                                  size_t requiredSize, void* data) { ... }
//
// // Metal matrix-vector multiply using custom kernel
// int metalMatVecMul(MetalContext* ctx, long* matrix, long* vector, long* result,
//                    int rows, int cols, long modulus) {
//     @autoreleasepool {
//         id<MTLDevice> device = (__bridge id<MTLDevice>)ctx->device;
//         id<MTLCommandQueue> queue = (__bridge id<MTLCommandQueue>)ctx->commandQueue;
//         id<MTLComputePipelineState> pipeline = (__bridge id<MTLComputePipelineState>)ctx->matvecPipeline;
//
//         // Buffer sizes
//         size_t matrixSize = rows * cols * sizeof(long);
//         size_t vectorSize = cols * sizeof(long);
//         size_t resultSize = rows * sizeof(long);
//
//         // Create fresh buffers each time (safer, avoids memory issues)
//         id<MTLBuffer> matrixBuffer = [device newBufferWithBytes:matrix length:matrixSize options:MTLResourceStorageModeShared];
//         id<MTLBuffer> vectorBuffer = [device newBufferWithBytes:vector length:vectorSize options:MTLResourceStorageModeShared];
//         id<MTLBuffer> resultBuffer = [device newBufferWithLength:resultSize options:MTLResourceStorageModeShared];
//         id<MTLBuffer> colsBuffer = [device newBufferWithBytes:&cols length:sizeof(int) options:MTLResourceStorageModeShared];
//         id<MTLBuffer> modBuffer = [device newBufferWithBytes:&modulus length:sizeof(long) options:MTLResourceStorageModeShared];
//
//         if (!matrixBuffer || !vectorBuffer || !resultBuffer || !colsBuffer || !modBuffer) {
//             return -1;
//         }
//
//         // Create command buffer and encoder
//         id<MTLCommandBuffer> commandBuffer = [queue commandBuffer];
//         id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
//
//         [encoder setComputePipelineState:pipeline];
//         [encoder setBuffer:matrixBuffer offset:0 atIndex:0];
//         [encoder setBuffer:vectorBuffer offset:0 atIndex:1];
//         [encoder setBuffer:resultBuffer offset:0 atIndex:2];
//         [encoder setBuffer:colsBuffer offset:0 atIndex:3];
//         [encoder setBuffer:modBuffer offset:0 atIndex:4];
//
//         // Configure thread groups
//         NSUInteger threadGroupSize = MIN(256, pipeline.maxTotalThreadsPerThreadgroup);
//         MTLSize threadsPerGroup = MTLSizeMake(threadGroupSize, 1, 1);
//         MTLSize numThreadGroups = MTLSizeMake((rows + threadGroupSize - 1) / threadGroupSize, 1, 1);
//
//         [encoder dispatchThreadgroups:numThreadGroups threadsPerThreadgroup:threadsPerGroup];
//         [encoder endEncoding];
//
//         [commandBuffer commit];
//         [commandBuffer waitUntilCompleted];
//
//         // Copy result back
//         memcpy(result, resultBuffer.contents, resultSize);
//
//         return 0;
//     }
// }
//
// // Metal matrix-matrix multiply (no persistent buffers - safer)
// int metalMatMatMul(MetalContext* ctx, long* matrixA, long* matrixB, long* result,
//                    int M, int N, int K, long modulus) {
//     @autoreleasepool {
//         id<MTLDevice> device = (__bridge id<MTLDevice>)ctx->device;
//         id<MTLCommandQueue> queue = (__bridge id<MTLCommandQueue>)ctx->commandQueue;
//         id<MTLComputePipelineState> pipeline = (__bridge id<MTLComputePipelineState>)ctx->matmulPipeline;
//
//         // Buffer sizes
//         size_t sizeA = M * N * sizeof(long);
//         size_t sizeB = N * K * sizeof(long);
//         size_t sizeC = M * K * sizeof(long);
//
//         // Create fresh buffers each time (safer, avoids memory issues)
//         id<MTLBuffer> bufferA = [device newBufferWithBytes:matrixA length:sizeA options:MTLResourceStorageModeShared];
//         id<MTLBuffer> bufferB = [device newBufferWithBytes:matrixB length:sizeB options:MTLResourceStorageModeShared];
//         id<MTLBuffer> bufferC = [device newBufferWithLength:sizeC options:MTLResourceStorageModeShared];
//
//         if (!bufferA || !bufferB || !bufferC) {
//             return -1;
//         }
//
//         // Create small constant buffers (these are tiny, OK to recreate)
//         id<MTLBuffer> bufferM = [device newBufferWithBytes:&M length:sizeof(int) options:MTLResourceStorageModeShared];
//         id<MTLBuffer> bufferN = [device newBufferWithBytes:&N length:sizeof(int) options:MTLResourceStorageModeShared];
//         id<MTLBuffer> bufferK = [device newBufferWithBytes:&K length:sizeof(int) options:MTLResourceStorageModeShared];
//         id<MTLBuffer> bufferMod = [device newBufferWithBytes:&modulus length:sizeof(long) options:MTLResourceStorageModeShared];
//
//         // Create command buffer and encoder
//         id<MTLCommandBuffer> commandBuffer = [queue commandBuffer];
//         id<MTLComputeCommandEncoder> encoder = [commandBuffer computeCommandEncoder];
//
//         [encoder setComputePipelineState:pipeline];
//         [encoder setBuffer:bufferA offset:0 atIndex:0];
//         [encoder setBuffer:bufferB offset:0 atIndex:1];
//         [encoder setBuffer:bufferC offset:0 atIndex:2];
//         [encoder setBuffer:bufferM offset:0 atIndex:3];
//         [encoder setBuffer:bufferN offset:0 atIndex:4];
//         [encoder setBuffer:bufferK offset:0 atIndex:5];
//         [encoder setBuffer:bufferMod offset:0 atIndex:6];
//
//         // Configure 2D thread groups (16x16 tiles)
//         NSUInteger tileSize = 16;
//         MTLSize threadsPerGroup = MTLSizeMake(tileSize, tileSize, 1);
//         MTLSize numThreadGroups = MTLSizeMake(
//             (K + tileSize - 1) / tileSize,
//             (M + tileSize - 1) / tileSize,
//             1
//         );
//
//         [encoder dispatchThreadgroups:numThreadGroups threadsPerThreadgroup:threadsPerGroup];
//         [encoder endEncoding];
//
//         [commandBuffer commit];
//         [commandBuffer waitUntilCompleted];
//
//         // Copy result
//         memcpy(result, bufferC.contents, sizeC);
//
//         return 0;
//     }
// }
import "C"

var (
	gpuInitialized bool
	gpuMutex       sync.RWMutex
	gpuDevice      *GPUDevice
	metalContext   *C.MetalContext

	// GPU usage statistics
	gpuOpsCount int64
	cpuOpsCount int64
	statsMutex  sync.RWMutex

	// Kernel execution mutex
	kernelMutex sync.Mutex

	// Buffer pools to reduce allocations
	flatBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]int64, 0, 1024*1024) // 1M elements initial capacity
		},
	}
)

// GPUDevice represents a GPU compute device
type GPUDevice struct {
	Name             string
	Available        bool
	MaxWorkGroupSize int
	GlobalMemSize    int64
}

// GPUStats tracks GPU vs CPU usage
type GPUStats struct {
	GPUOperations int64
	CPUOperations int64
	GPUEnabled    bool
	GPUAvailable  bool
}

// GetGPUStats returns current GPU usage statistics
func GetGPUStats() GPUStats {
	statsMutex.RLock()
	defer statsMutex.RUnlock()

	return GPUStats{
		GPUOperations: gpuOpsCount,
		CPUOperations: cpuOpsCount,
		GPUEnabled:    UseGPU,
		GPUAvailable:  IsGPUAvailable(),
	}
}

// ResetGPUStats resets GPU usage counters
func ResetGPUStats() {
	statsMutex.Lock()
	defer statsMutex.Unlock()

	gpuOpsCount = 0
	cpuOpsCount = 0
}

// BatchMatrixVectorMul performs multiple matrix-vector multiplications in parallel
func BatchMatrixVectorMul(matrices []*Matrix, vectors []*Vector) []*Vector {
	if len(matrices) != len(vectors) {
		panic("batch mul: matrices and vectors length mismatch")
	}

	results := make([]*Vector, len(matrices))

	// Check if GPU should be used for this batch
	useGPU := false
	if len(matrices) > 0 && UseGPU && IsGPUAvailable() {
		// Use GPU if any matrix is large enough
		for _, m := range matrices {
			if m.Rows >= GPUThreshold {
				useGPU = true
				break
			}
		}
	}

	if useGPU {
		// Process all on GPU
		for i := range matrices {
			results[i] = matrices[i].Mul(vectors[i])
		}
	} else {
		// Process all on CPU in parallel
		var wg sync.WaitGroup
		for i := range matrices {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = matrices[idx].Mul(vectors[idx])
			}(i)
		}
		wg.Wait()
	}

	return results
}

// InitGPU initializes the GPU for use
func InitGPU() error {
	gpuMutex.Lock()
	defer gpuMutex.Unlock()

	if gpuInitialized {
		return nil
	}

	device, err := detectGPU()
	if err != nil {
		return err
	}

	gpuDevice = device
	gpuInitialized = true
	return nil
}

// IsGPUAvailable checks if GPU is available for use (with lazy initialization)
func IsGPUAvailable() bool {
	gpuMutex.RLock()
	initialized := gpuInitialized
	gpuMutex.RUnlock()

	if !initialized {
		// Try lazy initialization
		if UseGPU {
			err := InitGPU()
			if err != nil {
				return false
			}
		} else {
			return false
		}
	}

	gpuMutex.RLock()
	defer gpuMutex.RUnlock()
	return gpuInitialized && gpuDevice != nil && gpuDevice.Available
}

// GetGPUDevice returns information about the GPU
func GetGPUDevice() *GPUDevice {
	gpuMutex.RLock()
	defer gpuMutex.RUnlock()
	return gpuDevice
}

// GetGPUInfo returns a formatted string with GPU information
func GetGPUInfo() string {
	if !IsGPUAvailable() {
		return "GPU: Not available"
	}
	device := GetGPUDevice()
	if device == nil {
		return "GPU: Not initialized"
	}
	return fmt.Sprintf("%s (Metal Performance Shaders, Unified Memory: %d MB)",
		device.Name, device.GlobalMemSize)
}

// detectGPU initializes Metal device
func detectGPU() (*GPUDevice, error) {
	ctx := C.createMetalContext()
	if ctx == nil {
		return nil, fmt.Errorf("no Metal device available")
	}

	metalContext = ctx

	fmt.Println("[GPU] Metal GPU initialized successfully (M3)")

	return &GPUDevice{
		Name:          "Apple Metal GPU (M3)",
		Available:     true,
		GlobalMemSize: 12 * 1024, // 12GB unified memory on M3
	}, nil
}

// gpuMatrixVectorMul performs matrix-vector multiplication using Metal with int64 precision
func gpuMatrixVectorMul(matrix [][]int64, vector []int64, modulus int64) ([]int64, error) {
	kernelMutex.Lock()
	defer kernelMutex.Unlock()

	if metalContext == nil {
		return nil, fmt.Errorf("Metal not initialized")
	}

	rows := len(matrix)
	cols := len(matrix[0])

	// Get pooled buffer for flattening
	flatInterface := flatBufferPool.Get()
	flatMatrix := flatInterface.([]int64)

	size := rows * cols
	if cap(flatMatrix) < size {
		flatMatrix = make([]int64, size)
	} else {
		flatMatrix = flatMatrix[:size]
	}

	// Flatten matrix using copy for speed
	for i := 0; i < rows; i++ {
		copy(flatMatrix[i*cols:(i+1)*cols], matrix[i])
	}

	// Prepare result buffer
	result := make([]int64, rows)

	// Call Metal matrix-vector multiplication with int64 precision
	ret := C.metalMatVecMul(
		metalContext,
		(*C.long)(unsafe.Pointer(&flatMatrix[0])),
		(*C.long)(unsafe.Pointer(&vector[0])),
		(*C.long)(unsafe.Pointer(&result[0])),
		C.int(rows),
		C.int(cols),
		C.long(modulus),
	)

	// Return buffer to pool
	flatBufferPool.Put(flatMatrix[:0])

	if ret != 0 {
		return nil, fmt.Errorf("Metal matrix multiplication failed")
	}

	recordGPUOp()
	return result, nil
}

// gpuMatrixMatrixMul performs matrix-matrix multiplication using Metal: C = A × B
// A is M×N, B is N×K, result is M×K
func gpuMatrixMatrixMul(matrixA [][]int64, matrixB [][]int64, modulus int64) ([][]int64, error) {
	kernelMutex.Lock()
	defer kernelMutex.Unlock()

	if metalContext == nil {
		return nil, fmt.Errorf("Metal not initialized")
	}

	M := len(matrixA)
	N := len(matrixA[0])
	K := len(matrixB[0])

	if len(matrixB) != N {
		return nil, fmt.Errorf("incompatible dimensions: A is %dx%d, B is %dx%d", M, N, len(matrixB), K)
	}

	// Get pooled buffers
	flatAInterface := flatBufferPool.Get()
	flatBInterface := flatBufferPool.Get()
	flatCInterface := flatBufferPool.Get()

	flatA := flatAInterface.([]int64)
	flatB := flatBInterface.([]int64)
	flatC := flatCInterface.([]int64)

	// Ensure capacity
	sizeA := M * N
	sizeB := N * K
	sizeC := M * K

	if cap(flatA) < sizeA {
		flatA = make([]int64, sizeA)
	} else {
		flatA = flatA[:sizeA]
	}
	if cap(flatB) < sizeB {
		flatB = make([]int64, sizeB)
	} else {
		flatB = flatB[:sizeB]
	}
	if cap(flatC) < sizeC {
		flatC = make([]int64, sizeC)
	} else {
		flatC = flatC[:sizeC]
	}

	// Flatten matrices to row-major format
	for i := 0; i < M; i++ {
		copy(flatA[i*N:(i+1)*N], matrixA[i])
	}
	for i := 0; i < N; i++ {
		copy(flatB[i*K:(i+1)*K], matrixB[i])
	}

	// Call Metal matrix-matrix multiplication
	ret := C.metalMatMatMul(
		metalContext,
		(*C.long)(unsafe.Pointer(&flatA[0])),
		(*C.long)(unsafe.Pointer(&flatB[0])),
		(*C.long)(unsafe.Pointer(&flatC[0])),
		C.int(M),
		C.int(N),
		C.int(K),
		C.long(modulus),
	)

	// Return buffers to pool
	flatBufferPool.Put(flatA[:0])
	flatBufferPool.Put(flatB[:0])

	if ret != 0 {
		flatBufferPool.Put(flatC[:0])
		return nil, fmt.Errorf("Metal matrix-matrix multiplication failed")
	}

	// Convert flat result back to 2D array
	result := make([][]int64, M)
	for i := 0; i < M; i++ {
		result[i] = make([]int64, K)
		copy(result[i], flatC[i*K:(i+1)*K])
	}

	flatBufferPool.Put(flatC[:0])

	recordGPUOp()
	return result, nil
}

// recordGPUOp increments the GPU operation counter
func recordGPUOp() {
	statsMutex.Lock()
	gpuOpsCount++
	statsMutex.Unlock()
}

// recordCPUOp increments the CPU operation counter
func recordCPUOp() {
	statsMutex.Lock()
	cpuOpsCount++
	statsMutex.Unlock()
}

// Cleanup releases GPU resources
func Cleanup() {
	gpuMutex.Lock()
	defer gpuMutex.Unlock()

	if metalContext != nil {
		C.releaseMetalContext(metalContext)
		metalContext = nil
	}

	gpuInitialized = false
	gpuDevice = nil
}
