#!/bin/bash

# Build script with CGO enabled for GPU support
# This allows linking with OpenCL/CUDA libraries

set -e

echo "Building with CGO enabled for GPU support..."
echo ""

# Enable CGO
export CGO_ENABLED=1

# Detect platform and set appropriate flags
OS=$(uname -s)
ARCH=$(uname -m)

echo "Platform: $OS $ARCH"
echo ""

# Platform-specific CGO flags
case "$OS" in
    Darwin)
        echo "macOS detected - checking for Metal/OpenCL support"
        # macOS has OpenCL built-in
        export CGO_CFLAGS="-I/System/Library/Frameworks/OpenCL.framework/Headers"
        export CGO_LDFLAGS="-framework OpenCL"
        ;;
    Linux)
        echo "Linux detected - checking for CUDA/OpenCL support"
        # Check for CUDA
        if [ -d "/usr/local/cuda" ]; then
            echo "  Found CUDA installation"
            export CGO_CFLAGS="-I/usr/local/cuda/include"
            export CGO_LDFLAGS="-L/usr/local/cuda/lib64 -lcuda -lcudart"
        # Check for OpenCL
        elif [ -f "/usr/lib/x86_64-linux-gnu/libOpenCL.so" ]; then
            echo "  Found OpenCL installation"
            export CGO_CFLAGS="-I/usr/include"
            export CGO_LDFLAGS="-L/usr/lib/x86_64-linux-gnu -lOpenCL"
        else
            echo "  No GPU libraries found - building with CPU fallback"
        fi
        ;;
    *)
        echo "Unknown OS - building with CPU fallback"
        ;;
esac

# Build flags
BUILD_FLAGS="-tags cgo"
OUTPUT="lattice-gs"

# Parse command line arguments
VERBOSE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-v|--verbose] [-o|--output filename]"
            exit 1
            ;;
    esac
done

# Show build configuration
if [ $VERBOSE -eq 1 ]; then
    echo "Build configuration:"
    echo "  CGO_ENABLED:  $CGO_ENABLED"
    echo "  CGO_CFLAGS:   $CGO_CFLAGS"
    echo "  CGO_LDFLAGS:  $CGO_LDFLAGS"
    echo "  BUILD_FLAGS:  $BUILD_FLAGS"
    echo "  OUTPUT:       $OUTPUT"
    echo ""
fi

# Build
echo "Compiling..."
if [ $VERBOSE -eq 1 ]; then
    go build -v $BUILD_FLAGS -o "$OUTPUT"
else
    go build $BUILD_FLAGS -o "$OUTPUT"
fi

# Check result
if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Build successful: $OUTPUT"
    
    # Show binary info
    if command -v file &> /dev/null; then
        echo ""
        file "$OUTPUT"
    fi
    
    # Show size
    if command -v ls &> /dev/null; then
        SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
        echo "Size: $SIZE"
    fi
    
    # Test GPU detection
    echo ""
    echo "Testing GPU detection..."
    ./"$OUTPUT" stats 2>&1 | grep -A 3 "GPU Configuration:"
    
else
    echo ""
    echo "✗ Build failed"
    exit 1
fi
