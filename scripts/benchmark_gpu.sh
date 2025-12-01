#!/bin/bash

# GPU vs CPU Performance Benchmark
# Compares matrix multiplication performance with different configurations

set -e

LAMBDA=128
MAX_USERS=16

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Matrix Multiplication Performance Benchmark               ║"
echo "║  Testing CPU vs GPU acceleration options                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Clean slate
rm -rf ~/.lattice-gs 2>/dev/null || true

echo "[1] Baseline: Default CPU (auto workers)"
echo "─────────────────────────────────────────"
time ./lattice-gs gm setup --lambda ${LAMBDA} --max-users ${MAX_USERS} --force
echo ""

# Clean and test with more workers
rm -rf ~/.lattice-gs 2>/dev/null || true
echo "[2] CPU with max workers=16"
echo "─────────────────────────────────────────"
time ./lattice-gs gm setup --lambda ${LAMBDA} --max-users ${MAX_USERS} --max-workers 16 --force
echo ""

# Clean and test with GPU enabled
rm -rf ~/.lattice-gs 2>/dev/null || true
echo "[3] GPU acceleration enabled (threshold=256)"
echo "─────────────────────────────────────────"
time ./lattice-gs gm setup --lambda ${LAMBDA} --max-users ${MAX_USERS} --use-gpu --force
echo ""

# Clean and test with lower GPU threshold
rm -rf ~/.lattice-gs 2>/dev/null || true
echo "[4] GPU acceleration (threshold=128, aggressive)"
echo "─────────────────────────────────────────"
time ./lattice-gs gm setup --lambda ${LAMBDA} --max-users ${MAX_USERS} --use-gpu --gpu-threshold 128 --force
echo ""

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Benchmark Complete                                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Note: GPU acceleration currently uses optimized CPU fallback."
echo "For actual GPU acceleration, CUDA/OpenCL integration is needed."
echo ""
echo "Configuration options:"
echo "  --use-gpu              Enable GPU acceleration"
echo "  --gpu-threshold N      Use GPU for matrices >= N×N"
echo "  --max-workers N        Set concurrent CPU workers"
