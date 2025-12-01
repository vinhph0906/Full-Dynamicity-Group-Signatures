#!/bin/bash

# Quick GPU performance experiment
# Compares CPU vs GPU-enabled performance

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     GPU Performance Experiment                             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Build
echo "[1] Building with CGO..."
./build_cgo.sh > /dev/null 2>&1 || go build -o lattice-gs

# Parameters
LAMBDA=256
MAX_USERS=16

echo "[2] Testing configurations with λ=$LAMBDA, N=$MAX_USERS"
echo ""

# Output file
OUTPUT="experiment_gpu.csv"
echo "mode,setup_time,keygen_time,sign_time,verify_time,trace_time,gpu_ops,cpu_ops,io_time" > $OUTPUT

# Test 1: Default CPU
echo "━━━ Test 1/4: Default CPU ━━━"
rm -rf ~/.lattice-gs 2>/dev/null || true
./lattice-gs reset-stats > /dev/null 2>&1 || true

setup_time=$( { time ./lattice-gs gm setup --lambda $LAMBDA --max-users $MAX_USERS --force > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
./lattice-gs member keygen 0 > /dev/null 2>&1
./lattice-gs gm issue 0 > /dev/null 2>&1
sign_output=$(NIZK_PROFILE=1 ./lattice-gs member sign 0 "test" 2>&1)
sign_time=$(echo "$sign_output" | grep "Sign total" | awk '{print $4}' | sed 's/s//')
save_time=$(echo "$sign_output" | grep "SaveSignature" | awk '{print $3}' | sed 's/s//')
SIG_ID=$(ls -t ~/.lattice-gs/sig_*.json | head -1 | xargs basename | sed 's/sig_//' | sed 's/.json//')
verify_time=$( { time ./lattice-gs verifier verify $SIG_ID > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
trace_time=$( { time ./lattice-gs tm trace $SIG_ID > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
stats=$(./lattice-gs stats 2>&1)
cpu_ops=$(echo "$stats" | grep "CPU ops:" | awk '{print $3}')

echo "CPU,$setup_time,0,$sign_time,$verify_time,$trace_time,0,$cpu_ops,$save_time" >> $OUTPUT
echo "  Setup: ${setup_time}s, Sign: ${sign_time}s (I/O: ${save_time}s), Verify: ${verify_time}s, Trace: ${trace_time}s"

# Test 2: GPU threshold 256
echo ""
echo "━━━ Test 2/4: GPU (threshold=256) ━━━"
rm -rf ~/.lattice-gs 2>/dev/null || true
./lattice-gs reset-stats > /dev/null 2>&1 || true

setup_time=$( { time ./lattice-gs gm setup --lambda $LAMBDA --max-users $MAX_USERS --use-gpu --gpu-threshold 256 --force > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
./lattice-gs member keygen 0 --use-gpu --gpu-threshold 256 > /dev/null 2>&1
./lattice-gs gm issue 0 --use-gpu --gpu-threshold 256 > /dev/null 2>&1
sign_output=$(NIZK_PROFILE=1 ./lattice-gs member sign 0 "test" --use-gpu --gpu-threshold 256 2>&1)
sign_time=$(echo "$sign_output" | grep "Sign total" | awk '{print $4}' | sed 's/s//')
save_time=$(echo "$sign_output" | grep "SaveSignature" | awk '{print $3}' | sed 's/s//')
SIG_ID=$(ls -t ~/.lattice-gs/sig_*.json | head -1 | xargs basename | sed 's/sig_//' | sed 's/.json//')
verify_time=$( { time ./lattice-gs verifier verify $SIG_ID --use-gpu --gpu-threshold 256 > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
trace_time=$( { time ./lattice-gs tm trace $SIG_ID --use-gpu --gpu-threshold 256 > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
stats=$(./lattice-gs stats 2>&1)
gpu_ops=$(echo "$stats" | grep "GPU ops:" | awk '{print $3}')
cpu_ops=$(echo "$stats" | grep "CPU ops:" | awk '{print $3}')

echo "GPU256,$setup_time,0,$sign_time,$verify_time,$trace_time,$gpu_ops,$cpu_ops,$save_time" >> $OUTPUT
echo "  Setup: ${setup_time}s, Sign: ${sign_time}s (I/O: ${save_time}s), Verify: ${verify_time}s, Trace: ${trace_time}s"

# Test 3: GPU threshold 128
echo ""
echo "━━━ Test 3/4: GPU (threshold=128) ━━━"
rm -rf ~/.lattice-gs 2>/dev/null || true
./lattice-gs reset-stats > /dev/null 2>&1 || true

setup_time=$( { time ./lattice-gs gm setup --lambda $LAMBDA --max-users $MAX_USERS --use-gpu --gpu-threshold 128 --force > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
./lattice-gs member keygen 0 --use-gpu --gpu-threshold 128 > /dev/null 2>&1
./lattice-gs gm issue 0 --use-gpu --gpu-threshold 128 > /dev/null 2>&1
sign_output=$(NIZK_PROFILE=1 ./lattice-gs member sign 0 "test" --use-gpu --gpu-threshold 128 2>&1)
sign_time=$(echo "$sign_output" | grep "Sign total" | awk '{print $4}' | sed 's/s//')
save_time=$(echo "$sign_output" | grep "SaveSignature" | awk '{print $3}' | sed 's/s//')
SIG_ID=$(ls -t ~/.lattice-gs/sig_*.json | head -1 | xargs basename | sed 's/sig_//' | sed 's/.json//')
verify_time=$( { time ./lattice-gs verifier verify $SIG_ID --use-gpu --gpu-threshold 128 > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
trace_time=$( { time ./lattice-gs tm trace $SIG_ID --use-gpu --gpu-threshold 128 > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
stats=$(./lattice-gs stats 2>&1)
gpu_ops=$(echo "$stats" | grep "GPU ops:" | awk '{print $3}')
cpu_ops=$(echo "$stats" | grep "CPU ops:" | awk '{print $3}')

echo "GPU128,$setup_time,0,$sign_time,$verify_time,$trace_time,$gpu_ops,$cpu_ops,$save_time" >> $OUTPUT
echo "  Setup: ${setup_time}s, Sign: ${sign_time}s (I/O: ${save_time}s), Verify: ${verify_time}s, Trace: ${trace_time}s"

# Test 4: Max workers 16
echo ""
echo "━━━ Test 4/4: CPU with 16 workers ━━━"
rm -rf ~/.lattice-gs 2>/dev/null || true
./lattice-gs reset-stats > /dev/null 2>&1 || true

setup_time=$( { time ./lattice-gs gm setup --lambda $LAMBDA --max-users $MAX_USERS --max-workers 16 --force > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
./lattice-gs member keygen 0 --max-workers 16 > /dev/null 2>&1
./lattice-gs gm issue 0 --max-workers 16 > /dev/null 2>&1
sign_output=$(NIZK_PROFILE=1 ./lattice-gs member sign 0 "test" --max-workers 16 2>&1)
sign_time=$(echo "$sign_output" | grep "Sign total" | awk '{print $4}' | sed 's/s//')
save_time=$(echo "$sign_output" | grep "SaveSignature" | awk '{print $3}' | sed 's/s//')
SIG_ID=$(ls -t ~/.lattice-gs/sig_*.json | head -1 | xargs basename | sed 's/sig_//' | sed 's/.json//')
verify_time=$( { time ./lattice-gs verifier verify $SIG_ID --max-workers 16 > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
trace_time=$( { time ./lattice-gs tm trace $SIG_ID --max-workers 16 > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//')
stats=$(./lattice-gs stats 2>&1)
cpu_ops=$(echo "$stats" | grep "CPU ops:" | awk '{print $3}')

echo "Workers16,$setup_time,0,$sign_time,$verify_time,$trace_time,0,$cpu_ops,$save_time" >> $OUTPUT
echo "  Setup: ${setup_time}s, Sign: ${sign_time}s (I/O: ${save_time}s), Verify: ${verify_time}s, Trace: ${trace_time}s"

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              Results Summary                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
column -t -s',' $OUTPUT
echo ""
echo "Results saved to: $OUTPUT"
