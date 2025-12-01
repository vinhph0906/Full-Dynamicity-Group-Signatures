#!/bin/zsh

# Experiment script for lattice-based group signatures
# Tests different security parameters and group sizes with GPU benchmarking

set -e
setopt null_glob

# Configuration
LAMBDAS=(256 512)  # Security parameters
MAX_USERS=(128 256 512 1024 2048)  # 2^8, 2^10, 2^12, 2^14, 2^16
ITERATIONS=1
RESULTS_FILE="experiment_results.txt"
GPU_RESULTS_FILE="experiment_gpu.csv"
DATA_DIR="$HOME/.lattice-gs"
BINARY="./lattice-gs"
VERBOSE=${VERBOSE:-0}  # Set VERBOSE=0 to hide command output
export NIZK_PROFILE=${NIZK_PROFILE:-0}  # Set NIZK_PROFILE=1 to enable NIZK profiling
GPU_TEST=${GPU_TEST:-1}  # Set GPU_TEST=1 to run GPU comparisons
GPU_ENABLED=${GPU_ENABLED:-0}  # Set GPU_ENABLED=1 to use GPU for all operations

# Build the binary
echo "Building lattice-gs with CGO support..."
if [[ -f "./build_cgo.sh" ]]; then
    ./build_cgo.sh > /dev/null 2>&1 || go build -o "$BINARY" .
else
    go build -o "$BINARY" .
fi

# Initialize results file
cat > "$RESULTS_FILE" << EOF
Lattice-based Group Signature Experiment Results
Generated: $(date)
GPU Testing: $([ $GPU_TEST -eq 1 ] && echo "Enabled" || echo "Disabled")
GPU Acceleration: $([ $GPU_ENABLED -eq 1 ] && echo "Enabled" || echo "Disabled")
================================================================================

EOF

# Initialize GPU results file if GPU testing is enabled
if [[ $GPU_TEST -eq 1 ]]; then
    echo "lambda,max_users,mode,setup_time,sign_time,verify_time,trace_time,gpu_ops,cpu_ops" > "$GPU_RESULTS_FILE"
fi

# Function to get file size in bytes
get_file_size() {
    if [[ -f "$1" ]]; then
        stat -f%z "$1" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Function to clean up temporary files
cleanup() {
    echo "Cleaning up temporary files..."
    rm -rf "$DATA_DIR"
    mkdir -p "$DATA_DIR"
}

# Function to run single experiment
run_experiment() {
    local lambda=$1
    local max_users=$2
    local iteration=$3
    local gpu_flags=${4:-""}  # Optional GPU flags
    
    echo "Running: λ=$lambda, N=$max_users, iteration $iteration $gpu_flags"
    
    # Cleanup before each run
    cleanup
    
    # Reset GPU stats
    "$BINARY" reset-stats > /dev/null 2>&1 || true
    
    # Timing variables
    local setup_time=0
    local user_keygen_time=0
    local sign_time=0
    local verify_time=0
    local trace_time=0
    local judge_time=0
    
    # 1. Group setup (GM generates keys)
    local start=$(gdate +%s.%N)
    if [[ $VERBOSE -eq 1 ]]; then
        echo "  -> Running: gm setup --lambda=$lambda --max-users=$max_users $gpu_flags"
        "$BINARY" gm setup --lambda="$lambda" --max-users="$max_users" ${=gpu_flags}
    else
        "$BINARY" gm setup --lambda="$lambda" --max-users="$max_users" ${=gpu_flags} > /dev/null 2>&1
    fi
    local end=$(gdate +%s.%N)
    setup_time=$(echo "$end - $start" | bc)
    
    # Extract parameters from public_params.json (on first iteration only)
    local n="" l="" q="" q_bits="" k="" m="" m_E="" beta="" kappa=""
    local m_rows="" m_cols="" z_size=""
    if [[ $iteration -eq 1 && -f "$DATA_DIR/public_params.json" ]]; then
        n=$(jq -r '.N' "$DATA_DIR/public_params.json")
        l=$(jq -r '.L' "$DATA_DIR/public_params.json")
        q=$(jq -r '.Q' "$DATA_DIR/public_params.json")
        k=$(jq -r '.K' "$DATA_DIR/public_params.json")
        m=$(jq -r '.M' "$DATA_DIR/public_params.json")
        m_E=$(jq -r '.M_E' "$DATA_DIR/public_params.json")
        beta=$(jq -r '.Beta' "$DATA_DIR/public_params.json")
        kappa=$(jq -r '.Kappa' "$DATA_DIR/public_params.json")
        q_bits=$(python3 -c "import math; print(int(math.log2($q)) + 1)" 2>/dev/null || echo "")
        
        echo "  Parameters: n=$n, ℓ=$l, q=$q ($q_bits bits), k=$k, m=$m, m_E=$m_E, β=$beta, κ=$kappa"
    fi
    
    # 2. User keygen and issue (for user 0)
    start=$(gdate +%s.%N)
    if [[ $VERBOSE -eq 1 ]]; then
        echo "  -> Running: member keygen 0"
        "$BINARY" member keygen 0
        echo "  -> Running: gm issue 0"
        "$BINARY" gm issue 0
    else
        "$BINARY" member keygen 0 > /dev/null 2>&1
        "$BINARY" gm issue 0 > /dev/null 2>&1
    fi
    end=$(gdate +%s.%N)
    user_keygen_time=$(echo "$end - $start" | bc)
    
    # 3. Sign
    start=$(gdate +%s.%N)
    local sign_output=""
    if [[ $VERBOSE -eq 1 ]]; then
        echo "  -> Running: member sign 0 'Test message for experiment' $gpu_flags"
        sign_output=$("$BINARY" member sign 0 "Test message for experiment" ${=gpu_flags} 2>&1)
        echo "$sign_output"
    else
        sign_output=$("$BINARY" member sign 0 "Test message for experiment" ${=gpu_flags} 2>&1)
    fi
    end=$(gdate +%s.%N)
    sign_time=$(echo "$end - $start" | bc)
    
    # Extract M and z dimensions from sign output
    if [[ -n "$sign_output" ]]; then
        # Parse: [Dimensions] M: 904×167335, z: 167335
        m_rows=$(echo "$sign_output" | grep "\[Dimensions\]" | sed -n 's/.*M: \([0-9]*\)×.*/\1/p')
        m_cols=$(echo "$sign_output" | grep "\[Dimensions\]" | sed -n 's/.*×\([0-9]*\),.*/\1/p')
        z_size=$(echo "$sign_output" | grep "\[Dimensions\]" | sed -n 's/.*z: \([0-9]*\).*/\1/p')
        
        if [[ -n "$m_rows" && -n "$m_cols" && -n "$z_size" ]]; then
            echo "  Matrix dimensions: M=$m_rows×$m_cols, z=$z_size"
        fi
    fi
    
    # Find the signature file
    local sig_file=$(ls -t "$DATA_DIR"/sig_*.json 2>/dev/null | head -1)
    local sig_id=""
    if [[ -n "$sig_file" ]]; then
        sig_id=$(basename "$sig_file" .json)
        sig_id="${sig_id#sig_}"  # Remove 'sig_' prefix
    fi
    
    # 4. Verify
    if [[ -n "$sig_id" ]]; then
        start=$(gdate +%s.%N)
        if [[ $VERBOSE -eq 1 ]]; then
            echo "  -> Running: verifier verify $sig_id $gpu_flags"
            "$BINARY" verifier verify "$sig_id" ${=gpu_flags}
        else
            "$BINARY" verifier verify "$sig_id" ${=gpu_flags} > /dev/null 2>&1
        fi
        end=$(gdate +%s.%N)
        verify_time=$(echo "$end - $start" | bc)
    fi
    
    # 5. Trace (Open)
    if [[ -n "$sig_id" ]]; then
        start=$(gdate +%s.%N)
        if [[ $VERBOSE -eq 1 ]]; then
            echo "  -> Running: tm trace $sig_id $gpu_flags"
            "$BINARY" tm trace "$sig_id" ${=gpu_flags}
        else
            "$BINARY" tm trace "$sig_id" ${=gpu_flags} > /dev/null 2>&1
        fi
        end=$(gdate +%s.%N)
        trace_time=$(echo "$end - $start" | bc)
    fi
    
    # Get GPU statistics
    local gpu_ops=0
    local cpu_ops=0
    if [[ -n "$gpu_flags" ]]; then
        local stats_output=$("$BINARY" stats 2>&1 || echo "")
        gpu_ops=$(echo "$stats_output" | grep "GPU ops:" | awk '{print $3}')
        cpu_ops=$(echo "$stats_output" | grep "CPU ops:" | awk '{print $3}')
    fi
    
    # 6. Judge
    if [[ -n "$sig_id" ]]; then
        start=$(gdate +%s.%N)
        if [[ $VERBOSE -eq 1 ]]; then
            echo "  -> Running: tm judge $sig_id 0"
            "$BINARY" tm judge "$sig_id" 0
        else
            "$BINARY" tm judge "$sig_id" 0 > /dev/null 2>&1
        fi
        end=$(gdate +%s.%N)
        judge_time=$(echo "$end - $start" | bc)
    fi
    
    # Measure file sizes
    local param_size=$(get_file_size "$DATA_DIR/public_params.json")
    local gm_key_size=$(get_file_size "$DATA_DIR/gm_keys.json")
    local tm_key_size=$(get_file_size "$DATA_DIR/tm_keys.json")
    local user_key_size=$(get_file_size "$DATA_DIR/user_0_keys.json")
    local sig_size=0
    if [[ -n "$sig_file" ]]; then
        sig_size=$(get_file_size "$sig_file")
    fi
    local trace_file=$(ls -t "$DATA_DIR"/trace_*.json 2>/dev/null | head -1)
    local proof_size=0
    if [[ -n "$trace_file" ]]; then
        proof_size=$(get_file_size "$trace_file")
    fi
    
    # Output results (CSV format for easy parsing) to stderr so it can be captured
    # Format: lambda,max_users,iteration,n,l,q,q_bits,k,m,m_E,beta,kappa,m_rows,m_cols,z_size,setup_time,user_keygen_time,sign_time,verify_time,trace_time,judge_time,param_size,gm_key_size,tm_key_size,user_key_size,sig_size,proof_size,gpu_ops,cpu_ops
    echo "$lambda,$max_users,$iteration,$n,$l,$q,$q_bits,$k,$m,$m_E,$beta,$kappa,$m_rows,$m_cols,$z_size,$setup_time,$user_keygen_time,$sign_time,$verify_time,$trace_time,$judge_time,$param_size,$gm_key_size,$tm_key_size,$user_key_size,$sig_size,$proof_size,$gpu_ops,$cpu_ops" >&2
}

# Function to run GPU comparison experiment
run_gpu_comparison() {
    local lambda=$1
    local max_users=$2
    
    echo ""
    echo "GPU Comparison Test: λ=$lambda, N=$max_users"
    
    # Test 1: CPU only (default)
    echo "  [1/4] Running with default CPU..."
    cleanup
    "$BINARY" reset-stats > /dev/null 2>&1 || true
    
    local cpu_setup=$(TIMEFORMAT='%R'; { time "$BINARY" gm setup --lambda="$lambda" --max-users="$max_users" --force > /dev/null 2>&1; } 2>&1)
    "$BINARY" member keygen 0 > /dev/null 2>&1
    "$BINARY" gm issue 0 > /dev/null 2>&1
    local cpu_sign=$(TIMEFORMAT='%R'; { time "$BINARY" member sign 0 "test" > /dev/null 2>&1; } 2>&1)
    local sig_id=$(ls -t "$DATA_DIR"/sig_*.json 2>/dev/null | head -1 | xargs basename | sed 's/sig_\(.*\)\.json/\1/')
    local cpu_verify=$(TIMEFORMAT='%R'; { time "$BINARY" verifier verify "$sig_id" > /dev/null 2>&1; } 2>&1)
    local cpu_trace=$(TIMEFORMAT='%R'; { time "$BINARY" tm trace "$sig_id" > /dev/null 2>&1; } 2>&1)
    local cpu_stats=$("$BINARY" stats 2>&1 || echo "")
    local cpu_ops=$(echo "$cpu_stats" | grep "CPU ops:" | awk '{print $3}' || echo "0")
    
    echo "$lambda,$max_users,CPU,$cpu_setup,$cpu_sign,$cpu_verify,$cpu_trace,0,$cpu_ops" >> "$GPU_RESULTS_FILE"
    
    # Test 2: GPU enabled (threshold 256)
    echo "  [2/4] Running with GPU (threshold=256)..."
    cleanup
    "$BINARY" reset-stats > /dev/null 2>&1 || true
    
    local gpu256_setup=$(TIMEFORMAT='%R'; { time "$BINARY" gm setup --lambda="$lambda" --max-users="$max_users" --use-gpu --gpu-threshold 256 --force > /dev/null 2>&1; } 2>&1)
    "$BINARY" member keygen 0 > /dev/null 2>&1
    "$BINARY" gm issue 0 > /dev/null 2>&1
    local gpu256_sign=$(TIMEFORMAT='%R'; { time "$BINARY" member sign 0 "test" --use-gpu --gpu-threshold 256 > /dev/null 2>&1; } 2>&1)
    sig_id=$(ls -t "$DATA_DIR"/sig_*.json 2>/dev/null | head -1 | xargs basename | sed 's/sig_\(.*\)\.json/\1/')
    local gpu256_verify=$(TIMEFORMAT='%R'; { time "$BINARY" verifier verify "$sig_id" --use-gpu --gpu-threshold 256 > /dev/null 2>&1; } 2>&1)
    local gpu256_trace=$(TIMEFORMAT='%R'; { time "$BINARY" tm trace "$sig_id" --use-gpu --gpu-threshold 256 > /dev/null 2>&1; } 2>&1)
    local gpu256_stats=$("$BINARY" stats 2>&1 || echo "")
    local gpu256_ops=$(echo "$gpu256_stats" | grep "GPU ops:" | awk '{print $3}' || echo "0")
    local gpu256_cpu=$(echo "$gpu256_stats" | grep "CPU ops:" | awk '{print $3}' || echo "0")
    
    echo "$lambda,$max_users,GPU256,$gpu256_setup,$gpu256_sign,$gpu256_verify,$gpu256_trace,$gpu256_ops,$gpu256_cpu" >> "$GPU_RESULTS_FILE"
    
    # Test 3: GPU enabled (threshold 128)
    echo "  [3/4] Running with GPU (threshold=128)..."
    cleanup
    "$BINARY" reset-stats > /dev/null 2>&1 || true
    
    local gpu128_setup=$(TIMEFORMAT='%R'; { time "$BINARY" gm setup --lambda="$lambda" --max-users="$max_users" --use-gpu --gpu-threshold 128 --force > /dev/null 2>&1; } 2>&1)
    "$BINARY" member keygen 0 > /dev/null 2>&1
    "$BINARY" gm issue 0 > /dev/null 2>&1
    local gpu128_sign=$(TIMEFORMAT='%R'; { time "$BINARY" member sign 0 "test" --use-gpu --gpu-threshold 128 > /dev/null 2>&1; } 2>&1)
    sig_id=$(ls -t "$DATA_DIR"/sig_*.json 2>/dev/null | head -1 | xargs basename | sed 's/sig_\(.*\)\.json/\1/')
    local gpu128_verify=$(TIMEFORMAT='%R'; { time "$BINARY" verifier verify "$sig_id" --use-gpu --gpu-threshold 128 > /dev/null 2>&1; } 2>&1)
    local gpu128_trace=$(TIMEFORMAT='%R'; { time "$BINARY" tm trace "$sig_id" --use-gpu --gpu-threshold 128 > /dev/null 2>&1; } 2>&1)
    local gpu128_stats=$("$BINARY" stats 2>&1 || echo "")
    local gpu128_ops=$(echo "$gpu128_stats" | grep "GPU ops:" | awk '{print $3}' || echo "0")
    local gpu128_cpu=$(echo "$gpu128_stats" | grep "CPU ops:" | awk '{print $3}' || echo "0")
    
    echo "$lambda,$max_users,GPU128,$gpu128_setup,$gpu128_sign,$gpu128_verify,$gpu128_trace,$gpu128_ops,$gpu128_cpu" >> "$GPU_RESULTS_FILE"
    
    # Test 4: Max workers
    echo "  [4/4] Running with max-workers=16..."
    cleanup
    "$BINARY" reset-stats > /dev/null 2>&1 || true
    
    local workers_setup=$(TIMEFORMAT='%R'; { time "$BINARY" gm setup --lambda="$lambda" --max-users="$max_users" --max-workers 16 --force > /dev/null 2>&1; } 2>&1)
    "$BINARY" member keygen 0 > /dev/null 2>&1
    "$BINARY" gm issue 0 > /dev/null 2>&1
    local workers_sign=$(TIMEFORMAT='%R'; { time "$BINARY" member sign 0 "test" --max-workers 16 > /dev/null 2>&1; } 2>&1)
    sig_id=$(ls -t "$DATA_DIR"/sig_*.json 2>/dev/null | head -1 | xargs basename | sed 's/sig_\(.*\)\.json/\1/')
    local workers_verify=$(TIMEFORMAT='%R'; { time "$BINARY" verifier verify "$sig_id" --max-workers 16 > /dev/null 2>&1; } 2>&1)
    local workers_trace=$(TIMEFORMAT='%R'; { time "$BINARY" tm trace "$sig_id" --max-workers 16 > /dev/null 2>&1; } 2>&1)
    local workers_stats=$("$BINARY" stats 2>&1 || echo "")
    local workers_cpu=$(echo "$workers_stats" | grep "CPU ops:" | awk '{print $3}' || echo "0")
    
    echo "$lambda,$max_users,Workers16,$workers_setup,$workers_sign,$workers_verify,$workers_trace,0,$workers_cpu" >> "$GPU_RESULTS_FILE"
    
    echo "  ✓ GPU comparison complete"
}

# Main experiment loop
echo "Starting experiments..."
echo ""
echo "lambda,max_users,iteration,n,l,q,q_bits,k,m,m_E,beta,kappa,m_rows,m_cols,z_size,setup_time,user_keygen_time,sign_time,verify_time,trace_time,judge_time,param_size,gm_key_size,tm_key_size,user_key_size,sig_size,proof_size,gpu_ops,cpu_ops" >> "$RESULTS_FILE"

# Redirect fd 3 to stdout so we can show verbose output while capturing CSV
exec 3>&1

# Determine GPU flags based on GPU_ENABLED
GPU_FLAGS=""
if [[ $GPU_ENABLED -eq 1 ]]; then
    GPU_FLAGS="--use-gpu --gpu-threshold 128"
    echo "Using GPU acceleration for all experiments"
fi

for lambda in "${LAMBDAS[@]}"; do
    for max_users in "${MAX_USERS[@]}"; do
        echo ""
        echo "Testing λ=$lambda, N=$max_users"
        
        # Run GPU comparison if enabled and this is a reasonable parameter set
        if [[ $GPU_TEST -eq 1 && $lambda -le 128 && $max_users -le 256 ]]; then
            run_gpu_comparison "$lambda" "$max_users"
        fi
        
        for iteration in $(seq 1 $ITERATIONS); do
            result=$(run_experiment "$lambda" "$max_users" "$iteration" "$GPU_FLAGS" 2>&1 1>&3)
            echo "$result" >> "$RESULTS_FILE"
        done
    done
done

# Compute averages and summary statistics
echo ""
echo "Computing summary statistics..."

cat >> "$RESULTS_FILE" << 'EOF'

================================================================================
SUMMARY STATISTICS (Average over 5 iterations)
================================================================================

EOF

# Use awk to compute averages
awk -F',' '
NR > 1 {
    key = $1 "," $2
    n[$1,$2] = $4
    l[$1,$2] = $5
    q[$1,$2] = $6
    q_bits[$1,$2] = $7
    k[$1,$2] = $8
    m[$1,$2] = $9
    m_E[$1,$2] = $10
    beta[$1,$2] = $11
    kappa[$1,$2] = $12
    m_rows[$1,$2] = $13
    m_cols[$1,$2] = $14
    z_size[$1,$2] = $15
    setup[$1,$2] += $16
    keygen[$1,$2] += $17
    sign[$1,$2] += $18
    verify[$1,$2] += $19
    trace[$1,$2] += $20
    judge[$1,$2] += $21
    param_size[$1,$2] = $22
    gm_key_size[$1,$2] = $23
    tm_key_size[$1,$2] = $24
    user_key_size[$1,$2] = $25
    sig_size[$1,$2] = $26
    proof_size[$1,$2] = $27
    count[$1,$2]++
}
END {
    print "Lambda,MaxUsers,n,l,q,q_bits,k,m,m_E,beta,kappa,M_rows,M_cols,z_size,Setup(s),UserKeygen(s),Sign(s),Verify(s),Trace(s),Judge(s),ParamSize(B),GMKeySize(B),TMKeySize(B),UserKeySize(B),SigSize(B),ProofSize(B)"
    for (key in count) {
        split(key, arr, SUBSEP)
        lambda = arr[1]
        max_users = arr[2]
        cnt = count[key]
        printf "%d,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%d,%d,%d,%d,%d,%d\n",
            lambda, max_users,
            n[key], l[key], q[key], q_bits[key], k[key], m[key], m_E[key], beta[key], kappa[key],
            m_rows[key], m_cols[key], z_size[key],
            setup[key]/cnt, keygen[key]/cnt, sign[key]/cnt, verify[key]/cnt, trace[key]/cnt, judge[key]/cnt,
            param_size[key], gm_key_size[key], tm_key_size[key], user_key_size[key], sig_size[key], proof_size[key]
    }
}' "$RESULTS_FILE" >> "$RESULTS_FILE"

# Final cleanup
cleanup

echo ""
echo "Experiments complete! Results saved to $RESULTS_FILE"
if [[ $GPU_TEST -eq 1 ]]; then
    echo "GPU comparison results saved to $GPU_RESULTS_FILE"
fi
echo ""
echo "Summary:"
wc -l "$RESULTS_FILE"

# Display GPU comparison summary if available
if [[ $GPU_TEST -eq 1 && -f "$GPU_RESULTS_FILE" ]]; then
    echo ""
    echo "GPU Performance Summary:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    column -t -s',' "$GPU_RESULTS_FILE"
fi
