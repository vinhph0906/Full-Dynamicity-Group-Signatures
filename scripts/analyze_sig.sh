#!/bin/zsh
# Analyze signature JSON file size breakdown

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <signature_file.json>"
    exit 1
fi

SIG_FILE=$1

if [[ ! -f "$SIG_FILE" ]]; then
    echo "Error: File not found: $SIG_FILE"
    exit 1
fi

echo "=== Signature Size Analysis ==="
echo "File: $(basename $SIG_FILE)"

TOTAL_SIZE=$(stat -f%z "$SIG_FILE")
echo "Total size: $TOTAL_SIZE bytes ($(echo "scale=2; $TOTAL_SIZE/1024/1024" | bc) MB)"
echo ""

echo "=== Component Breakdown ==="

# Extract and measure each top-level field
for field in Epoch Message Ciphertext Proof; do
    SIZE=$(jq -r ".$field" "$SIG_FILE" | wc -c)
    PCT=$(echo "scale=2; $SIZE * 100 / $TOTAL_SIZE" | bc)
    echo "$field: $SIZE bytes ($PCT%)"
done

echo ""
echo "=== Ciphertext Details ==="
for field in C1_U C1_V C2_U C2_V; do
    SIZE=$(jq -r ".Ciphertext.$field" "$SIG_FILE" | wc -c)
    DIMS=$(jq -r ".Ciphertext.$field.Size" "$SIG_FILE")
    echo "  $field: $SIZE bytes [$DIMS dims]"
done

echo ""
echo "=== ZK Proof Details ==="

# Count rounds
ROUNDS=$(jq -r '.Proof.Responses | length' "$SIG_FILE")
echo "Rounds (κ): $ROUNDS"

# Commitments
COMMIT_SIZE=$(jq -r '.Proof.Commitments' "$SIG_FILE" | wc -c)
echo "Commitments total: $COMMIT_SIZE bytes ($(echo "scale=2; $COMMIT_SIZE/1024/1024" | bc) MB)"

if [[ $ROUNDS -gt 0 ]]; then
    COMMIT_PER_ROUND=$(echo "$COMMIT_SIZE / $ROUNDS" | bc)
    echo "  Per round: ~$COMMIT_PER_ROUND bytes"
fi

# Responses (the big one!)
RESP_SIZE=$(jq -r '.Proof.Responses' "$SIG_FILE" | wc -c)
RESP_PCT=$(echo "scale=1; $RESP_SIZE * 100 / $TOTAL_SIZE" | bc)
echo ""
echo "Responses total: $RESP_SIZE bytes ($(echo "scale=2; $RESP_SIZE/1024/1024" | bc) MB) - $RESP_PCT% of signature!"

if [[ $ROUNDS -gt 0 ]]; then
    RESP_PER_ROUND=$(echo "$RESP_SIZE / $ROUNDS" | bc)
    echo "  Per round: ~$RESP_PER_ROUND bytes"
    
    # Sample first response vector size
    FIRST_RESP_DIMS=$(jq -r '.Proof.Responses[0].Size' "$SIG_FILE")
    echo "  Response vector dims: $FIRST_RESP_DIMS"
    
    # Check if responses are sparse
    FIRST_RESP_SIZE=$(jq -r '.Proof.Responses[0]' "$SIG_FILE" | wc -c)
    BYTES_PER_DIM=$(echo "$FIRST_RESP_SIZE / $FIRST_RESP_DIMS" | bc)
    echo "  Bytes per dimension: ~$BYTES_PER_DIM"
fi

echo ""
echo "=== Optimization Analysis ==="

if [[ $(echo "$RESP_PCT > 50" | bc) -eq 1 ]]; then
    echo "⚠️  Responses are $RESP_PCT% of signature - MAIN BOTTLENECK!"
    echo ""
    echo "Possible optimizations:"
    echo "1. Sparse encoding: Store only non-zero elements + indices"
    echo "2. Delta/Huffman compression on response values"
    echo "3. Reduce κ (currently $ROUNDS rounds)"
    echo "4. Use compact base64 encoding (currently JSON with quotes/commas)"
    
    # Estimate potential savings
    CURRENT_JSON=$(jq -r '.Proof.Responses[0].Data | .[0:5]' "$SIG_FILE")
    echo ""
    echo "Sample response data (first 5 elements):"
    echo "$CURRENT_JSON"
    
    # Calculate overhead from JSON formatting
    RAW_NUMBERS=$(jq -r '.Proof.Responses[0].Data | join(",")' "$SIG_FILE" | wc -c)
    JSON_OVERHEAD=$(echo "scale=1; ($FIRST_RESP_SIZE - $RAW_NUMBERS) * 100 / $FIRST_RESP_SIZE" | bc)
    echo ""
    echo "JSON overhead: ~$JSON_OVERHEAD% (brackets, quotes, commas)"
    echo "Potential saving with binary encoding: $(echo "scale=2; $RESP_SIZE * $JSON_OVERHEAD / 100 / 1024 / 1024" | bc) MB"
fi

echo ""
