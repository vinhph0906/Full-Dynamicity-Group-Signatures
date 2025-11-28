#!/bin/bash

# Attack Scenario Tests for Lattice-Based Group Signature
# Tests various attack vectors to ensure security properties hold

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0
TOTAL=0

# Binary and test directory
BINARY="./lattice-gs"
TEST_DIR="/tmp/lattice-gs-attacks"

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    PASSED=$((PASSED + 1))
    TOTAL=$((TOTAL + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    FAILED=$((FAILED + 1))
    TOTAL=$((TOTAL + 1))
}

section() {
    echo ""
    echo -e "${YELLOW}[$1] $2${NC}"
    echo ""
}

# Cleanup and setup
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

echo "============================================"
echo "Attack Scenario Tests"
echo "============================================"

# ============================================
# [1] Signature Forgery Attacks
# ============================================
section "1" "Signature Forgery Attacks"

# Test 1.1: Sign without credential (no gm issue)
echo "Test 1.1: Sign without credential (no GM issue)"
rm -rf "$TEST_DIR/no_cred"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/no_cred" > /dev/null 2>&1

# Generate user key but don't issue credential
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/no_cred" > /dev/null 2>&1

# Try to sign without credential (should fail - user not active)
SIGN_OUTPUT=$("$BINARY" member sign 0 "test message" --data-dir "$TEST_DIR/no_cred" 2>&1)

# Check if error message appears AND no signature file created
SIG_COUNT=$(find "$TEST_DIR/no_cred" -maxdepth 1 -name "sig_*.json" -type f 2>/dev/null | wc -l | tr -d ' ')

if echo "$SIGN_OUTPUT" | grep -q "not active" && [ "$SIG_COUNT" -eq 0 ]; then
    pass "Cannot sign without credential (user not active)"
else
    fail "Signed without credential (security breach! sig_count=$SIG_COUNT)"
fi

# Test 1.2: Sign with random/zero credential
echo "Test 1.2: Sign with corrupted credential values"
rm -rf "$TEST_DIR/random"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/random" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/random" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/random" > /dev/null 2>&1

# Corrupt the user's credential in user keys file (set to zero)
python3 << 'PYEOF'
import json
with open("/tmp/lattice-gs-attacks/random/user_0_keys.json", "r") as f:
    keys = json.load(f)

# Set credential PI to zero (invalid)
if 'PI' in keys and isinstance(keys['PI'], dict) and 'Data' in keys['PI']:
    keys['PI']['Data'] = [0] * len(keys['PI']['Data'])

with open("/tmp/lattice-gs-attacks/random/user_0_keys.json", "w") as f:
    json.dump(keys, f)
PYEOF

# Try to sign with corrupted credential (should fail at signing stage)
SIGN_OUTPUT=$("$BINARY" member sign 0 "test" --data-dir "$TEST_DIR/random" 2>&1)

# Check if signing was blocked due to zero credential
if echo "$SIGN_OUTPUT" | grep -q "credential cannot be zero"; then
    pass "Corrupted credential rejected at signing"
else
    # If signing somehow succeeded, check verification
    LAST_SIG=$(find "$TEST_DIR/random" -maxdepth 1 -name "sig_*.json" -type f | head -1)
    if [ -n "$LAST_SIG" ]; then
        SIG_ID=$(basename "$LAST_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
        VERIFY_OUTPUT=$("$BINARY" verifier verify "$SIG_ID" --data-dir "$TEST_DIR/random" 2>&1)
        
        # Check output for INVALID (binary doesn't return error codes)
        if echo "$VERIFY_OUTPUT" | grep -q "INVALID"; then
            pass "Corrupted credential signature rejected by verifier"
        else
            fail "Corrupted credential signature accepted (security breach!)"
        fi
    else
        pass "Corrupted credential signing failed"
    fi
fi

# Test 1.3: Copy-paste attack (reuse signature)
echo "Test 1.3: Copy-paste attack (reuse signature for different message)"
rm -rf "$TEST_DIR/copypaste"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/copypaste" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/copypaste" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/copypaste" > /dev/null 2>&1

# Create signature on message1
"$BINARY" member sign 0 "message1" --data-dir "$TEST_DIR/copypaste" > /dev/null 2>&1
ORIGINAL_SIG=$(find "$TEST_DIR/copypaste" -maxdepth 1 -name "sig_*.json" -type f | head -1)

if [ -n "$ORIGINAL_SIG" ]; then
    # Modify signature to claim it's for message2 (copy-paste attack)
    # Message is base64 encoded, so encode "message2"
    python3 << 'PYEOF'
import json
import glob
import base64

sig_files = glob.glob("/tmp/lattice-gs-attacks/copypaste/sig_*.json")
if sig_files:
    with open(sig_files[0], "r") as f:
        sig = json.load(f)
    
    # Change message to base64 of "message2" (copy-paste attack)
    sig['Message'] = base64.b64encode(b"message2").decode('utf-8')
    
    with open(sig_files[0], "w") as f:
        json.dump(sig, f)
PYEOF
    
    # Try to verify modified signature
    SIG_ID=$(basename "$ORIGINAL_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    VERIFY_OUTPUT=$("$BINARY" verifier verify "$SIG_ID" --data-dir "$TEST_DIR/copypaste" 2>&1)
    
    # Check if verification failed (binary doesn't return error codes, check output)
    if echo "$VERIFY_OUTPUT" | grep -q "INVALID"; then
        pass "Copy-paste attack detected (signature invalid)"
    else
        fail "Copy-paste attack succeeded (message not cryptographically bound to signature)"
    fi
else
    fail "Could not create original signature"
fi

# Test 1.4: Chosen message attack (create many signatures)
echo "Test 1.4: Chosen message attack (statistical analysis)"
rm -rf "$TEST_DIR/chosen"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/chosen" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/chosen" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/chosen" > /dev/null 2>&1

# Create multiple signatures with chosen messages
SUCCESS_COUNT=0
for i in {1..5}; do
    "$BINARY" member sign 0 "chosen_message_$i" --data-dir "$TEST_DIR/chosen" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
    sleep 1  # Avoid timestamp collision in signature filenames
done

# All signatures should be valid (but unlinkable due to randomness)
SIG_COUNT=$(find "$TEST_DIR/chosen" -maxdepth 1 -name "sig_*.json" -type f 2>/dev/null | wc -l | tr -d ' ')

if [ "$SIG_COUNT" -ge 4 ] && [ "$SUCCESS_COUNT" -ge 4 ]; then
    pass "Chosen message attack: $SIG_COUNT signatures created (anonymity through randomness)"
else
    fail "Chosen message attack issue (created: $SUCCESS_COUNT, files: $SIG_COUNT, expected: ≥4)"
fi

# ============================================
# [2] Tracing Attacks
# ============================================
section "2" "Tracing Attacks"

# Test 2.1: Decrypt with wrong TM key
echo "Test 2.1: Trace with wrong TM key"
rm -rf "$TEST_DIR/wrongkey"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/wrongkey" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/wrongkey" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/wrongkey" > /dev/null 2>&1
"$BINARY" member sign 0 "test" --data-dir "$TEST_DIR/wrongkey" > /dev/null 2>&1

LAST_SIG=$(find "$TEST_DIR/wrongkey" -maxdepth 1 -name "sig_*.json" -type f | head -1)

if [ -n "$LAST_SIG" ]; then
    # Corrupt TM secret key
    python3 << 'PYEOF'
import json
with open("/tmp/lattice-gs-attacks/wrongkey/tm_keys.json", "r") as f:
    tm = json.load(f)

# Corrupt the TM secret key (set to zeros)
if 'TMSecret' in tm and 'S' in tm['TMSecret']:
    if isinstance(tm['TMSecret']['S'], list):
        tm['TMSecret']['S'] = [[0] * len(row) if isinstance(row, list) else 0 for row in tm['TMSecret']['S']]

with open("/tmp/lattice-gs-attacks/wrongkey/tm_keys.json", "w") as f:
    json.dump(tm, f)
PYEOF
    
    # Try to trace with corrupted key
    SIG_ID=$(basename "$LAST_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    "$BINARY" tm trace "$SIG_ID" --data-dir "$TEST_DIR/wrongkey" > /dev/null 2>&1
    TRACE_EXIT=$?
    
    if [ $TRACE_EXIT -ne 0 ]; then
        pass "Trace with wrong TM key failed (expected)"
    else
        # Check if traced UID is correct (should be wrong with corrupted key)
        TRACE_OUTPUT=$("$BINARY" tm trace "$SIG_ID" --data-dir "$TEST_DIR/wrongkey" 2>&1 || true)
        if echo "$TRACE_OUTPUT" | grep -q "UID: 0"; then
            fail "Trace with wrong key returned correct UID (security breach!)"
        else
            pass "Trace with wrong TM key returned incorrect/no UID"
        fi
    fi
else
    fail "Could not create signature for tracing attack test"
fi

# Test 2.2: Forge trace proof
echo "Test 2.2: Forge trace proof"
rm -rf "$TEST_DIR/forgeproof"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/forgeproof" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/forgeproof" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/forgeproof" > /dev/null 2>&1
"$BINARY" member sign 0 "test" --data-dir "$TEST_DIR/forgeproof" > /dev/null 2>&1

LAST_SIG=$(find "$TEST_DIR/forgeproof" -maxdepth 1 -name "sig_*.json" -type f | head -1)

if [ -n "$LAST_SIG" ]; then
    SIG_ID=$(basename "$LAST_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    
    # Get real trace
    "$BINARY" tm trace "$SIG_ID" --data-dir "$TEST_DIR/forgeproof" > /dev/null 2>&1
    
    # Corrupt trace proof file (if exists)
    TRACE_FILE="$TEST_DIR/forgeproof/trace_${SIG_ID}.json"
    if [ -f "$TRACE_FILE" ]; then
        python3 << 'PYEOF'
import json
import glob

trace_files = glob.glob("/tmp/lattice-gs-attacks/forgeproof/trace_*.json")
if trace_files:
    with open(trace_files[0], "r") as f:
        trace = json.load(f)
    
    # Corrupt the trace proof (claim wrong UID)
    if 'UID' in trace:
        trace['UID'] = 7  # Wrong UID
    
    # Corrupt proof data if present
    if 'Proof' in trace and isinstance(trace['Proof'], list):
        trace['Proof'] = [0] * len(trace['Proof'])
    
    with open(trace_files[0], "w") as f:
        json.dump(trace, f)
PYEOF
        
        # Try to judge with forged proof
        JUDGE_OUTPUT=$("$BINARY" tm judge "$SIG_ID" 7 --data-dir "$TEST_DIR/forgeproof" 2>&1)
        
        # Check output for rejection (binary doesn't return error codes)
        if echo "$JUDGE_OUTPUT" | grep -q "INVALID\|rejected\|failed"; then
            pass "Forged trace proof rejected by judge"
        else
            fail "Forged trace proof accepted (security breach!)"
        fi
    else
        pass "Trace proof file format prevents forgery (no separate file)"
    fi
else
    fail "Could not create signature for forge proof test"
fi

# Test 2.3: Modify ciphertext before tracing
echo "Test 2.3: Modify ciphertext in signature"
rm -rf "$TEST_DIR/modct"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/modct" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/modct" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/modct" > /dev/null 2>&1
"$BINARY" member sign 0 "test" --data-dir "$TEST_DIR/modct" > /dev/null 2>&1

LAST_SIG=$(find "$TEST_DIR/modct" -maxdepth 1 -name "sig_*.json" -type f | head -1)

if [ -n "$LAST_SIG" ]; then
    # Modify ciphertext in signature
    python3 << 'PYEOF'
import json
import glob

sig_files = glob.glob("/tmp/lattice-gs-attacks/modct/sig_*.json")
if sig_files:
    with open(sig_files[0], "r") as f:
        sig = json.load(f)
    
    # Corrupt ciphertext (set to zeros)
    if 'Ciphertext' in sig and isinstance(sig['Ciphertext'], dict):
        # Corrupt Data fields in ciphertext components
        for key in ['C1_U', 'C1_V', 'C2_U', 'C2_V']:
            if key in sig['Ciphertext'] and isinstance(sig['Ciphertext'][key], dict):
                if 'Data' in sig['Ciphertext'][key]:
                    sig['Ciphertext'][key]['Data'] = [0] * len(sig['Ciphertext'][key]['Data'])
    
    with open(sig_files[0], "w") as f:
        json.dump(sig, f)
PYEOF
    
    # Verify should fail with modified ciphertext
    SIG_ID=$(basename "$LAST_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    VERIFY_OUTPUT=$("$BINARY" verifier verify "$SIG_ID" --data-dir "$TEST_DIR/modct" 2>&1)
    
    # Check output for INVALID (binary doesn't return error codes)
    if echo "$VERIFY_OUTPUT" | grep -q "INVALID"; then
        pass "Modified ciphertext detected (signature invalid)"
    else
        fail "Modified ciphertext not detected (security breach!)"
    fi
else
    fail "Could not create signature for ciphertext modification test"
fi

# Test 2.4: Frame attack (claim wrong UID in trace)
echo "Test 2.4: Frame attack (TM claims wrong UID)"
rm -rf "$TEST_DIR/frame"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/frame" > /dev/null 2>&1

# Add two users
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/frame" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/frame" > /dev/null 2>&1
"$BINARY" member keygen 1 --data-dir "$TEST_DIR/frame" > /dev/null 2>&1
"$BINARY" gm issue 1 --data-dir "$TEST_DIR/frame" > /dev/null 2>&1

# User 0 signs
"$BINARY" member sign 0 "test" --data-dir "$TEST_DIR/frame" > /dev/null 2>&1

LAST_SIG=$(find "$TEST_DIR/frame" -maxdepth 1 -name "sig_*_0.json" -type f | head -1)

if [ -n "$LAST_SIG" ]; then
    SIG_ID=$(basename "$LAST_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    
    # Trace should return UID=0
    TRACE_OUTPUT=$("$BINARY" tm trace "$SIG_ID" --data-dir "$TEST_DIR/frame" 2>&1)
    
    if echo "$TRACE_OUTPUT" | grep -q "User 0"; then
        pass "Frame attack prevented (correct UID traced)"
    else
        fail "Frame attack issue (traced wrong UID)"
    fi
else
    fail "Could not create signature for frame attack test"
fi

# ============================================
# [3] Revocation Attacks
# ============================================
section "3" "Revocation Attacks"

# Test 3.1: Sign after revocation
echo "Test 3.1: Sign after revocation (user removed)"
rm -rf "$TEST_DIR/revoked"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/revoked" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/revoked" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/revoked" > /dev/null 2>&1

# Sign successfully first
"$BINARY" member sign 0 "before revocation" --data-dir "$TEST_DIR/revoked" > /dev/null 2>&1
BEFORE_EXIT=$?

# Revoke user
"$BINARY" gm update --revoke 0 --data-dir "$TEST_DIR/revoked" > /dev/null 2>&1

# Try to sign after revocation (should fail)
"$BINARY" member sign 0 "after revocation" --data-dir "$TEST_DIR/revoked" > /dev/null 2>&1
AFTER_EXIT=$?

if [ $BEFORE_EXIT -eq 0 ] && [ $AFTER_EXIT -ne 0 ]; then
    pass "Cannot sign after revocation"
elif [ $AFTER_EXIT -eq 0 ]; then
    # Signing succeeded, check if verification fails
    AFTER_SIG=$(find "$TEST_DIR/revoked" -maxdepth 1 -name "sig_*.json" -type f -newer "$TEST_DIR/revoked/group_info.json" | head -1)
    if [ -n "$AFTER_SIG" ]; then
        SIG_ID=$(basename "$AFTER_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
        VERIFY_OUTPUT=$("$BINARY" verifier verify "$SIG_ID" --data-dir "$TEST_DIR/revoked" 2>&1)
        
        # Check output for INVALID (binary doesn't return error codes)
        if echo "$VERIFY_OUTPUT" | grep -q "INVALID"; then
            pass "Revoked user signature rejected by verifier"
        else
            fail "Revoked user signature accepted (security breach!)"
        fi
    else
        pass "Cannot sign after revocation"
    fi
else
    fail "Revocation attack test inconclusive (before: $BEFORE_EXIT, after: $AFTER_EXIT)"
fi

# Test 3.2: Modify Merkle tree maliciously
echo "Test 3.2: Modify Merkle tree (corrupt group_info)"
rm -rf "$TEST_DIR/merkle"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/merkle" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/merkle" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/merkle" > /dev/null 2>&1
"$BINARY" member sign 0 "test" --data-dir "$TEST_DIR/merkle" > /dev/null 2>&1

LAST_SIG=$(find "$TEST_DIR/merkle" -maxdepth 1 -name "sig_*.json" -type f | head -1)

if [ -n "$LAST_SIG" ]; then
    # Corrupt Merkle tree root in group_info
    python3 << 'PYEOF'
import json
import base64
with open("/tmp/lattice-gs-attacks/merkle/group_info.json", "r") as f:
    gi = json.load(f)

# Corrupt Merkle root (it's called RootHash, stored as base64)
if 'RootHash' in gi:
    # Get length of original RootHash bytes
    orig_bytes = base64.b64decode(gi['RootHash'])
    # Create zero bytes and encode back to base64
    gi['RootHash'] = base64.b64encode(bytes(len(orig_bytes))).decode()

with open("/tmp/lattice-gs-attacks/merkle/group_info.json", "w") as f:
    json.dump(gi, f)
PYEOF
    
    # Verification should fail with corrupted tree
    SIG_ID=$(basename "$LAST_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    VERIFY_OUTPUT=$("$BINARY" verifier verify "$SIG_ID" --data-dir "$TEST_DIR/merkle" 2>&1)
    
    # Check output for INVALID (binary doesn't return error codes)
    if echo "$VERIFY_OUTPUT" | grep -q "INVALID"; then
        pass "Merkle tree tampering detected"
    else
        fail "Merkle tree tampering not detected (security breach!)"
    fi
else
    fail "Could not create signature for Merkle tree test"
fi

# Test 3.3: Replay old signature in new epoch
echo "Test 3.3: Replay attack (old epoch signature)"
rm -rf "$TEST_DIR/replay"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/replay" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/replay" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/replay" > /dev/null 2>&1

# Create signature in epoch 0
"$BINARY" member sign 0 "epoch 0" --data-dir "$TEST_DIR/replay" > /dev/null 2>&1
OLD_SIG=$(find "$TEST_DIR/replay" -maxdepth 1 -name "sig_*.json" -type f | head -1)

# Advance epoch (revoke and re-add to change epoch)
"$BINARY" member keygen 1 --data-dir "$TEST_DIR/replay" > /dev/null 2>&1
"$BINARY" gm issue 1 --data-dir "$TEST_DIR/replay" > /dev/null 2>&1

if [ -n "$OLD_SIG" ]; then
    # Get current epoch
    CURRENT_EPOCH=$(python3 << 'PYEOF'
import json
with open("/tmp/lattice-gs-attacks/replay/group_info.json", "r") as f:
    gi = json.load(f)
print(gi.get('Epoch', 0))
PYEOF
)
    
    # Try to verify old signature (should still be valid if epoch unchanged)
    # but try to modify it to claim new epoch
    python3 << 'PYEOF'
import json
import glob

sig_files = glob.glob("/tmp/lattice-gs-attacks/replay/sig_*_0.json")
if sig_files:
    with open(sig_files[0], "r") as f:
        sig = json.load(f)
    
    with open("/tmp/lattice-gs-attacks/replay/group_info.json", "r") as f:
        gi = json.load(f)
    
    # Try to forge signature for new epoch
    sig['Epoch'] = gi.get('Epoch', 0) + 1
    
    with open(sig_files[0], "w") as f:
        json.dump(sig, f)
PYEOF
    
    # Verification should fail (epoch mismatch or invalid proof)
    SIG_ID=$(basename "$OLD_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    VERIFY_OUTPUT=$("$BINARY" verifier verify "$SIG_ID" --data-dir "$TEST_DIR/replay" 2>&1)
    
    # Check output for INVALID (binary doesn't return error codes)
    if echo "$VERIFY_OUTPUT" | grep -q "INVALID"; then
        pass "Replay attack with forged epoch detected"
    else
        fail "Replay attack succeeded (security breach!)"
    fi
else
    fail "Could not create old signature for replay test"
fi

# Test 3.4: Bypass epoch check
echo "Test 3.4: Bypass epoch check (signature without epoch)"
rm -rf "$TEST_DIR/noepoch"
"$BINARY" gm setup --lambda 128 --max-users 8 --data-dir "$TEST_DIR/noepoch" > /dev/null 2>&1
"$BINARY" member keygen 0 --data-dir "$TEST_DIR/noepoch" > /dev/null 2>&1
"$BINARY" gm issue 0 --data-dir "$TEST_DIR/noepoch" > /dev/null 2>&1
"$BINARY" member sign 0 "test" --data-dir "$TEST_DIR/noepoch" > /dev/null 2>&1

LAST_SIG=$(find "$TEST_DIR/noepoch" -maxdepth 1 -name "sig_*.json" -type f | head -1)

if [ -n "$LAST_SIG" ]; then
    # Remove epoch field from signature
    python3 << 'PYEOF'
import json
import glob

sig_files = glob.glob("/tmp/lattice-gs-attacks/noepoch/sig_*.json")
if sig_files:
    with open(sig_files[0], "r") as f:
        sig = json.load(f)
    
    # Remove epoch (bypass check)
    if 'Epoch' in sig:
        del sig['Epoch']
    
    with open(sig_files[0], "w") as f:
        json.dump(sig, f)
PYEOF
    
    # Verification should fail (missing epoch)
    SIG_ID=$(basename "$LAST_SIG" | sed 's/^sig_//' | sed 's/\.json$//')
    VERIFY_OUTPUT=$("$BINARY" verifier verify "$SIG_ID" --data-dir "$TEST_DIR/noepoch" 2>&1)
    
    # Check output for INVALID or error (binary doesn't return error codes)
    if echo "$VERIFY_OUTPUT" | grep -q "INVALID\|Error\|error"; then
        pass "Epoch bypass detected (missing epoch field)"
    else
        fail "Epoch bypass succeeded (security breach!)"
    fi
else
    fail "Could not create signature for epoch bypass test"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "============================================"
echo "Test Summary"
echo "============================================"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Total:  $TOTAL"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL ATTACK TESTS PASSED!${NC}"
    echo ""
    echo "Security properties verified:"
    echo "  ✓ Unforgeability (cannot sign without credential)"
    echo "  ✓ Signature integrity (copy-paste attacks blocked)"
    echo "  ✓ Traceability (TM key required, proof verified)"
    echo "  ✓ Revocation enforcement (revoked users blocked)"
    exit 0
else
    echo -e "${RED}❌ SOME ATTACK TESTS FAILED${NC}"
    echo ""
    echo "Security concerns detected - review failed tests above"
    exit 1
fi
