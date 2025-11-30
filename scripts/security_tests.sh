#!/bin/bash

# Security Tests for Lattice-Based Group Signature
# Tests critical security properties: Unforgeability, Non-frameability, ZK Proof Validation

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0

echo "================================================"
echo "Lattice-Based Group Signature - Security Tests"
echo "Testing Critical Security Properties"
echo "================================================"
echo ""

# Setup test environment
TEST_DIR="/tmp/lattice-gs-security"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

BINARY="/Users/vinhphamhuu/thesis/lattice-gs"
DATA_FLAG="--data-dir=$TEST_DIR"

echo "Test directory: $TEST_DIR"
echo ""

# Initialize system
echo "=== Setup: Initializing System ==="
$BINARY $DATA_FLAG gm setup > /dev/null 2>&1
$BINARY $DATA_FLAG gm keygen > /dev/null 2>&1
$BINARY $DATA_FLAG tm keygen > /dev/null 2>&1
echo "✓ System initialized"
echo ""

# Add legitimate users
$BINARY $DATA_FLAG member keygen 0 > /dev/null 2>&1
$BINARY $DATA_FLAG gm issue 0 > /dev/null 2>&1
$BINARY $DATA_FLAG member keygen 1 > /dev/null 2>&1
$BINARY $DATA_FLAG gm issue 1 > /dev/null 2>&1
echo "✓ Two users (UID=0, UID=1) added to group"
echo ""

# Helper function for test results
check_test() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    
    if [ "$expected" = "$actual" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $test_name"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $test_name"
        echo "  Expected: $expected, Got: $actual"
        ((FAILED++))
    fi
}

echo "================================================"
echo "TEST 1: Unforgeability"
echo "Non-member cannot create valid signature"
echo "================================================"
echo ""

echo "Test 1.1: Non-member (UID=99) tries to sign without credentials"
# Try to sign with non-existent user
$BINARY $DATA_FLAG member sign 99 "forged message" > /tmp/forgery_test.txt 2>&1 || true

if grep -q "Error\|not found\|failed" /tmp/forgery_test.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Non-member correctly rejected"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Non-member was able to sign!"
    ((FAILED++))
fi
echo ""

echo "Test 1.2: Create fake signature with random data"
# Create a fake signature file with random data
cat > "$TEST_DIR/fake_sig.json" << 'EOF'
{
  "epoch": 0,
  "ciphertext": {
    "c1_u": {"size": 10, "data": ["123", "456"]},
    "c1_v": {"size": 10, "data": ["789", "012"]},
    "c2_u": {"size": 10, "data": ["345", "678"]},
    "c2_v": {"size": 10, "data": ["901", "234"]}
  },
  "proof": {
    "commitments": [],
    "challenges": [],
    "responses": [],
    "merkle_path": [],
    "directions": []
  },
  "message": "Zm9yZ2VkIG1lc3NhZ2U="
}
EOF

# Try to verify fake signature
$BINARY $DATA_FLAG verifier verify fake_sig > /tmp/fake_verify.txt 2>&1 || true

if grep -q "INVALID\|Error\|failed" /tmp/fake_verify.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Fake signature correctly rejected"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Fake signature was accepted!"
    ((FAILED++))
fi
echo ""

echo "Test 1.3: Sign without proper credential (modify user key)"
# Create user with invalid credential
mkdir -p "$TEST_DIR/member_99"
cat > "$TEST_DIR/member_99/key.json" << 'EOF'
{
  "uid": 99,
  "x": {"size": 640, "data": ["0", "0", "0"]},
  "upk": {
    "pk": {"size": 128, "data": ["0", "0", "0"]}
  }
}
EOF

$BINARY $DATA_FLAG member sign 99 "test" > /tmp/invalid_cred.txt 2>&1 || true

if grep -q "Error\|not found\|not active" /tmp/invalid_cred.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Invalid credential rejected"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Invalid credential was accepted!"
    ((FAILED++))
fi
echo ""

echo "================================================"
echo "TEST 2: Non-frameability"
echo "GM/TM cannot frame innocent users"
echo "================================================"
echo ""

echo "Test 2.1: User 0 creates signature, TM traces it"
$BINARY $DATA_FLAG member sign 0 "Alice's message" > /dev/null 2>&1
SIG_ID=$(ls -t "$TEST_DIR"/sig_*_0.json | head -1 | sed 's/.*sig_//' | sed 's/.json$//')
$BINARY $DATA_FLAG tm trace "$SIG_ID" > /dev/null 2>&1

echo "Test 2.2: Try to judge with wrong UID (frame User 1)"
$BINARY $DATA_FLAG tm judge "$SIG_ID" 1 > /tmp/frame_test.txt 2>&1 || true

if grep -q "INVALID\|verification failed\|incorrect" /tmp/frame_test.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Cannot frame innocent user (User 1)"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Frame attack succeeded!"
    ((FAILED++))
fi
echo ""

echo "Test 2.3: Verify correct signer (User 0)"
$BINARY $DATA_FLAG tm judge "$SIG_ID" 0 > /tmp/correct_judge.txt 2>&1

if grep -q "VALID.*correct" /tmp/correct_judge.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Correct signer verified (User 0)"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Could not verify correct signer!"
    ((FAILED++))
fi
echo ""

echo "Test 2.4: Modify trace proof (tampering detection)"
TRACE_FILE="$TEST_DIR/trace_${SIG_ID}.json"
if [ -f "$TRACE_FILE" ]; then
    # Backup original
    cp "$TRACE_FILE" "$TRACE_FILE.bak"
    
    # Corrupt the trace proof by modifying UID
    python3 << EOF
import json
with open('$TRACE_FILE', 'r') as f:
    trace = json.load(f)
if 'uid' in trace:
    trace['uid'] = 1  # Change from 0 to 1
elif 'UID' in trace:
    trace['UID'] = 1
with open('$TRACE_FILE', 'w') as f:
    json.dump(trace, f)
EOF
    
    # Try to judge with corrupted proof
    $BINARY $DATA_FLAG tm judge "$SIG_ID" 0 > /tmp/tamper_test.txt 2>&1 || true
    
    # Restore original
    mv "$TRACE_FILE.bak" "$TRACE_FILE"
    
    if grep -q "INVALID\|failed\|incorrect" /tmp/tamper_test.txt; then
        echo -e "${GREEN}✓ PASS${NC}: Tampered trace proof detected"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: Tampered proof was accepted!"
        ((FAILED++))
    fi
else
    echo -e "${YELLOW}⊘ SKIP${NC}: Trace file not found"
fi
echo ""

echo "================================================"
echo "TEST 3: Invalid ZK Proof Rejection"
echo "Malformed proofs must be rejected"
echo "================================================"
echo ""

echo "Test 3.1: Create valid signature from User 1"
$BINARY $DATA_FLAG member sign 1 "Bob's message" > /dev/null 2>&1
SIG_ID_BOB=$(ls -t "$TEST_DIR"/sig_*_1.json | head -1 | sed 's/.*sig_//' | sed 's/.json$//')

echo "Test 3.2: Verify valid signature"
$BINARY $DATA_FLAG verifier verify "$SIG_ID_BOB" > /tmp/valid_sig.txt 2>&1

if grep -q "VALID SIGNATURE" /tmp/valid_sig.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Valid signature accepted"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Valid signature was rejected!"
    ((FAILED++))
fi
echo ""

echo "Test 3.3: Corrupt ZK proof (remove commitments)"
SIG_FILE="$TEST_DIR/sig_${SIG_ID_BOB}.json"
if [ -f "$SIG_FILE" ]; then
    cp "$SIG_FILE" "$SIG_FILE.bak"
    
    # Use Python to properly modify JSON (sed doesn't work well with large JSON)
    python3 << EOF
import json
with open('$SIG_FILE', 'r') as f:
    sig = json.load(f)
sig['Proof']['Commitments'] = []
with open('$SIG_FILE', 'w') as f:
    json.dump(sig, f)
EOF
    
    $BINARY $DATA_FLAG verifier verify "$SIG_ID_BOB" > /tmp/corrupt_proof.txt 2>&1 || true
    
    mv "$SIG_FILE.bak" "$SIG_FILE"
    
    if grep -q "INVALID" /tmp/corrupt_proof.txt; then
        echo -e "${GREEN}✓ PASS${NC}: Corrupted proof rejected"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: Corrupted proof was accepted!"
        ((FAILED++))
    fi
else
    echo -e "${YELLOW}⊘ SKIP${NC}: Signature file not found"
fi
echo ""

echo "Test 3.4: Modify ZK challenges (should fail Fiat-Shamir check)"
if [ -f "$SIG_FILE" ]; then
    cp "$SIG_FILE" "$SIG_FILE.bak"
    
    # Use Python to modify challenge value
    python3 << EOF
import json
with open('$SIG_FILE', 'r') as f:
    sig = json.load(f)
sig['Proof']['Challenges'][0] = 999  # Invalid challenge (not in {1,2,3})
with open('$SIG_FILE', 'w') as f:
    json.dump(sig, f)
EOF
    
    $BINARY $DATA_FLAG verifier verify "$SIG_ID_BOB" > /tmp/bad_challenge.txt 2>&1 || true
    
    mv "$SIG_FILE.bak" "$SIG_FILE"
    
    if grep -q "INVALID" /tmp/bad_challenge.txt; then
        echo -e "${GREEN}✓ PASS${NC}: Modified challenges rejected"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: Modified challenges accepted!"
        ((FAILED++))
    fi
else
    echo -e "${YELLOW}⊘ SKIP${NC}: Signature file not found"
fi
echo ""

echo "Test 3.5: Empty Merkle path (should fail)"
if [ -f "$SIG_FILE" ]; then
    cp "$SIG_FILE" "$SIG_FILE.bak"
    
    # Use Python to empty Merkle path
    python3 << EOF
import json
with open('$SIG_FILE', 'r') as f:
    sig = json.load(f)
sig['Proof']['MerklePath'] = []
with open('$SIG_FILE', 'w') as f:
    json.dump(sig, f)
EOF
    
    $BINARY $DATA_FLAG verifier verify "$SIG_ID_BOB" > /tmp/no_merkle.txt 2>&1 || true
    
    mv "$SIG_FILE.bak" "$SIG_FILE"
    
    if grep -q "INVALID" /tmp/no_merkle.txt; then
        echo -e "${GREEN}✓ PASS${NC}: Empty Merkle path rejected"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: Empty Merkle path accepted!"
        ((FAILED++))
    fi
else
    echo -e "${YELLOW}⊘ SKIP${NC}: Signature file not found"
fi
echo ""

echo "================================================"
echo "TEST 4: Ciphertext Integrity"
echo "Modified ciphertext must be detected"
echo "================================================"
echo ""

echo "Test 4.1: Create signature and trace it"
$BINARY $DATA_FLAG member sign 0 "Message for tampering test" > /dev/null 2>&1
SIG_ID_TAMPER=$(ls -t "$TEST_DIR"/sig_*_0.json | head -1 | sed 's/.*sig_//' | sed 's/.json$//')
$BINARY $DATA_FLAG tm trace "$SIG_ID_TAMPER" > /tmp/trace_before.txt 2>&1

TRACED_UID_BEFORE=$(grep "Signer: User" /tmp/trace_before.txt | awk '{print $3}')
echo "Original traced UID: $TRACED_UID_BEFORE"

echo "Test 4.2: Modify ciphertext and try to trace"
SIG_FILE_TAMPER="$TEST_DIR/sig_${SIG_ID_TAMPER}.json"
if [ -f "$SIG_FILE_TAMPER" ]; then
    cp "$SIG_FILE_TAMPER" "$SIG_FILE_TAMPER.bak"
    
    # Modify ciphertext data
    python3 << EOF
import json
with open('$SIG_FILE_TAMPER', 'r') as f:
    sig = json.load(f)
# Flip some bits in ciphertext
if 'Ciphertext' in sig and 'C1_V' in sig['Ciphertext']:
    if 'Data' in sig['Ciphertext']['C1_V'] and len(sig['Ciphertext']['C1_V']['Data']) > 0:
        # Modify first value (keep as int, not string!)
        sig['Ciphertext']['C1_V']['Data'][0] = sig['Ciphertext']['C1_V']['Data'][0] + 12345
with open('$SIG_FILE_TAMPER', 'w') as f:
    json.dump(sig, f)
EOF
    
    # Re-verify signature
    $BINARY $DATA_FLAG verifier verify "$SIG_ID_TAMPER" > /tmp/tamper_verify.txt 2>&1 || true
    
    mv "$SIG_FILE_TAMPER.bak" "$SIG_FILE_TAMPER"
    
    if grep -q "INVALID" /tmp/tamper_verify.txt; then
        echo -e "${GREEN}✓ PASS${NC}: Modified ciphertext rejected by verifier"
        ((PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: Modified ciphertext was accepted!"
        ((FAILED++))
    fi
else
    echo -e "${YELLOW}⊘ SKIP${NC}: Signature file not found"
fi
echo ""

echo "Test 4.3: Verify ciphertext consistency (re-verify original)"
$BINARY $DATA_FLAG verifier verify "$SIG_ID_TAMPER" > /tmp/recheck.txt 2>&1

if grep -q "VALID SIGNATURE" /tmp/recheck.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Original signature still valid"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Original signature became invalid!"
    ((FAILED++))
fi
echo ""

echo "================================================"
echo "TEST 5: Revoked User Protection"
echo "Revoked users cannot sign (zero public key)"
echo "================================================"
echo ""

echo "Test 5.1: User 0 signs before revocation"
$BINARY $DATA_FLAG member sign 0 "Before revocation" > /dev/null 2>&1
SIG_BEFORE=$(ls -t "$TEST_DIR"/sig_*_0.json | head -1 | sed 's/.*sig_//' | sed 's/.json$//')

$BINARY $DATA_FLAG verifier verify "$SIG_BEFORE" > /tmp/before_revoke.txt 2>&1

if grep -q "VALID SIGNATURE" /tmp/before_revoke.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Signature valid before revocation"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Signature invalid before revocation!"
    ((FAILED++))
fi
echo ""

echo "Test 5.2: Revoke User 0"
$BINARY $DATA_FLAG gm update --revoke 0 > /dev/null 2>&1
echo "✓ User 0 revoked (public key set to 0)"
echo ""

echo "Test 5.3: Revoked User 0 attempts to sign"
$BINARY $DATA_FLAG member sign 0 "After revocation" > /tmp/revoked_sign.txt 2>&1 || true

if grep -q "Error\|not active\|revoked" /tmp/revoked_sign.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Revoked user correctly blocked from signing"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Revoked user was able to sign!"
    cat /tmp/revoked_sign.txt
    ((FAILED++))
fi
echo ""

echo "Test 5.4: Active User 1 can still sign"
$BINARY $DATA_FLAG member sign 1 "Still active" > /dev/null 2>&1
SIG_ACTIVE=$(ls -t "$TEST_DIR"/sig_*_1.json | head -1 | sed 's/.*sig_//' | sed 's/.json$//')

$BINARY $DATA_FLAG verifier verify "$SIG_ACTIVE" > /tmp/active_verify.txt 2>&1

if grep -q "VALID SIGNATURE" /tmp/active_verify.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Active user (User 1) unaffected by User 0's revocation"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Active user affected by other's revocation!"
    ((FAILED++))
fi
echo ""

echo "Test 5.5: Old signature from User 0 still valid"
$BINARY $DATA_FLAG verifier verify "$SIG_BEFORE" > /tmp/old_sig_check.txt 2>&1

if grep -q "VALID SIGNATURE" /tmp/old_sig_check.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Old signature from revoked user still valid"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Old signature became invalid after revocation!"
    ((FAILED++))
fi
echo ""

echo "Test 5.6: Cannot create signature with pi = 0 (zero public key)"
# Try to manually create user with zero public key
mkdir -p "$TEST_DIR/member_88"
cat > "$TEST_DIR/member_88/key.json" << 'EOF'
{
  "uid": 88,
  "x": {"size": 640, "data": ["1", "2", "3"]},
  "upk": {
    "pk": {"size": 128, "data": ["0", "0", "0", "0"]}
  }
}
EOF

$BINARY $DATA_FLAG gm issue 88 > /dev/null 2>&1 || true
$BINARY $DATA_FLAG member sign 88 "Zero key test" > /tmp/zero_key.txt 2>&1 || true

if grep -q "Error\|zero\|cannot" /tmp/zero_key.txt; then
    echo -e "${GREEN}✓ PASS${NC}: Zero public key correctly rejected"
    ((PASSED++))
else
    echo -e "${RED}✗ FAIL${NC}: Zero public key was accepted!"
    ((FAILED++))
fi
echo ""

# Summary
echo "================================================"
echo "Security Test Summary"
echo "================================================"
echo ""
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"
echo "Total:  $((PASSED + FAILED))"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ ALL SECURITY TESTS PASSED!${NC}"
    echo ""
    echo "Security Properties Verified:"
    echo "  ✓ Unforgeability: Non-members cannot forge signatures"
    echo "  ✓ Non-frameability: Cannot frame innocent users"
    echo "  ✓ ZK Proof Integrity: Invalid proofs rejected"
    echo "  ✓ Ciphertext Integrity: Tampering detected"
    echo "  ✓ Revocation Security: Revoked users blocked"
    echo ""
    exit 0
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo "Review failed tests above"
    echo ""
    exit 1
fi
