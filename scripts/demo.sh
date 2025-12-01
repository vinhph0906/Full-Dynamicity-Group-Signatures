#!/bin/bash

# Lattice-Based Group Signature System - Complete Demo
# This script demonstrates all key features of the system

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
LAMBDA=32
MAX_USERS=8

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Lattice-Based Group Signature System - Demo              ║${NC}"
echo -e "${BLUE}║  Security Parameter: λ=${LAMBDA}, Max Users: ${MAX_USERS}                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: Initialize System
echo -e "${YELLOW}[Step 1] Initialize Group Signature System${NC}"
echo "----------------------------------------"
./lattice-gs gm setup --lambda ${LAMBDA} --max-users ${MAX_USERS} --force
echo ""
sleep 1

# Step 2: Generate Keys for Members
echo -e "${YELLOW}[Step 2] Generate Keys for 3 Members${NC}"
echo "----------------------------------------"
for uid in 0 1 2; do
    echo -e "${GREEN}Generating keys for User ${uid}...${NC}"
    ./lattice-gs member keygen ${uid}
    echo ""
    sleep 0.5
done

# Step 3: GM Issues Certificates
echo -e "${YELLOW}[Step 3] GM Issues Certificates${NC}"
echo "----------------------------------------"
for uid in 0 1 2; do
    echo -e "${GREEN}Issuing certificate to User ${uid}...${NC}"
    ./lattice-gs gm issue ${uid}
    echo ""
    sleep 0.5
done

# Step 4: View Group Membership
echo -e "${YELLOW}[Step 4] View Current Group Membership${NC}"
echo "----------------------------------------"
./lattice-gs gm list --format compact
echo ""
sleep 1

# Step 5: Members Create Signatures
echo -e "${YELLOW}[Step 5] Members Create Anonymous Signatures${NC}"
echo "----------------------------------------"
echo -e "${GREEN}User 0 signs: 'Hello from User 0'${NC}"
SIG_0=$(./lattice-gs member sign 0 "Hello from User 0" | grep "Signature ID:" | awk '{print $3}')
echo ""
sleep 0.5

echo -e "${GREEN}User 1 signs: 'Confidential message'${NC}"
SIG_1=$(./lattice-gs member sign 1 "Confidential message" | grep "Signature ID:" | awk '{print $3}')
echo ""
sleep 0.5

echo -e "${GREEN}User 2 signs: 'Anonymous report'${NC}"
SIG_2=$(./lattice-gs member sign 2 "Anonymous report" | grep "Signature ID:" | awk '{print $3}')
echo ""
sleep 1

# Step 6: Verify Signatures
echo -e "${YELLOW}[Step 6] Public Verification (No Secret Keys Needed)${NC}"
echo "----------------------------------------"
echo -e "${GREEN}Verifying signature: ${SIG_0}${NC}"
./lattice-gs verifier verify ${SIG_0}
echo ""
sleep 0.5

echo -e "${GREEN}Verifying signature: ${SIG_1}${NC}"
./lattice-gs verifier verify ${SIG_1}
echo ""
sleep 1

# Step 7: Trace Signatures
echo -e "${YELLOW}[Step 7] Tracing Manager Identifies Signers${NC}"
echo "----------------------------------------"
echo -e "${GREEN}Tracing signature: ${SIG_1}${NC}"
./lattice-gs tm trace ${SIG_1}
echo ""
sleep 0.5

echo -e "${GREEN}Tracing signature: ${SIG_2}${NC}"
./lattice-gs tm trace ${SIG_2}
echo ""
sleep 1

# Step 8: Verify Tracing Proof
echo -e "${YELLOW}[Step 8] Judge Protocol - Verify TM's Tracing Proof${NC}"
echo "----------------------------------------"
echo -e "${GREEN}Judging trace proof: ${SIG_1} -> User 1${NC}"
./lattice-gs tm judge ${SIG_1} 1
echo ""
sleep 1

# Step 9: Revoke a Member
echo -e "${YELLOW}[Step 9] GM Revokes User 1${NC}"
echo "----------------------------------------"
./lattice-gs gm update --revoke 1 --confirm=false
echo ""
sleep 0.5

echo -e "${GREEN}Updated group membership:${NC}"
./lattice-gs gm list --format compact
echo ""
sleep 1

# Step 10: Revoked Member Cannot Sign
echo -e "${YELLOW}[Step 10] Verify Revoked Member Cannot Sign${NC}"
echo "----------------------------------------"
echo -e "${GREEN}User 1 attempts to sign after revocation:${NC}"
if ./lattice-gs member sign 1 "Trying to sign after revocation" 2>&1; then
    echo -e "${RED}ERROR: Revoked user was able to sign!${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Correctly rejected - User 1 cannot sign${NC}"
fi
echo ""
sleep 1

# Step 11: Active Members Continue Signing
echo -e "${YELLOW}[Step 11] Active Members Can Still Sign${NC}"
echo "----------------------------------------"
echo -e "${GREEN}User 0 signs after revocation:${NC}"
SIG_AFTER=$(./lattice-gs member sign 0 "Still active and anonymous" | grep "Signature ID:" | awk '{print $3}')
echo ""
sleep 0.5

echo -e "${GREEN}Verifying new signature: ${SIG_AFTER}${NC}"
./lattice-gs verifier verify ${SIG_AFTER}
echo ""
sleep 1

# Summary
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    DEMO COMPLETE ✓                         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Summary:${NC}"
echo "  - Initialized system with λ=${LAMBDA}, max users=${MAX_USERS}"
echo "  - Generated keys for 3 members (Users 0, 1, 2)"
echo "  - GM issued certificates to all 3 members"
echo "  - Members created anonymous signatures"
echo "  - Anyone verified signatures (no secret keys needed)"
echo "  - TM traced identities when needed"
echo "  - Anyone verified TM's tracing proofs (non-frameability)"
echo "  - GM revoked User 1"
echo "  - Revoked member cannot sign anymore"
echo "  - Active members continue signing normally"
echo ""
echo -e "${GREEN}Key Features Demonstrated:${NC}"
echo "  ✓ Anonymity: Signatures don't reveal signer identity"
echo "  ✓ Traceability: TM can identify signers when needed"
echo "  ✓ Non-frameability: TM must prove tracing correctness"
echo "  ✓ Public verifiability: Anyone can verify signatures and traces"
echo "  ✓ Dynamic membership: Members can be revoked"
echo "  ✓ Forward security: Revoked members cannot create new signatures"
echo ""
echo -e "${BLUE}All signatures stored in: ~/.lattice-gs/${NC}"
