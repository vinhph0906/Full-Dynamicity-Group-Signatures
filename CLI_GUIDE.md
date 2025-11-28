# Lattice-Based Group Signature CLI

Complete command-line interface implementation strictly following the paper:
**"Lattice-Based Group Signatures: Achieving Full Dynamicity with Ease"** (ACNS 2017)

## Overview

This CLI provides four roles matching the paper's architecture:
- **Group Manager (GM)**: Manages group membership
- **Tracing Manager (TM)**: Traces signatures to signers  
- **Member**: Creates anonymous signatures
- **Verifier**: Verifies signatures (public)

## Installation

```bash
# Build the CLI
go build -o lattice-gs .

# Install (optional)
go install
```

## Quick Start

```bash
# 1. Initialize system (GM)
./lattice-gs gm setup

# 2. Generate user keys (Member)
./lattice-gs member keygen 0

# 3. Issue certificate (GM)
./lattice-gs gm issue 0

# 4. Create signature (Member)
./lattice-gs member sign 0 "Hello World"

# 5. Verify signature (Anyone)
./lattice-gs verifier verify <signature-id>

# 6. Trace signature (TM)
./lattice-gs tm trace <signature-id>
```

## Commands Reference

### Global Flags

```bash
--data-dir string   # Data directory (default: ~/.lattice-gs)
```

## Group Manager Commands

### `gm setup`

**Paper Algorithm**: GSetup (Section 4.1)

Initializes the group signature system. Generates:
- Public parameters `pp` (matrices A, A0, A1)
- GM key pair `(mpk, msk)` via GKgenGM
- TM key pair `(tpk, tsk)` via GKgenTM
- Initial group info with Merkle tree
- Registration table

```bash
./lattice-gs gm setup [flags]

Flags:
  --lambda int      Security parameter (default: 128)
  --max-users int   Maximum users N (default: 16)
```

**Example:**
```bash
./lattice-gs gm setup --lambda=128 --max-users=32
```

**Output:**
- Saves `public_params.json`
- Saves `gm_keys.json` (mpk, msk)
- Saves `tm_keys.json` (tpk, tsk)
- Initializes `group_info.json` at epoch 0
- Creates `registry.json`

---

### `gm issue [uid]`

**Paper Algorithm**: Issue (Section 4.1, Interactive Protocol)

Issues a certificate to a user, adding them to the group. The user must have already generated keys and credentials via `member keygen`.

```bash
./lattice-gs gm issue [uid]
```

**Paper Details:**
1. GM receives user's `(upk, pi)` where `pi = A * x`
2. GM updates Merkle tree: `leaf[uid] = upk`
3. GM adds record to registration table
4. GM marks user as active
5. Updates Merkle root

**Example:**
```bash
./lattice-gs gm issue 0
./lattice-gs gm issue 1
```

---

### `gm update`

**Paper Algorithm**: GUpdate (Section 4.1 - Core of Full Dynamicity!)

Revokes users from the group by setting their Merkle tree leaves to 0. This is the **key innovation** for achieving full dynamicity.

```bash
./lattice-gs gm update --revoke=uid1,uid2,...
```

**Paper Details:**
1. For each revoked UID: `leaf[uid] = 0`
2. Update Merkle tree (O(log N) per user)
3. Increment epoch
4. Update root hash
5. Revoked users can no longer prove `pi ≠ 0`

**Example:**
```bash
./lattice-gs gm update --revoke=1,3,5
```

---

### `gm list`

Lists current group members and state.

```bash
./lattice-gs gm list
```

---

## Tracing Manager Commands

### `tm trace [signature-id]`

**Paper Algorithm**: Trace (Section 4.1)

Traces a signature to identify the signer by decrypting the ciphertext.

```bash
./lattice-gs tm trace [signature-id]
```

**Paper Details:**
1. Load signature with ciphertext `(c1, c2)`
2. Decrypt: `uid = c1 - A0 * tsk`
3. Look up UID in registration table
4. Generate proof `Π_trace` of correct decryption
5. Output `(uid, Π_trace)`

**Example:**
```bash
./lattice-gs tm trace 1729512000_0
```

---

### `tm judge [signature-id] [uid]`

**Paper Algorithm**: Judge (Section 4.1)

Verifies a tracing proof to ensure tracing soundness.

```bash
./lattice-gs tm judge [signature-id] [uid]
```

**Paper Details:**
1. Load trace proof `Π_trace`
2. Verify proof is consistent with ciphertext
3. Confirm claimed UID matches decryption
4. Output valid/invalid

**Example:**
```bash
./lattice-gs tm judge 1729512000_0 0
```

---

### `tm info`

Shows TM public key and capabilities.

```bash
./lattice-gs tm info
```

---

## Member Commands

### `member keygen [uid]`

**Paper Algorithm**: UKgen + Join (Section 4.1)

Generates user's key pair and credentials for joining the group.

```bash
./lattice-gs member keygen [uid]
```

**Paper Details:**
1. **UKgen**: Generate `(upk, usk)` where:
   - `usk` is a binary vector
   - `upk = Hash(usk)`
2. **Join** (user's part):
   - Generate secret credential `x` (small vector)
   - Compute public credential `pi = A * x`
   - Store `(uid, usk, upk, x, pi)`

**Example:**
```bash
./lattice-gs member keygen 0
./lattice-gs member keygen 1
```

---

### `member sign [uid] [message]`

**Paper Algorithm**: Sign (Section 4.1 - Core Signature Algorithm)

Creates an anonymous group signature with zero-knowledge proof.

```bash
./lattice-gs member sign [uid] [message]
```

**Paper Details:**
1. Check user is active at current epoch
2. **Encrypt identity**: Use Naor-Yung double encryption
   - `c1 = A0 * r1 + Encode(uid)`
   - `c2 = A1 * r2 + Encode(uid)`
3. **Get Merkle path**: Authentication path from `upk` to root
4. **Generate ZK proof** (Stern-like protocol):
   - Prove knowledge of `x` where `pi = A * x`
   - Prove `upk ≠ 0` (KEY for full dynamicity!)
   - Prove valid Merkle path
   - Prove well-formed ciphertext
5. Output signature `Σ = (epoch, ciphertext, proof)`

**Example:**
```bash
./lattice-gs member sign 0 "Hello World"
./lattice-gs member sign 1 "Anonymous message"
```

**Output:**
- Saves signature to `sig_<timestamp>_<uid>.json`
- Returns signature ID for verification

---

### `member info [uid]`

Shows member's key status and group membership.

```bash
./lattice-gs member info [uid]
```

---

## Verifier Commands

### `verifier verify [signature-id]`

**Paper Algorithm**: Verify (Section 4.1)

Verifies a group signature. Anyone can run this - no secrets needed!

```bash
./lattice-gs verifier verify [signature-id]
```

**Paper Details:**
1. Check signature epoch matches group state
2. **Verify ZK proof**:
   - Recompute Fiat-Shamir challenges
   - Check Stern protocol responses
   - Verify each round: `A * response = commitment + challenge * public_value`
3. **Verify Merkle path**: Check path leads to current root
4. Check ciphertext well-formedness
5. Output valid/invalid

**Example:**
```bash
./lattice-gs verifier verify 1729512000_0
```

---

### `verifier info`

Shows public system information.

```bash
./lattice-gs verifier info
```

---

## Complete Workflow Example

Following the paper's protocol flow:

```bash
# === SETUP PHASE (Section 4.1: GSetup) ===

# 1. GM initializes system
./lattice-gs gm setup --lambda=128 --max-users=16

# === ENROLLMENT PHASE (Section 4.1: Join/Issue) ===

# 2. User 0 generates keys (UKgen + Join)
./lattice-gs member keygen 0

# 3. User 1 generates keys
./lattice-gs member keygen 1

# 4. User 2 generates keys
./lattice-gs member keygen 2

# 5. GM issues certificates (Issue protocol)
./lattice-gs gm issue 0
./lattice-gs gm issue 1
./lattice-gs gm issue 2

# 6. Check group membership
./lattice-gs gm list

# === SIGNING PHASE (Section 4.1: Sign) ===

# 7. Users create anonymous signatures
./lattice-gs member sign 0 "Message from User 0"
./lattice-gs member sign 1 "Message from User 1"

# Get signature IDs (example)
SIG0="1729512000_0"
SIG1="1729512001_1"

# === VERIFICATION PHASE (Section 4.1: Verify) ===

# 8. Anyone can verify signatures
./lattice-gs verifier verify $SIG0
./lattice-gs verifier verify $SIG1

# === TRACING PHASE (Section 4.1: Trace/Judge) ===

# 9. TM traces signatures to signers
./lattice-gs tm trace $SIG0
./lattice-gs tm trace $SIG1

# 10. Anyone can judge trace proofs
./lattice-gs tm judge $SIG0 0
./lattice-gs tm judge $SIG1 1

# === REVOCATION PHASE (Section 4.1: GUpdate - FULL DYNAMICITY!) ===

# 11. GM revokes User 1
./lattice-gs gm update --revoke=1

# 12. Verify revocation
./lattice-gs gm list

# 13. Revoked user cannot sign
./lattice-gs member sign 1 "Should fail" # FAILS

# 14. Active users can still sign
./lattice-gs member sign 0 "Still works" # SUCCEEDS
```

---

## Data Storage

All data is stored in JSON format in the data directory (default: `~/.lattice-gs`):

```
~/.lattice-gs/
├── public_params.json      # Public parameters (pp)
├── gm_keys.json            # GM keys (mpk, msk)
├── tm_keys.json            # TM keys (tpk, tsk)
├── group_info.json         # Group state (epoch, Merkle tree)
├── registry.json           # Registration table
├── user_0_keys.json        # User 0 keys (gsk)
├── user_1_keys.json        # User 1 keys
├── sig_<id>.json           # Signatures
└── trace_<id>.json         # Trace proofs
```

---

## Security Properties

As proven in the paper (Section 4.2):

### ✅ Correctness
Honest signatures from active users always verify and trace correctly.

### ✅ Anonymity
Signatures reveal no information about the signer (under LWE assumption).

### ✅ Traceability
TM can always identify the signer (soundness of ZK proof).

### ✅ Non-Frameability
Cannot forge signatures on behalf of honest users (binding of commitment).

### ✅ Tracing Soundness
Signatures trace to unique users (soundness of decryption proof).

### ✅ Full Dynamicity
- Users join via Join/Issue (O(log N))
- Users revoked via GUpdate (O(log N))
- No re-initialization needed!

---

## Implementation Notes

### Strictly Following the Paper

This implementation directly maps to the paper's algorithms:

| Paper Algorithm | CLI Command | Section |
|----------------|-------------|---------|
| GSetup | `gm setup` | 4.1 |
| GKgenGM | `gm setup` | 4.1 |
| GKgenTM | `gm setup` | 4.1 |
| UKgen | `member keygen` | 4.1 |
| Join | `member keygen` | 4.1 |
| Issue | `gm issue` | 4.1 |
| GUpdate | `gm update` | 4.1 |
| Sign | `member sign` | 4.1 |
| Verify | `verifier verify` | 4.1 |
| Trace | `tm trace` | 4.1 |
| Judge | `tm judge` | 4.1 |

### Key Innovation: Updatable Merkle Tree

From Section 3 of the paper:
- Inactive user: `leaf[uid] = 0`
- Active user: `leaf[uid] = upk`
- Update cost: O(log N)
- Signing requires proving `upk ≠ 0` in ZK

---

## Testing

Run the automated test workflow:

```bash
./test_workflow.sh
```

This demonstrates all algorithms from the paper in sequence.

---

## Complexity

As stated in the paper (Table 1):

| Operation | Complexity |
|-----------|------------|
| Signature size | Õ(λ·log N) |
| Group PK size | Õ(λ² + λ·log N) |
| User SK size | Õ(λ) + log N |
| Sign | O(m² + log N) |
| Verify | O(m² + log N) |
| Join/Revoke | O(log N) |

Where m = O(λ·log N) and N = maximum users.

---

## References

This implementation strictly follows:

**Ling, S., Nguyen, K., Wang, H., Xu, Y.**: "Lattice-Based Group Signatures: Achieving Full Dynamicity with Ease", _ACNS 2017_, pp. 293-312.

DOI: [10.1007/978-3-319-61204-1_15](https://doi.org/10.1007/978-3-319-61204-1_15)
