# Lattice-Based Fully Dynamic Group Signature Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    PUBLIC PARAMETERS (pp)                        │
│  - Security parameter λ                                          │
│  - Modulus q, dimensions m, n                                    │
│  - Public matrices: A, A₀, A₁  (for SIS/LWE)                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │
        ┌─────────────────────┴─────────────────────┐
        │                                           │
        ▼                                           ▼
┌──────────────────┐                      ┌──────────────────┐
│  Group Manager   │                      │ Tracing Manager  │
│      (GM)        │                      │      (TM)        │
├──────────────────┤                      ├──────────────────┤
│ mpk: A·msk       │                      │ tpk: (A₀·tsk,    │
│ msk: secret      │                      │       A₁·tsk)    │
│                  │                      │ tsk: secret      │
│ Manages:         │                      │                  │
│ - Join/Issue     │                      │ Can:             │
│ - Revocations    │                      │ - Trace sigs     │
│ - Group info     │                      │ - Prove tracing  │
└──────────────────┘                      └──────────────────┘
        │                                            │
        │                                            │
        └────────────┬───────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │   GROUP PUBLIC KEY (gpk)   │
        │   = (pp, mpk, tpk)        │
        └────────────────────────────┘
                     │
                     │
        ┏━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
        ┃                                          ┃
        ▼                                          ▼
┌──────────────────┐                        ┌──────────────────┐
│   User 0         │                        │   User i         │
├──────────────────┤                        ├──────────────────┤
│ upk₀: public key │                        │ upkᵢ: public key │
│ usk₀: secret key │                        │ uskᵢ: secret key │
│                  │         ...            │                  │
│ Credentials:     │                        │ Credentials:     │
│ - xᵢ: secret     │                        │ - xᵢ: secret     │
│ - πᵢ = A·xᵢ      │                        │ - πᵢ = A·xᵢ      │
└──────────────────┘                        └──────────────────┘
```

## Updatable Merkle Tree Accumulator

```
                      Root Hash u
                          │
                    ┌─────┴─────┐
                    │           │
              ┌─────┴─────┐     │
              │           │     │
          ┌───┴───┐   ┌───┴───┐ ...
          │       │   │       │
       Leaf₀  Leaf₁ Leaf₂  Leaf₃
         │      │     │      │
         │      │     │      │
      upk₀=0  upk₁  upk₂   upk₃=0
      (inactive)(active)(active)(revoked)

Key Innovation:
- Active user → leaf = user's public key (≠ 0)
- Inactive user → leaf = 0
- Update complexity: O(log N)
```

## Signature Generation Flow

```
User i wants to sign message M:

1. Check Active Status
   ├─→ Get current Merkle root u
   └─→ Verify upkᵢ is accumulated in u

2. Encrypt Identity
   ├─→ c₁ = Enc_tpk₁(uid_i)  (first encryption)
   └─→ c₂ = Enc_tpk₂(uid_i)  (second encryption, for CCA)

3. Generate ZK Proof π proving:
   ├─→ Knowledge of xᵢ where πᵢ = A·xᵢ
   ├─→ upkᵢ ≠ 0  (KEY: proves not revoked!)
   ├─→ Valid Merkle path from upkᵢ to u
   └─→ c₁, c₂ encrypt same uid_i

4. Output Signature
   Σ = (epoch, c₁, c₂, π, M)
```

## Signature Verification Flow

```
Verifier receives Σ = (epoch, c₁, c₂, π, M):

1. Get Group Info
   └─→ Fetch Merkle root u for epoch

2. Verify ZK Proof π:
   ├─→ Check commitment-challenge-response
   ├─→ Verify Merkle path leads to u
   ├─→ Verify public key ≠ 0
   └─→ Verify ciphertext well-formedness

3. Accept if all checks pass
   └─→ Output: VALID or INVALID
```

## Signature Tracing Flow

```
TM receives Σ = (epoch, c₁, c₂, π, M):

1. Decrypt Identity
   ├─→ uid = Dec_tsk(c₁)
   └─→ Verify Dec_tsk(c₂) = uid  (consistency check)

2. Lookup User
   └─→ Find user record for uid in registration table

3. Generate Proof
   └─→ Create proof π_trace of correct decryption

4. Output
   └─→ (uid, π_trace)
```

## Dynamic Operations

### User Joins Group
```
User                    GM
  │                     │
  ├─ (upk, π) ────────→ │
  │                     │
  │                     ├─ Verify credentials
  │                     │
  │                     ├─ Assign UID
  │                     │
  │                     ├─ Update Merkle tree:
  │                     │   tree.SetActive(uid, upk)
  │                     │
  │                     ├─ Update registration table
  │                     │
  │ ←────── (UID) ───── │
  │                     │
  └─ Store (uid, x, π) ─┘
```

### User Revoked
```
GM decides to revoke user i:

1. Update Merkle tree:
   tree.SetInactive(i)
   // Sets leaf_i = 0

2. Increment epoch

3. Publish new root u'

Result:
- User i cannot prove upk_i ≠ 0
- User i cannot generate valid signatures
- Active users unaffected (O(log N) update)
```

## Security Properties

```
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY GUARANTEES                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Anonymity                                                   │
│  └─→ Based on LWE hardness (ciphertext hides identity)     │
│                                                              │
│  Traceability                                               │
│  └─→ TM can always decrypt identity                        │
│                                                              │
│  Non-Frameability                                           │
│  └─→ Users generate own credentials (x, π)                 │
│                                                              │
│  Tracing Soundness                                          │
│  └─→ Signature traces to unique user                       │
│                                                              │
│  Full Dynamicity                                            │
│  └─→ Join/Revoke in O(log N) time                          │
│                                                              │
│  Post-Quantum Security                                      │
│  └─→ Based on SIS and LWE (lattice problems)               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Complexity Summary

```
┌──────────────────┬────────────────┬──────────────────┐
│ Operation        │ Time           │ Space            │
├──────────────────┼────────────────┼──────────────────┤
│ Setup            │ O(m²)          │ O(m²)            │
│ Join             │ O(log N)       │ O(m)             │
│ Revoke           │ O(log N)       │ O(log N)         │
│ Sign             │ O(m² + log N)  │ O(m)             │
│ Verify           │ O(m² + log N)  │ O(log N)         │
│ Trace            │ O(m²)          │ O(m)             │
├──────────────────┼────────────────┼──────────────────┤
│ Signature Size   │ Õ(λ·log N)     │                  │
│ Public Key Size  │ Õ(λ² + λ·log N)│                  │
│ Secret Key Size  │ Õ(λ) + log N   │                  │
└──────────────────┴────────────────┴──────────────────┘

where:
  m = O(λ·log N)
  λ = security parameter
  N = max number of users
  Õ = soft-O notation (hiding log factors)
```

## Comparison with Prior Work

```
┌────────────────┬──────────┬──────────┬────────────┐
│ Scheme         │ Dynamic  │ Trapdoor │ Sig Size   │
│                │ Feature  │ Required │            │
├────────────────┼──────────┼──────────┼────────────┤
│ Gordon+ 2010   │ Static   │ Yes      │ O(λ²·N)    │
│ LLNW 2014      │ VLR only │ Yes      │ Õ(λ·log N) │
│ Libert+ 2016   │ Join only│ Yes      │ Õ(λ·log N) │
│ THIS WORK      │ FULL     │ No       │ Õ(λ·log N) │
└────────────────┴──────────┴──────────┴────────────┘

Key Advantages:
✓ First to achieve FULL dynamicity (join + revoke)
✓ No lattice trapdoors needed
✓ Simple and elegant solution
✓ Smaller signatures than prior static scheme
```

## Key Insight

```
The seemingly large gap between static and fully dynamic
group signatures is reduced to a simple difference:

  Static:  Prove knowledge of accumulated public key
  Dynamic: Prove knowledge of NON-ZERO accumulated public key

This small addition enables:
  - Active users (pk ≠ 0) can sign
  - Revoked users (pk = 0) cannot sign
  - O(log N) updates via Merkle tree

Full dynamicity achieved with ease! 🎉
```
