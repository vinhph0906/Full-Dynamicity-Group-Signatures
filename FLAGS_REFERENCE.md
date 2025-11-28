# Command Flags Reference

This document provides a comprehensive reference of all command-line flags available in the lattice-gs CLI, organized by role and subcommand.

## Global Flags

Available for all commands:

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--data-dir` | string | `~/.lattice-gs` | Data directory for keys and state |
| `--quiet` | bool | `false` | Suppress non-essential output |
| `--debug` | bool | `false` | Enable debug logging for troubleshooting |
| `--log-file` | string | - | Write logs to file instead of stdout |

## Group Manager (gm) Commands

### gm setup

Initialize the group signature system.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--lambda` | int | `128` | Security parameter λ (bits) - affects lattice dimensions and proof size |
| `--max-users` | int | `16` | Maximum number of users N (must be power of 2) - determines Merkle tree height |
| `--force` | bool | `false` | Force reinitialize even if system already exists (WARNING: destroys data!) |

**Examples:**
```bash
lattice-gs gm setup --lambda=128 --max-users=32
lattice-gs gm setup --force
```

### gm issue <uid>

Issue a certificate to a user, adding them to the group.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--auto-approve` | bool | `true` | Automatically approve join request without manual confirmation |
| `--verbose` | bool | `false` | Show detailed issue protocol steps |

**Examples:**
```bash
lattice-gs gm issue 5
lattice-gs gm issue 5 --verbose
```

### gm update

Update group state by revoking users.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--revoke` | int[] | - | **REQUIRED** User IDs to revoke (comma-separated, e.g., `--revoke=1,3,5`) |
| `--confirm` | bool | `true` | Require confirmation before revoking users |
| `--verbose` | bool | `false` | Show detailed update protocol steps |

**Examples:**
```bash
lattice-gs gm update --revoke=3,5,7
lattice-gs gm update --revoke=1 --verbose --confirm=false
```

### gm list

List all group members and their status.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--show-revoked` | bool | `true` | Include revoked members in the list |
| `--show-keys` | bool | `false` | Display public key information for each member |
| `--format` | string | `table` | Output format: `table`, `json`, or `csv` |

**Examples:**
```bash
lattice-gs gm list
lattice-gs gm list --show-keys --format=json
```

---

## Member Commands

### member keygen <uid>

Generate user keys and credentials.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--force` | bool | `false` | Force regenerate keys even if they already exist |
| `--verbose` | bool | `false` | Show detailed key generation steps |
| `--output` | string | - | Custom output path for member keys (default: `data-dir/user_<uid>.json`) |

**Examples:**
```bash
lattice-gs member keygen 5
lattice-gs member keygen 5 --force --verbose
lattice-gs member keygen 5 --output=/tmp/user5.json
```

### member sign <uid> <message>

Create an anonymous group signature.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--verbose` | bool | `false` | Show detailed signing protocol steps |
| `--message-file` | string | - | Read message from file instead of command line argument |
| `--sig-output` | string | - | Custom signature ID or output filename |
| `--save-proof-details` | bool | `false` | Save detailed zero-knowledge proof information |

**Examples:**
```bash
lattice-gs member sign 5 "Hello, world!"
lattice-gs member sign 5 "Transaction data" --verbose
lattice-gs member sign 5 --message-file=msg.txt --sig-output=sig_001
```

### member info <uid>

Display member status and credential information.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--show-credentials` | bool | `false` | Display credential information (upk, pi hash) |
| `--show-history` | bool | `false` | Show signing history for this member |
| `--format` | string | `text` | Output format: `text` or `json` |

**Examples:**
```bash
lattice-gs member info 5
lattice-gs member info 5 --show-credentials --format=json
```

---

## Tracing Manager (tm) Commands

### tm trace <signature-id>

Trace a signature to identify the signer.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--verbose` | bool | `false` | Show detailed tracing protocol steps |
| `--proof-output` | string | - | Custom output path for trace proof (default: `data-dir/trace_<sig-id>.json`) |
| `--verify-before-trace` | bool | `true` | Verify signature validity before attempting to trace |
| `--save-decryption-log` | bool | `false` | Save decryption intermediate steps for audit |

**Examples:**
```bash
lattice-gs tm trace sig_12345
lattice-gs tm trace sig_12345 --verbose
lattice-gs tm trace sig_12345 --proof-output=/tmp/trace.json
```

### tm judge <signature-id> <uid>

Verify a tracing proof for correctness.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--verbose` | bool | `false` | Show detailed judge verification steps |
| `--proof-file` | string | - | Custom path to trace proof file (default: `data-dir/trace_<sig-id>.json`) |
| `--strict` | bool | `true` | Use strict verification mode |

**Examples:**
```bash
lattice-gs tm judge sig_12345 5
lattice-gs tm judge sig_12345 5 --verbose
lattice-gs tm judge sig_12345 5 --proof-file=/tmp/trace.json
```

### tm info

Display Tracing Manager information and capabilities.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--show-stats` | bool | `false` | Display tracing statistics and history |
| `--format` | string | `text` | Output format: `text` or `json` |

**Examples:**
```bash
lattice-gs tm info
lattice-gs tm info --show-stats --format=json
```

---

## Verifier Commands

### verifier verify <signature-id>

Verify a group signature's validity.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--verbose` | bool | `false` | Show detailed verification steps and proof checks |
| `--show-proof` | bool | `false` | Display zero-knowledge proof components |
| `--check-epoch` | bool | `true` | Verify signature epoch matches current group state |
| `--benchmark` | bool | `false` | Measure and report verification time |
| `--sig-file` | string | - | Custom path to signature file (default: `data-dir/sig_<sig-id>.json`) |

**Examples:**
```bash
lattice-gs verifier verify sig_12345
lattice-gs verifier verify sig_12345 --verbose --show-proof
lattice-gs verifier verify sig_12345 --benchmark
```

### verifier info

Display public system information and parameters.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--show-params` | bool | `true` | Display public parameters and cryptographic settings |
| `--show-members` | bool | `true` | Display group membership information |
| `--show-complexity` | bool | `true` | Show complexity analysis and performance metrics |
| `--format` | string | `text` | Output format: `text` or `json` |

**Examples:**
```bash
lattice-gs verifier info
lattice-gs verifier info --format=json
lattice-gs verifier info --show-params=false
```

---

## Flag Naming Conventions

Flags follow these conventions for consistency:

### Boolean Flags
- **Action flags**: Use verbs (e.g., `--force`, `--confirm`, `--benchmark`)
- **Display flags**: Use `--show-*` prefix (e.g., `--show-proof`, `--show-keys`)
- **Toggle flags**: Use `--enable-*` or state (e.g., `--verbose`, `--strict`)

### String/Path Flags
- **Output paths**: Use `*-output` or `*-file` suffix (e.g., `--sig-output`, `--proof-file`)
- **Input paths**: Use `*-file` suffix (e.g., `--message-file`)
- **Format**: Always `--format` for output format selection

### Numeric Flags
- **Parameters**: Use descriptive names (e.g., `--lambda`, `--max-users`)
- **Lists**: Use `--revoke`, `--uids` for comma-separated values

### Consistency
- All flags use kebab-case (e.g., `--show-proof`, not `--showProof`)
- Boolean flags default to `false` unless there's a strong reason otherwise
- Common flags (`--verbose`, `--format`) behave consistently across commands
- Role-specific flags are prefixed or suffixed appropriately

## Quick Reference by Use Case

### System Setup
```bash
# Initialize system
lattice-gs gm setup --lambda=128 --max-users=32

# Check system info
lattice-gs verifier info
```

### Member Operations
```bash
# Generate keys
lattice-gs member keygen 5 --verbose

# Check status
lattice-gs member info 5

# Sign message
lattice-gs member sign 5 "Hello" --verbose
```

### Group Management
```bash
# Add member
lattice-gs gm issue 5

# List members
lattice-gs gm list --show-keys

# Revoke members
lattice-gs gm update --revoke=3,5,7
```

### Verification & Tracing
```bash
# Verify signature
lattice-gs verifier verify sig_12345 --verbose

# Trace signature
lattice-gs tm trace sig_12345 --verbose

# Verify tracing
lattice-gs tm judge sig_12345 5
```
