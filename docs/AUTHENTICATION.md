# Authentication Testing

This module provides tools for testing 3G/4G/5G authentication using Milenage and TUAK algorithms.

## Overview

The authentication module allows you to:
- Compute authentication vectors (RAND, AUTN, XRES, CK, IK, AK)
- Send authentication challenges to SIM cards
- Process synchronization failures (AUTS)
- Compute derived keys (KASME for LTE, 2G triplets)
- Work with pre-captured authentication data from dumps

## Supported Algorithms

| Algorithm | Standard | Key Size | Description |
|-----------|----------|----------|-------------|
| Milenage | 3GPP TS 35.206 | 128-bit | AES-based, most common |
| TUAK | 3GPP TS 35.231 | 128/256-bit | Keccak-based, newer |

## Basic Usage

### Compute Authentication Vector (without card)

```bash
# Using OPc (pre-computed)
./sim_reader -auth \
  -auth-k F2464E3293019A7E51ABAA7B1262B7D8 \
  -auth-opc B10B351A0CCD8BE31E0C9F088945A812 \
  -auth-sqn 000000000001 \
  -auth-mcc 250 -auth-mnc 88 \
  -auth-no-card

# Using OP (will compute OPc automatically)
./sim_reader -auth \
  -auth-k F2464E3293019A7E51ABAA7B1262B7D8 \
  -auth-op CDC202D5123E20F62B6D676AC72CB318 \
  -auth-sqn 000000000001 \
  -auth-no-card
```

### Test Authentication with SIM Card

```bash
# Send authentication challenge to card
./sim_reader -auth \
  -auth-k F2464E3293019A7E51ABAA7B1262B7D8 \
  -auth-opc B10B351A0CCD8BE31E0C9F088945A812 \
  -auth-sqn 000000000001 \
  -auth-mcc 250 -auth-mnc 88
```

### Card-Only Mode (No K required)

When you have RAND and AUTN from a network capture or dump, you can send them directly to the card without knowing K:

```bash
./sim_reader -auth \
  -auth-rand 3A8F7BE7E6DA0B3149B0386F5466C96A \
  -auth-autn 47757E6B3DCD8000510F1A2B54119237
```

This mode:
- Sends RAND+AUTN to the SIM card
- Returns RES, CK, IK (on success) or AUTS (on sync failure)
- Does not compute XRES or other values (K is unknown)

### Process AUTS for SQN Resynchronization

When you receive AUTS from a sync failure (either from card or from a dump):

```bash
./sim_reader -auth \
  -auth-k F2464E3293019A7E51ABAA7B1262B7D8 \
  -auth-opc B10B351A0CCD8BE31E0C9F088945A812 \
  -auth-rand 7D6AF2DF993240BA9B191B68F1750C43 \
  -auth-auts AABBCCDDEEFF0011223344556677 \
  -auth-no-card
```

This extracts SQNms (the SIM card's current SQN) and suggests the next SQN to use.

## Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-auth` | Enable authentication mode | |
| `-auth-k` | Subscriber key K (32/64 hex chars) | `F2464E3293019A7E51ABAA7B1262B7D8` |
| `-auth-op` | Operator key OP (computes OPc) | `CDC202D5123E20F62B6D676AC72CB318` |
| `-auth-opc` | Pre-computed OPc | `B10B351A0CCD8BE31E0C9F088945A812` |
| `-auth-sqn` | Sequence number (12 hex chars) | `000000000001` |
| `-auth-amf` | Auth Management Field (4 hex chars) | `8000` |
| `-auth-rand` | Random challenge (32 hex chars) | Auto-generated if empty |
| `-auth-autn` | Pre-computed AUTN (32 hex chars) | Skip calculation |
| `-auth-auts` | AUTS for SQN resync (28/44/76 hex) | From sync failure |
| `-auth-algo` | Algorithm: `milenage` or `tuak` | Default: `milenage` |
| `-auth-mcc` | Mobile Country Code | `250` |
| `-auth-mnc` | Mobile Network Code | `88` |
| `-auth-no-card` | Compute without sending to card | |

## Output Fields

### Authentication Vector (Network Side)

| Field | Description |
|-------|-------------|
| MAC-A (f1) | Network authentication code |
| XRES (f2) | Expected response |
| CK (f3) | Cipher key |
| IK (f4) | Integrity key |
| AK (f5) | Anonymity key |
| AUTN | Authentication token = (SQN⊕AK) ‖ AMF ‖ MAC-A |

### SIM Card Response

| Field | Description |
|-------|-------------|
| RES | Response (should match XRES) |
| CK | Cipher key from card |
| IK | Integrity key from card |
| AUTS | Resync token (on sync failure) |

### Derived Keys

| Field | Description |
|-------|-------------|
| KASME | LTE master key (requires MCC/MNC) |
| SRES | 2G triplet response |
| Kc | 2G cipher key |

### Resync Data (from AUTS)

| Field | Description |
|-------|-------------|
| AK* (f5*) | Anonymity key for resync |
| SQNms | SIM card's current sequence number |
| MAC-S | Resync authentication code |

## Working with Dumps

### Scenario 1: You have RAND and AUTN from network capture

```bash
# Send to card, get RES/CK/IK
./sim_reader -auth \
  -auth-rand 3A8F7BE7E6DA0B3149B0386F5466C96A \
  -auth-autn 47757E6B3DCD8000510F1A2B54119237
```

### Scenario 2: You have K, OPc, and pre-computed AUTN

```bash
# Use AUTN directly, skip calculation, compare with card
./sim_reader -auth \
  -auth-k F2464E3293019A7E51ABAA7B1262B7D8 \
  -auth-opc B10B351A0CCD8BE31E0C9F088945A812 \
  -auth-rand 7D6AF2DF993240BA9B191B68F1750C43 \
  -auth-autn F20BB82D5AC1800011E6F3F4E94052F2
```

### Scenario 3: You have AUTS from sync failure

```bash
# Extract SQNms from AUTS
./sim_reader -auth \
  -auth-k F2464E3293019A7E51ABAA7B1262B7D8 \
  -auth-opc B10B351A0CCD8BE31E0C9F088945A812 \
  -auth-rand 7D6AF2DF993240BA9B191B68F1750C43 \
  -auth-auts AABBCCDDEEFF0011223344556677 \
  -auth-no-card

# Output will show SQNms and suggest next SQN (SQNms+1)
```

## Sync Failure Handling

When SQN is out of range, the SIM card returns AUTS instead of RES:

1. **Automatic handling**: When card returns AUTS, the tool automatically:
   - Computes AK* using f5*
   - Extracts SQNms from AUTS
   - Suggests next SQN value (SQNms + 1)

2. **Manual AUTS processing**: Use `-auth-auts` flag with captured AUTS

## Algorithm Selection

The algorithm is determined at SIM card personalization and cannot be changed. The tool supports both:

```bash
# Milenage (default)
./sim_reader -auth -auth-algo milenage ...

# TUAK (256-bit key support)
./sim_reader -auth -auth-algo tuak ...
```

**Note**: There is no standard way to detect which algorithm a SIM card uses. You need to know this from the card documentation or test with known vectors.

## TUAK-Specific Parameters

TUAK supports configurable output lengths:

| Parameter | Values | Default |
|-----------|--------|---------|
| MAC length | 64, 128, 256 bits | 64 |
| RES length | 32, 64, 128, 256 bits | 64 |
| CK length | 128, 256 bits | 128 |
| IK length | 128, 256 bits | 128 |
| Key length | 128, 256 bits | 128 |

## Example Output

```
╭───────────────────────────────────────────────────────────────────────────────────────────────╮
│ AUTHENTICATION TEST (MILENAGE)                                                                │
├──────────────────────┬────────────────────────────────────────────────────────────────────────┤
│ ─── INPUT ───        │                                                                        │
│ K (Subscriber Key)   │ F2464E3293019A7E51ABAA7B1262B7D8                                       │
│ OP                   │ CDC202D5123E20F62B6D676AC72CB318                                       │
│ OPc                  │ B10B351A0CCD8BE31E0C9F088945A812                                       │
│ RAND                 │ 7D6AF2DF993240BA9B191B68F1750C43                                       │
│ SQN                  │ 000000000C80                                                           │
│ AMF                  │ 8000                                                                   │
╰──────────────────────┴────────────────────────────────────────────────────────────────────────╯

╭───────────────────────────────────────────────────────────────────────────────────────────────╮
│ COMPUTED AUTHENTICATION VECTOR (Network)                                                      │
├──────────────────────┬────────────────────────────────────────────────────────────────────────┤
│ MAC-A (f1)           │ 11E6F3F4E94052F2                                                       │
│ XRES (f2)            │ 720238AF6CA3B0FF                                                       │
│ CK (f3)              │ C5C3CB6A21FA59B006056AC63FDE57E7                                       │
│ IK (f4)              │ 391047293774561577FBFDF4759EF5A2                                       │
│ AK (f5)              │ F20BB82D5641                                                           │
│ AUTN                 │ F20BB82D5AC1800011E6F3F4E94052F2                                       │
╰──────────────────────┴────────────────────────────────────────────────────────────────────────╯

╭───────────────────────────────────────────────────────────────────────────────────────────────╮
│ DERIVED KEYS                                                                                  │
├──────────────────────┬────────────────────────────────────────────────────────────────────────┤
│ KASME (LTE)          │ 00EDE4B9FA210423F0DF41B35CD8C255761CCDF14C734AD0C006E5835656EBBE       │
│ ─── 2G TRIPLET ───   │                                                                        │
│ SRES                 │ 1EA18850                                                               │
│ Kc                   │ 8D2D1B715CCEADE0                                                       │
╰──────────────────────┴────────────────────────────────────────────────────────────────────────╯
```

## References

- 3GPP TS 33.102 - Security architecture
- 3GPP TS 33.401 - EPS security architecture (KASME derivation)
- 3GPP TS 35.205 - Milenage algorithm specification
- 3GPP TS 35.206 - Milenage algorithm specification (continued)
- 3GPP TS 35.231 - TUAK algorithm specification

