# Programmable SIM Cards

⚠️ **CRITICAL WARNING**: Programming SIM cards is an **IRREVERSIBLE** operation that can **PERMANENTLY DAMAGE** the card if done incorrectly!

---

## 📖 Table of Contents

- [What are Programmable Cards](#what-are-programmable-cards)
- [Supported Cards](#supported-cards)
- [Safe Usage](#safe-usage)
- [Usage Examples](#usage-examples)
- [Proprietary Files](#proprietary-files)
- [JSON Configuration](#json-configuration)
- [Troubleshooting](#troubleshooting)

---

## What are Programmable Cards

**Programmable SIM cards** (blank SIM, writable SIM) are empty cards that can be programmed from scratch, setting:

- **Ki** - Subscriber key (authentication key)
- **OPc/OP** - Operator key
- **ICCID** - Card identifier
- **IMSI** - Subscriber identity
- **MSISDN** - Phone number
- **PIN/PUK** - PIN codes
- Other parameters (PLMN, ACC, etc.)

### Usage:

✅ **Allowed**:
- Test networks (Open5GS, srsRAN, etc.)
- Research and development
- Private LTE/5G networks
- Educational purposes

❌ **Prohibited**:
- Cloning operator SIM cards
- Fraudulent activities
- Violating operator terms

---

## Supported Cards

### ✅ GRv2 (Grcard Version 2)

**ATR patterns**:
```
3B 9F 95 80 1F C7 80 31 A0 73 B6 A1 00 67 CF 32 11 B2 52 C6 79 F3  (open5gs)
3B 9F 94 80 1F C3 80 31 A0 73 B6 A1 00 67 CF 32 10 DF 0E F5 20 EC
3B 9F 95 80 1F C7 80 31 A0 73 B6 A1 00 67 CF 32 11 B2 52 C6 79 B3
```

**Manufacturers**:
- open5gs project
- Gialer/Glaier (China)
- OYEITIMES (AliExpress)
- Huahong (Private LTE)

**Features**:
- Requires special activation command (`A0 58 00 00 08 ...`)
- Uses direct APDU commands
- Supports: Milenage, XOR algorithms

### ✅ GRv1 (Grcard Version 1)

**Features**:
- Uses standard USIM commands
- Proprietary File IDs in `7FF0 FFxx` range
- No handshake required

### ✅ sysmocom sysmoUSIM-GR1

**ATR pattern**:
```
3B 9F 95 80 1F C7 80 31 E0 73 FE 21 13 57 12 29 11 02 01 00 00 C2
```

**Features**:
- Professional programmable cards
- TUAK support
- Extended capabilities

---

## Safe Usage

### 🔴 Safety Rules

1. **ALWAYS use `-prog-dry-run` first!**
   ```bash
   ./sim_reader -adm KEY -write config.json -prog-dry-run
   ```

2. **Check card type**:
   ```bash
   ./sim_reader -prog-info
   ```

3. **Have a backup card** for testing

4. **Double-check all values**:
   - Ki must be 32 hex characters (128-bit)
   - OPc must be 32 hex characters (128-bit)
   - ICCID must be 18-20 digits

5. **Don't interrupt** the programming process!

### ⚠️ What Can Go Wrong:

| Problem | Consequences | Solution |
|---------|--------------|----------|
| Wrong Ki/OPc | Authentication fails | ❌ Irreversible! |
| Wrong ICCID | Card not recognized | ❌ Irreversible! |
| Interrupted write | Partially programmed card | ❌ Card bricked |
| Wrong card type | Commands don't work | ⚠️ May brick card |

---

## Usage Examples

### 1. Check Card

```bash
# Show programmable card information
./sim_reader -prog-info
```

**Output**:
```
╔════════════════════════════════════════════════════════════════════╗
║              PROGRAMMABLE CARD INFORMATION                         ║
╚════════════════════════════════════════════════════════════════════╝

Card Type:        Grcard v2 / open5gs (GRv2)
Description:      Programmable USIM card (GRv2 protocol)
ATR Pattern:      3B9F95801FC78031A073B6A10067CF3211B252C679

Proprietary File IDs:
  Ki:             0001
  OPc:            6002
  Milenage R:     2FE6
  Algorithm Type: 2FD0
  ADM Key:        0B00
  PIN1/PUK1:      0100
  PIN2/PUK2:      0200

✓ This card supports programmable operations
```

### 2. Dry Run (Safe Test)

```bash
# Test without writing
./sim_reader -adm 4444444444444444 -write programmable_config.json -prog-dry-run
```

**Output**:
```
🧪 DRY RUN MODE: No data will be written
    Remove -prog-dry-run to actually program the card

⚠️  PROGRAMMABLE CARD DETECTED: Grcard v2 / open5gs (GRv2)
    Description: Programmable USIM card (GRv2 protocol)

[DRY RUN] Would activate programming mode
[DRY RUN] Would write 16 bytes to file 0001
[DRY RUN] Would write 17 bytes to file 6002
[DRY RUN] Would write R constants: [40 00 20 40 60]
[DRY RUN] Would write C constants: 5x16 bytes
[DRY RUN] Would write algorithm type 1910

Dry run completed. Review the commands above.
```

### 3. Write Ki and OPc

```bash
# CAUTION: Real write!
./sim_reader -adm 4444444444444444 -write programmable_config.json
```

### 4. Using OP (OPc computed automatically)

Create `programmable_config.json`:
```json
{
  "programmable": {
    "ki": "F2464E3293019A7E51ABAA7B1262B7D8",
    "op": "CDC202D5123E20F62B6D676AC72CB318",
    "iccid": "89860061100000000123",
    "pin1": "1234",
    "puk1": "12345678"
  },
  "imsi": "250880000000001",
  "spn": "My Network"
}
```

### 5. Full Card Programming

```json
{
  "programmable": {
    "ki": "F2464E3293019A7E51ABAA7B1262B7D8",
    "opc": "B10B351A0CCD8BE31E0C9F088945A812",
    "iccid": "89860061100000000123",
    "msisdn": "+1234567890",
    "acc": "0001",
    "pin1": "1234",
    "puk1": "12345678",
    "pin2": "5678",
    "puk2": "87654321",
    "algorithm": "milenage"
  },
  "imsi": "250880000000001",
  "spn": "My Network",
  "mcc": "250",
  "mnc": "88",
  "hplmn": [
    {"mcc": "250", "mnc": "88", "act": ["eutran", "utran", "gsm"]}
  ],
  "isim": {
    "impi": "250880000000001@ims.mnc088.mcc250.3gppnetwork.org",
    "impu": ["sip:250880000000001@ims.mnc088.mcc250.3gppnetwork.org"],
    "domain": "ims.mnc088.mcc250.3gppnetwork.org"
  }
}
```

---

## Proprietary Files

### GRv2 File IDs

| Parameter | File ID | Size | Description |
|-----------|---------|------|-------------|
| Ki | `0001` | 16 bytes | Subscriber key K |
| OPc | `6002` | 17 bytes | Operator code (1 byte prefix + 16 bytes OPc) |
| Algorithm Type | `2FD0` | 2 bytes | `1910` = Milenage, `1920` = XOR |
| Milenage R | `2FE6` | Records | R constants (5 records x 17 bytes) |
| Milenage Params | `2FE5` | 5 bytes | `08 1C 2A 00 01` |
| ADM Key | `0B00` | variable | ADM key file |
| PIN1/PUK1 | `0100` | 23 bytes | PIN1 + PUK1 |
| PIN2/PUK2 | `0200` | 23 bytes | PIN2 + PUK2 |

### GRv1 File IDs

| Parameter | File ID | Description |
|-----------|---------|-------------|
| Ki | `7FF0 FF02` | Subscriber key K |
| OPc | `7FF0 FF01` | Operator code OPc |
| Milenage R | `7FF0 FF03` | R constants (5 bytes) |
| Milenage C | `7FF0 FF04` | C constants (5 records x 16 bytes) |
| Secret | `7F20 0001` | Additional secret |

---

## JSON Configuration

### Programmable Section

Add a `programmable` section to your JSON config:

```json
{
  "programmable": {
    "ki": "F2464E3293019A7E51ABAA7B1262B7D8",
    "op": "CDC202D5123E20F62B6D676AC72CB318",
    "opc": "B10B351A0CCD8BE31E0C9F088945A812",
    "iccid": "89860061100000000123",
    "msisdn": "+1234567890",
    "acc": "0001",
    "pin1": "1234",
    "puk1": "12345678",
    "pin2": "5678",
    "puk2": "87654321",
    "algorithm": "milenage"
  },
  "imsi": "250880000000001",
  "spn": "My Network"
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `programmable.ki` | Yes | Subscriber key (32 hex chars) |
| `programmable.op` | Yes* | Operator key OP (32 hex chars) |
| `programmable.opc` | Yes* | Operator key OPc (32 hex chars) |
| `programmable.iccid` | No | Card identifier (18-20 digits) |
| `programmable.msisdn` | No | Phone number |
| `programmable.acc` | No | Access Control Class (4 hex chars) |
| `programmable.pin1` | No | PIN1 code (4-8 digits) |
| `programmable.puk1` | No | PUK1 code (8 digits) |
| `programmable.pin2` | No | PIN2 code (4-8 digits) |
| `programmable.puk2` | No | PUK2 code (8 digits) |
| `programmable.algorithm` | No | Algorithm: milenage, xor (default: milenage) |

*Either `op` or `opc` must be provided. If `op` is given, `opc` will be computed automatically.

### Usage

```bash
# Dry run (safe)
./sim_reader -adm YOUR_ADM_KEY -write programmable_config.json -prog-dry-run

# Real write
./sim_reader -adm YOUR_ADM_KEY -write programmable_config.json

# Force on unrecognized cards (dangerous!)
./sim_reader -adm YOUR_ADM_KEY -write programmable_config.json -prog-force
```

---

## Troubleshooting

### Problem: "Card is not recognized as programmable"

**Solution**:
1. Check ATR: `./sim_reader -analyze`
2. Use `-prog-force` (dangerous!):
   ```bash
   ./sim_reader -prog-force -write config.json
   ```
3. Contact support to add your card's ATR

### Problem: "Handshake failed"

**Causes**:
- Card already programmed (handshake needs to run twice)
- Wrong card type
- Card not in programming mode

**Solution**:
- Try restart (remove and insert card)
- Check ATR

### Problem: "UPDATE returned error: 6982"

**Cause**: Insufficient permissions (wrong ADM key)

**Solution**: Check ADM key for your card

### Problem: Card doesn't authenticate after programming

**Cause**: Wrong Ki or OPc

**Solution**: 
- ❌ Cannot be fixed! Card is bricked.
- Make sure to use `-prog-dry-run` before real write

---

## Important Notes

1. **Always start with `-prog-dry-run`**
2. **Check card type** with `-prog-info`
3. **Have backup cards** for testing
4. **Record parameters** you used
5. **Don't use on operator cards** - won't work and may damage them

---

## Additional Resources

- [3GPP TS 35.206](https://www.3gpp.org/ftp/Specs/archive/35_series/35.206/) - Milenage algorithm
- [Open5GS Documentation](https://open5gs.org/) - Test 5G network
- [sysmocom](https://www.sysmocom.de/) - Professional programmable cards

---

## License and Liability

⚠️ **Authors are NOT responsible for damaged cards!**

Use this functionality at your own risk. Programming SIM cards requires deep understanding of the process and can lead to irreversible equipment damage.

**If you're not sure what you're doing - DON'T DO IT!**
