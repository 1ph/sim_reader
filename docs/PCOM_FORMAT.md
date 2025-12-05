# PCOM Script Format Specification

## Overview

PCOM (Programmable Card Object Model) is a script format used for SIM card personalization. It allows you to define variables, execute APDU commands, and call nested scripts to fully program a smart card.

This format is commonly used with programmable SIM cards like OX24/RuSIM and similar cards that support low-level file system creation and personalization.

## File Extensions

- `.pcom` - Main script files containing APDU commands and directives
- `.var` - Variable definition files (same syntax, typically only `.DEFINE` directives)

## Basic Syntax

### Comments

```pcom
; Single line comment
;; Also a comment
A0A4 0000 02 3F00 (9000)  ; Inline comment after command
```

### APDU Commands

Format: `CLA INS P1 P2 [Lc] [DATA] (EXPECTED_SW)`

```pcom
; SELECT MF (Master File)
A0A4 0000 02 3F00 (9F22)

; UPDATE BINARY - write data to selected file
A0D6 0000 09 082905058700006008 (9000)

; UPDATE RECORD - write record to linear fixed file
A0DC 0104 2C 800101900080011AA4068301... (9000)

; READ BINARY
A0B0 0000 0A (9000)
```

**Notes:**
- Spaces in hex data are ignored: `A0 A4 00 00` = `A0A40000`
- `(XXXX)` at the end specifies expected Status Word (SW)

### Expected Response

```pcom
; Exact SW match
A0A4 0000 02 3F00 (9000)

; Wildcard SW (X matches any nibble)
A0A4 0000 02 3F00 (9XXX)
A0A4 0000 02 3F00 (61XX)

; Expected response data in brackets
A0B0 0000 0A [98075110700800008660] (9000)

; Wildcard data (X matches any nibble)
A0C0 0000 22 [0000XXXX3F000100...] (9000)
```

## Directives

### .DEFINE - Variable Definition

```pcom
; Simple variable
.DEFINE %ICCID 98075110700800008660

; Variable referencing another variable
.DEFINE %OP_OPC %OP

; Multi-line value (use backslash)
.DEFINE %LONG_VALUE 0102030405060708 \
    090A0B0C0D0E0F10 \
    1112131415161718
```

### .CALL - Include Another Script

```pcom
; Call another script file (relative to current script directory)
.CALL Data_Variables.var
.CALL 01.create_GSM.pcom
.CALL subfolder/script.pcom
```

Variables defined before `.CALL` are available in the called script.
Variables defined in called script are available after `.CALL` returns.

### .POWER_ON / .POWER_OFF - Card Reset

```pcom
; Warm reset (keeps card powered)
.POWER_ON

; Cold reset (power cycle)
.POWER_ON /COLD

; Power off card
.POWER_OFF
```

### .ALLUNDEFINE - Clear Variables

```pcom
; Clear all defined variables
.ALLUNDEFINE
```

### .INSERT - Card Insertion (Ignored)

```pcom
; Placeholder for card insertion (ignored by executor)
.INSERT
```

## Variable Substitution

Variables are substituted in APDU data:

```pcom
.DEFINE %IMSI 082905058700006008
.DEFINE %PIN1 31323334FFFFFFFF

; Variables are replaced with their values
A0D6 0000 09 %IMSI (9000)
A020 0001 08 %PIN1 (9000)
```

## Response Extraction Functions

### W(pos;len) - Extract from Last Response

Used in APDU commands to insert bytes from the previous response:

```pcom
; First command returns data
A0A4 0000 02 3F00 (9F22)
A0C0 0000 22 (9000)

; Use W() to extract bytes for next command
; W(2;1) = byte at position 2, length 1
A0C0 0000 W(2;1) (9000)
```

### R(pos;len) - Extract for Variable Definition

Used in `.DEFINE` to capture response data:

```pcom
; Read version info
A0B8 0000 20 (9000)

; Define variable from response bytes 17-32 (16 bytes)
.DEFINE %VERSION R(17;16)
```

## Complete Example

Here's a minimal example that creates a basic SIM card structure:

### Main Script: `personalize.pcom`

```pcom
;; ============================================================
;; SIM Card Personalization Script
;; ============================================================

; Clear any previous variables
.ALLUNDEFINE

; Load variables from external file
.CALL card_data.var

; Power on with cold reset
.POWER_ON /COLD

; Authenticate with ADM key
A020 0000 08 %ADM_KEY (9000)

; Format card (ERASE - BE CAREFUL!)
A0A0 0000 00 (9000)

; Re-authenticate after format
A020 0000 08 %ADM_KEY (9000)

;; ------------------------------------------------------------
;; Create Master File (MF)
;; ------------------------------------------------------------

A0E0 0001 20 0000 0009 3F00 1000 000000 911300010000 0F55FF 2F0600010000000000000000 (9000)

; Select MF
A0A4 0000 02 3F00 (9F22)
A0C0 0000 W(2;1) (9000)

;; ------------------------------------------------------------
;; Create EF_ICCID
;; ------------------------------------------------------------

A0E0 0001 20 0000000A 2FE2 0002 000000 5113DC030000 05F555 2F0601 00 0000000000000000 (9000)
A0EA 0000 0A %ICCID (9000)

;; ------------------------------------------------------------
;; Create DF_GSM and files
;; ------------------------------------------------------------

.CALL create_gsm.pcom

;; ------------------------------------------------------------
;; Create ADF_USIM
;; ------------------------------------------------------------

.CALL create_usim.pcom

;; ------------------------------------------------------------
;; Final verification
;; ------------------------------------------------------------

.POWER_ON

; Select MF and verify ICCID
A0A4 0000 02 3F00 (9XXX)
A0A4 0000 02 2FE2 (9XXX)
A0B0 0000 0A [%ICCID] (9000)

.POWER_OFF

;; Done!
```

### Variables File: `card_data.var`

```pcom
;; ============================================================
;; Card Data Variables
;; ============================================================

; Administrative key (8 bytes hex)
.DEFINE %ADM_KEY 0102030405060708

; Card identity
.DEFINE %ICCID 98701234567890123456
.DEFINE %IMSI 082501230000000001

; Authentication
.DEFINE %KI 00112233445566778899AABBCCDDEEFF
.DEFINE %OP 00112233445566778899AABBCCDDEEFF

; Subscriber info
.DEFINE %SPN 034D794F70 FFFFFFFFFFFF
.DEFINE %MSISDN 07911234567890F1

; PIN codes (ASCII encoded, padded with FF)
.DEFINE %PIN1 31323334FFFFFFFF
.DEFINE %PIN2 31323334FFFFFFFF
.DEFINE %PUK1 3132333435363738
.DEFINE %PUK2 3132333435363738

; Algorithm selection
; 1F = MILENAGE, 2E = S3G-128, 3D = TUAK
.DEFINE %ALGO 1F
```

### Sub-script: `create_gsm.pcom`

```pcom
;; ============================================================
;; Create DF_GSM (7F20) and files
;; ============================================================

; Select MF first
A0A4 0000 02 3F00 (9F22)
A0C0 0000 W(2;1) (9000)

; Create DF_GSM
A0E0 0001 20 0000002F 7F20 10 000000001113B0010000 0F55FF 000000000000000000000000 (9000)

; Create EF_IMSI (6F07) under DF_GSM
A0E0 0000 20 00000009 6F07 00 000000005113DC010000 15F515 000000000000000000000000 (9000)
A0D6 0000 09 %IMSI (9000)

; Create EF_SPN (6F46)
A0E0 0001 20 00000011 6F46 00 000000005113DC010000 15F555 000000000000000000000000 (9000)
A0EA 0000 11 %SPN (9000)

; Create EF_KC (6F20) - cipher key
A0E0 0000 20 00000009 6F20 00 000000005113DC010000 11F555 000000000000000000000000 (9000)
A0D6 0000 09 FFFFFFFFFFFFFFFF07 (9000)

; Create EF_AD (6FAD) - administrative data
A0E0 0000 20 00000004 6FAD 00 000000005113DC010000 05F555 000000000000000000000000 (9000)
A0D6 0000 04 00000002 (9000)
```

## Command Reference

### Common GSM APDU Commands

| Command | CLA INS | Description |
|---------|---------|-------------|
| SELECT | A0 A4 | Select file or directory |
| GET RESPONSE | A0 C0 | Get response data |
| READ BINARY | A0 B0 | Read transparent file |
| UPDATE BINARY | A0 D6 | Write transparent file |
| READ RECORD | A0 B2 | Read record from linear fixed |
| UPDATE RECORD | A0 DC | Write record to linear fixed |
| VERIFY CHV | A0 20 | Verify PIN/ADM |
| CREATE FILE | A0 E0 | Create EF/DF (proprietary) |
| CREATE RECORD | A0 E2 | Create record (proprietary) |
| WRITE BINARY | A0 EA | Write binary (proprietary) |
| FORMAT | A0 A0 | Erase card (proprietary) |

### File Types

| Code | Type | Description |
|------|------|-------------|
| 00 | Transparent | Binary file |
| 01 | Linear Fixed | Record-based file |
| 03 | Cyclic | Circular record file |
| 10 | DF | Directory |

## Script Hierarchy Example

```
_2.LTE_Profile.pcom          (Main script)
├── Data_Variables.var       (Variables: ICCID, IMSI, KI, etc.)
├── 01.create_GSM.pcom       (Creates DF_GSM + files)
├── 01.create_TELECOM.pcom   (Creates DF_TELECOM + files)
├── 01.create_TOOLKIT.pcom   (Creates DF_TOOLKIT)
├── 02.01.create_USIM.pcom   (Creates ADF_USIM at 7FF0)
└── 02.02.create_ISIM.pcom   (Creates ADF_ISIM at 7FF2)
```

## Running Scripts

```bash
# Run personalization script
./sim_reader -pcom personalize.pcom

# Run with verbose output (default)
./sim_reader -pcom personalize.pcom -pcom-verbose

# Run and stop on first error
./sim_reader -pcom personalize.pcom -pcom-stop-on-error

# Run quietly
./sim_reader -pcom personalize.pcom -pcom-verbose=false
```

## Security Considerations

⚠️ **WARNING:**

1. **Card Destruction**: PCOM scripts can completely erase a card. Always test on non-critical cards first.

2. **ADM Key Blocking**: Incorrect ADM key will decrement retry counter. After exhaustion (typically 3-10 attempts), the card is permanently locked.

3. **Backup Data**: Always dump card data before running personalization scripts.

4. **Key Security**: Never commit real ADM keys, KI, or OP values to version control. Use placeholder values in examples.

## References

- 3GPP TS 31.101 - UICC-Terminal Interface
- 3GPP TS 31.102 - USIM Application
- 3GPP TS 31.103 - ISIM Application
- ETSI TS 102 221 - UICC-Terminal Interface
- ISO/IEC 7816-4 - Smart Card Commands
