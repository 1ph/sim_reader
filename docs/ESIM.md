# eSIM Profile Support in sim_reader

## Overview

The `esim` package provides tools for working with eSIM profiles in GSMA SGP.22 / SAIP (Subscriber Identity Application Programming) format. It supports decoding, validation, and building profiles, including support for Java Card applets.

### Supported Profile Elements

| Tag | Element Name | Description |
|-----|--------------|----------|
| 0 | ProfileHeader | Profile header (version, ICCID, services) |
| 1 | MF | Master File (root file system) |
| 2 | PukCodes | PUK codes |
| 3 | PinCodes | PIN codes |
| 4 | Telecom | Telecom directory |
| 8 | **Application** | **Java Card applets (PE-Application)** |
| 9 | USIM | USIM application |
| 10 | OptUSIM | Optional USIM files |
| 12 | ISIM | ISIM application |
| 13 | OptISIM | Optional ISIM files |
| 14 | CSIM | CSIM application |
| 15 | OptCSIM | Optional CSIM files |
| 20 | GSMAccess | GSM Access files |
| 22 | AKAParameter | Authentication parameters (Ki, OPc, algorithm) |
| 23 | CDMAParameter | CDMA parameters |
| 24 | DF5GS | 5G files |
| 25 | DFSAIP | SAIP files |
| 26 | GenericFileManagement | File management |
| 55 | SecurityDomain | GlobalPlatform Security Domain |
| 56 | RFM | Remote File Management |
| 63 | End | Profile end marker |

---

## CLI Commands

### General Syntax

```bash
sim_reader esim <subcommand> [flags]
```

### Available Subcommands

| Command | Description |
|---------|----------|
| `decode` | Decode and display profile content |
| `validate` | Validate profile correctness |
| `build` | Build a profile from configuration and template |

---

## Profile Decoding (decode)

```bash
sim_reader esim decode <profile.der> [--verbose] [--json]
```

### Flags

| Flag | Description |
|------|----------|
| `-v, --verbose` | Show detailed information (AKA parameters, applets, PIN/PUK) |
| `--json` | Output in JSON format |

### Examples

```bash
# Basic profile information
sim_reader esim decode profile.der

# Detailed information including applets and keys
sim_reader esim decode profile.der --verbose

# Export to JSON
sim_reader esim decode profile.der --json > profile_info.json
```

### Sample Output

```
=== eSIM Profile Summary ===

Version:      2.3
Profile Type: operationalProfile
ICCID:        89701501078000006814

--- Applications ---
USIM: true
ISIM: true
CSIM: false

--- USIM ---
IMSI: 250880000000010
AID:  a0000000871002ff33ff01890000010f

--- Authentication ---
Algorithm: Milenage
Ki:        00112233445566778899aabbccddeeff
OPc:       ffeeddccbbaa99887766554433221100

--- PIN/PUK ---
PIN1: 0000
PUK1: 12345678
ADM1: 88888888

--- Profile Elements: 25 ---
  [ 0] ProfileHeader
  [ 1] MasterFile
  [ 2] PukCodes
  ...
```

---

## Profile Validation (validate)

```bash
sim_reader esim validate <profile.der> [--template <base.der>]
```

### Flags

| Flag | Description |
|------|----------|
| `-t, --template` | Profile template to compare structure against |
| `--json` | Output results in JSON format |

### Performed Checks

1. **Mandatory Elements**
   - ProfileHeader (required)
   - MasterFile (required)
   - End (required)

2. **ICCID**
   - Length: 18-20 digits
   - Format: numeric only
   - Luhn checksum verification

3. **IMSI**
   - Length: 15 digits
   - Format: numeric only
   - Required if USIM is present

4. **AKA Parameters**
   - Presence of AlgoConfiguration
   - Ki: 16 or 32 bytes
   - OPc: 16 or 32 bytes (recommended for Milenage/TUAK)

5. **PIN/PUK**
   - PIN: 4-8 digits
   - PUK: 8 digits

6. **Applets (PE-Application)**
   - AID validity (5-16 bytes)
   - Presence of LoadBlock or InstanceList
   - Personalization APDU command format

### Examples

```bash
# Basic validation
sim_reader esim validate profile.der

# Comparison with template
sim_reader esim validate profile.der --template TS48v4_SAIP2.3.der

# JSON output for automation
sim_reader esim validate profile.der --json
```

### Sample Output

```
Profile validation: PASSED

✓ ProfileHeader: v2.3
✓ MasterFile: Present
✓ ProfileEnd: Present
✓ ICCID: 89701501078000006814 (Luhn OK)
✓ IMSI: 250880000000010
✓ AKA: Milenage, Ki/OPc present
✓ PIN/PUK: PIN/PUK codes valid
✓ Applications: 1 applet(s) found, 1 instance(s)
✓ SecurityDomains: 1 SD(s) found
```

---

## Profile Building (build)

```bash
sim_reader esim build --config <config.json> --template <base.der> -o <output.der> [flags]
```

### Flags

| Flag | Description |
|------|----------|
| `-c, --config` | JSON configuration file (required) |
| `-t, --template` | DER profile template (required) |
| `-o, --output` | Output profile file (default: profile.der) |
| `--applet` | CAP applet file to include in the profile |
| `--use-applet-auth` | Delegate authentication to the applet (algorithmID=3) |

### Configuration Format (JSON)

```json
{
  "iccid": "89701501078000006814",
  "imsi": "250880000000010",
  "ki": "00112233445566778899aabbccddeeff",
  "opc": "ffeeddccbbaa99887766554433221100",
  
  "impi": "250880000000010@ims.mnc088.mcc250.3gppnetwork.org",
  "impu": [
    "sip:250880000000010@ims.mnc088.mcc250.3gppnetwork.org",
    "tel:+70000000010"
  ],
  "domain": "ims.mnc088.mcc250.3gppnetwork.org",
  
  "pin1": "0000",
  "puk1": "12345678",
  "adm1": "88888888",
  
  "algorithm_id": 1,
  "profile_type": "operationalProfile",
  
  "applet_cap": "/path/to/milenage_usim.cap",
  "applet_config": {
    "package_aid": "A00000008710020101",
    "class_aid": "A0000000871002010101",
    "instance_aid": "A000000087100201010101",
    "milenage_usim": {
      "ki": "00112233445566778899aabbccddeeff",
      "opc": "ffeeddccbbaa99887766554433221100",
      "amf": "8000"
    }
  }
}
```

### Build Example

```bash
# Basic build
sim_reader esim build \
  --config rusim.json \
  --template TS48v4_SAIP2.3_NoBERTLV.der \
  -o my_profile.der

# With Milenage USIM applet
sim_reader esim build \
  --config rusim.json \
  --template TS48v4_SAIP2.3_NoBERTLV.der \
  --applet milenage_usim.cap \
  --use-applet-auth \
  -o my_profile.der
```

---

## Applet Support (PE-Application)

### PE-Application Structure

PE-Application (Tag 8) contains:

1. **LoadBlock** - CAP file data
   - `LoadPackageAID` - Package AID
   - `SecurityDomainAID` - Target Security Domain (optional)
   - `LoadBlockObject` - CAP file content

2. **InstanceList** - List of applet instances
   - `ApplicationLoadPackageAID` - Reference to the package
   - `ClassAID` - Applet class AID
   - `InstanceAID` - Instance AID
   - `ApplicationPrivileges` - GP privileges
   - `LifeCycleState` - Lifecycle state (0x07 = SELECTABLE)
   - `ProcessData` - Personalization APDU commands

### ProcessData (Personalization Commands)

ProcessData contains APDU commands executed after applet installation. A typical use case is loading keys into a Milenage USIM applet:

```
STORE DATA (CLA=80, INS=E2):
  80 E2 00 00 12 01 10 <16 bytes Ki>          # Ki
  80 E2 00 00 12 02 10 <16 bytes OPc>         # OPc
  80 E2 00 00 04 04 02 80 00                  # AMF
```

### Applet Configuration in JSON

```json
{
  "applet_config": {
    "package_aid": "A00000008710020101",
    "class_aid": "A0000000871002010101",
    "instance_aid": "A000000087100201010101",
    "sd_aid": "A000000151000000",
    
    "apdus": [
      "80E20000120110FFEEDDCCBBAA99887766554433221100",
      "80E20000120210FFEEDDCCBBAA99887766554433221100"
    ],
    
    "milenage_usim": {
      "ki": "00112233445566778899aabbccddeeff",
      "opc": "ffeeddccbbaa99887766554433221100",
      "amf": "8000",
      "sqn": "000000000000"
    }
  }
}
```

---

## Usage Examples

### 1. Validating a Profile Before Upload

```bash
# Validation
sim_reader esim validate my_profile.der

# If OK, upload to eUICC
# (using external tools or SM-DP+)
```

### 2. Creating a Profile for Testing

```bash
# 1. Prepare configuration
cat > test_config.json << 'EOF'
{
  "iccid": "89701501078000006814",
  "imsi": "250880000000010",
  "ki": "00112233445566778899aabbccddeeff",
  "opc": "ffeeddccbbaa99887766554433221100",
  "pin1": "0000",
  "puk1": "12345678"
}
EOF

# 2. Build profile
sim_reader esim build \
  -c test_config.json \
  -t base_template.der \
  -o test_profile.der

# 3. Verify result
sim_reader esim decode test_profile.der --verbose
```

### 3. Analyzing Applets in a Profile

```bash
sim_reader esim decode profile_with_applet.der --verbose

# Output will show:
# --- Java Card Applications (PE-Application) ---
# Application[0]:
#   LoadBlock:
#     PackageAID: a00000008710020101
#     LoadBlockObject: 15234 bytes
#   Instance[0]:
#     PackageAID: a00000008710020101
#     ClassAID:   a0000000871002010101
#     InstanceAID: a000000087100201010101
#     LifeCycle: 0x07
#     ProcessData (3 APDUs):
#       [0] 80e20000120110ffeeddccbbaa998877665544...
```

---

## Troubleshooting

### Profile Decoding Fails

1. Check file format (must be DER, not PEM)
2. Check file integrity (size > 0)
3. Run with `--verbose` for detailed diagnostics

### Validation Shows Errors

| Error | Cause | Resolution |
|--------|---------|---------|
| ICCID Luhn failed | Incorrect checksum | Recalculate ICCID |
| Ki missing | Key not found in AKA parameters | Add Ki to configuration |
| Invalid AID | AID < 5 or > 16 bytes | Verify AID format |

### Applet Not Working After Upload

1. Check CAP file compatibility with the eUICC platform
2. Ensure ProcessData contains all necessary commands
3. Verify the correct order of personalization commands

---

## Glossary

| Term | Description |
|--------|----------|
| ICCID | Integrated Circuit Card Identifier - 18-20 digit card identifier |
| IMSI | International Mobile Subscriber Identity - 15 digit subscriber identifier |
| Ki | Subscriber Key - 128-bit authentication key |
| OPc | Derived Operator Key - operator-derived key |
| AID | Application Identifier - identifier for applications (5-16 bytes) |
| CAP | Converted Applet - Java Card applet file |
| PE | Profile Element - part of a profile |
| SAIP | Subscriber Identity Application Programming - SGP.22 profile format |
| ProcessData | APDU commands for applet personalization |
