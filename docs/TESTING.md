# SIM Card Test Suite

Comprehensive test suite for validating USIM/ISIM/eSIM cards according to 3GPP and GSMA specifications.

## Overview

The test suite covers:

- **USIM** - 23 tests for files and services (TS 31.102)
- **ISIM** - 7 tests for IMS parameters (TS 31.103)
- **AUTH** - 4 authentication tests for Milenage (TS 35.206)
- **APDU** - 10 low-level command tests (TS 102.221)
- **Security** - 7 negative security tests

## Quick Start

### Full Test with Reports

```bash
./sim_reader -test \
    -adm 4444444444444444 \
    -auth-k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 \
    -auth-opc 808182838485868788898A8B8C8D8E8F \
    -test-output baseline
```

This creates:
- `baseline.json` - results in JSON format
- `baseline.html` - visual HTML report

### Test Without Authentication

```bash
./sim_reader -test -adm 4444444444444444
```

### Run Specific Categories Only

```bash
# USIM files only
./sim_reader -test -test-only usim -adm 4444444444444444

# ISIM only
./sim_reader -test -test-only isim -adm 4444444444444444

# Authentication only
./sim_reader -test -test-only auth \
    -auth-k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 \
    -auth-opc 808182838485868788898A8B8C8D8E8F

# Multiple categories
./sim_reader -test -test-only usim,auth -adm 4444444444444444
```

## Command Line Flags

| Flag | Description |
|------|-------------|
| `-test` | Run the test suite |
| `-test-output <prefix>` | Output file prefix for reports (.json + .html) |
| `-test-only <categories>` | Run only specified categories: usim, isim, auth, apdu, security |
| `-adm` | ADM1 key for accessing protected files |
| `-auth-k` | K key for authentication tests |
| `-auth-opc` | Pre-computed OPc |
| `-auth-op` | OP (OPc will be computed automatically) |
| `-auth-sqn` | Sequence Number (default: 000000000000) |
| `-auth-amf` | Authentication Management Field (default: 8000) |

## Test Categories

### USIM (TS 31.102)

Tests for mandatory and optional EF files:

| File | FID | Description |
|------|-----|-------------|
| EF.IMSI | 6F07 | Subscriber IMSI |
| EF.AD | 6FAD | Administrative Data |
| EF.UST | 6F38 | USIM Service Table |
| EF.EST | 6F56 | Enabled Services Table |
| EF.ACC | 6F78 | Access Control Classes |
| EF.SPN | 6F46 | Service Provider Name |
| EF.HPPLMN | 6F31 | HPLMN Search Period |
| EF.PLMNwAcT | 6F60 | User PLMN with ACT |
| EF.OPLMNwAcT | 6F61 | Operator PLMN with ACT |
| EF.HPLMNwAcT | 6F62 | Home PLMN with ACT |
| EF.FPLMN | 6F7B | Forbidden PLMNs |
| EF.LOCI | 6F7E | CS Location Information |
| EF.PSLOCI | 6F73 | PS Location Information |
| EF.EPSLOCI | 6FE3 | EPS Location Information |
| EF.Keys | 6F08 | CK/IK Keys |
| EF.KeysPS | 6F09 | PS Keys |
| EF.LI | 6F05 | Language Indication |
| EF.START-HFN | 6F5B | START-HFN |
| EF.THRESHOLD | 6F5C | Threshold |
| EF.SMS | 6F3C | SMS Messages |
| EF.SMSP | 6F42 | SMS Parameters |
| EF.MSISDN | 6F40 | Phone Number |
| EF.ECC | 6FB7 | Emergency Call Codes |

### ISIM (TS 31.103)

Tests for IMS parameters:

| File | FID | Description |
|------|-----|-------------|
| EF.IMPI | 6F02 | IMS Private Identity |
| EF.IMPU | 6F04 | IMS Public Identity |
| EF.DOMAIN | 6F03 | Home Network Domain |
| EF.IST | 6F07 | ISIM Service Table |
| EF.PCSCF | 6F09 | P-CSCF Addresses |
| EF.AD | 6FAD | Administrative Data |
| EF.ARR | 6F06 | Access Rule Reference |

### AUTH (TS 35.206, TS 33.102)

Authentication tests:

| Test | Description |
|------|-------------|
| 3G AUTHENTICATE | UMTS authentication (P2=0x81) |
| GSM AUTHENTICATE | GSM context (P2=0x80) |
| Multiple AUTHENTICATE | Sequential authentications |
| sim.RunAuthentication | Vector computation function test |

### APDU (TS 102.221)

Command tests:

| Test | Description |
|------|-------------|
| SELECT MF | Select Master File |
| SELECT by AID | Select by AID (USIM) |
| SELECT by FID | Select by File ID |
| SELECT P2 Variants | Different P2 values |
| READ BINARY | Read transparent file |
| READ BINARY Offset | Read with offset |
| READ RECORD | Read linear fixed record |
| STATUS | Get current status |
| VERIFY PIN Query | Query PIN status |
| GET RESPONSE | Get data after 61XX |

### Security (Negative Tests)

| Test | Expected SW | Description |
|------|-------------|-------------|
| Wrong PIN | 63CX | Incorrect PIN |
| File Not Found | 6A82 | Non-existent file |
| Security Not Satisfied | 6982 | Access denied |
| Wrong Length | 6700 | Incorrect length |
| Wrong P1P2 | 6A86/6B00 | Incorrect P1/P2 |
| Wrong CLA | 6E00 | Incorrect class byte |
| Wrong INS | 6D00 | Incorrect instruction |

## Usage Scenarios

### Baseline Test (Profile Without Applet)

```bash
# Test baseline profile
./sim_reader -test \
    -adm 4444444444444444 \
    -auth-k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 \
    -auth-opc 808182838485868788898A8B8C8D8E8F \
    -test-output baseline_no_applet
```

### Test With Milenage Applet

```bash
# After loading the applet, use the applet's key
./sim_reader -test \
    -adm 4444444444444444 \
    -auth-k 000102030405060708090A0B0C0D0E0F \
    -auth-opc 808182838485868788898A8B8C8D8E8F \
    -test-output with_applet
```

### Comparing Results

After testing, compare the JSON files:

```bash
diff baseline_no_applet.json with_applet.json
```

Or open the HTML reports in a browser for visual comparison.

## JSON Report Structure

```json
{
  "timestamp": "2024-12-28T12:00:00Z",
  "card_atr": "3B9F96801FC78031E073FE211B...",
  "summary": {
    "total": 51,
    "passed": 48,
    "failed": 3,
    "pass_rate": 94.1,
    "by_category": {
      "usim": 23,
      "isim": 7,
      "auth": 4,
      "apdu": 10,
      "security": 7
    },
    "failed_tests": ["Test Name 1", "Test Name 2"]
  },
  "results": [
    {
      "name": "EF.IMSI (6F07)",
      "category": "usim",
      "passed": true,
      "actual": "250880000000010",
      "sw": 36864,
      "spec": "TS 31.102 4.2.2"
    }
  ]
}
```

## HTML Report

The HTML report contains:

- Summary (total/passed/failed/pass rate)
- List of failed tests
- Detailed table of all results
- APDU commands for each test
- Specification references

## Interpreting Results

### Successful Test

```
[✓] EF.IMSI (6F07): 250880000000010
```

### Failed Test

```
[✗] EF.Keys (6F08): Expected 33 bytes, got 0 bytes
```

### Partially Successful (Resync)

```
[✓] 3G AUTHENTICATE (P2=0x81): AUTS returned (SQN resync needed), SQNms=000000000042
```

When AUTS is received, use the obtained SQNms+1 for the next authentication:

```bash
./sim_reader -auth -auth-sqn 000000000043 ...
```

## Extending the Test Suite

To add new tests:

1. Create a test function in the appropriate file:
   - `tests_usim.go` - USIM tests
   - `tests_isim.go` - ISIM tests
   - `tests_auth.go` - authentication tests
   - `tests_apdu.go` - APDU and negative tests

2. Add the call to the category's run function

3. Use helper functions:
   - `s.readEF(fid)` - read transparent file
   - `s.AddResult()` - add result
   - `s.pass()`, `s.fail()` - create results

## Known Limitations

1. PIN tests do not perform actual wrong PIN verification (to avoid blocking)
2. AUTS resync requires correct SQN on the card
3. Some files are optional and their absence is not considered an error

## Specification References

- **3GPP TS 31.102** - USIM Application
- **3GPP TS 31.103** - ISIM Application
- **3GPP TS 35.206** - Milenage Algorithm
- **3GPP TS 33.102** - 3G Security Architecture
- **ETSI TS 102.221** - UICC-Terminal Interface
- **GSMA SGP.22** - eSIM Remote Provisioning
