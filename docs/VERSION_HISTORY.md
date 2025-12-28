# Version History

## v3.2.0 - Cobra CLI Refactoring

### Complete CLI Refactoring with Cobra

The command-line interface has been completely refactored using [spf13/cobra](https://github.com/spf13/cobra) library for better organization and usability:

- **Subcommand Architecture**: All operations are now organized into logical subcommands
- **~70 flags** reorganized from flat structure into hierarchical commands
- **main.go** reduced from 1569 lines to 9 lines
- **Shell Autocomplete**: Built-in completion for bash, zsh, fish, and PowerShell

### New Command Structure

```
sim_reader [global flags] <command> [command flags]

Commands:
  read        Read SIM card data (--list, --phonebook, --sms, --analyze, etc.)
  write       Write SIM card parameters (--imsi, --enable-volte, --dry-run, etc.)
  gp          GlobalPlatform operations
    ├── list    List applets via Secure Channel
    ├── probe   Verify keys
    ├── delete  Delete by AID
    ├── load    Load CAP file
    ├── aram    Add ARA-M rule
    └── verify  Verify AID
  auth        Run authentication test
  test        Run SIM card test suite
  prog        Programmable card operations
    └── info    Show card information
  script      Execute APDU scripts
    ├── run     Simple APDU script
    └── pcom    PCOM personalization script
  completion  Generate shell completion scripts
```

### Migration from Old Syntax

| Old Syntax | New Syntax |
|------------|------------|
| `sim_reader -list` | `sim_reader read --list` |
| `sim_reader -adm KEY` | `sim_reader read -a KEY` |
| `sim_reader -adm KEY -phonebook` | `sim_reader read -a KEY --phonebook` |
| `sim_reader -gp-list -gp-key-enc X` | `sim_reader gp list --key-enc X` |
| `sim_reader -auth -auth-k X` | `sim_reader auth -k X` |
| `sim_reader -write config.json` | `sim_reader write -f config.json` |
| `sim_reader -test` | `sim_reader test` |
| `sim_reader -pcom script.pcom` | `sim_reader script pcom script.pcom` |
| `sim_reader -prog-info` | `sim_reader prog info` |

### Global Flags (available for all commands)

| Flag | Short | Description |
|------|-------|-------------|
| `--reader` | `-r` | Reader index |
| `--adm` | `-a` | ADM1 key |
| `--adm2` | | ADM2 key |
| `--adm3` | | ADM3 key |
| `--adm4` | | ADM4 key |
| `--pin` | `-p` | PIN1 code |
| `--json` | | JSON output |

### Shell Completion

Generate shell completion scripts for improved CLI experience:

```bash
# Bash
sim_reader completion bash > /etc/bash_completion.d/sim_reader

# Zsh
sim_reader completion zsh > "${fpath[1]}/_sim_reader"

# Fish
sim_reader completion fish > ~/.config/fish/completions/sim_reader.fish

# PowerShell
sim_reader completion powershell > sim_reader.ps1
```

### File Structure Changes

```
sim_reader/
├── main.go              # Minimal entry point (9 lines)
├── cmd/                 # NEW: Cobra commands
│   ├── root.go          # Root command + global flags
│   ├── read.go          # Read command
│   ├── write.go         # Write command
│   ├── gp.go            # GlobalPlatform commands
│   ├── auth.go          # Authentication command
│   ├── test.go          # Test suite command
│   ├── prog.go          # Programmable card command
│   ├── script.go        # Script commands
│   ├── completion.go    # Shell completion
│   └── common.go        # Common helpers
├── card/                # Unchanged
├── sim/                 # Unchanged
└── ...
```

### Breaking Changes

⚠️ **The old flat flag syntax is no longer supported.** All commands now require the new subcommand syntax.

### Documentation Updates

All documentation files updated with new command syntax:
- README.md
- docs/USAGE.md
- docs/WRITING.md
- docs/AUTHENTICATION.md
- docs/PROGRAMMABLE_CARDS.md
- docs/TESTING.md
- docs/GLOBALPLATFORM.md
- docs/PCOM.md

---

## v3.1.0 - Comprehensive SIM Card Test Suite

### Full Test Suite for USIM/ISIM Cards
Complete implementation of SIM card conformance testing according to 3GPP TS 31.102, TS 31.103, and ETSI TS 102.221 specifications:

- **46+ automated tests** covering all major card functions
- **JSON and HTML reports** for test documentation and analysis
- **Specification references** for each test (e.g., "TS 31.102 4.2.8")

### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| usim | 24 | USIM EF files: IMSI, AD, UST, EST, ACC, SPN, PLMN lists, Keys, LOCI |
| isim | 8 | ISIM parameters: IMPI, IMPU, Domain, IST, PCSCF, ARR |
| auth | 4 | 3G/GSM AUTHENTICATE, Milenage vectors, SQN resync |
| apdu | 10 | Low-level commands: SELECT, READ BINARY/RECORD, STATUS, VERIFY |
| security | 7 | Negative tests: wrong PIN, CLA, INS, P1P2, file not found |

### USIM Tests (TS 31.102)
- Application selection and AID verification
- EF.IMSI - International Mobile Subscriber Identity
- EF.AD - Administrative Data (operation mode, MNC length)
- EF.UST - USIM Service Table (enabled services count)
- EF.EST - Enabled Services Table
- EF.ACC - Access Control Class
- EF.SPN - Service Provider Name
- EF.HPPLMN - HPLMN search period
- PLMN lists: PLMNwAcT, OPLMNwAcT, HPLMNwAcT, FPLMN
- Location files: LOCI, PSLOCI, EPSLOCI
- Key files: Keys, KeysPS (KSI verification)
- EF.LI - Language preference
- EF.START-HFN, EF.THRESHOLD
- Linear fixed files: SMS, SMSP, MSISDN, ECC

### ISIM Tests (TS 31.103)
- Application selection
- EF.IMPI - IMS Private User Identity (BER-TLV tag 0x80)
- EF.IMPU - IMS Public User Identity (linear fixed)
- EF.DOMAIN - Home Network Domain Name
- EF.IST - ISIM Service Table
- EF.PCSCF - P-CSCF addresses
- EF.AD - Administrative Data (ISIM variant)
- EF.ARR - Access Rule Reference

### Authentication Tests (TS 35.206)
- 3G AUTHENTICATE (P2=0x81) with AUTS/SQN resync detection
- GSM AUTHENTICATE (P2=0x80) for 2G context
- Multiple sequential authentications
- Milenage vector computation and verification

### APDU Command Tests (TS 102.221)
- SELECT by MF (3F00), AID, FID
- SELECT P2 variants (FCP, no data, FCI)
- READ BINARY with offset
- READ RECORD (absolute mode, 6CXX handling)
- STATUS command (optional)
- VERIFY PIN status query (63CX remaining attempts)
- GET RESPONSE after 61XX

### Security/Negative Tests
- Wrong PIN → 63CX (skipped to avoid blocking)
- File not found → 6A82
- Security condition not satisfied → 6982
- Wrong length → 6700
- Wrong P1P2 → 6A86/6B00
- Wrong CLA → 6E00 (PC/SC reader filtering)
- Wrong INS → 6D00/6E00

### Card State Management
- **Automatic warm reset** on connection to ensure clean card state
- **Reset between test categories** to prevent cross-contamination
- **Robust error handling** for transport-level failures

### New Command Line Flags

| Flag | Description |
|------|-------------|
| `-test` | Run comprehensive SIM card test suite |
| `-test-output <prefix>` | Output file prefix for reports (.json + .html) |
| `-test-only <categories>` | Run specific categories: usim,isim,auth,apdu,security |

### Report Formats

#### JSON Report
```json
{
  "timestamp": "2025-12-28T20:46:49Z",
  "card_atr": "3B9F96801F878031E073FE211B674A357530350265F8",
  "summary": {
    "total": 53,
    "passed": 53,
    "failed": 0,
    "pass_rate": 100.0
  },
  "results": [...]
}
```

#### HTML Report
- Modern dark theme with responsive layout
- Color-coded pass/fail status
- APDU commands and responses
- Specification references
- Summary statistics with charts

### Usage Examples

```bash
# Run full test suite
./sim_reader -test -adm 24068496 -auth-k F2464E... -auth-opc B10B35... -test-output baseline

# Run only USIM file tests
./sim_reader -test -test-only usim -adm 24068496

# Run authentication tests
./sim_reader -test -test-only auth -auth-k F2464E... -auth-opc B10B35...

# Run multiple categories
./sim_reader -test -test-only usim,isim,auth -adm 24068496
```

### Documentation
- New [docs/TESTING.md](TESTING.md) with comprehensive test suite guide

---

## v3.0.0 - eSIM Profile Encoder/Decoder (SGP.22 SAIP 2.3)

### Full eSIM Profile Support
Complete implementation of GSMA eSIM Profile encoding and decoding according to SGP.22 / TS48 specification (SAIP 2.3):
- **Decode** DER-encoded eSIM profiles into structured Go types
- **Encode** Go structures back to DER with **100% byte-exact round-trip fidelity**
- Support for all 34 ProfileElement types defined in PE_Definitions

### Supported Profile Elements
| Tag | Element | Description |
|-----|---------|-------------|
| 0 | ProfileHeader | Version, ICCID, ProfileType, MandatoryServices |
| 1 | GenericFileManagement | File creation and content commands |
| 2 | PINCodes | PIN configurations and values |
| 3 | PUKCodes | PUK values and retry counters |
| 4 | AKAParameter | Ki, OPc, algorithm configuration (Milenage/TUAK) |
| 5 | CDMAParameter | CDMA authentication keys |
| 6 | SecurityDomain | GlobalPlatform SD with keys |
| 7 | RFM | Remote File Management configuration |
| 8 | Application | Generic application data |
| 10 | End | Profile termination element |
| 16 | MF | Master File with ICCID, DIR, ARR |
| 17 | CD | Card Directory |
| 18 | Telecom | Telecom DF with phonebook, graphics |
| 19 | USIM | USIM application (IMSI, keys, UST) |
| 20 | OptUSIM | Optional USIM files |
| 21 | ISIM | ISIM application (IMPI, IMPU) |
| 22 | OptISIM | Optional ISIM files |
| 23 | Phonebook | Phonebook DF |
| 24 | GSMAccess | GSM backward compatibility files |
| 25 | CSIM | CDMA SIM application |
| 26 | OptCSIM | Optional CSIM files |
| 27 | EAP | EAP application |
| 28 | DF5GS | 5G SA/NSA files (SUCI, 5G-GUTI) |
| 29 | DFSAIP | SAIP-specific files |

### ASN.1 Implementation
- **Custom BER/DER Parser**: Based on existing telecom protocol parser
- **Multi-byte Tag Support**: Handles tags > 30 (e.g., `BF 1F` for tag 31)
- **PRIVATE Class Tags**: Support for `[PRIVATE 6]` and `[PRIVATE 7]` tags in FCP
- **Long Length Encoding**: Handles lengths up to 65535 bytes
- **File SEQUENCE OF CHOICE**: Preserves exact structure of File elements

### Correct ASN.1 Tag Mapping (Fcp Structure)
Fixed tag numbers to match SGP.22 PE_Definitions:
| Field | Correct Tag | Previous |
|-------|-------------|----------|
| efFileSize | [0] | [5] |
| fileDescriptor | [2] | [0] |
| fileID | [3] | [1] |
| dfName | [4] | [6] |
| proprietaryEFInfo | [5] | [8] |
| shortEFID | [8] | [4] |
| lcsi | [10] | [2] |
| securityAttributesReferenced | [11] | [3] |
| pinStatusTemplateDO | [PRIVATE 6] | [7] |
| linkPath | [PRIVATE 7] | [9] |

### Lossless Round-Trip Encoding
- **RawBytes Preservation**: Original TLV bytes stored for each ProfileElement
- **Byte-Exact Output**: Encoded profile matches original DER exactly
- **Element-by-Element Verification**: Test compares each element's raw bytes

### New Package Structure
```
sim_reader/esim/
├── asn1/
│   ├── asn1.go          # Core ASN.1 BER/DER parser
│   └── asn1_test.go     # Parser unit tests
├── types.go             # Go struct definitions for all elements
├── tags.go              # ProfileElement tag constants
├── decoder.go           # DER → Go struct decoder
├── encoder.go           # Go struct → DER encoder
├── helpers.go           # BCD, OID, integer encoding utilities
├── profile.go           # High-level Profile API
├── decoder_test.go      # Decoder unit tests
└── integration_test.go  # Real profile round-trip tests
```

### New Types and Structures
- `Profile` - Complete eSIM profile with convenience accessors
- `ProfileElement` - Single element with Tag, Value, and RawBytes
- `FileElement` / `File` - Preserves SEQUENCE OF CHOICE structure
- `FileDescriptor` / `ElementaryFile` - FCP and file content
- `MandatoryServices` - eUICC capability flags
- `AlgoConfiguration` - Ki, OPc, algorithm parameters

### Profile API
```go
// Load and decode profile
profile, err := esim.LoadProfile("profile.der")

// Access fields
iccid := profile.GetICCID()           // "89000123456789012341"
imsi := profile.GetIMSI()             // "001010000000001"
ki, opc := profile.GetKiOPc()         // Authentication keys
profileType := profile.GetProfileType() // "GSMA Generic eUICC Test Profile"

// Check applications
hasUSIM := profile.HasUSIM()
hasISIM := profile.HasISIM()

// Modify and save
profile.Header.ProfileType = "Custom Profile"
err = profile.Save("modified.der")

// Create from scratch
newProfile := &esim.Profile{}
newProfile.Elements = append(newProfile.Elements, esim.ProfileElement{
    Tag: esim.TagProfileHeader,
    Value: &esim.ProfileHeader{
        MajorVersion: 2,
        MinorVersion: 3,
        ICCID: []byte{0x89, 0x00, 0x01, ...},
    },
})
data, err := esim.EncodeProfile(newProfile)
```

### Test Coverage
- **TestDecodeRealProfile**: Verifies decoding of GSMA test profile (TS48 V7.0)
- **TestRoundTripProfile**: Confirms byte-exact round-trip encoding
- **TestProfileElementsOrder**: Validates correct element sequence
- **TestEncodeProfileHeader**: Tests header encoding
- **TestEncodeWithPINPUK**: Tests PIN/PUK encoding
- **TestEncodeAKAParameter**: Tests authentication key encoding

### Tested With
- GSMA Generic eUICC Test Profile (TS48 V7.0 SAIP 2.3)
- 30 profile elements, 12,385 bytes
- 100% byte-exact round-trip verified

---

## v2.5.0 - Proprietary Driver Architecture & Deep ATR Analysis

### Internal Refactoring & Plugin Architecture
- **Proprietary Card Drivers**: All vendor-specific logic moved to `sim/card_drivers/` folder.
- **ProgrammableDriver Interface**: New decoupled architecture allowing easy addition of new card types.
- **Automatic Driver Discovery**: Cards are now identified via `init()` registration and ATR matching.
- **Algorithm Validation**: Ki and OPc validation moved to `algorithms/` package.
- **Codebase Cleanup**: Removed deprecated `card/programmable.go` and `sim/programmable_info.go`.

### New Card Support (based on pySim analysis)
- **sysmocom Extended Support**: 
  - sysmoUSIM-GR1 (proprietary unlock & write)
  - sysmoSIM-GR2 (SUPER ADM authentication)
  - sysmoUSIM-SJS1 (ADM1 verification)
  - sysmoISIM-SJA2 / SJA5 (Model detection and safety warnings for ICCID writes)
- **RuSIM / OX24**: New dedicated driver for algorithm selection (EF 8F90).

### Advanced ATR Analysis
- **Detailed Decomposition**: Full breakdown of ATR fields (TS, T0, TAi, TBi, TCi, TDi).
- **Technical Parameters**: Displaying Voltage Class (1.8V, 3V, 5V), Protocol (T=0/T=1), and Convention.
- **Transmission Specs**: Calculation of Fi, Di, and Baud Rate Factor.
- **Historical Bytes**: Decoding and displaying printable ASCII from historical bytes.
- **Integrated into `-analyze`**: Detailed ATR table added to the card analysis output.

### Compatibility & Reliability
- **Smart PIN Verification**: Automatic fallback to GSM class (`0xA0`) if standard PIN verify fails.
- **Dynamic CLA Selection**: The base class (0x00 or 0xA0) is now determined by the card driver.
- **PrepareWrite Handshake**: Drivers can now perform necessary setup (like GRv2 handshake) before any write operation (IMSI, SPN, etc.).

---

## v2.4.0 - Programmable SIM Card Support

### Full Programmable Card Support
- Complete support for programming blank/writable SIM cards
- Supported card types:
  - **Grcard v2 (GRv2)**: open5gs, Gialer, OYEITIMES cards with proprietary APDU protocol
  - **Grcard v1 (GRv1)**: Generic programmable cards with standard USIM commands
  - **sysmocom sysmoUSIM-GR1**: Professional programmable cards
- Automatic card type detection by ATR pattern matching

### Cryptographic Key Programming
- **Ki (Subscriber Key)**: Write 128-bit authentication key
- **OPc/OP**: Write operator code or compute OPc from OP automatically
- **Milenage Parameters**: Write R and C constants according to 3GPP TS 35.206
- **Algorithm Selection**: Set authentication algorithm (Milenage/XOR) for GRv2 cards

### Standard File Programming
- **ICCID**: Write card identifier (18-20 digits)
- **MSISDN**: Write phone number
- **ACC**: Write Access Control Class
- **PIN/PUK Codes**: Set PIN1/PUK1 and PIN2/PUK2 (GRv2)

### JSON Configuration
- New `programmable` section in JSON config:
```json
{
  "programmable": {
    "ki": "F2464E3293019A7E51ABAA7B1262B7D8",
    "op": "CDC202D5123E20F62B6D676AC72CB318",
    "iccid": "89860061100000000123",
    "msisdn": "+1234567890",
    "pin1": "1234",
    "puk1": "12345678",
    "algorithm": "milenage"
  },
  "imsi": "250880000000001",
  "spn": "My Network"
}
```
- Single unified config file for all card parameters
- Combine programmable and standard parameters in one JSON

### Safety Features
- **Dry Run Mode** (`-prog-dry-run`): Test all operations without writing to card
- **Card Type Detection**: Automatic identification of programmable cards by ATR
- **Force Override** (`-prog-force`): Option to program unrecognized cards (dangerous!)
- **Interactive Warnings**: Clear warnings about permanent nature of operations
- **Validation**: All parameters validated before writing

### New Command Line Flags
| Flag | Description |
|------|-------------|
| `-prog-info` | Show programmable card information (card type, File IDs) |
| `-prog-dry-run` | Simulate programming without writing (safe test mode) |
| `-prog-force` | Force programming on unrecognized cards (DANGEROUS!) |

### Low-Level APDU Support
- **GRv2 Handshake**: Proprietary activation command for GRv2 cards
- **GRv2 File Selection**: Low-level SELECT commands with proprietary class byte (A0)
- **GRv2 Binary Update**: Direct binary writes to proprietary files
- **GRv2 Record Update**: Record-based writes for Milenage constants

### Proprietary File IDs
#### GRv1 Cards
- Ki: `7FF0 FF02`
- OPc: `7FF0 FF01`
- Milenage R: `7FF0 FF03`
- Milenage C: `7FF0 FF04`

#### GRv2 Cards
- Ki: `0001`
- OPc: `6002`
- Algorithm Type: `2FD0`
- Milenage R/C: `2FE6`
- ADM Key: `0B00`
- PIN1/PUK1: `0100`
- PIN2/PUK2: `0200`

### Documentation
- New [docs/PROGRAMMABLE_CARDS.md](PROGRAMMABLE_CARDS.md) with comprehensive guide (English)
- Example configuration file: [docs/programmable_custom_example.json](programmable_custom_example.json)
- Safety warnings and best practices
- ATR patterns for known programmable cards
- Troubleshooting guide for common issues

### Internal Architecture
- New `sim/programmable.go`: High-level programming functions
- New `sim/programmable_info.go`: Card information display
- Enhanced `card/programmable.go`: Low-level GRv2 protocol implementation
- New `card.FileInfo` type for file metadata
- New `card.GetFileInfo()` method for reading file parameters
- OPc computation using existing Milenage implementation

### Usage Examples
```bash
# Show card info
./sim_reader -prog-info

# Safe test (dry run)
./sim_reader -adm 4444444444444444 -write config.json -prog-dry-run

# Program card
./sim_reader -adm 4444444444444444 -write config.json
```

### Breaking Changes
- None - all changes are additions

### Compatibility
- Fully backward compatible with v2.3.0
- Standard USIM/ISIM cards unaffected
- ATR-gated detection prevents accidental probing of non-programmable cards

---

## v2.3.0 - Extended APDU, Improved FCP Parsing, Full JSON Export

### Extended APDU Support (ISO 7816-4)
- Added `ReadBinaryExtended()` for reading files up to 65535 bytes
- Added `UpdateBinaryExtended()` for writing files up to 65535 bytes
- Automatic fallback to chunked mode if card doesn't support extended APDU

### Improved READ RECORD Command
- Added `ReadRecordWithMode()` with addressing mode parameter
- New modes: Absolute (0x04), Next (0x02), Previous (0x03)
- Added helper functions: `ReadNextRecord()`, `ReadPreviousRecord()`

### Improved UPDATE BINARY Command
- Automatic chunk size reduction on SW=6700 (Wrong Length)
- `WriteAllBinary()` now handles cards with smaller buffer sizes
- Added `WriteAllBinaryWithChunkSize()` for explicit chunk control

### Enhanced FCP Parsing (ETSI TS 102 221)
- Added support for extended length format (0x81, 0x82, 0x83 length bytes)
- Added support for tag 0x81 as alternative file size tag
- Fixed record size parsing for various card formats
- Improved robustness for proprietary card implementations

### GBA/MBMS Authentication Context Support
- Added `AUTH_CONTEXT_GBA_NAF` (0x83) for NAF key derivation
- Added `AUTH_CONTEXT_LOCAL` (0x86) for local key establishment
- New `AuthenticateWithData()` function supporting NAF_Id parameter
- Enhanced MBMS context handling

### Full JSON Export/Import Parity
- JSON export (`-json`) now includes all readable parameters:
  - ICCID, MSISDN (read-only, for reference)
  - Languages preference (EF_LI)
  - Access Control Classes (read-only)
  - HPLMN search period
  - Forbidden PLMNs list (read-only, use `clear_fplmn` to clear)
- Complete round-trip: read card → edit JSON → write back

### New JSON Config Fields
| Field | Type | Description |
|-------|------|-------------|
| `iccid` | string | Card ID (read-only) |
| `msisdn` | string | Phone number (read-only) |
| `languages` | []string | Language preferences |
| `acc` | []int | Access Control Classes (read-only) |
| `hplmn_period` | int | HPLMN search period in minutes |
| `fplmn` | []string | Forbidden PLMNs (read-only) |

---

## v2.2.2 - Programmable Card Guardrails and Proprietary NAA (EF 8F90) Support

### Proprietary USIM Algorithm Selector (EF 8F90)
- Added optional support for reading and writing the proprietary USIM authentication algorithm selector EF `8F90` (NAA byte)
- Supported values:
  - `0x1F` = Milenage
  - `0x2E` = S3G-128
  - `0x3D` = TUAK
  - `0x4C` = S3G-256

### Safety Guardrails (No Impact on Standard Cards)
- The `8F90` feature is **ATR-gated** and is only enabled for supported programmable/proprietary card families
- Standard vendor USIM/ISIM cards are not probed for this proprietary EF

### New Command Line Flags
| Flag | Description |
|------|-------------|
| `-show-card-algo` | Show current proprietary USIM algorithm selector (EF `8F90`) when supported |
| `-set-card-algo` | Set proprietary USIM algorithm selector (EF `8F90`) when supported |

### Compatibility Improvements
- Improved USIM/ISIM selection logic: fallback to DF path (`7FF0`/`7FF2`) for cards that do not reliably expose EF_DIR/AID selection
- Added GSM class (`CLA=A0`) fallback for administrative operations on cards that require legacy GSM class APDUs

---

## v2.2.1 - Embedded Dictionaries for ATR and MCC/MNC Lookup

### Embedded Dictionaries
- ATR and MCC/MNC dictionaries are now compiled into the binary using Go embed
- Binary is fully self-contained - no external dictionary files needed
- Lazy initialization with thread-safe loading (sync.Once)

### ATR Dictionary
- **17,000+ ATR patterns** from the PC/SC Tools project
- Automatic card type identification by ATR
- Regex-based pattern matching with wildcard support (`..` = any byte)
- Source: [pcsc-tools.apdu.fr/smartcard_list.txt](https://pcsc-tools.apdu.fr/smartcard_list.txt)

### MCC/MNC Dictionary  
- **2,700+ mobile operators** worldwide
- Country identification by MCC
- Operator and brand names by MCC+MNC
- Region and ISO country codes
- Source: [csvbase.com/ilya/mcc-mnc](https://csvbase.com/ilya/mcc-mnc)

### Dictionary Updates
To update dictionaries, download fresh files to `dictionaries/` folder and rebuild:
```bash
curl -o dictionaries/smartcard_list.txt https://pcsc-tools.apdu.fr/smartcard_list.txt
curl -o dictionaries/mcc-mnc.csv "https://csvbase.com/ilya/mcc-mnc.csv"
go build .
```

---

## v2.2.0 - Authentication Testing with Milenage and TUAK

### Authentication Module
- New `-auth` flag to enable authentication test mode
- Full implementation of **Milenage** algorithm (3GPP TS 35.206)
- Full implementation of **TUAK** algorithm (3GPP TS 35.231) with Keccak-f[1600]
- Support for 128-bit and 256-bit keys (TUAK)

### Authentication Vector Computation
- Compute all authentication functions: f1, f1*, f2, f3, f4, f5, f5*
- Generate authentication vectors (RAND, AUTN, XRES, CK, IK, AK)
- Automatic RAND generation if not provided
- OP to OPc conversion

### SIM Card Authentication
- Send AUTHENTICATE command to USIM
- Verify RES matches XRES
- Handle sync failures (AUTS processing)
- Extract SQNms from AUTS for resynchronization
- Suggest next SQN value (SQNms + 1)

### Derived Key Computation
- **KASME** computation for LTE (3GPP TS 33.401)
- **2G triplets** generation (SRES, Kc) for backward compatibility

### Card-Only Mode
- Send pre-captured RAND+AUTN to card without knowing K
- Useful for testing with network captures or dumps
- Returns RES, CK, IK from card

### Pre-Computed Values Support
- `-auth-autn` flag to use AUTN from dump (skip calculation)
- `-auth-auts` flag to process AUTS from dump (extract SQNms)

### New Command Line Flags
| Flag | Description |
|------|-------------|
| `-auth` | Enable authentication mode |
| `-auth-k` | Subscriber key K |
| `-auth-op` | Operator key OP |
| `-auth-opc` | Pre-computed OPc |
| `-auth-sqn` | Sequence number |
| `-auth-amf` | Auth Management Field |
| `-auth-rand` | Random challenge |
| `-auth-autn` | Pre-computed AUTN |
| `-auth-auts` | AUTS for SQN resync |
| `-auth-algo` | Algorithm (milenage/tuak) |
| `-auth-mcc` | Mobile Country Code |
| `-auth-mnc` | Mobile Network Code |
| `-auth-no-card` | Compute without card |

### Documentation
- New [docs/AUTHENTICATION.md](AUTHENTICATION.md) with detailed usage guide

---

## v2.1.0 - Multi-ADM key support and file access conditions analysis

### Multiple ADM Keys Support
- Added `-adm2`, `-adm3`, `-adm4` flags for cards with multiple administrative keys
- Automatic re-authentication after application selection (fixes "Security status not satisfied" error)
- Support for cards with up to 4 ADM levels

### File Access Conditions Analysis (`-adm-check` flag)
- New `-adm-check` flag to display file access requirements
- Shows READ and WRITE access conditions for all USIM/ISIM files
- Color-coded output: PIN1 (green), ADM1 (cyan), ADM2 (yellow), ADM3 (magenta), ADM4 (red)
- Parses EF_ARR (Access Rule Reference) format per ETSI TS 102 221
- Works independently from `-analyze` flag

### ADM Keys Status Table
- Shows which ADM keys exist on the card (ADM1-ADM4)
- Displays remaining retry attempts for each key
- Safe status check using VERIFY with Lc=0 (doesn't decrement counters)

### Debug Mode (`-debug-fcp` flag)
- New `-debug-fcp` flag for FCP (File Control Parameters) debugging
- Shows raw FCP data and ARR record parsing details

### Bug Fixes
- Fixed "Security status not satisfied" error after USIM/ISIM application selection
- Fixed AID detection order (now detected before write operations)

---

## v2.0.7 - Extended card support and PCOM script execution

- Added support for additional programmable cards
- Auto-detection of card type by ATR
- GSM class commands (CLA=A0) support
- File ID selection fallback when AID selection not supported
- Added `-pcom` flag for executing .pcom personalization scripts
- Full .pcom syntax support:
  - `.DEFINE %VAR value` - Variable definitions with recursive expansion
  - `.CALL filename` - Nested script execution with shared context
  - `.POWER_ON` / `.POWER_ON /COLD` - Warm/cold card reset
  - `.POWER_OFF` - Card power off
  - `.ALLUNDEFINE` - Clear all variables
  - `%VAR` - Variable substitution in APDU commands
  - `W(pos;len)` / `R(pos;len)` - Extract bytes from response
  - `(9XXX)` - Wildcard SW matching
  - `[XXXX]` - Wildcard response data matching
  - `;` / `;;` - Comments
  - `\` - Line continuation for long values
- Added `-pcom-verbose` and `-pcom-stop-on-error` flags
- Script execution statistics (total/success/failed commands)
- Call stack tracking for debugging nested scripts

---

## v2.0.6 - GlobalPlatform and APDU scripting

- Added `-applets` flag to list GlobalPlatform applets
- Added `-script` flag for pysim-like APDU script execution
- Script format: `apdu <hex>` commands with `#` comments
- Useful for SIM personalization and provisioning

---

## v2.0.5 - JSON export and extended reading

- Added `-json` flag for config-compatible JSON output (edit and reload with `-write`)
- Added `-phonebook` flag to read phonebook entries (EF_ADN)
- Added `-sms` flag to read SMS messages (EF_SMS)
- Added Location Information display (EF_LOCI, EF_PSLOCI, EF_EPSLOCI)
- Added Language preference display (EF_LI)
- Added HPLMN Search Period display (EF_HPPLMN)
- PLMN tables only shown when data exists (cleaner output)
- Clean JSON output without progress messages

---

## v2.0.4 - PLMN improvements

- Added Operator PLMN write (`-write-oplmn` flag)
- Added full EF Files Reference in README

---

## v2.0.3 - Test network support

- Added UE Operation Mode support (`-set-op-mode` flag)
- All 3GPP modes: normal, type-approval, cell-test, maintenance, etc.
- Added User Controlled PLMN write (`-write-user-plmn` flag)
- JSON config support for `operation_mode` and `user_plmn`
- Better support for test PLMNs (001-01, 999-99)

---

## v2.0.2 - Card analysis and testing improvements

- Added `-analyze` flag for unknown card analysis
- Added `-dump` flag for generating test data
- Auto-detect non-standard AIDs from EF_DIR
- Card manufacturer detection by ATR
- GSM 2G fallback for legacy SIM cards
- Unit tests with real card data

---

## v2.0.1

- Added HPLMN (Home PLMN) write support with Access Technology

---

## v2.0.0

- Added write support (IMSI, ISIM params, services, JSON config)

---

## v1.0.0

- Initial release (read-only)

