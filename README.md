# SIM Reader

A command-line tool written in Go for reading and writing SIM/USIM/ISIM card parameters using PC/SC smart card readers.

**Version 2.5.0**

---

## ⚠️ DISCLAIMER

**READ THIS BEFORE USING THE SOFTWARE**

### Open Standards Only

**This software is developed using only publicly available specifications:**
- 3GPP TS 31.102 - USIM Application
- 3GPP TS 31.103 - ISIM Application  
- ETSI TS 102 221 - UICC-Terminal Interface
- ISO/IEC 7816-4 - Smart Card Commands
- GlobalPlatform Card Specification

**The author(s) do not have access to any proprietary, confidential, or non-public information from any smart card manufacturer, mobile operator, or other organization.** All functionality is implemented based solely on publicly available 3GPP/ETSI/ISO standards and open documentation.

### Liability

This software is provided "AS IS", without warranty of any kind, express or implied.

**WARNINGS:**
1. **IRREVERSIBLE DAMAGE**: Writing incorrect data to a SIM card can permanently damage it
2. **ADM KEY BLOCKING**: Incorrect ADM key attempts will **permanently block** administrative access
3. **SERVICE DISRUPTION**: Incorrect modifications can cause loss of network connectivity
4. **LEGAL COMPLIANCE**: Users are responsible for compliance with applicable laws

**THE AUTHOR(S) SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM THE USE OF THIS SOFTWARE.**

**If you do not agree to these terms, do not use this software.**

---

## Features

- **Reading**: ICCID, IMSI, MSISDN, PLMN lists, Service Tables, ISIM parameters
- **Writing**: IMSI, SPN, PLMN lists, ISIM parameters, service configuration
- **JSON Export/Import**: Full round-trip support (`-json` → edit → `-write`)
- **Advanced ATR Analysis**: Detailed breakdown of voltage, protocols, and transmission parameters (ISO 7816-3)
- **Programmable SIM Cards**: Modular driver-based support for blank/programmable cards
  - **Supported**: Grcard v1/v2, sysmocom (GR1, GR2, SJS1, SJA2, SJA5), RuSIM/OX24
  - Write cryptographic keys (Ki, OPc/OP)
  - Write Milenage R/C constants
  - Write ICCID, MSISDN, ACC
  - Set PIN/PUK codes
  - Safe dry-run mode for testing
- **Authentication**: Test 3G/4G/5G authentication with Milenage and TUAK algorithms
- **Card Analysis**: Auto-detect card type by ATR, read EF_DIR, file access conditions
- **Multiple ADM Keys**: Support for up to 4 ADM keys (`-adm`, `-adm2`, `-adm3`, `-adm4`)
- **PCOM Scripts**: Execute personalization scripts for programmable cards
- **GlobalPlatform**: Secure channel (SCP02/SCP03) for applet management
- **Extended APDU**: Support for large file operations (up to 64KB)
- **Proprietary Profiles**: Plug-and-play drivers for switching USIM authentication algorithms.

## Supported Card Types

- Standard SIM (2G)
- USIM (3G/4G/5G)
- ISIM (IMS/VoLTE/VoWiFi)

## Prerequisites

### macOS

```bash
brew install pkg-config go
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install libpcsclite-dev pcscd pcsc-tools golang-go
sudo systemctl start pcscd
```

### Windows

- Go 1.21+ from https://go.dev/dl/
- MinGW or MSYS2 for CGO compilation

## Building

```bash
# Download dependencies
go mod tidy

# Build
go build -o sim_reader .
```

### Cross-Platform Build with Docker

```bash
# Build for ALL platforms
make build-all

# Build for specific platform
make build-linux
make build-darwin
make build-windows
```

## Quick Start

```bash
# List readers
./sim_reader -list

# Read card
./sim_reader -adm YOUR_ADM_KEY

# Export card data to JSON (for editing and re-importing)
./sim_reader -adm YOUR_ADM_KEY -json > card_config.json

# Write configuration from JSON
./sim_reader -adm YOUR_ADM_KEY -write card_config.json

# Analyze card
./sim_reader -analyze

# Check file access conditions
./sim_reader -adm-check

# Test authentication (compute vectors)
./sim_reader -auth -auth-k YOUR_K -auth-opc YOUR_OPC -auth-mcc 250 -auth-mnc 88 -auth-no-card

# Test authentication with card
./sim_reader -auth -auth-k YOUR_K -auth-opc YOUR_OPC -auth-mcc 250 -auth-mnc 88

# (Programmable cards only) Show / set proprietary USIM algorithm selector (EF 8F90)
# Supported values: milenage, s3g-128, tuak, s3g-256
./sim_reader -adm YOUR_ADM_KEY -show-card-algo
./sim_reader -adm YOUR_ADM_KEY -set-card-algo milenage -show-card-algo

# Program blank SIM cards (Grcard, open5gs)
# Show programmable card info
./sim_reader -prog-info

# Safe test (dry run) - no data written
./sim_reader -adm YOUR_ADM_KEY -write programmable_config.json -prog-dry-run

# Actually program the card (PERMANENT!)
./sim_reader -adm YOUR_ADM_KEY -write programmable_config.json
```

## Command Line Reference

### Reading Options

| Flag | Description |
|------|-------------|
| `-list` | List available smart card readers |
| `-r N` | Use reader index N (default: auto-select if only one) |
| `-adm KEY` | ADM1 key (hex or decimal format) |
| `-adm2 KEY` | ADM2 key for higher access level |
| `-adm3 KEY` | ADM3 key for even higher access level |
| `-adm4 KEY` | ADM4 key |
| `-pin CODE` | PIN1 code (if card is PIN-protected) |
| `-raw` | Show raw hex data |
| `-services` | Show all UST/IST services in detail |
| `-phonebook` | Show phonebook entries (EF_ADN) |
| `-json` | Output in JSON format (for editing and re-importing with -write) |
| `-analyze` | Analyze card structure and applications |
| `-adm-check` | Show file access conditions (which key is needed for each file) |
| `-debug-fcp` | Debug FCP (File Control Parameters) parsing |

### Writing Options

| Flag | Description |
|------|-------------|
| `-write FILE` | Write configuration from JSON file |
| `-sample FILE` | Create sample configuration file |
| `-write-imsi VALUE` | Write IMSI |
| `-write-spn VALUE` | Write Service Provider Name |
| `-write-hplmn MCC:MNC:ACT` | Write Home PLMN with Access Technology |
| `-write-oplmn MCC:MNC:ACT` | Write Operator PLMN |
| `-write-user-plmn MCC:MNC:ACT` | Write User Controlled PLMN |
| `-set-op-mode MODE` | Set UE Operation Mode (normal, cell-test, etc.) |
| `-clear-fplmn` | Clear Forbidden PLMN list |
| `-enable-volte` | Enable VoLTE services |
| `-disable-volte` | Disable VoLTE services |
| `-enable-vowifi` | Enable VoWiFi services |
| `-disable-vowifi` | Disable VoWiFi services |

### Authentication Options

| Flag | Description |
|------|-------------|
| `-auth` | Enable authentication mode |
| `-auth-k KEY` | Subscriber key K (hex) |
| `-auth-op OP` | Operator key OP (hex) |
| `-auth-opc OPC` | Pre-computed OPc (hex) |
| `-auth-sqn SQN` | Sequence number (hex, default: 000000000000) |
| `-auth-amf AMF` | Authentication Management Field (hex, default: 8000) |
| `-auth-rand RAND` | Random challenge (hex, auto-generated if not provided) |
| `-auth-autn AUTN` | Pre-computed AUTN (for card-only mode) |
| `-auth-auts AUTS` | AUTS for SQN resynchronization |
| `-auth-algo ALGO` | Algorithm: milenage or tuak (default: milenage) |
| `-auth-mcc MCC` | Mobile Country Code (for KASME) |
| `-auth-mnc MNC` | Mobile Network Code (for KASME) |
| `-auth-no-card` | Compute vectors without card |

### GlobalPlatform Options

| Flag | Description |
|------|-------------|
| `-applets` | List GlobalPlatform applets |
| `-gp-key KEY` | GlobalPlatform key (hex) |
| `-gp-key-enc` | Separate ENC key |
| `-gp-key-mac` | Separate MAC key |
| `-gp-key-dek` | Separate DEK key |
| `-gp-kvn N` | Key Version Number (0-255) |
| `-gp-scp VER` | Secure Channel Protocol (auto, 02, 03) |

### Script Execution

| Flag | Description |
|------|-------------|
| `-pcom FILE` | Execute PCOM personalization script |
| `-pcom-verbose` | Show detailed script execution |
| `-pcom-stop-on-error` | Stop on first error |
| `-script FILE` | Execute APDU script (pysim format) |

### Programmable Card Options

| Flag | Description |
|------|-------------|
| `-prog-info` | Show programmable card information (card type, supported operations) |
| `-prog-dry-run` | Test programmable card operations without writing (safe mode) |
| `-prog-force` | Force programming on unrecognized cards (DANGEROUS!) |
| `-show-card-algo` | Show current USIM algorithm selector (EF 8F90) |
| `-set-card-algo ALGO` | Set USIM algorithm (milenage, s3g-128, tuak, s3g-256) |

**Note**: Programmable card write operations use JSON configuration with `programmable` section. See [docs/PROGRAMMABLE_CARDS.md](docs/PROGRAMMABLE_CARDS.md) for details.

### Other Options

| Flag | Description |
|------|-------------|
| `-version` | Show version |
| `-dump NAME` | Dump card data as Go test code |

## JSON Configuration Format

The `-json` flag exports all readable card parameters. Edit and re-import with `-write`:

```bash
# Export current card configuration
./sim_reader -adm YOUR_KEY -json > config.json

# Edit config.json, then write back
./sim_reader -adm YOUR_KEY -write config.json
```

### JSON Fields

| Field | Type | Writable | Description |
|-------|------|----------|-------------|
| `iccid` | string | No | Card identifier (read-only) |
| `msisdn` | string | No | Phone number (read-only) |
| `imsi` | string | Yes | International Mobile Subscriber Identity |
| `spn` | string | Yes | Service Provider Name |
| `mcc` | string | Yes | Mobile Country Code |
| `mnc` | string | Yes | Mobile Network Code |
| `operation_mode` | string | Yes | UE mode: normal, cell-test, type-approval, etc. |
| `languages` | []string | No | Language preferences (read-only) |
| `acc` | []int | No | Access Control Classes (read-only) |
| `hplmn_period` | int | No | HPLMN search period in minutes (read-only) |
| `hplmn` | []object | Yes | Home PLMN with Access Technology |
| `oplmn` | []object | Yes | Operator PLMN list |
| `user_plmn` | []object | Yes | User Controlled PLMN list |
| `fplmn` | []string | No | Forbidden PLMNs (use `clear_fplmn` to clear) |
| `clear_fplmn` | bool | Yes | Clear Forbidden PLMN list on write |
| `isim` | object | Yes | ISIM parameters (IMPI, IMPU, Domain, PCSCF) |
| `services` | object | Yes | Service flags (VoLTE, VoWiFi, GBA, etc.) |
| `programmable` | object | Yes | Programmable card parameters (Ki, OPc, ICCID, etc.) - see [PROGRAMMABLE_CARDS.md](docs/PROGRAMMABLE_CARDS.md) |

### Example JSON

```json
{
  "iccid": "89701880000000000176",
  "imsi": "250880000000017",
  "spn": "My Operator",
  "mcc": "250",
  "mnc": "88",
  "operation_mode": "normal",
  "hplmn": [
    {"mcc": "250", "mnc": "88", "act": ["eutran", "utran", "gsm"]}
  ],
  "isim": {
    "impi": "250880000000017@ims.mnc088.mcc250.3gppnetwork.org",
    "impu": ["sip:250880000000017@ims.mnc088.mcc250.3gppnetwork.org"],
    "domain": "ims.mnc088.mcc250.3gppnetwork.org"
  },
  "services": {
    "volte": true,
    "vowifi": true
  },
  "clear_fplmn": true
}
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USAGE.md](docs/USAGE.md) | Detailed usage guide |
| [docs/WRITING.md](docs/WRITING.md) | Writing card data |
| [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) | Authentication testing (Milenage/TUAK) |
| [docs/PROGRAMMABLE_CARDS.md](docs/PROGRAMMABLE_CARDS.md) | Programmable SIM cards (Grcard, open5gs) |
| [docs/GLOBALPLATFORM.md](docs/GLOBALPLATFORM.md) | GlobalPlatform secure channels |
| [docs/PCOM.md](docs/PCOM.md) | PCOM script execution |
| [docs/EF_FILES.md](docs/EF_FILES.md) | EF file reference |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Problem solving |
| [docs/VERSION_HISTORY.md](docs/VERSION_HISTORY.md) | Version history |

## Project Structure

```
sim_reader/
├── main.go              # CLI entry point
├── algorithms/          # Milenage and TUAK authentication algorithms
├── card/                # PC/SC reader, APDU commands, authentication
├── sim/                 # USIM/ISIM readers, decoders, writers
├── output/              # Colored table output
├── dictionaries/        # Embedded ATR and MCC/MNC dictionaries
├── docs/                # Documentation
└── Makefile             # Build commands
```

## Embedded Dictionaries

The binary includes embedded dictionaries for card identification and operator lookup. These are compiled into the executable using Go embed - no external files needed at runtime.

| Dictionary | Records | Description | Source |
|------------|---------|-------------|--------|
| ATR | 17,000+ | Smart card identification by ATR | [PC/SC Tools](https://pcsc-tools.apdu.fr/smartcard_list.txt) |
| MCC/MNC | 2,700+ | Mobile operators worldwide | [csvbase.com](https://csvbase.com/ilya/mcc-mnc) |

### Updating Dictionaries

To update dictionaries with the latest data:

```bash
# Download fresh dictionary files
curl -o dictionaries/smartcard_list.txt https://pcsc-tools.apdu.fr/smartcard_list.txt
curl -o dictionaries/mcc-mnc.csv "https://csvbase.com/ilya/mcc-mnc.csv"

# Rebuild to embed updated dictionaries
go build .
```

## Dependencies

- [github.com/ebfe/scard](https://github.com/ebfe/scard) - PC/SC bindings for Go
- [github.com/jedib0t/go-pretty/v6](https://github.com/jedib0t/go-pretty) - Tables
- [github.com/fatih/color](https://github.com/fatih/color) - Colored output

## References

- 3GPP TS 31.102 - USIM Application
- 3GPP TS 31.103 - ISIM Application
- 3GPP TS 33.102 - Security architecture
- 3GPP TS 33.401 - EPS security architecture
- 3GPP TS 35.206 - Milenage algorithm
- 3GPP TS 35.231 - TUAK algorithm
- ETSI TS 102 221 - UICC-Terminal Interface
- ISO/IEC 7816-4 - Smart Card Commands

## License

MIT License
