# SIM Reader

A command-line tool written in Go for reading and writing SIM/USIM/ISIM card parameters using PC/SC smart card readers.

**Version 3.2.0**

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
- **JSON Export/Import**: Full round-trip support (`--json` → edit → `write -f`)
- **Advanced ATR Analysis**: Detailed breakdown of voltage, protocols, and transmission parameters (ISO 7816-3)
- **Programmable SIM Cards**: Modular driver-based support for blank/programmable cards
  - **Supported**: Grcard v1/v2, sysmocom (GR1, GR2, SJS1, SJA2, SJA5), RuSIM/OX24
  - Write cryptographic keys (Ki, OPc/OP)
  - Write Milenage R/C constants
  - Write ICCID, MSISDN, ACC
  - Set PIN/PUK codes
  - Safe dry-run mode for testing
- **Authentication**: Test 3G/4G/5G authentication with Milenage and TUAK algorithms
- **Test Suite**: Comprehensive conformance testing (46+ tests) with JSON/HTML reports
- **Card Analysis**: Auto-detect card type by ATR, read EF_DIR, file access conditions
- **Multiple ADM Keys**: Support for up to 4 ADM keys (`-a`, `--adm2`, `--adm3`, `--adm4`)
- **PCOM Scripts**: Execute personalization scripts for programmable cards
- **GlobalPlatform**: Secure channel (SCP02/SCP03) for applet management
- **Extended APDU**: Support for large file operations (up to 64KB)
- **Proprietary Profiles**: Plug-and-play drivers for switching USIM authentication algorithms.
- **Shell Autocomplete**: Built-in completion for bash, zsh, fish, and PowerShell

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
# Show help
./sim_reader --help

# List readers
./sim_reader read --list

# Read card
./sim_reader read -a YOUR_ADM_KEY

# Export card data to JSON (for editing and re-importing)
./sim_reader read -a YOUR_ADM_KEY --json > card_config.json

# Write configuration from JSON
./sim_reader write -a YOUR_ADM_KEY -f card_config.json

# Analyze card
./sim_reader read --analyze

# Check file access conditions
./sim_reader read --adm-check

# Test authentication (compute vectors)
./sim_reader auth -k YOUR_K --opc YOUR_OPC --mcc 250 --mnc 88 --no-card

# Test authentication with card
./sim_reader auth -k YOUR_K --opc YOUR_OPC --mcc 250 --mnc 88

# Run comprehensive test suite
./sim_reader test -a YOUR_ADM -k YOUR_K --opc YOUR_OPC -o report

# (Programmable cards only) Show / set proprietary USIM algorithm selector
./sim_reader write -a YOUR_ADM_KEY --show-algo
./sim_reader write -a YOUR_ADM_KEY --set-algo milenage

# Program blank SIM cards (Grcard, open5gs)
# Show programmable card info
./sim_reader prog info

# Safe test (dry run) - no data written
./sim_reader write -a YOUR_ADM_KEY -f programmable_config.json --dry-run

# Actually program the card (PERMANENT!)
./sim_reader write -a YOUR_ADM_KEY -f programmable_config.json

# Generate shell completion
./sim_reader completion bash > /etc/bash_completion.d/sim_reader
```

## Command Structure

sim_reader uses subcommands for different operations:

```
sim_reader [global flags] <command> [command flags]

Commands:
  read        Read SIM card data
  write       Write SIM card parameters
  gp          GlobalPlatform operations
  auth        Run authentication test
  test        Run SIM card test suite
  prog        Programmable card operations
  script      Execute APDU scripts
  completion  Generate shell completion scripts
```

### Global Flags (available for all commands)

| Flag | Description |
|------|-------------|
| `-r, --reader N` | Use reader index N (default: auto-select) |
| `-a, --adm KEY` | ADM1 key (hex or decimal format) |
| `--adm2 KEY` | ADM2 key for higher access level |
| `--adm3 KEY` | ADM3 key for even higher access level |
| `--adm4 KEY` | ADM4 key |
| `-p, --pin CODE` | PIN1 code (if card is PIN-protected) |
| `--json` | Output in JSON format |

### Read Command

```bash
./sim_reader read [flags]
```

| Flag | Description |
|------|-------------|
| `-l, --list` | List available smart card readers |
| `--analyze` | Analyze card structure and applications |
| `--phonebook` | Show phonebook entries (EF_ADN) |
| `--sms` | Show SMS messages |
| `--applets` | Show GlobalPlatform applets |
| `--services` | Show all UST/IST services in detail |
| `--raw` | Show raw hex data |
| `--adm-check` | Show file access conditions |
| `--dump NAME` | Dump card data as Go test code |
| `--create-sample FILE` | Create sample configuration file |

### Write Command

```bash
./sim_reader write [flags]
```

| Flag | Description |
|------|-------------|
| `-f, --file FILE` | Apply configuration from JSON file |
| `--imsi VALUE` | Write IMSI |
| `--impi VALUE` | Write IMPI (IMS Private Identity) |
| `--impu VALUE` | Write IMPU (IMS Public Identity) |
| `--domain VALUE` | Write Home Network Domain |
| `--pcscf VALUE` | Write P-CSCF address |
| `--spn VALUE` | Write Service Provider Name |
| `--hplmn MCC:MNC:ACT` | Write Home PLMN with Access Technology |
| `--oplmn MCC:MNC:ACT` | Write Operator PLMN |
| `--user-plmn MCC:MNC:ACT` | Write User Controlled PLMN |
| `--op-mode MODE` | Set UE Operation Mode |
| `--enable-volte` | Enable VoLTE services |
| `--disable-volte` | Disable VoLTE services |
| `--enable-vowifi` | Enable VoWiFi services |
| `--disable-vowifi` | Disable VoWiFi services |
| `--clear-fplmn` | Clear Forbidden PLMN list |
| `--change-adm1 KEY` | Change ADM1 key |
| `--show-algo` | Show current USIM auth algorithm |
| `--set-algo ALGO` | Set USIM algorithm (milenage, tuak, etc.) |
| `--dry-run` | Simulate without writing (safe mode) |
| `--force` | Force on unrecognized cards (DANGEROUS!) |

### Auth Command

```bash
./sim_reader auth [flags]
```

| Flag | Description |
|------|-------------|
| `-k, --key KEY` | Subscriber key K (hex) |
| `--op OP` | Operator key OP (hex) |
| `--opc OPC` | Pre-computed OPc (hex) |
| `--sqn SQN` | Sequence number (default: 000000000000) |
| `--amf AMF` | Authentication Management Field (default: 8000) |
| `--rand RAND` | Random challenge (auto-generated if empty) |
| `--autn AUTN` | Pre-computed AUTN |
| `--auts AUTS` | AUTS for SQN resynchronization |
| `--algo ALGO` | Algorithm: milenage or tuak |
| `--mcc MCC` | Mobile Country Code (for KASME) |
| `--mnc MNC` | Mobile Network Code (for KASME) |
| `--no-card` | Compute vectors without card |

### GlobalPlatform Commands

```bash
./sim_reader gp <subcommand> [flags]

Subcommands:
  list      List applets via Secure Channel
  probe     Verify keys without EXTERNAL AUTH
  delete    Delete applets/packages by AID
  load      Load and install CAP file
  aram      Add ARA-M access rule
  verify    Verify applet AID (SELECT)
```

Common GP flags:
| Flag | Description |
|------|-------------|
| `--kvn N` | Key Version Number (0-255) |
| `--sec LEVEL` | Security level: mac or mac+enc |
| `--key-enc KEY` | Static ENC key |
| `--key-mac KEY` | Static MAC key |
| `--key-dek KEY` | Static DEK key |
| `--key-psk KEY` | Convenience: ENC=MAC=PSK |
| `--sd-aid AID` | Security Domain AID |
| `--dms FILE` | DMS var_out key file |
| `--auto` | Auto-probe KVN+keyset |

### Test Command

```bash
./sim_reader test [flags]
```

| Flag | Description |
|------|-------------|
| `-o, --output PREFIX` | Output file prefix for reports (.json + .html) |
| `--only CATEGORIES` | Run specific categories: usim,isim,auth,apdu,security |
| `-k, --key KEY` | K key for auth tests |
| `--opc OPC` | OPc for auth tests |
| `--sqn SQN` | Sequence number |

### Script Commands

```bash
./sim_reader script run <file>    # Run simple APDU script
./sim_reader script pcom <file>   # Run PCOM personalization script
```

| Flag | Description |
|------|-------------|
| `--verbose` | Verbose output (default: true) |
| `--stop-on-error` | Stop on first error |

### Prog Command

```bash
./sim_reader prog info    # Show programmable card information
```

## Usage Examples

```bash
# List readers
./sim_reader read --list

# Read card with ADM key
./sim_reader read -a 77111606

# Read with all services
./sim_reader read -a 77111606 --services

# Export to JSON
./sim_reader read -a 77111606 --json > config.json

# Write from JSON
./sim_reader write -a 77111606 -f config.json

# Write individual parameters
./sim_reader write -a 77111606 --imsi 250880000000001
./sim_reader write -a 77111606 --pcscf pcscf.ims.domain.org

# Enable services
./sim_reader write -a 77111606 --enable-volte --enable-vowifi

# Clear forbidden networks
./sim_reader write -a 77111606 --clear-fplmn

# Run PCOM script
./sim_reader script pcom /path/to/script.pcom

# Authentication test (compute only)
./sim_reader auth -k F2464E3293019A7E51ABAA7B1262B7D8 \
  --opc B10B351A0CCD8BE31E0C9F088945A812 --no-card

# Authentication with card
./sim_reader auth -k F2464E3293019A7E51ABAA7B1262B7D8 \
  --opc B10B351A0CCD8BE31E0C9F088945A812 --mcc 250 --mnc 88

# Run full test suite
./sim_reader test -a 4444444444444444 \
  -k FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0 \
  --opc 808182838485868788898A8B8C8D8E8F -o baseline

# GlobalPlatform list applets
./sim_reader gp list --key-enc AABBCC... --key-mac DDEEFF...

# Programmable card: dry run
./sim_reader write -a 4444444444444444 -f prog_config.json --dry-run

# Generate bash completion
./sim_reader completion bash
```

## JSON Configuration Format

The `--json` flag exports all readable card parameters. Edit and re-import with `write -f`:

```bash
# Export current card configuration
./sim_reader read -a YOUR_KEY --json > config.json

# Edit config.json, then write back
./sim_reader write -a YOUR_KEY -f config.json
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
| [docs/TESTING.md](docs/TESTING.md) | Comprehensive test suite for USIM/ISIM |
| [docs/GLOBALPLATFORM.md](docs/GLOBALPLATFORM.md) | GlobalPlatform secure channels |
| [docs/PCOM.md](docs/PCOM.md) | PCOM script execution |
| [docs/EF_FILES.md](docs/EF_FILES.md) | EF file reference |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Problem solving |
| [docs/VERSION_HISTORY.md](docs/VERSION_HISTORY.md) | Version history |

## Project Structure

```
sim_reader/
├── main.go              # CLI entry point
├── cmd/                 # Cobra commands
│   ├── root.go          # Root command and global flags
│   ├── read.go          # Read command
│   ├── write.go         # Write command
│   ├── gp.go            # GlobalPlatform commands
│   ├── auth.go          # Authentication command
│   ├── test.go          # Test suite command
│   ├── prog.go          # Programmable card command
│   ├── script.go        # Script execution commands
│   └── completion.go    # Shell completion
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
- [github.com/spf13/cobra](https://github.com/spf13/cobra) - CLI framework

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
