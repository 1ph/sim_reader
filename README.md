# SIM Reader

A command-line tool written in Go for reading and writing SIM/USIM/ISIM card parameters using PC/SC smart card readers.

---

## ⚠️ DISCLAIMER

**READ THIS BEFORE USING THE SOFTWARE**

### Open Standards Only

**This software is developed using only publicly available specifications:**
- 3GPP TS 31.102 - USIM Application
- 3GPP TS 31.103 - ISIM Application  
- ETSI TS 102 221 - UICC-Terminal Interface
- ISO/IEC 7816-4 - Smart Card Commands

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
- **Authentication**: Test 3G/4G authentication with Milenage and TUAK algorithms
- **Card Analysis**: Auto-detect card type by ATR, read EF_DIR, file access conditions
- **Multiple ADM Keys**: Support for up to 4 ADM keys (`-adm`, `-adm2`, `-adm3`, `-adm4`)
- **PCOM Scripts**: Execute personalization scripts for programmable cards

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

# Analyze card
./sim_reader -analyze

# Check file access conditions
./sim_reader -adm-check

# Write configuration
./sim_reader -adm YOUR_ADM_KEY -write config.json

# Test authentication (compute vectors)
./sim_reader -auth -auth-k YOUR_K -auth-opc YOUR_OPC -auth-mcc 250 -auth-mnc 88 -auth-no-card

# Test authentication with card
./sim_reader -auth -auth-k YOUR_K -auth-opc YOUR_OPC -auth-mcc 250 -auth-mnc 88
```

## Documentation

| Document | Description |
|----------|-------------|
| [docs/USAGE.md](docs/USAGE.md) | Detailed usage guide |
| [docs/WRITING.md](docs/WRITING.md) | Writing card data |
| [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) | Authentication testing (Milenage/TUAK) |
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
