


A command-line tool written in Go for reading and writing SIM/USIM/ISIM card parameters using PC/SC smart card readers.

---

## ⚠️ DISCLAIMER

**READ THIS BEFORE USING THE SOFTWARE**

This software is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.

**THIS TOOL IS INTENDED FOR:**
- Telecommunications professionals and engineers
- Researchers working with SIM card technology
- Developers of mobile network infrastructure
- Individuals who have legitimate access to programmable SIM cards and understand the implications of modifying them

**WARNINGS:**
1. **IRREVERSIBLE DAMAGE**: Writing incorrect data to a SIM card can permanently damage it, rendering it unusable. This damage is typically irreversible.

2. **ADM KEY BLOCKING**: The administrative (ADM) keys have a limited number of retry attempts. Entering an incorrect ADM key multiple times will **permanently block** the card's administrative access. This cannot be recovered.

3. **SERVICE DISRUPTION**: Modifying SIM card parameters incorrectly can cause loss of network connectivity, inability to make calls, or other service disruptions.

4. **LEGAL COMPLIANCE**: Users are responsible for ensuring their use of this software complies with all applicable laws and regulations in their jurisdiction. Unauthorized modification of SIM cards may be illegal in some countries.

**BY USING THIS SOFTWARE, YOU ACKNOWLEDGE THAT:**
- You understand the risks involved in modifying SIM card data
- You have the necessary technical knowledge to use this tool safely
- You have legitimate authorization to modify the SIM cards you are working with
- You accept full responsibility for any damage, data loss, or other consequences resulting from the use of this software

**THE AUTHOR(S) AND CONTRIBUTOR(S) SHALL NOT BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM THE USE OF THIS SOFTWARE, INCLUDING BUT NOT LIMITED TO:**
- Damaged or bricked SIM cards
- Loss of mobile network access
- Blocked ADM keys
- Any direct, indirect, incidental, special, exemplary, or consequential damages

**If you do not agree to these terms, do not use this software.**

---

## Features

### Reading
- Read SIM card identity: ICCID, IMSI, MSISDN
- Display network information: MCC, MNC, PLMN lists (HPLMN, OPLMN, FPLMN)
- Read USIM Service Table (UST) with human-readable service names
- Read ISIM application: IMPI, IMPU, Home Domain, P-CSCF addresses
- Read ISIM Service Table (IST)
- Beautiful colored console output with tables

### Writing (NEW in v2.0)
- Write IMSI, SPN (Service Provider Name)
- Write ISIM parameters: IMPI, IMPU, Domain, P-CSCF
- Enable/disable services: VoLTE, VoWiFi, SMS over IP
- Clear Forbidden PLMN list
- JSON configuration file support for batch operations
- Individual parameter flags for quick changes

## Supported Card Types

- Standard SIM (2G)
- USIM (3G/4G/5G)
- ISIM (IMS/VoLTE/VoWiFi)

## Prerequisites

### macOS

1. **PC/SC Framework** - comes pre-installed with macOS (PCSC.framework)

2. **pkg-config** - required for building:
   ```bash
   brew install pkg-config
   ```

3. **Go 1.21+** - install from https://go.dev/dl/ or via Homebrew:
   ```bash
   brew install go
   ```

4. **Smart Card Reader** - any PC/SC compatible reader, for example:
   - ACS ACR38/ACR39/ACR40/ACR122U
   - Omnikey 3121/5021
   - Gemalto IDBridge
   - Any USB CCID reader

### Linux (Debian/Ubuntu)

1. **PC/SC libraries**:
   ```bash
   sudo apt-get install libpcsclite-dev pcscd pcsc-tools
   ```

2. **Start PC/SC daemon**:
   ```bash
   sudo systemctl start pcscd
   sudo systemctl enable pcscd
   ```

3. **Go 1.21+**:
   ```bash
   sudo apt-get install golang-go
   # or download from https://go.dev/dl/
   ```

### Windows

1. **WinSCard** - comes pre-installed with Windows

2. **Go 1.21+** - download from https://go.dev/dl/

3. **MinGW or MSYS2** - for CGO compilation:
   ```bash
   choco install mingw
   ```

## Building

```bash
# Clone or download the project
cd sim_reader

# Download dependencies
go mod tidy

# Build
go build -o sim_reader .

# Or build for specific platform
GOOS=darwin GOARCH=amd64 go build -o sim_reader_mac_amd64 .
GOOS=darwin GOARCH=arm64 go build -o sim_reader_mac_arm64 .
GOOS=linux GOARCH=amd64 go build -o sim_reader_linux .
GOOS=windows GOARCH=amd64 go build -o sim_reader.exe .
```

## Usage

### Reading Card Data

```bash
# List available smart card readers
./sim_reader -list

# Read card (auto-selects reader if only one)
./sim_reader -adm 77111606

# Read card in specific reader
./sim_reader -r 0 -adm 77111606

# Show all UST/IST services in detail
./sim_reader -adm 77111606 -services

# Show raw hex data
./sim_reader -adm 77111606 -raw

# If card is PIN-protected
./sim_reader -pin 0000 -adm 77111606
```

### Writing Card Data

#### Method 1: JSON Configuration File (Recommended for batch operations)

```bash
# Create a sample configuration file
./sim_reader -create-sample my_config.json

# Edit the configuration file, then apply it
./sim_reader -adm 77111606 -write my_config.json
```

**Sample configuration file:**
```json
{
  "imsi": "250880000000001",
  "spn": "My Operator",
  "mcc": "250",
  "mnc": "88",
  "isim": {
    "impi": "250880000000001@ims.mnc088.mcc250.3gppnetwork.org",
    "impu": [
      "sip:250880000000001@ims.mnc088.mcc250.3gppnetwork.org"
    ],
    "domain": "ims.mnc088.mcc250.3gppnetwork.org",
    "pcscf": [
      "pcscf.ims.mnc088.mcc250.3gppnetwork.org"
    ]
  },
  "services": {
    "volte": true,
    "vowifi": true,
    "isim_pcscf": true,
    "isim_sms_over_ip": true,
    "isim_voice_domain_pref": true
  },
  "clear_fplmn": true
}
```

#### Method 2: Command Line Flags (Quick individual changes)

```bash
# Write IMSI
./sim_reader -adm 77111606 -write-imsi 250880000000001

# Write Service Provider Name
./sim_reader -adm 77111606 -write-spn "My Operator"

# Write ISIM parameters
./sim_reader -adm 77111606 -write-impi "250880000000001@ims.mnc088.mcc250.3gppnetwork.org"
./sim_reader -adm 77111606 -write-impu "sip:250880000000001@ims.mnc088.mcc250.3gppnetwork.org"
./sim_reader -adm 77111606 -write-domain "ims.mnc088.mcc250.3gppnetwork.org"
./sim_reader -adm 77111606 -write-pcscf "pcscf.ims.mnc088.mcc250.3gppnetwork.org"

# Enable VoLTE services (UST service 87)
./sim_reader -adm 77111606 -enable-volte

# Enable VoWiFi services (UST services 89, 90, 124)
./sim_reader -adm 77111606 -enable-vowifi

# Enable SMS over IP in ISIM (IST service 7)
./sim_reader -adm 77111606 -enable-sms-ip

# Enable Voice Domain Preference in ISIM (IST service 12)
./sim_reader -adm 77111606 -enable-voice-pref

# Disable VoLTE services
./sim_reader -adm 77111606 -disable-volte

# Disable VoWiFi services
./sim_reader -adm 77111606 -disable-vowifi

# Disable SMS over IP in ISIM
./sim_reader -adm 77111606 -disable-sms-ip

# Disable Voice Domain Preference in ISIM
./sim_reader -adm 77111606 -disable-voice-pref

# Clear Forbidden PLMN list
./sim_reader -adm 77111606 -clear-fplmn
```

#### Method 3: Combined (Config + Flags)

```bash
# Apply config and also enable VoLTE and clear FPLMN
./sim_reader -adm 77111606 -write config.json -enable-volte -clear-fplmn
```

## ADM Key Formats

The tool automatically detects the ADM key format:

| Format | Example | Description |
|--------|---------|-------------|
| Hex (16 chars) | `F38A3DECF6C7D239` | NovaCard, most programmable SIMs |
| Decimal (8 digits) | `77111606` | Sysmocom cards (converted to ASCII) |

## Configuration File Reference

| Field | Type | Description |
|-------|------|-------------|
| `imsi` | string | IMSI (15 digits) |
| `spn` | string | Service Provider Name |
| `mcc` | string | Mobile Country Code (3 digits) |
| `mnc` | string | Mobile Network Code (2-3 digits) |
| `isim.impi` | string | IMS Private User Identity |
| `isim.impu` | array | IMS Public User Identities |
| `isim.domain` | string | Home Network Domain Name |
| `isim.pcscf` | array | P-CSCF addresses |
| `services.volte` | bool | Enable VoLTE (UST 87) |
| `services.vowifi` | bool | Enable VoWiFi (UST 89,90,124) |
| `services.gsm_access` | bool | GSM Access (UST 27) |
| `services.isim_pcscf` | bool | P-CSCF in IST (IST 1) |
| `services.isim_sms_over_ip` | bool | SMS over IP (IST 7) |
| `services.isim_voice_domain_pref` | bool | Voice Domain Pref (IST 12) |
| `clear_fplmn` | bool | Clear Forbidden PLMN list |

## Output Example

```
╭───────────────────────────────────────────────────────────────────────────╮
│ SIM CARD INFORMATION (USIM)                                               │
├──────────────────────┬────────────────────────────────────────────────────┤
│ ICCID                │ 89701880000000000176                               │
│ IMSI                 │ 250880000000017                                    │
│ Service Provider     │ SUPER                                              │
╰──────────────────────┴────────────────────────────────────────────────────╯

╭───────────────────────────────────────────────────────────────────────────────────────╮
│ IMS PARAMETERS (ISIM)                                                                 │
├────────────────────────┬──────────────────────────────────────────────────────────────┤
│ IMPI (Private ID)      │ 250880000000017@ims.mnc088.mcc250.3gppnetwork.org            │
│ IMPU 1 (Public ID)     │ sip:250880000000017@ims.mnc088.mcc250.3gppnetwork.org        │
│ Home Domain            │ ims.mnc088.mcc250.3gppnetwork.org                            │
╰────────────────────────┴──────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────────────────╮
│ P-CSCF ADDRESSES                                                     │
├─────────────────┬────────────────────────────────────────────────────┤
│ P-CSCF 1        │ pcscf.rf.epc.ims.mnc088.mcc250.3gppnetwork.org     │
╰─────────────────┴────────────────────────────────────────────────────╯
```

## Project Structure

```
sim_reader/
├── main.go              # CLI entry point
├── card/
│   ├── reader.go        # PC/SC reader connection
│   ├── apdu.go          # APDU commands (SELECT, READ, UPDATE)
│   └── auth.go          # ADM1/PIN authentication
├── sim/
│   ├── files.go         # EF file definitions (IDs, names)
│   ├── usim.go          # USIM application reader
│   ├── isim.go          # ISIM application reader
│   ├── decoder.go       # Data decoders (BCD, PLMN, TLV)
│   ├── encoder.go       # Data encoders for writing
│   ├── usim_write.go    # USIM write functions
│   ├── isim_write.go    # ISIM write functions
│   └── config.go        # JSON config handling
├── output/
│   └── table.go         # Colored table output
├── go.mod
├── go.sum
├── sample_config.json   # Sample configuration
└── README.md
```

## Dependencies

- [github.com/ebfe/scard](https://github.com/ebfe/scard) - PC/SC bindings for Go
- [github.com/jedib0t/go-pretty/v6](https://github.com/jedib0t/go-pretty) - Beautiful tables
- [github.com/fatih/color](https://github.com/fatih/color) - Colored console output

## Troubleshooting

### "Service not available" error

**macOS:**
```bash
# Check if reader is detected
system_profiler SPUSBDataType | grep -i reader

# PC/SC service should auto-start
ps aux | grep pcscd
```

**Linux:**
```bash
# Start PC/SC daemon
sudo systemctl start pcscd

# Check reader
pcsc_scan
```

### "No smart card readers found"

1. Make sure the reader is connected via USB
2. Try a different USB port
3. Check if the reader LED is on
4. On Linux, ensure your user is in the `pcscd` group

### "Failed to connect to card"

1. Make sure a SIM card is inserted in the reader
2. Check card orientation (chip facing down for most readers)
3. Try reinserting the card

### ADM key verification fails

1. Double-check the ADM key value
2. Make sure you're using the correct format (hex vs decimal)
3. **Warning:** Too many failed attempts will permanently block the ADM key!

### Write operation fails

1. Verify ADM1 key is correct
2. Some files may require ADM2 or higher access level
3. Check if the file exists on the card (not all cards have all files)
4. ISIM application must be present for ISIM writes

## Security Warning

⚠️ **Important:**
- ADM keys have a limited retry counter (typically 3-10 attempts)
- After exhausting retries, the ADM key is **permanently blocked**
- A blocked ADM key **cannot be recovered**
- Always verify your ADM key before using it
- Test with non-critical cards first

## References

- 3GPP TS 31.102 - USIM Application
- 3GPP TS 31.103 - ISIM Application
- ETSI TS 102 221 - UICC-Terminal Interface
- ISO/IEC 7816-4 - Smart Card Commands

## License

MIT License

## Version History

- **v2.0.0** - Added write support (IMSI, ISIM params, services, JSON config)
- **v1.0.0** - Initial release (read-only)
