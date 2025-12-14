# Version History

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

