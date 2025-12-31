# Writing SIM Card Data

Complete guide for writing parameters to SIM/USIM/ISIM cards, including programmable cards.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Standard Cards](#standard-cards)
- [Programmable Cards](#programmable-cards)
- [JSON Configuration Reference](#json-configuration-reference)
- [Command Line Reference](#command-line-reference)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Export → Edit → Import (Recommended)

```bash
# Step 1: Export current card configuration
./sim_reader read -a 77111606 --json > my_card.json

# Step 2: Edit my_card.json with any text editor

# Step 3: Write back to card
./sim_reader write -a 77111606 -f my_card.json
```

### Create New Configuration

```bash
# Create sample configuration file
./sim_reader read --create-sample my_config.json

# Edit and apply
./sim_reader write -a 77111606 -f my_config.json
```

---

## Standard Cards

Standard (non-programmable) SIM cards support writing the following parameters:

### Writable Parameters

| Parameter | Description |
|-----------|-------------|
| IMSI | Subscriber identity (15 digits) |
| SPN | Service Provider Name |
| HPLMN | Home PLMN with Access Technology |
| OPLMN | Operator PLMN (roaming partners) |
| User PLMN | User preferred networks |
| ISIM params | IMPI, IMPU, Domain, P-CSCF |
| Services | VoLTE, VoWiFi, SMS over IP, etc. |
| Operation Mode | Normal, Cell Test, etc. |

### Example Configuration

```json
{
  "imsi": "250880000000001",
  "spn": "My Operator",
  "mcc": "250",
  "mnc": "88",
  "operation_mode": "normal",
  "hplmn": [
    {"mcc": "250", "mnc": "88", "act": ["eutran", "utran", "gsm"]}
  ],
  "user_plmn": [
    {"mcc": "001", "mnc": "01", "act": ["eutran", "utran", "gsm"]}
  ],
  "isim": {
    "impi": "250880000000001@ims.mnc088.mcc250.3gppnetwork.org",
    "impu": ["sip:250880000000001@ims.mnc088.mcc250.3gppnetwork.org"],
    "domain": "ims.mnc088.mcc250.3gppnetwork.org",
    "pcscf": ["pcscf.ims.mnc088.mcc250.3gppnetwork.org"]
  },
  "services": {
    "volte": true,
    "vowifi": true,
    "isim_pcscf": true,
    "isim_voice_domain_pref": true
  },
  "clear_fplmn": true
}
```

---

## Programmable Cards

⚠️ **CRITICAL WARNING**: Programming SIM cards is an **IRREVERSIBLE** operation that can **PERMANENTLY DAMAGE** the card!

### What are Programmable Cards?

Programmable SIM cards (blank SIM, writable SIM) are empty cards that can be programmed from scratch:

- **Ki** - Subscriber key (authentication key)
- **OPc/OP** - Operator key  
- **ICCID** - Card identifier
- **MSISDN** - Phone number
- **PIN/PUK** - Security codes
- **Algorithm** - Authentication algorithm (Milenage, TUAK, etc.)

### Legal Usage

✅ **Allowed**: Test networks, R&D, Private LTE/5G, Education

❌ **Prohibited**: Cloning operator cards, Fraud, Violating operator terms

### Supported Cards

| Card Type | Ki/OPc | ICCID | Notes |
|-----------|--------|-------|-------|
| Grcard V2 | ✅ | ✅ | Full support (open5gs, Gialer, OYEITIMES) |
| Grcard V1 | ✅ | ✅ | Fallback driver |
| sysmoUSIM-SJS1 | ✅ | ✅ | Standard sysmocom profile |
| sysmoISIM-SJA2/SJA5 | ✅ | ⚠️ | ICCID may affect license |
| sysmoUSIM-GR1 | ⚠️ | ✅ | Requires special unlock |
| sysmoSIM-GR2 | ⚠️ | ✅ | Uses SUPER ADM |
| RuSIM/OX24 | ❌ | ✅ | Ki via .pcom scripts only |

### Check Card Type

```bash
# Show programmable card information
./sim_reader read --card-info
```

**Output**:
```
╔════════════════════════════════════════════════════════════════════╗
║              PROGRAMMABLE CARD INFORMATION                         ║
╚════════════════════════════════════════════════════════════════════╝

Card Type:        Grcard v2 / open5gs (GRv2)
ATR Pattern:      3B9F95801FC78031A073B6A10067CF3211B252C679

✓ This card supports programmable operations
```

### Safety Rules

1. **ALWAYS use `--dry-run` first!**
   ```bash
   ./sim_reader write -a ADM_KEY -f config.json --dry-run
   ```

2. **Check card type** before writing

3. **Have backup cards** for testing

4. **Double-check values**:
   - Ki: 32 hex characters (128-bit)
   - OPc: 32 hex characters (128-bit)
   - ICCID: 18-20 digits

5. **Never interrupt** the programming process!

### What Can Go Wrong

| Problem | Consequence | Recovery |
|---------|-------------|----------|
| Wrong Ki/OPc | Auth fails | ❌ Irreversible |
| Wrong ICCID | Card not recognized | ❌ Irreversible |
| Interrupted write | Partial data | ❌ Card bricked |
| Wrong card type | Commands fail | ⚠️ May brick |

### Programmable Card Configuration

```json
{
  "imsi": "250880000000001",
  "iccid": "89860061100000000123",
  "msisdn": "+1234567890",
  
  "ki": "F2464E3293019A7E51ABAA7B1262B7D8",
  "opc": "B10B351A0CCD8BE31E0C9F088945A812",
  "algorithm": "milenage",
  
  "acc_hex": "0001",
  "pin1": "1234",
  "puk1": "12345678",
  "pin2": "5678",
  "puk2": "87654321",
  
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

### Using OP Instead of OPc

If you have OP (not OPc), provide both Ki and OP - OPc will be computed automatically:

```json
{
  "ki": "F2464E3293019A7E51ABAA7B1262B7D8",
  "op": "CDC202D5123E20F62B6D676AC72CB318",
  "imsi": "250880000000001"
}
```

### Programming Commands

```bash
# Dry run (ALWAYS do this first!)
./sim_reader write -a 4444444444444444 -f config.json --dry-run

# Real write
./sim_reader write -a 4444444444444444 -f config.json

# Force on unrecognized cards (DANGEROUS!)
./sim_reader write -a 4444444444444444 -f config.json --force
```

### ATR Patterns

**Grcard V2**:
```
3B9F95801FC78031A073B6A10067CF3211B252C679  (open5gs)
3B9F94801FC38031A073B6A10067CF3210DF0EF5
3B9F94801FC38031A073B6A10067CF3250DF0E72
```

**sysmoISIM-SJA2**:
```
3B9F96801F878031E073FE211B674A4C753034054BA9
3B9F96801F878031E073FE211B674A4C7531330251B2
```

**sysmoISIM-SJA5**:
```
3B9F96801F878031E073FE211B674A357530350251CC
```

**RuSIM/OX24**:
```
3B959640F00F050A0F0A
```

---

## JSON Configuration Reference

### Identity Fields

| Field | Type | Writable | Description |
|-------|------|----------|-------------|
| `iccid` | string | Prog only | Card identifier (18-20 digits) |
| `msisdn` | string | Yes | Phone number |
| `imsi` | string | Yes | Subscriber identity (15 digits) |

### Network Parameters

| Field | Type | Description |
|-------|------|-------------|
| `spn` | string | Service Provider Name |
| `mcc` | string | Mobile Country Code (3 digits) |
| `mnc` | string | Mobile Network Code (2-3 digits) |
| `operation_mode` | string | UE operation mode |
| `hplmn` | array | Home PLMN entries |
| `oplmn` | array | Operator PLMN entries |
| `user_plmn` | array | User preferred networks |
| `clear_fplmn` | bool | Clear forbidden PLMN list |

### PLMN Entry Format

```json
{
  "mcc": "250",
  "mnc": "88", 
  "act": ["eutran", "utran", "gsm", "nr", "ngran"]
}
```

### ISIM Parameters

| Field | Type | Description |
|-------|------|-------------|
| `isim.impi` | string | IMS Private User Identity |
| `isim.impu` | array | IMS Public User Identities |
| `isim.domain` | string | Home Network Domain Name |
| `isim.pcscf` | array | P-CSCF addresses |

### Programmable Card Fields

| Field | Type | Description |
|-------|------|-------------|
| `ki` | string | Subscriber key (32 hex chars) |
| `op` | string | Operator key OP (32 hex chars) |
| `opc` | string | Operator key OPc (32 hex chars) |
| `algorithm` | string | Auth algorithm: milenage, xor, tuak, s3g-128, s3g-256 |
| `acc_hex` | string | Access Control Class (4 hex chars) |
| `pin1` | string | PIN1 code (4-8 digits) |
| `puk1` | string | PUK1 code (8 digits) |
| `pin2` | string | PIN2 code (4-8 digits) |
| `puk2` | string | PUK2 code (8 digits) |

### Service Flags

| Field | Type | UST/IST | Description |
|-------|------|---------|-------------|
| `services.volte` | bool | UST 87 | VoLTE support |
| `services.vowifi` | bool | UST 89,90,124 | VoWiFi/ePDG support |
| `services.sms_over_ip` | bool | UST | SMS over IP |
| `services.gsm_access` | bool | UST 27 | GSM Access |
| `services.call_control` | bool | UST 30 | Call Control |
| `services.gba` | bool | UST 67 | GBA support |
| `services.5g_nas_config` | bool | UST 104 | 5G NAS config |
| `services.5g_nssai` | bool | UST 108 | 5G NSSAI |
| `services.suci_calculation` | bool | UST 112 | SUCI calculation |
| `services.isim_pcscf` | bool | IST 1 | P-CSCF in ISIM |
| `services.isim_sms_over_ip` | bool | IST 7 | SMS over IP (ISIM) |
| `services.isim_voice_domain_pref` | bool | IST 12 | Voice Domain Preference |
| `services.isim_gba` | bool | IST 2 | GBA in ISIM |
| `services.isim_http_digest` | bool | IST 3 | HTTP Digest |

### UE Operation Modes

| Mode | Value | Description |
|------|-------|-------------|
| `normal` | 0x00 | Normal operation |
| `type-approval` | 0x01 | Type approval operations |
| `normal-specific` | 0x02 | Normal + specific facilities |
| `type-approval-specific` | 0x04 | Type approval + specific |
| `maintenance` | 0x08 | Maintenance (off-line) |
| `cell-test` | 0x80 | Cell test (for PLMNs 001-01, 999-99) |

---

## Command Line Reference

### Read Commands

```bash
# List readers
./sim_reader read --list

# Read card data
./sim_reader read -a ADM_KEY

# Export as JSON
./sim_reader read -a ADM_KEY --json > card.json

# Show programmable card info
./sim_reader read --card-info

# Analyze card structure
./sim_reader read --analyze

# Create sample config
./sim_reader read --create-sample config.json
```

### Write Commands

```bash
# Write from JSON file
./sim_reader write -a ADM_KEY -f config.json

# Dry run (test without writing)
./sim_reader write -a ADM_KEY -f config.json --dry-run

# Force on unrecognized programmable cards
./sim_reader write -a ADM_KEY -f config.json --force

# Individual parameters
./sim_reader write -a ADM_KEY --imsi 250880000000001
./sim_reader write -a ADM_KEY --spn "My Operator"
./sim_reader write -a ADM_KEY --impi "user@domain"
./sim_reader write -a ADM_KEY --hplmn "250:88:eutran,utran,gsm"
./sim_reader write -a ADM_KEY --user-plmn "001:01:eutran"
./sim_reader write -a ADM_KEY --op-mode cell-test

# Enable/disable services
./sim_reader write -a ADM_KEY --enable-volte
./sim_reader write -a ADM_KEY --enable-vowifi
./sim_reader write -a ADM_KEY --disable-volte
./sim_reader write -a ADM_KEY --clear-fplmn

# Set algorithm (programmable cards)
./sim_reader write -a ADM_KEY --set-algo milenage
./sim_reader write -a ADM_KEY --show-algo

# Change ADM keys
./sim_reader write -a OLD_KEY --change-adm1 NEW_KEY
```

---

## Troubleshooting

### "Card is not recognized as programmable"

1. Check ATR: `./sim_reader read --analyze`
2. Check if card is supported (see ATR patterns above)
3. Use `--force` if you're sure it's programmable (dangerous!)
4. Contact support to add new ATR patterns

### "Handshake failed"

- Card may already be programmed
- Wrong card type
- Try removing and reinserting the card

### "UPDATE returned error: 6982"

- Wrong ADM key
- Insufficient permissions

### "Card doesn't authenticate after programming"

- Wrong Ki or OPc values
- ❌ **Cannot be fixed - card is bricked**
- Always use `--dry-run` first!

### "SELECT failed" or "No USIM application"

- Card may be GSM-only (no USIM)
- Try: `./sim_reader read --analyze`

---

## Backward Compatibility

Old configuration files with `"programmable": {...}` section are still supported but deprecated:

```json
{
  "programmable": {
    "ki": "...",
    "opc": "..."
  }
}
```

Will be automatically migrated to:

```json
{
  "ki": "...",
  "opc": "..."
}
```

---

## Additional Resources

- [3GPP TS 35.206](https://www.3gpp.org/ftp/Specs/archive/35_series/35.206/) - Milenage algorithm
- [Open5GS](https://open5gs.org/) - Open source 5G core
- [sysmocom](https://www.sysmocom.de/) - Professional programmable cards

---

## Disclaimer

⚠️ **Authors are NOT responsible for damaged cards!**

Programming SIM cards requires understanding of the process and can lead to irreversible damage.

**If you're not sure what you're doing - DON'T DO IT!**
