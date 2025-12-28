# Writing Card Data

## Method 1: Export, Edit, Import (Recommended)

The easiest way to modify card data is to export current settings, edit the JSON, and write back:

```bash
# Step 1: Export current card configuration to JSON
./sim_reader read -a 77111606 --json > my_card.json

# Step 2: Edit my_card.json with any text editor
# - Modify writable fields (imsi, spn, hplmn, services, etc.)
# - Read-only fields (iccid, msisdn, acc) are for reference only

# Step 3: Write the modified configuration back to card
./sim_reader write -a 77111606 -f my_card.json
```

This ensures all parameters are correctly formatted and you can see what values are currently on the card.

## Method 2: Create New Configuration

```bash
# Create a sample configuration file (with example values)
./sim_reader read --create-sample my_config.json

# Edit the configuration file, then apply it
./sim_reader write -a 77111606 -f my_config.json
```

**Sample configuration file:**
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
  "oplmn": [
    {"mcc": "250", "mnc": "20", "act": ["eutran", "utran", "gsm"]}
  ],
  "user_plmn": [
    {"mcc": "001", "mnc": "01", "act": ["eutran", "utran", "gsm"]}
  ],
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

## Method 3: Command Line Flags (Quick individual changes)

```bash
# Write IMSI
./sim_reader write -a 77111606 --imsi 250880000000001

# Write Service Provider Name
./sim_reader write -a 77111606 --spn "My Operator"

# Write ISIM parameters
./sim_reader write -a 77111606 --impi "250880000000001@ims.mnc088.mcc250.3gppnetwork.org"
./sim_reader write -a 77111606 --impu "sip:250880000000001@ims.mnc088.mcc250.3gppnetwork.org"
./sim_reader write -a 77111606 --domain "ims.mnc088.mcc250.3gppnetwork.org"
./sim_reader write -a 77111606 --pcscf "pcscf.ims.mnc088.mcc250.3gppnetwork.org"

# Enable VoLTE services (UST service 87)
./sim_reader write -a 77111606 --enable-volte

# Enable VoWiFi services (UST services 89, 90, 124)
./sim_reader write -a 77111606 --enable-vowifi

# Enable SMS over IP in ISIM (IST service 7)
./sim_reader write -a 77111606 --enable-sms-ip

# Enable Voice Domain Preference in ISIM (IST service 12)
./sim_reader write -a 77111606 --enable-voice-pref

# Disable VoLTE services
./sim_reader write -a 77111606 --disable-volte

# Disable VoWiFi services
./sim_reader write -a 77111606 --disable-vowifi

# Disable SMS over IP in ISIM
./sim_reader write -a 77111606 --disable-sms-ip

# Disable Voice Domain Preference in ISIM
./sim_reader write -a 77111606 --disable-voice-pref

# Clear Forbidden PLMN list
./sim_reader write -a 77111606 --clear-fplmn

# Write HPLMN (Home PLMN) with Access Technology
./sim_reader write -a 77111606 --hplmn "250:88:eutran,utran,gsm"

# HPLMN with all technologies
./sim_reader write -a 77111606 --hplmn "250:88:all"

# Write Operator PLMN (roaming partners)
./sim_reader write -a 77111606 --oplmn "250:20:eutran,utran,gsm"

# Write User Controlled PLMN (for test networks)
./sim_reader write -a 77111606 --user-plmn "001:01:eutran,utran,gsm"

# Set UE Operation Mode for test networks
./sim_reader write -a 77111606 --op-mode cell-test

# Set normal operation mode
./sim_reader write -a 77111606 --op-mode normal
```

## Important for Programmable Cards (v2.5.0+)

If you are using programmable cards (sysmocom, Grcard, etc.), the tool will automatically detect the driver and apply necessary settings (like CLA byte or pre-write handshakes).

```bash
# Recommended check before writing
./sim_reader prog info
```

## Configuration File Reference

### Read-Only Fields (exported for reference)

| Field | Type | Description |
|-------|------|-------------|
| `iccid` | string | Card identifier |
| `msisdn` | string | Phone number |
| `languages` | []string | Language preferences (EF_LI) |
| `acc` | []int | Access Control Classes |
| `hplmn_period` | int | HPLMN search period in minutes |
| `fplmn` | []string | Forbidden PLMN list (use `clear_fplmn` to clear) |

### Writable Fields

| Field | Type | Description |
|-------|------|-------------|
| `imsi` | string | IMSI (15 digits) |
| `spn` | string | Service Provider Name |
| `mcc` | string | Mobile Country Code (3 digits) |
| `mnc` | string | Mobile Network Code (2-3 digits) |
| `operation_mode` | string | UE operation mode (see below) |
| `hplmn` | array | Home PLMN entries with Access Technology |
| `hplmn[].mcc` | string | HPLMN Mobile Country Code |
| `hplmn[].mnc` | string | HPLMN Mobile Network Code |
| `hplmn[].act` | array | Access Technologies: eutran, utran, gsm, nr, ngran |
| `oplmn` | array | Operator PLMN entries (same format as hplmn) |
| `user_plmn` | array | User Controlled PLMN entries (same format as hplmn) |
| `isim.impi` | string | IMS Private User Identity |
| `isim.impu` | array | IMS Public User Identities |
| `isim.domain` | string | Home Network Domain Name |
| `isim.pcscf` | array | P-CSCF addresses |
| `clear_fplmn` | bool | Clear Forbidden PLMN list on write |

### Service Flags

| Field | Type | Description |
|-------|------|-------------|
| `services.volte` | bool | Enable VoLTE (UST 87) |
| `services.vowifi` | bool | Enable VoWiFi (UST 89, 90, 124) |
| `services.sms_over_ip` | bool | SMS over IP (UST) |
| `services.gsm_access` | bool | GSM Access (UST 27) |
| `services.call_control` | bool | Call Control (UST 30) |
| `services.gba` | bool | GBA support (UST 67) |
| `services.5g_nas_config` | bool | 5G NAS config (UST 104) |
| `services.5g_nssai` | bool | 5G NSSAI (UST 108) |
| `services.suci_calculation` | bool | SUCI calculation (UST 112) |
| `services.isim_pcscf` | bool | P-CSCF in IST (IST 1) |
| `services.isim_sms_over_ip` | bool | SMS over IP (IST 7) |
| `services.isim_voice_domain_pref` | bool | Voice Domain Pref (IST 12) |
| `services.isim_gba` | bool | GBA in ISIM (IST 2) |
| `services.isim_http_digest` | bool | HTTP Digest (IST 3) |

## UE Operation Modes (3GPP TS 31.102)

| Mode | Value | Description |
|------|-------|-------------|
| `normal` | 0x00 | Normal operation |
| `type-approval` | 0x01 | Type approval operations |
| `normal-specific` | 0x02 | Normal + specific facilities |
| `type-approval-specific` | 0x04 | Type approval + specific facilities |
| `maintenance` | 0x08 | Maintenance (off-line) |
| `cell-test` | 0x80 | Cell test operation (for test PLMNs 001-01, 999-99) |

**Note:** Use `cell-test` mode when working with test networks (MCC 001 or 999).
