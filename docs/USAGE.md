# Usage Guide

## Reading Card Data

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

## Analyzing Cards

```bash
# Detailed card analysis
./sim_reader -analyze

# This version (2.5.0) provides:
# - Deep ATR analysis (Convention, Voltage, Protocols, Fi/Di)
# - Historical bytes decoding
# - Card type detection by ATR
# - List of applications from EF_DIR
# - GSM 2G data if available
```

## Checking File Access Conditions

```bash
# Show file access conditions (which ADM key is needed for each file)
./sim_reader -adm-check

# This displays a color-coded table:
# - PIN1 (green) - user PIN required
# - ADM1 (cyan) - administrative key 1
# - ADM2 (yellow) - administrative key 2
# - ADM3 (magenta) - administrative key 3
# - ADM4 (red) - administrative key 4
# - Always (bright green) - no authentication needed
# - Never (bright red) - operation not allowed

# Combine with analyze for full card examination
./sim_reader -analyze -adm-check

# Debug FCP data for troubleshooting
./sim_reader -adm-check -debug-fcp
```

## Using Multiple ADM Keys

Some cards have multiple ADM keys for different access levels:

```bash
# Card with single ADM key
./sim_reader -adm 77111606 -write config.json

# Card with multiple ADM keys
./sim_reader -adm KEY1 -adm2 KEY2 -adm3 KEY3 -write config.json

# Example with hex keys
./sim_reader -adm 2AABE9DD20141276 -adm2 248484E2663D34D1 -adm3 4BF91F4D6B25B480 -write config.json

# Check which ADM key is needed for each file
./sim_reader -adm-check
```

**Typical ADM key mapping:**

| Key | Flag | Typical Use |
|-----|------|-------------|
| ADM1 | `-adm` | Card management, EF_ARR |
| ADM2 | `-adm2` | USIM/ISIM file writes (IMSI, SPN, PLMN, etc.) |
| ADM3 | `-adm3` | Specific protected files |
| ADM4 | `-adm4` | Reserved/special operations |

**Note:** Use `-adm-check` to determine which ADM key is required for specific files on your card.

## Generating Test Data

```bash
# Dump card data as Go test code (for regression testing)
./sim_reader -adm 77111606 -dump "MyCard"

# Output can be copied directly to sim/decoder_test.go
```

## ADM Key Formats

The tool automatically detects the ADM key format:

| Format | Example | Description |
|--------|---------|-------------|
| Hex (16 chars) | `F38A3DECF6C7D239` | Most programmable SIMs |
| Decimal (8 digits) | `77111606` | Some cards (converted to ASCII) |

### Multiple ADM Keys

Many cards have multiple ADM keys for different access levels:

| Flag | Key Type | Description |
|------|----------|-------------|
| `-adm` | ADM1 | Primary administrative key |
| `-adm2` | ADM2 | Secondary administrative key (most write operations) |
| `-adm3` | ADM3 | Tertiary administrative key |
| `-adm4` | ADM4 | Quaternary administrative key |

Use `-adm-check` to see which key is required for each file operation.

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
```

### File Access Conditions Output

```
╭──────────────────────────────────────────────────────────╮
│ FILE ACCESS CONDITIONS                                   │
├─────────────────┬──────────┬──────────────┬──────────────┤
│ FILE            │ FILE ID  │ READ         │ WRITE        │
├─────────────────┼──────────┼──────────────┼──────────────┤
│ ─── USIM ───    │          │              │              │
│ EF_IMSI         │ 6F07     │ PIN1         │ ADM2         │
│ EF_SPN          │ 6F46     │ Always       │ ADM2         │
│ EF_AD           │ 6FAD     │ Always       │ ADM2         │
│ EF_UST          │ 6F38     │ PIN1         │ ADM2         │
╰─────────────────┴──────────┴──────────────┴──────────────╯
```

**Color Legend (in terminal):**
- **PIN1** - Green (user PIN)
- **ADM1** - Cyan (admin key 1)
- **ADM2** - Yellow (admin key 2)
- **ADM3** - Magenta (admin key 3)
- **ADM4** - Red (admin key 4)
- **Always** - Bright Green (no auth needed)
- **Never** - Bright Red (not allowed)

