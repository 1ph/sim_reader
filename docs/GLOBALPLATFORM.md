# GlobalPlatform (GP) Support in sim_reader

This document explains the GlobalPlatform-related features added to `sim_reader`.

## DISCLAIMER (Read this first)

**Experimental feature:** GlobalPlatform support in `sim_reader` is currently **experimental**. Card vendors and profiles vary widely, and not all cards behave the same even when they implement the same GP/SCP standards.

**Use at your own risk:** Everything you do with this tool is **at your own risk**.

**No liability:** The authors/maintainers of `sim_reader` assume **no responsibility** for any damage, data loss, service disruption, key blocking, or permanent card failure (including "bricked" SIM/UICC/Java Card devices) resulting from the use of this software.

**Dangerous operations:** GP operations can permanently remove card functionality. Always test on non-production cards and avoid destructive commands unless you fully understand the impact.

---

## What GlobalPlatform is (short)

GlobalPlatform (GP) is a set of specifications for managing applications ("applets") on smart cards (Java Card / UICC). Typical GP operations include:

- Listing installed objects (Issuer Security Domain, applets, packages, modules)
- Deleting objects
- Loading and installing CAP files (Java Card applets)

Most cards require a **Secure Channel** to access the registry on a secured Issuer Security Domain (ISD).

---

## Secure Channel support (SCP02 and SCP03)

`sim_reader` supports opening a secure channel and then executing GP management commands over it.

### SCP02 (3DES)

- Uses 3DES-based session key derivation
- Uses Retail MAC (ISO 9797-1 MAC Algorithm 3) for C-MAC
- Supports security levels:
  - `mac` (C-MAC)
  - `mac+enc` (C-MAC + C-ENC; minimal support)

### SCP03 (AES)

- Uses AES-CMAC and GP SCP03 KDF
- Supports:
  - S8 mode (8-byte cryptograms / 8-byte C-MAC truncation)
  - S16 mode (16-byte cryptograms / 16-byte C-MAC)
- Supports security level:
  - `mac` (C-MAC) (recommended)

### Auto-detect

The secure channel protocol is detected from the card's response to **INITIALIZE UPDATE** (`80 50`).

- If the card reports SCP02 (`scp_id=0x02`), `sim_reader` uses SCP02.
- If the card reports SCP03 (`scp_id=0x03`), `sim_reader` uses SCP03.
  - If the card indicates S16, `sim_reader` automatically retries INITIALIZE UPDATE with a 16-byte host challenge.

---

## Key concepts: ENC / MAC / DEK, KVN, and SD AID

### ENC / MAC / DEK

GP secure channel keysets commonly include three static keys:

- **ENC**: encryption base key (used to derive S-ENC)
- **MAC**: MAC base key (used to derive S-MAC)
- **DEK**: data encryption key (used for encrypting key blobs when doing key management such as PUT KEY). Many registry operations don't need DEK.

`sim_reader` expects keys as hex strings.

### KVN (Key Version Number)

KVN is provided as P1 of INITIALIZE UPDATE. Some cards accept `KVN=0` as "first available keyset", others require an explicit version.

### SD AID (Issuer Security Domain / Card Manager AID)

Many cards only accept INITIALIZE UPDATE after selecting the Security Domain / Card Manager.

`sim_reader` uses `--sd-aid` for this. Common values:

- `A000000003000000` (often used by cards as ISD)
- `A0000001510000` (common GP ISD AID on many UICC/JavaCard platforms)

---

## Command Structure

GlobalPlatform operations are grouped under the `gp` command:

```bash
./sim_reader gp <subcommand> [flags]

Subcommands:
  list      List GlobalPlatform applets via Secure Channel
  probe     Verify keys without EXTERNAL AUTH
  delete    Delete objects by AID
  load      Load and install CAP file
  aram      Add ARA-M access rule
  verify    Verify applet AID (SELECT)
```

### Common GP Flags

| Flag | Description |
|------|-------------|
| `--sd-aid <HEX>` | AID of the Security Domain |
| `--kvn <0..255>` | Key Version Number |
| `--sec <mac\|mac+enc>` | Security level |
| `--key-enc <HEX>` | Static ENC key |
| `--key-mac <HEX>` | Static MAC key |
| `--key-dek <HEX>` | Static DEK key (optional) |
| `--key-psk <HEX>` | Convenience: ENC=MAC=PSK |
| `--dms <PATH>` | DMS var_out key file |
| `--dms-iccid <ICCID>` | Choose row by ICCID |
| `--dms-imsi <IMSI>` | Choose row by IMSI |
| `--dms-keyset <name>` | Which keyset to extract |
| `--auto` | Auto-probe KVN+keyset |

---

## Operations

### 1) Probe keys (safe)

`gp probe` runs INITIALIZE UPDATE and verifies the card cryptogram. It does not perform DELETE/LOAD.

```bash
./sim_reader gp probe \
  --sd-aid A000000003000000 \
  --kvn 0 \
  --sec mac \
  --key-enc D3A1028C9445DE428A8858F10E092DA7 \
  --key-mac 9F59C4323AECC44ECD592477EC7CF164
```

### 2) Auto-probe (find working KVN + keyset)

`--auto` performs repeated probe attempts across candidate keysets and KVN ranges.

```bash
./sim_reader gp list --auto \
  --sd-aid A000000003000000 \
  --sec mac \
  --dms /path/to/var_out_file \
  --dms-iccid 89701501078000006814
```

### 3) List registry (applets / packages / modules)

```bash
./sim_reader gp list \
  --sd-aid A000000003000000 \
  --kvn 0 --sec mac \
  --key-enc D3A1028C9445DE428A8858F10E092DA7 \
  --key-mac 9F59C4323AECC44ECD592477EC7CF164 \
  --key-dek D3A1028C9445DE428A8858F10E092DA7
```

### 4) Verify an AID (SELECT)

This performs a GP SELECT of the provided AID and prints SW.

```bash
./sim_reader gp verify --aid A0000005591010FFFFFFFF89000100
```

### 5) Delete objects (dangerous)

Deletes objects by AID. This can brick the card.

```bash
./sim_reader gp delete \
  --aid A0000005591010FFFFFFFF8900,A0000005591010FFFFFFFF89000100 \
  --sd-aid A000000003000000 \
  --kvn 0 --sec mac \
  --key-enc D3A1028C9445DE428A8858F10E092DA7 \
  --key-mac 9F59C4323AECC44ECD592477EC7CF164
```

### 6) Load + install a CAP (dangerous)

This is a minimal GP LOAD/INSTALL flow:

- INSTALL [for load]
- LOAD blocks
- INSTALL [for install]

```bash
./sim_reader gp load \
  --cap /path/to/applet.cap \
  --package-aid A0000005591010FFFFFFFF8900 \
  --applet-aid A0000005591010FFFFFFFF89000100 \
  --instance-aid A0000005591010FFFFFFFF89000100 \
  --sd-aid A000000003000000 \
  --kvn 0 --sec mac \
  --key-enc D3A1028C9445DE428A8858F10E092DA7 \
  --key-mac 9F59C4323AECC44ECD592477EC7CF164 \
  --key-dek D3A1028C9445DE428A8858F10E092DA7
```

Notes:

- CAP files are ZIP containers; `sim_reader` extracts CAP components and concatenates them into a "load file".
- DAP, tokens, and encrypted load blocks are not implemented in this minimal flow.

---

## DMS Key Database Format

Some environments store per-card key material in a text file with the format:

- first line: `var_out: FIELD1/FIELD2/...`
- following lines: values, whitespace-separated

Supported `--dms-keyset` values:

- `cm`: use `CM_KIC`/`CM_KID`/`CM_KIK` as ENC/MAC/DEK
- `psk40`: use `PSK40_ISD` as ENC=MAC and `PSK40_ISD_DEK` as DEK
- `psk41`: use `PSK41_ISD` as ENC=MAC and `PSK41_ISD_DEK` as DEK
- `a`..`h`: use `KIC_<X>` / `KID_<X>` / `KIK_<X>` as ENC/MAC/DEK
- `auto`: let `--auto` determine a working combination

---

## Troubleshooting

### "Card cryptogram mismatch"

This usually means one of:

- wrong keyset (ENC/MAC mismatch)
- wrong KVN
- wrong SD AID selected before INITIALIZE UPDATE
- the card uses SCP03 (AES) while you assumed SCP02 (3DES)
- the card uses SCP03 S16 while you used an 8-byte host challenge

Recommended approach:

1) Try `gp probe` with your known-good keys.
2) If you have a DMS key DB, try `--auto`.

### "SW=6982 / 6985 on GET STATUS"

- Likely the ISD is secured and requires a secure channel.
- Use `gp list` with correct keys.

### Reader disappears ("No smart card readers found")

This is usually a PC/SC reader/driver issue or transient disconnect. Reinsert the card and retry.

---

## Security and safety notes

- **Never brute-force ADM/keys**: many cards have permanent attempt counters.
- Prefer `gp probe` and `--auto` first.
- Use `gp delete` only if you fully understand which AIDs you are removing.

---

## Glossary

- **ISD**: Issuer Security Domain
- **AID**: Application Identifier
- **CAP**: Java Card applet package file
- **KVN**: Key Version Number
- **SCP02 / SCP03**: Secure Channel Protocol (3DES / AES)
