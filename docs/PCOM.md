# PCOM Script Execution

The tool supports `.pcom` personalization scripts used by programmable cards.

## Running Scripts

```bash
# Run a .pcom personalization script
./sim_reader -pcom /path/to/script.pcom

# Run with stop on first error
./sim_reader -pcom /path/to/script.pcom -pcom-stop-on-error

# Run in quiet mode (no command output)
./sim_reader -pcom /path/to/script.pcom -pcom-verbose=false
```

## Supported Syntax

| Syntax | Description | Example |
|--------|-------------|---------|
| `.DEFINE %VAR value` | Define variable | `.DEFINE %ICCID 98701234...` |
| `.CALL filename` | Execute another script | `.CALL Data.var` |
| `.POWER_ON` | Warm reset card | `.POWER_ON` |
| `.POWER_ON /COLD` | Cold reset (power cycle) | `.POWER_ON /COLD` |
| `.POWER_OFF` | Power off card | `.POWER_OFF` |
| `.ALLUNDEFINE` | Clear all variables | `.ALLUNDEFINE` |
| `%VAR` | Variable substitution | `A0D6 0000 09 %IMSI (9000)` |
| `W(pos;len)` | Extract from last response | `A0C0 0000 W(2;1) (9000)` |
| `R(pos;len)` | Extract for .DEFINE | `.DEFINE %VER R(17;16)` |
| `(9000)` | Expected status word | `A0A4 0000 02 3F00 (9000)` |
| `(9XXX)` | Wildcard SW | `A0A4 0000 02 3F00 (9XXX)` |
| `[data]` | Expected response data | `A0B0 0000 0A [%ICCID] (9000)` |
| `[XXXX]` | Wildcard data | `A0C0 0000 22 [XXXX...] (9000)` |
| `;` or `;;` | Comment | `;; This is a comment` |
| `\` | Line continuation | `.DEFINE %VAL 01020304 \`<br>`  05060708` |

## Script Structure Example

```
main_profile.pcom (main script)
├── .CALL Data.var           ← Variables: %ICCID, %IMSI, %KI...
├── .CALL 01.create_GSM.pcom     ← Creates DF_GSM
├── .CALL 01.create_TELECOM.pcom ← Creates DF_TELECOM
├── .CALL 02.01.create_USIM.pcom ← Creates ADF_USIM
└── .CALL 02.02.create_ISIM.pcom ← Creates ADF_ISIM
```

## Output Example

```
✓ Running .pcom script: main_profile.pcom

  [DEF] %ICCID = 98075110700800008660
  [DEF] %IMSI = 082905058700006008
  [CALL] Data.var
  [POWER_ON /COLD]
  [main_profile.pcom:48] A024000010... → 9000 ✓
  [main_profile.pcom:49] A020000008... → 9000 ✓
  [CALL] 01.create_GSM.pcom
  ...

✓ Script completed: 245 commands, 245 success
```

## Warning

⚠️ **WARNING:** PCOM scripts can completely erase and reprogram the card. Use only on test cards!

