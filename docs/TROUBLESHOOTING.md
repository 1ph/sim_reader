# Troubleshooting

## "Service not available" error

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

## "No smart card readers found"

1. Make sure the reader is connected via USB
2. Try a different USB port
3. Check if the reader LED is on
4. On Linux, ensure your user is in the `pcscd` group

## "Failed to connect to card"

1. Make sure a SIM card is inserted in the reader
2. Check card orientation (chip facing down for most readers)
3. Try reinserting the card

## ADM key verification fails

1. Double-check the ADM key value
2. Make sure you're using the correct format (hex vs decimal)
3. **Warning:** Too many failed attempts will permanently block the ADM key!

## Write operation fails

1. Verify ADM key is correct
2. Use `-adm-check` to see which ADM key is required for the file
3. Some files may require ADM2 or higher access level - use `-adm2`, `-adm3` flags
4. Check if the file exists on the card (not all cards have all files)
5. ISIM application must be present for ISIM writes

## "Security status not satisfied" error

This error occurs when the required ADM key is not verified. Solutions:

1. Use `-adm-check` to determine which ADM key is needed
2. Provide the correct ADM key with the appropriate flag:
   ```bash
   # If file requires ADM2
   ./sim_reader -adm2 YOUR_ADM2_KEY -write config.json
   
   # If multiple ADM keys are needed
   ./sim_reader -adm KEY1 -adm2 KEY2 -adm3 KEY3 -write config.json
   ```
3. The tool automatically re-authenticates after application selection (fixed in v2.1.0)

## Security Warning

⚠️ **Important:**
- ADM keys have a limited retry counter (typically 3-10 attempts)
- After exhausting retries, the ADM key is **permanently blocked**
- A blocked ADM key **cannot be recovered**
- Always verify your ADM key before using it
- Test with non-critical cards first

