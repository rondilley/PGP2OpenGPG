# PGP to GPG Key Migration Tool

A Python script to export keys from Symantec/PGP Desktop and import them into GnuPG (GPG).

## Features

- Automatically locates PGP Desktop keyring files
- Exports PGP keys to ASCII armored format
- Imports exported keys into GPG keyring
- Supports both public and private key migration
- Handles Windows and Unix-like systems
- Comprehensive error handling and logging

## Requirements

- Python 3.6 or higher
- GnuPG (GPG) installed and accessible in PATH
- Symantec PGP Desktop (for key export)
- Optional: PGP command line tools

## Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/yourusername/pgp2gpg.git
   cd pgp2gpg
   ```

2. Ensure Python 3 is installed:
   ```bash
   python --version
   ```

3. Verify GPG is installed:
   ```bash
   gpg --version
   ```

## Usage

### Basic Usage

Export and import public keys only (skips keys that already exist):
```bash
python pgp2gpg.py
```

**Note**: By default, the tool checks for existing keys and skips duplicates. Use `--allow-overwrite` to force re-import.

### Export and Import Private Keys

To migrate both public and private keys:
```bash
# Will prompt for passphrase if keys are encrypted
python pgp2gpg.py --include-private

# Provide passphrase directly (less secure - visible in process list)
python pgp2gpg.py --include-private --passphrase "your-passphrase"

# Provide passphrase from file (more secure)
python pgp2gpg.py --include-private --passphrase-file passphrase.txt
```

**Security Note**: Using `--passphrase-file` is more secure than `--passphrase` as it avoids exposing the passphrase in command history and process listings.

### Custom Paths

If your PGP installation is in a non-standard location:
```bash
python pgp2gpg.py --keyring-path "C:\Users\YourName\Documents\PGP" --pgp-path "C:\Program Files\PGP\pgp.exe"
```

### Export Only

Export keys without importing to GPG:
```bash
python pgp2gpg.py --export-only --output-dir ./my_keys
```

### Import Only

Import previously exported keys:
```bash
python pgp2gpg.py --import-only --key-file ./exported_keys/pgp_public_keys.asc
```

### List Keys After Import

Verify the import by listing all GPG keys:
```bash
python pgp2gpg.py --list-keys
```

### Duplicate Prevention (Default Behavior)

By default, the tool checks for existing keys before importing:
```bash
python pgp2gpg.py
```

This will:
- Check if keys already exist in GPG keyring
- Display which keys are duplicates
- Skip import if all keys already exist
- Only import new keys if some exist

To force re-import of existing keys (allowing updates):
```bash
python pgp2gpg.py --allow-overwrite
```

### Enable Detailed Logging

Write detailed logs to a file for troubleshooting:
```bash
python pgp2gpg.py --log-file migration.log --verbose
```

This creates a detailed log file with timestamps and full error traces, useful for debugging issues.

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--pgp-path PATH` | Path to PGP executable |
| `--keyring-path PATH` | Path to PGP keyring directory |
| `--gpg-path PATH` | Path to GPG executable |
| `--output-dir DIR` | Directory to save exported keys (default: ./exported_keys) |
| `--include-private` | Also export and import private keys |
| `--passphrase TEXT` | Passphrase for encrypted private keys (less secure) |
| `--passphrase-file FILE` | File containing passphrase (more secure) |
| `--export-only` | Only export keys, do not import into GPG |
| `--import-only` | Only import keys from existing file |
| `--key-file FILE` | Key file to import (required with --import-only) |
| `--list-keys` | List all GPG keys after import |
| `--allow-overwrite` | Allow re-importing keys that already exist (default: skip existing) |
| `--log-file FILE` | Write detailed logs to file (e.g., migration.log) |
| `-v, --verbose` | Enable verbose logging |
| `-h, --help` | Show help message |

## How It Works

1. **Key Location**: The script searches common locations for PGP Desktop keyring files:
   - Windows: `%APPDATA%\PGP Corporation\PGP Desktop`
   - Windows: `%USERPROFILE%\Documents\PGP`
   - Unix: `~/.pgp`

2. **Export Process** (multiple fallback strategies):
   - **Primary**: Uses PGP command line tools to export to ASCII armored format
   - **Fallback 1**: Uses GPG to convert binary keyrings to ASCII format
   - **Fallback 2**: Copies binary keyring files directly as last resort
   - Prioritizes ASCII armored format for maximum compatibility

3. **Import Process**:
   - Uses `gpg --import` to add keys to GPG keyring
   - Preserves key metadata and signatures
   - Reports import results and any errors

4. **Duplicate Detection** (enabled by default):
   - Extracts key fingerprints from the import file
   - Compares against existing keys in GPG keyring
   - Lists all duplicate keys found
   - Skips import if all keys already exist
   - Only imports new keys if partial overlap
   - Use `--allow-overwrite` to disable this check

## Error Logging and Reporting

The script includes comprehensive error tracking and reporting:

### Features

- **Real-time Logging**: All operations are logged with timestamps
- **Error Tracking**: Errors and warnings are collected throughout the process
- **Summary Report**: Displays a complete summary of all errors and warnings at the end
- **File Logging**: Optional detailed logging to file with `--log-file`
- **Debug Mode**: Verbose output with `--verbose` flag

### Error Summary

At the end of execution, the script displays a summary like this:

```
======================================================================
WARNINGS (2):
======================================================================
1. [2025-11-12T09:30:15] PGP executable not found in PATH
2. [2025-11-12T09:30:16] Private keyring file not found: /path/to/secring.skr

======================================================================
ERRORS (1):
======================================================================
1. [2025-11-12T09:30:20] GPG import failed with return code 2
   Exception: GPG output: invalid key format
```

### Log Levels

- **INFO**: Normal operation messages
- **WARNING**: Issues that don't prevent operation but should be noted
- **ERROR**: Failures that prevent successful completion
- **DEBUG**: Detailed information for troubleshooting (enabled with `-v`)

### Example with Full Logging

```bash
python pgp2gpg.py --include-private --log-file migration.log --verbose --list-keys
```

This will:
1. Run with maximum detail in console
2. Write all logs to `migration.log` file
3. Display error summary at the end
4. Show imported keys if successful

## Common PGP Keyring Locations

### Windows
- `C:\Users\<Username>\AppData\Roaming\PGP Corporation\PGP Desktop`
- `C:\Documents and Settings\<Username>\Application Data\PGP Corporation\PGP Desktop`
- `C:\Users\<Username>\Documents\PGP`

### Linux/Mac
- `~/.pgp`
- `/usr/local/pgp`

### Keyring Files
- `pubring.pkr` - Public keys
- `secring.skr` - Private keys

## Troubleshooting

### PGP keyring not found

If the script cannot locate your PGP keyrings:
1. Manually locate your PGP keyring directory
2. Use the `--keyring-path` option to specify the location
3. Look for files named `pubring.pkr` or `secring.skr`

### PGP executable not found

If PGP command line tools are not available:
- The script automatically attempts GPG-based conversion
- GPG will try to import and convert PGP binary keyrings to ASCII format
- Uses a temporary GPG home directory (cleaned up automatically)
- If GPG conversion also fails, binary keyring files are copied as last resort
- Specify the PGP executable path with `--pgp-path` if you have PGP CLI installed

### GPG import fails

If GPG cannot import the keys:
1. Verify the exported key file format (.asc is preferred)
2. Try importing manually: `gpg --import keyfile.asc`
3. Check if keys are password-protected
4. For `.pkr` files, export them to `.asc` format using PGP Desktop first

### Permission denied errors

On Unix systems, ensure you have read permissions:
```bash
chmod +r /path/to/keyring/*
```

## Security Considerations

- **Private Keys**: Use `--include-private` with caution. Private keys should be handled securely.
- **Passphrases**:
  - Use `--passphrase-file` instead of `--passphrase` when possible
  - The `--passphrase` option exposes the passphrase in process listings and shell history
  - Create passphrase file: `echo "your-passphrase" > passphrase.txt && chmod 600 passphrase.txt`
  - Passphrase is passed to PGP/GPG tools via command line or environment variables
  - Passphrases are never logged (shown as `***` in debug output)
- **Backup**: Always keep a backup of your original PGP keyrings before migration.
- **Cleanup**: Securely delete exported key files and passphrase files after successful import:
  ```bash
  # Windows
  del /P exported_keys\*.asc
  del /P passphrase.txt

  # Unix
  shred -u exported_keys/*.asc
  shred -u passphrase.txt
  ```

## Examples

### Complete Migration

Migrate all keys and verify (skips existing keys by default):
```bash
python pgp2gpg.py --include-private --list-keys
```

### Force Re-import (Update Existing Keys)

Re-import keys even if they already exist (useful for updating keys):
```bash
python pgp2gpg.py --include-private --allow-overwrite --list-keys
```

This will import all keys, updating any that already exist in your GPG keyring.

### Backup Keys Only

Export keys for backup without importing:
```bash
python pgp2gpg.py --export-only --include-private --output-dir ./backup
```

### Import from Backup

Restore keys from backup:
```bash
python pgp2gpg.py --import-only --key-file ./backup/pgp_public_keys.asc
python pgp2gpg.py --import-only --key-file ./backup/pgp_private_keys.asc
```

### Re-import Check

Re-run import on previously imported keys (will skip duplicates by default):
```bash
python pgp2gpg.py --import-only --key-file ./exported_keys/pgp_public_keys.asc
```

Output will show which keys already exist and which are new. If all keys exist, import will be skipped.

## License

This tool is provided as-is for personal use. Use at your own risk.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Support

For issues and questions:
1. Check the Troubleshooting section above
2. Verify your PGP and GPG installations
3. Run with `--verbose` flag for detailed logging
4. Open an issue on GitHub with the error message and log output
