#!/usr/bin/env python3
"""
PGP to GPG Key Migration Tool

Exports keys from Symantec/PGP Desktop and imports them into GPG.
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime


# Error tracking
class ErrorTracker:
    """Tracks errors and warnings during migration."""
    def __init__(self):
        self.errors = []
        self.warnings = []

    def add_error(self, message: str, exception: Optional[Exception] = None):
        """Add an error to the tracker."""
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'exception': str(exception) if exception else None
        }
        self.errors.append(error_entry)
        if exception:
            logger.error(f"{message}: {exception}", exc_info=True)
        else:
            logger.error(message)

    def add_warning(self, message: str):
        """Add a warning to the tracker."""
        warning_entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message
        }
        self.warnings.append(warning_entry)
        logger.warning(message)

    def has_errors(self) -> bool:
        """Check if any errors were recorded."""
        return len(self.errors) > 0

    def print_summary(self):
        """Print a summary of all errors and warnings."""
        if self.warnings:
            print("\n" + "="*70)
            print(f"WARNINGS ({len(self.warnings)}):")
            print("="*70)
            for i, warning in enumerate(self.warnings, 1):
                print(f"{i}. [{warning['timestamp']}] {warning['message']}")

        if self.errors:
            print("\n" + "="*70)
            print(f"ERRORS ({len(self.errors)}):")
            print("="*70)
            for i, error in enumerate(self.errors, 1):
                print(f"{i}. [{error['timestamp']}] {error['message']}")
                if error['exception']:
                    print(f"   Exception: {error['exception']}")

        if not self.errors and not self.warnings:
            print("\n[OK] No errors or warnings recorded")


# Configure logging
def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """Setup logging configuration."""
    log_level = logging.DEBUG if verbose else logging.INFO

    # Create formatters
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers
    root_logger.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='a')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
            logger.info(f"Logging to file: {log_file}")
        except Exception as e:
            logger.error(f"Failed to setup file logging: {e}")


logger = logging.getLogger(__name__)


class PGPKeyExporter:
    """Handles exporting keys from PGP Desktop."""

    COMMON_PGP_PATHS = [
        # Windows paths
        Path(os.environ.get('APPDATA', '')) / 'PGP Corporation' / 'PGP Desktop',
        Path(os.environ.get('USERPROFILE', '')) / 'Documents' / 'PGP',
        Path(os.environ.get('PROGRAMFILES', 'C:\\Program Files')) / 'PGP Corporation' / 'PGP Desktop',
        Path(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')) / 'PGP Corporation' / 'PGP Desktop',
        # Unix-like paths
        Path.home() / '.pgp',
        Path('/usr/local/pgp'),
    ]

    def __init__(self, pgp_path: Optional[str] = None, keyring_path: Optional[str] = None,
                 error_tracker: Optional[ErrorTracker] = None, passphrase: Optional[str] = None):
        """
        Initialize the PGP exporter.

        Args:
            pgp_path: Path to PGP executable (pgp.exe or pgp)
            keyring_path: Path to PGP keyring directory
            error_tracker: ErrorTracker instance for logging errors
            passphrase: Passphrase for encrypted private keys
        """
        self.error_tracker = error_tracker or ErrorTracker()
        self.passphrase = passphrase
        self.pgp_executable = self._find_pgp_executable(pgp_path)
        self.keyring_path = self._find_keyring_path(keyring_path)

    def _find_pgp_executable(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Find the PGP executable."""
        if custom_path:
            if os.path.isfile(custom_path):
                logger.info(f"Using custom PGP executable: {custom_path}")
                return custom_path
            else:
                self.error_tracker.add_warning(f"Custom PGP path not found: {custom_path}")

        # Try common executable names
        for exe_name in ['pgp', 'pgp.exe']:
            try:
                result = subprocess.run(
                    ['which', exe_name] if os.name != 'nt' else ['where', exe_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    found_path = result.stdout.strip().split('\n')[0]
                    logger.info(f"Found PGP executable: {found_path}")
                    return found_path
            except subprocess.TimeoutExpired:
                self.error_tracker.add_warning(f"Timeout while searching for {exe_name}")
            except FileNotFoundError:
                logger.debug(f"Command not found while searching for {exe_name}")
            except Exception as e:
                self.error_tracker.add_warning(f"Error searching for {exe_name}: {e}")

        self.error_tracker.add_warning("PGP executable not found in PATH")
        return None

    def _find_keyring_path(self, custom_path: Optional[str] = None) -> Optional[Path]:
        """Find the PGP keyring directory."""
        if custom_path:
            path = Path(custom_path)
            if path.exists():
                # Verify it contains keyring files
                has_public = (path / 'pubring.pkr').exists()
                has_private = (path / 'secring.skr').exists()

                if has_public or has_private:
                    logger.info(f"Using custom PGP keyring path: {path}")
                    if has_public:
                        logger.debug(f"Found public keyring: {path / 'pubring.pkr'}")
                    if has_private:
                        logger.debug(f"Found private keyring: {path / 'secring.skr'}")
                    return path
                else:
                    self.error_tracker.add_warning(
                        f"Custom keyring path exists but no keyring files found: {path}"
                    )
            else:
                self.error_tracker.add_error(f"Custom keyring path does not exist: {custom_path}")
                return None

        # Check common locations
        logger.debug("Searching for PGP keyring in common locations...")
        for path in self.COMMON_PGP_PATHS:
            try:
                if path.exists():
                    # Look for keyring files
                    has_public = (path / 'pubring.pkr').exists()
                    has_private = (path / 'secring.skr').exists()

                    if has_public or has_private:
                        logger.info(f"Found PGP keyring at: {path}")
                        if has_public:
                            logger.debug(f"  - Public keyring: {path / 'pubring.pkr'}")
                        if has_private:
                            logger.debug(f"  - Private keyring: {path / 'secring.skr'}")
                        return path
            except Exception as e:
                logger.debug(f"Error checking path {path}: {e}")

        self.error_tracker.add_error("PGP keyring directory not found in any common location")
        return None

    def export_keys(self, output_dir: Path, export_private: bool = False) -> Tuple[Optional[Path], Optional[Path]]:
        """
        Export PGP keys to ASCII armored files.

        Args:
            output_dir: Directory to save exported keys
            export_private: Whether to export private keys (requires passphrase)

        Returns:
            Tuple of (public_key_file, private_key_file) paths
        """
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Export directory: {output_dir}")
        except Exception as e:
            self.error_tracker.add_error(f"Failed to create output directory {output_dir}", e)
            return (None, None)

        public_key_file = output_dir / 'pgp_public_keys.asc'
        private_key_file = output_dir / 'pgp_private_keys.asc' if export_private else None

        # Method 1: Try using PGP command line
        if self.pgp_executable and self.keyring_path:
            logger.info("Attempting export using PGP command line tools...")
            success = self._export_with_pgp_cli(public_key_file, private_key_file)
            if success:
                return (public_key_file, private_key_file)
            else:
                self.error_tracker.add_warning("PGP CLI export failed, trying alternative method")
        elif not self.pgp_executable:
            self.error_tracker.add_warning("PGP executable not available for CLI export")
        elif not self.keyring_path:
            self.error_tracker.add_warning("PGP keyring path not available for CLI export")

        # Method 2: Manual keyring export
        logger.info("Attempting manual keyring file export...")
        return self._export_keyring_files(output_dir, export_private)

    def _export_with_pgp_cli(self, public_file: Path, private_file: Optional[Path]) -> bool:
        """Export keys using PGP command line tools."""
        try:
            # Export public keys
            logger.info("Exporting public keys using PGP CLI...")
            cmd = [
                self.pgp_executable,
                '--export-keys',
                '--output', str(public_file)
            ]

            if self.keyring_path:
                keyring_file = self.keyring_path / 'pubring.pkr'
                if not keyring_file.exists():
                    self.error_tracker.add_error(f"Public keyring file not found: {keyring_file}")
                    return False
                cmd.extend(['--keyring', str(keyring_file)])

            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                error_msg = f"PGP public key export failed (return code {result.returncode})"
                if result.stderr:
                    error_msg += f": {result.stderr.strip()}"
                if result.stdout:
                    error_msg += f"\nOutput: {result.stdout.strip()}"
                self.error_tracker.add_error(error_msg)
                return False

            if not public_file.exists() or public_file.stat().st_size == 0:
                self.error_tracker.add_error(
                    f"Public key export command succeeded but file is missing or empty: {public_file}"
                )
                return False

            logger.info(f"SUCCESS: Public keys exported to: {public_file} ({public_file.stat().st_size} bytes)")

            # Export private keys if requested
            if private_file:
                logger.info("Exporting private keys using PGP CLI...")
                cmd = [
                    self.pgp_executable,
                    '--export-secret-keys',
                    '--output', str(private_file)
                ]

                if self.keyring_path:
                    keyring_file = self.keyring_path / 'secring.skr'
                    if not keyring_file.exists():
                        self.error_tracker.add_warning(f"Private keyring file not found: {keyring_file}")
                        return True  # Public keys succeeded
                    cmd.extend(['--keyring', str(keyring_file)])

                # Add passphrase if provided
                env = os.environ.copy()
                stdin_input = None
                if self.passphrase:
                    # Different PGP implementations handle passphrases differently
                    # Try common options
                    cmd.extend(['--passphrase', self.passphrase])
                    env['PGPPASSPHRASE'] = self.passphrase

                logger.debug(f"Running command: {' '.join([c if c != self.passphrase else '***' for c in cmd])}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)

                if result.returncode != 0:
                    error_msg = f"PGP private key export failed (return code {result.returncode})"
                    if result.stderr:
                        error_msg += f": {result.stderr.strip()}"
                    self.error_tracker.add_error(error_msg)
                else:
                    if private_file.exists() and private_file.stat().st_size > 0:
                        logger.info(f"SUCCESS: Private keys exported to: {private_file} ({private_file.stat().st_size} bytes)")
                    else:
                        self.error_tracker.add_warning(
                            f"Private key export command succeeded but file is missing or empty: {private_file}"
                        )

            return True

        except subprocess.TimeoutExpired:
            self.error_tracker.add_error("PGP CLI export timed out after 60 seconds")
            return False
        except Exception as e:
            self.error_tracker.add_error("Unexpected error during PGP CLI export", e)
            return False

    def _convert_keyring_with_gpg(self, keyring_file: Path, output_file: Path, is_secret: bool = False) -> bool:
        """
        Convert PGP keyring to ASCII armored format using GPG.

        Uses a temporary GPG home directory to import PGP keys and export to ASCII.

        Args:
            keyring_file: Path to PGP keyring (.pkr or .skr)
            output_file: Path for ASCII armored output
            is_secret: Whether this is a secret keyring

        Returns:
            True if conversion succeeded
        """
        import tempfile
        import shutil

        temp_home = None
        try:
            # Find GPG executable
            gpg_cmd = None
            for exe_name in ['gpg', 'gpg.exe', 'gpg2', 'gpg2.exe']:
                try:
                    result = subprocess.run(
                        ['which', exe_name] if os.name != 'nt' else ['where', exe_name],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        gpg_cmd = result.stdout.strip().split('\n')[0]
                        break
                except:
                    continue

            if not gpg_cmd:
                logger.debug("GPG not found for keyring conversion")
                return False

            logger.info(f"Attempting to convert {keyring_file.name} to ASCII format using GPG...")

            # Create temporary GPG home directory
            temp_home = Path(tempfile.mkdtemp(prefix='pgp2gpg_temp_'))
            logger.debug(f"Using temporary GPG home: {temp_home}")

            # Step 1: Import PGP keyring into temporary GPG home
            import_cmd = [
                gpg_cmd,
                '--homedir', str(temp_home),
                '--batch',
                '--import',
                str(keyring_file)
            ]

            # Add passphrase handling for encrypted keyrings
            env = os.environ.copy()
            if self.passphrase and is_secret:
                import_cmd.extend([
                    '--pinentry-mode', 'loopback',
                    '--passphrase', self.passphrase
                ])

            logger.debug(f"Importing: {' '.join([c if c != self.passphrase else '***' for c in import_cmd])}")
            import_result = subprocess.run(import_cmd, capture_output=True, text=True, timeout=60, env=env)

            if import_result.returncode != 0:
                logger.debug(f"GPG import from PGP keyring failed: {import_result.stderr}")
                return False

            # Check if any keys were imported
            if 'imported' not in import_result.stderr.lower() and 'processed' not in import_result.stderr.lower():
                logger.debug("No keys found in PGP keyring")
                return False

            # Step 2: Export keys from temporary GPG home to ASCII armored format
            export_cmd = [
                gpg_cmd,
                '--homedir', str(temp_home),
                '--batch',
                '--armor',
                '--export-secret-keys' if is_secret else '--export',
                '--output', str(output_file)
            ]

            # Add passphrase for exporting secret keys
            if self.passphrase and is_secret:
                export_cmd.extend([
                    '--pinentry-mode', 'loopback',
                    '--passphrase', self.passphrase
                ])

            logger.debug(f"Exporting: {' '.join([c if c != self.passphrase else '***' for c in export_cmd])}")
            export_result = subprocess.run(export_cmd, capture_output=True, text=True, timeout=60, env=env)

            if export_result.returncode == 0 and output_file.exists() and output_file.stat().st_size > 0:
                size = output_file.stat().st_size
                logger.info(f"SUCCESS: Converted {keyring_file.name} to ASCII armored format: {output_file} ({size} bytes)")
                return True
            else:
                logger.debug(f"GPG export failed: {export_result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.debug("GPG conversion timed out")
            return False
        except Exception as e:
            logger.debug(f"Error during GPG conversion: {e}")
            return False
        finally:
            # Clean up temporary directory
            if temp_home and temp_home.exists():
                try:
                    shutil.rmtree(temp_home)
                    logger.debug(f"Cleaned up temporary GPG home: {temp_home}")
                except Exception as e:
                    logger.debug(f"Failed to clean up temporary directory: {e}")

    def _export_keyring_files(self, output_dir: Path, export_private: bool) -> Tuple[Optional[Path], Optional[Path]]:
        """
        Export keyring files, attempting conversion to ASCII armored format.

        Priority order:
        1. Try GPG conversion to ASCII armored format
        2. Fall back to direct binary copy if conversion fails
        """
        if not self.keyring_path:
            self.error_tracker.add_error("Cannot export keyring files: keyring path not found")
            return (None, None)

        public_keyring = self.keyring_path / 'pubring.pkr'
        private_keyring = self.keyring_path / 'secring.skr'

        public_out = None
        private_out = None

        # Export public keyring
        if public_keyring.exists():
            # Try ASCII conversion first
            ascii_output = output_dir / 'pgp_public_keys.asc'
            if self._convert_keyring_with_gpg(public_keyring, ascii_output, is_secret=False):
                public_out = ascii_output
            else:
                # Fall back to binary copy
                logger.info("GPG conversion failed, falling back to binary copy")
                try:
                    public_out = output_dir / 'pubring.pkr'
                    import shutil
                    shutil.copy2(public_keyring, public_out)
                    size = public_out.stat().st_size
                    logger.info(f"SUCCESS: Copied public keyring to: {public_out} ({size} bytes)")
                    self.error_tracker.add_warning(
                        f"Could not convert to ASCII format - copied binary keyring. "
                        "GPG may have trouble importing this format."
                    )
                except Exception as e:
                    self.error_tracker.add_error(f"Failed to copy public keyring from {public_keyring}", e)
                    public_out = None
        else:
            self.error_tracker.add_error(f"Public keyring file not found: {public_keyring}")

        # Export private keyring
        if export_private:
            if private_keyring.exists():
                # Try ASCII conversion first
                ascii_output = output_dir / 'pgp_private_keys.asc'
                if self._convert_keyring_with_gpg(private_keyring, ascii_output, is_secret=True):
                    private_out = ascii_output
                else:
                    # Fall back to binary copy
                    logger.info("GPG conversion failed, falling back to binary copy")
                    try:
                        private_out = output_dir / 'secring.skr'
                        import shutil
                        shutil.copy2(private_keyring, private_out)
                        size = private_out.stat().st_size
                        logger.info(f"SUCCESS: Copied private keyring to: {private_out} ({size} bytes)")
                        self.error_tracker.add_warning(
                            f"Could not convert to ASCII format - copied binary keyring. "
                            "GPG may have trouble importing this format."
                        )
                    except Exception as e:
                        self.error_tracker.add_error(f"Failed to copy private keyring from {private_keyring}", e)
                        private_out = None
            else:
                self.error_tracker.add_warning(f"Private keyring file not found: {private_keyring}")

        return (public_out, private_out)


class GPGKeyImporter:
    """Handles importing keys into GPG."""

    def __init__(self, gpg_path: Optional[str] = None, error_tracker: Optional[ErrorTracker] = None):
        """
        Initialize the GPG importer.

        Args:
            gpg_path: Path to GPG executable
            error_tracker: ErrorTracker instance for logging errors
        """
        self.error_tracker = error_tracker or ErrorTracker()
        self.gpg_executable = self._find_gpg_executable(gpg_path)
        if not self.gpg_executable:
            self.error_tracker.add_error("GPG executable not found. Please install GPG.")
            raise RuntimeError("GPG executable not found. Please install GPG.")

    def _find_gpg_executable(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Find the GPG executable."""
        if custom_path:
            if os.path.isfile(custom_path):
                logger.info(f"Using custom GPG executable: {custom_path}")
                return custom_path
            else:
                self.error_tracker.add_warning(f"Custom GPG path not found: {custom_path}")

        # Try common executable names
        for exe_name in ['gpg', 'gpg.exe', 'gpg2', 'gpg2.exe']:
            try:
                result = subprocess.run(
                    ['which', exe_name] if os.name != 'nt' else ['where', exe_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    found_path = result.stdout.strip().split('\n')[0]
                    logger.info(f"Found GPG executable: {found_path}")
                    return found_path
            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout while searching for {exe_name}")
            except FileNotFoundError:
                logger.debug(f"Command not found while searching for {exe_name}")
            except Exception as e:
                logger.debug(f"Error searching for {exe_name}: {e}")

        return None

    def get_existing_key_ids(self, secret_keys: bool = False) -> set:
        """
        Get all key IDs currently in GPG keyring.

        Args:
            secret_keys: If True, get secret key IDs; otherwise public key IDs

        Returns:
            Set of key IDs (fingerprints)
        """
        try:
            cmd = [
                self.gpg_executable,
                '--list-secret-keys' if secret_keys else '--list-keys',
                '--with-colons',
                '--fingerprint'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                logger.debug(f"Failed to list existing keys: {result.stderr}")
                return set()

            # Parse GPG output to extract fingerprints
            key_ids = set()
            for line in result.stdout.split('\n'):
                if line.startswith('fpr:'):
                    # Format: fpr:::::::::FINGERPRINT:
                    parts = line.split(':')
                    if len(parts) >= 10 and parts[9]:
                        key_ids.add(parts[9])

            logger.debug(f"Found {len(key_ids)} existing {'secret' if secret_keys else 'public'} keys in GPG")
            return key_ids

        except subprocess.TimeoutExpired:
            logger.debug("Timeout while listing existing keys")
            return set()
        except Exception as e:
            logger.debug(f"Error getting existing key IDs: {e}")
            return set()

    def extract_key_ids_from_file(self, key_file: Path) -> set:
        """
        Extract key IDs (fingerprints) from a key file.

        Args:
            key_file: Path to the key file

        Returns:
            Set of key IDs found in the file
        """
        try:
            cmd = [
                self.gpg_executable,
                '--with-colons',
                '--import-options', 'show-only',
                '--import',
                str(key_file)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse output to extract fingerprints
            key_ids = set()
            key_info = []

            for line in result.stdout.split('\n'):
                if line.startswith('fpr:'):
                    # Format: fpr:::::::::FINGERPRINT:
                    parts = line.split(':')
                    if len(parts) >= 10 and parts[9]:
                        key_ids.add(parts[9])
                elif line.startswith('pub:') or line.startswith('sec:'):
                    # Extract key info for logging
                    parts = line.split(':')
                    if len(parts) >= 5:
                        key_type = 'Secret' if line.startswith('sec:') else 'Public'
                        key_id = parts[4][-16:] if len(parts[4]) >= 16 else parts[4]
                        key_info.append(f"{key_type} key {key_id}")

            if key_info:
                logger.debug(f"Found in file: {', '.join(key_info)}")

            return key_ids

        except subprocess.TimeoutExpired:
            logger.debug(f"Timeout while extracting keys from {key_file}")
            return set()
        except Exception as e:
            logger.debug(f"Error extracting key IDs from file: {e}")
            return set()

    def check_for_duplicates(self, key_file: Path, check_secret: bool = False) -> tuple[set, set]:
        """
        Check if keys in the file already exist in GPG.

        Args:
            key_file: Path to the key file to check
            check_secret: Whether to check secret keys

        Returns:
            Tuple of (keys_in_file, existing_keys)
        """
        keys_in_file = self.extract_key_ids_from_file(key_file)
        existing_keys = self.get_existing_key_ids(secret_keys=check_secret)

        duplicates = keys_in_file & existing_keys

        return (keys_in_file, duplicates)

    def import_keys(self, key_file: Path, skip_existing: bool = False) -> bool:
        """
        Import keys from a file into GPG.

        Args:
            key_file: Path to the key file (.asc, .pgp, or .pkr)
            skip_existing: If True, skip keys that already exist in GPG

        Returns:
            True if import was successful
        """
        if not key_file.exists():
            self.error_tracker.add_error(f"Key file not found: {key_file}")
            return False

        try:
            file_size = key_file.stat().st_size
            logger.info(f"Importing keys from {key_file} ({file_size} bytes) into GPG...")

            # For .pkr files (PGP keyring format), we need to convert them first
            if key_file.suffix == '.pkr':
                self.error_tracker.add_warning(
                    f"File {key_file.name} is in PGP keyring format (.pkr). "
                    "GPG may not be able to import this directly. "
                    "Consider using PGP tools to export to ASCII armored format first."
                )

            # Check for duplicates if requested
            if skip_existing:
                logger.info("Checking for existing keys in GPG keyring...")
                is_secret_key = 'private' in key_file.name.lower() or 'secret' in key_file.name.lower()
                keys_in_file, duplicates = self.check_for_duplicates(key_file, check_secret=is_secret_key)

                if duplicates:
                    logger.info(f"Found {len(duplicates)} key(s) that already exist in GPG:")
                    for key_id in duplicates:
                        logger.info(f"  - {key_id}")

                    if len(duplicates) == len(keys_in_file):
                        logger.info("SUCCESS: All keys already exist in GPG keyring - skipping import")
                        self.error_tracker.add_warning(
                            f"Skipped import of {key_file.name} - all {len(duplicates)} key(s) already exist"
                        )
                        return True  # Not an error, just skipping
                    else:
                        new_keys = len(keys_in_file) - len(duplicates)
                        logger.info(f"Found {new_keys} new key(s) to import (skipping {len(duplicates)} existing)")
                        self.error_tracker.add_warning(
                            f"{len(duplicates)} key(s) already exist and will be skipped/updated"
                        )
                else:
                    logger.info(f"No duplicate keys found - proceeding with import of {len(keys_in_file)} key(s)")

            cmd = [self.gpg_executable, '--import', str(key_file)]
            logger.debug(f"Running command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            # GPG outputs import results to stderr (even on success)
            if result.stderr:
                logger.info(f"GPG import output:\n{result.stderr}")

            if result.returncode == 0:
                # Parse stderr to count imported keys
                imported_count = 0
                unchanged_count = 0
                updated_count = 0

                for line in result.stderr.split('\n'):
                    if 'imported:' in line.lower():
                        # Extract count: "gpg: Total number processed: 5"
                        parts = line.split(':')
                        if len(parts) >= 2:
                            try:
                                imported_count = int(parts[-1].strip().split()[0])
                            except (ValueError, IndexError):
                                pass
                    elif 'unchanged:' in line.lower():
                        try:
                            unchanged_count = int(line.split(':')[-1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif 'new key ids' in line.lower() or 'updated' in line.lower():
                        try:
                            updated_count = int(line.split(':')[-1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass

                # Build success message
                status_parts = []
                if imported_count > 0:
                    status_parts.append(f"{imported_count} imported")
                if updated_count > 0:
                    status_parts.append(f"{updated_count} updated")
                if unchanged_count > 0:
                    status_parts.append(f"{unchanged_count} unchanged")

                if status_parts:
                    logger.info(f"SUCCESS: Keys processed: {', '.join(status_parts)}")
                else:
                    logger.info("SUCCESS: Keys imported successfully into GPG")

                return True
            else:
                error_msg = f"GPG import failed with return code {result.returncode}"
                if result.stderr:
                    error_msg += f"\nGPG output: {result.stderr.strip()}"
                if result.stdout:
                    error_msg += f"\nStdout: {result.stdout.strip()}"
                self.error_tracker.add_error(error_msg)
                return False

        except subprocess.TimeoutExpired:
            self.error_tracker.add_error(f"GPG import timed out after 120 seconds for file: {key_file}")
            return False
        except Exception as e:
            self.error_tracker.add_error(f"Unexpected error during GPG import of {key_file}", e)
            return False

    def list_keys(self):
        """List all keys in GPG keyring."""
        try:
            result = subprocess.run(
                [self.gpg_executable, '--list-keys'],
                capture_output=True,
                text=True,
                timeout=30
            )
            print("\n=== GPG Public Keys ===")
            if result.returncode == 0:
                print(result.stdout if result.stdout.strip() else "No public keys found")
            else:
                self.error_tracker.add_error(f"Failed to list public keys: {result.stderr}")

            result = subprocess.run(
                [self.gpg_executable, '--list-secret-keys'],
                capture_output=True,
                text=True,
                timeout=30
            )
            print("\n=== GPG Private Keys ===")
            if result.returncode == 0:
                print(result.stdout if result.stdout.strip() else "No private keys found")
            else:
                self.error_tracker.add_error(f"Failed to list private keys: {result.stderr}")

        except subprocess.TimeoutExpired:
            self.error_tracker.add_error("GPG list keys operation timed out")
        except Exception as e:
            self.error_tracker.add_error("Error listing GPG keys", e)


def main():
    """Main entry point for the PGP to GPG migration tool."""
    parser = argparse.ArgumentParser(
        description='Export PGP keys and import them into GPG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export and import public keys only
  python pgp2gpg.py

  # Export and import both public and private keys
  python pgp2gpg.py --include-private

  # Specify custom paths
  python pgp2gpg.py --pgp-path /path/to/pgp --keyring-path /path/to/keyrings

  # Only export keys (don't import)
  python pgp2gpg.py --export-only

  # Only import from existing file
  python pgp2gpg.py --import-only --key-file exported_keys.asc
        """
    )

    parser.add_argument(
        '--pgp-path',
        help='Path to PGP executable'
    )
    parser.add_argument(
        '--keyring-path',
        help='Path to PGP keyring directory'
    )
    parser.add_argument(
        '--gpg-path',
        help='Path to GPG executable'
    )
    parser.add_argument(
        '--output-dir',
        default='./exported_keys',
        help='Directory to save exported keys (default: ./exported_keys)'
    )
    parser.add_argument(
        '--include-private',
        action='store_true',
        help='Also export and import private keys'
    )
    parser.add_argument(
        '--passphrase',
        help='Passphrase for encrypted private keys (use with --include-private)'
    )
    parser.add_argument(
        '--passphrase-file',
        help='File containing passphrase (one line, more secure than --passphrase)'
    )
    parser.add_argument(
        '--export-only',
        action='store_true',
        help='Only export keys, do not import into GPG'
    )
    parser.add_argument(
        '--import-only',
        action='store_true',
        help='Only import keys from existing file'
    )
    parser.add_argument(
        '--key-file',
        help='Key file to import (required with --import-only)'
    )
    parser.add_argument(
        '--list-keys',
        action='store_true',
        help='List all GPG keys after import'
    )
    parser.add_argument(
        '--allow-overwrite',
        action='store_true',
        help='Allow re-importing keys that already exist (by default, existing keys are skipped)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--log-file',
        help='Write detailed logs to file (e.g., migration.log)'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    output_dir = Path(args.output_dir)
    error_tracker = ErrorTracker()

    # Handle passphrase
    passphrase = None
    if args.passphrase:
        passphrase = args.passphrase
        logger.debug("Using passphrase from command line")
    elif args.passphrase_file:
        try:
            passphrase_path = Path(args.passphrase_file)
            if not passphrase_path.exists():
                error_tracker.add_error(f"Passphrase file not found: {args.passphrase_file}")
                sys.exit(1)
            with open(passphrase_path, 'r') as f:
                passphrase = f.readline().strip()
            logger.debug(f"Loaded passphrase from file: {args.passphrase_file}")
        except Exception as e:
            error_tracker.add_error(f"Failed to read passphrase file", e)
            sys.exit(1)
    elif args.include_private:
        # Warn if exporting private keys without passphrase
        logger.warning("Exporting private keys without passphrase - this may fail if keys are encrypted")

    try:
        # Import only mode
        if args.import_only:
            if not args.key_file:
                error_tracker.add_error("--key-file is required with --import-only")
                sys.exit(1)

            importer = GPGKeyImporter(args.gpg_path, error_tracker)
            # By default, skip existing keys unless --allow-overwrite is specified
            skip_existing = not args.allow_overwrite
            success = importer.import_keys(Path(args.key_file), skip_existing=skip_existing)

            if success and args.list_keys:
                importer.list_keys()

            # Print error summary
            error_tracker.print_summary()
            sys.exit(0 if success and not error_tracker.has_errors() else 1)

        # Export keys from PGP
        logger.info("=" * 70)
        logger.info("Starting PGP to GPG key migration...")
        logger.info("=" * 70)

        exporter = PGPKeyExporter(args.pgp_path, args.keyring_path, error_tracker, passphrase)

        public_file, private_file = exporter.export_keys(
            output_dir,
            export_private=args.include_private
        )

        if not public_file:
            error_tracker.add_error("Failed to export PGP keys")
            error_tracker.print_summary()
            sys.exit(1)

        logger.info("PGP keys exported successfully")

        # Exit if export-only mode
        if args.export_only:
            logger.info(f"Exported keys saved to: {output_dir}")
            error_tracker.print_summary()
            sys.exit(0 if not error_tracker.has_errors() else 1)

        # Import keys into GPG
        logger.info("\n" + "=" * 70)
        logger.info("Importing keys into GPG...")
        logger.info("=" * 70)

        importer = GPGKeyImporter(args.gpg_path, error_tracker)

        # By default, skip existing keys unless --allow-overwrite is specified
        skip_existing = not args.allow_overwrite

        import_success = True
        if public_file and public_file.exists():
            import_success = importer.import_keys(public_file, skip_existing=skip_existing) and import_success

        if private_file and private_file.exists():
            import_success = importer.import_keys(private_file, skip_existing=skip_existing) and import_success

        # Print error summary
        error_tracker.print_summary()

        if import_success and not error_tracker.has_errors():
            logger.info("\n" + "=" * 70)
            logger.info("SUCCESS: Migration completed successfully!")
            logger.info("=" * 70)
            if args.list_keys:
                importer.list_keys()
            sys.exit(0)
        else:
            logger.error("\n" + "=" * 70)
            logger.error("ERROR: Migration completed with errors")
            logger.error("=" * 70)
            sys.exit(1)

    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
        error_tracker.print_summary()
        sys.exit(130)
    except Exception as e:
        error_tracker.add_error("Unexpected error during migration", e)
        error_tracker.print_summary()
        sys.exit(1)


if __name__ == '__main__':
    main()
