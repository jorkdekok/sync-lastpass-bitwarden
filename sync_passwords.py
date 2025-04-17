#!/usr/bin/env python3

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import tempfile
from loguru import logger
import pandas as pd
import hashlib
import csv
from typing import Set

class PasswordSyncError(Exception):
    pass

class VaultEntry:
    def __init__(self, url: str, username: str, password: str, name: str, notes: str = ""):
        self.url = url or ""
        self.username = username or ""
        self.password = password or ""
        self.name = name or ""
        self.notes = notes or ""

    def get_hash(self) -> str:
        """Generate a unique hash for the entry based on its content"""
        content = f"{self.url}{self.username}{self.password}{self.name}{self.notes}"
        return hashlib.blake2b(content.encode(), digest_size=32).hexdigest()

    def __eq__(self, other):
        if not isinstance(other, VaultEntry):
            return False
        return self.get_hash() == other.get_hash()

    def __hash__(self):
        return hash(self.get_hash())

class PasswordSync:
    def __init__(self):
        self.temp_dir = Path(tempfile.gettempdir())
        self.setup_logging()

    def setup_logging(self):
        """Configure logging with loguru"""
        logger.remove()
        logger.add(
            sys.stdout,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <white>{message}</white>",
            level="INFO"
        )
        logger.add(
            "sync_passwords.log",
            rotation="1 week",
            retention="1 month",
            level="DEBUG"
        )

    def check_cli_tools(self):
        """Verify that both LastPass and Bitwarden CLI tools are installed"""
        try:
            subprocess.run(['lpass', '--version'], capture_output=True, check=True)
            subprocess.run(['bw', '--version'], capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            raise PasswordSyncError(f"CLI tool check failed: {str(e)}")
        except FileNotFoundError:
            raise PasswordSyncError("LastPass CLI (lpass) and/or Bitwarden CLI (bw) not found. Please install both tools.")

    def check_lastpass_login(self):
        """Check if logged into LastPass and login if needed using environment variables"""
        import os
        
        try:
            result = subprocess.run(['lpass', 'status'], capture_output=True, text=True)
            if 'Not logged in' in result.stdout or 'Not logged in' in result.stderr:
                username = os.environ.get('LASTPASS_USERNAME')
                password = os.environ.get('LASTPASS_PASSWORD')
                if not username or not password:
                    raise PasswordSyncError("LASTPASS_USERNAME and LASTPASS_PASSWORD environment variables must be set")
                
                # Login with MFA
                try:
                    process = subprocess.run(['lpass', 'login', '--trust', username], 
                                          input=password, 
                                          text=True, 
                                          capture_output=True)
                    if process.returncode != 0:
                        raise PasswordSyncError(f"LastPass login failed: {process.stderr}")
                except subprocess.CalledProcessError as e:
                    raise PasswordSyncError(f"LastPass login failed: {str(e)}")
                
                logger.info("Successfully logged into LastPass")
        except subprocess.CalledProcessError as e:
            raise PasswordSyncError(f"LastPass status check failed: {str(e)}")

    def check_bitwarden_login(self):
        """Check if logged into Bitwarden and login if needed using environment variables"""
        import os

        try:
            result = subprocess.run(['bw', 'status'], capture_output=True, text=True)
            status = json.loads(result.stdout)
            
            if status.get('status') != 'unlocked':
                username = os.environ.get('BITWARDEN_USERNAME')
                password = os.environ.get('BITWARDEN_PASSWORD')
                if not username or not password:
                    raise PasswordSyncError("BITWARDEN_USERNAME and BITWARDEN_PASSWORD environment variables must be set")
                
                try:
                    process = subprocess.run(['bw', 'login', username], 
                                          input=password,
                                          text=True,
                                          capture_output=True)
                    if process.returncode != 0:
                        raise PasswordSyncError(f"Bitwarden login failed: {process.stderr}")
                except subprocess.CalledProcessError as e:
                    raise PasswordSyncError(f"Bitwarden login failed: {str(e)}")
                
                logger.info("Successfully logged into Bitwarden")
        except subprocess.CalledProcessError as e:
            raise PasswordSyncError(f"Bitwarden status check failed: {str(e)}")
        except json.JSONDecodeError:
            raise PasswordSyncError("Failed to parse Bitwarden status")

    def get_lastpass_entries(self) -> Set[VaultEntry]:
        """Export and parse LastPass entries"""
        export_path = self.temp_dir / f"lastpass_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            logger.info("Exporting LastPass vault...")
            subprocess.run(['lpass', 'export'], capture_output=True, text=True, check=True,
                         stdout=open(export_path, 'w'))
            
            entries = set()
            df = pd.read_csv(export_path)
            for _, row in df.iterrows():
                entry = VaultEntry(
                    url=str(row.get('url', '')),
                    username=str(row.get('username', '')),
                    password=str(row.get('password', '')),
                    name=str(row.get('name', '')),
                    notes=str(row.get('notes', ''))
                )
                entries.add(entry)
            
            logger.info(f"Parsed {len(entries)} entries from LastPass")
            return entries
        except Exception as e:
            raise PasswordSyncError(f"Failed to export/parse LastPass vault: {str(e)}")
        finally:
            if export_path.exists():
                export_path.unlink()

    def get_bitwarden_entries(self) -> Set[VaultEntry]:
        """Export and parse Bitwarden entries"""
        export_path = self.temp_dir / f"bitwarden_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            logger.info("Exporting Bitwarden vault...")
            subprocess.run(['bw', 'export', '--output', str(export_path), '--format', 'json'],
                         capture_output=True, check=True)
            
            entries = set()
            with open(export_path) as f:
                data = json.load(f)
                for item in data.get('items', []):
                    if item.get('type') == 1:  # Login
                        login = item.get('login', {})
                        entry = VaultEntry(
                            url=login.get('uri', ''),
                            username=login.get('username', ''),
                            password=login.get('password', ''),
                            name=item.get('name', ''),
                            notes=item.get('notes', '')
                        )
                        entries.add(entry)
            
            logger.info(f"Parsed {len(entries)} entries from Bitwarden")
            return entries
        except Exception as e:
            raise PasswordSyncError(f"Failed to export/parse Bitwarden vault: {str(e)}")
        finally:
            if export_path.exists():
                export_path.unlink()

    def prepare_import_csv(self, entries: Set[VaultEntry]) -> Path:
        """Create a CSV file for Bitwarden import"""
        import_path = self.temp_dir / f"bitwarden_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(import_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['folder', 'favorite', 'type', 'name', 'notes', 'fields',
                               'login_uri', 'login_username', 'login_password'])
                for entry in entries:
                    writer.writerow(['', '0', 'login', entry.name, entry.notes, '',
                                   entry.url, entry.username, entry.password])
            return import_path
        except Exception as e:
            raise PasswordSyncError(f"Failed to prepare import CSV: {str(e)}")

    def import_to_bitwarden(self, csv_path: Path):
        """Import CSV file into Bitwarden"""
        try:
            logger.info("Importing to Bitwarden...")
            subprocess.run(['bw', 'import', 'lastpass', str(csv_path)], check=True)
            logger.success("Successfully imported to Bitwarden")
        except subprocess.CalledProcessError as e:
            raise PasswordSyncError(f"Failed to import to Bitwarden: {str(e)}")

    def find_differences(self, lastpass_entries: Set[VaultEntry],
                        bitwarden_entries: Set[VaultEntry]) -> Set[VaultEntry]:
        """Find entries that need to be synced (in LastPass but not in Bitwarden)"""
        return lastpass_entries - bitwarden_entries

    def sync(self):
        """Main sync process"""
        try:
            logger.info("Starting password sync process...")
            self.check_cli_tools()
            self.check_lastpass_login()
            self.check_bitwarden_login()
            
            # Get entries from both vaults
            lastpass_entries = self.get_lastpass_entries()
            bitwarden_entries = self.get_bitwarden_entries()
            
            # Find differences
            entries_to_sync = self.find_differences(lastpass_entries, bitwarden_entries)
            
            if not entries_to_sync:
                logger.info("No differences found between vaults. Nothing to sync.")
                return
            
            logger.info(f"Found {len(entries_to_sync)} entries to sync")
            
            # Check if import is enabled
            import os
            if os.environ.get('IMPORT_TO_BITWARDEN', '').lower() == 'true':
                # Prepare and import differences
                import_path = self.prepare_import_csv(entries_to_sync)
                self.import_to_bitwarden(import_path)
                
                # Cleanup
                if import_path.exists():
                    import_path.unlink()
                
                logger.success(f"Password sync completed successfully! Synced {len(entries_to_sync)} entries.")
            else:
                logger.info("Import to Bitwarden skipped (IMPORT_TO_BITWARDEN not set to 'true')")
        except PasswordSyncError as e:
            logger.error(f"Sync failed: {str(e)}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    syncer = PasswordSync()
    syncer.sync()
