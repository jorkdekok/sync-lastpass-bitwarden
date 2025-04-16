# LastPass to Bitwarden Password Sync

This script synchronizes passwords from LastPass to Bitwarden using their respective CLI tools. It performs an intelligent sync by only importing entries that exist in LastPass but not in Bitwarden, avoiding duplicate entries.

## Prerequisites

### Local Installation
1. LastPass CLI (`lpass`) installed and configured
2. Bitwarden CLI (`bw`) installed and configured
3. Python 3.7+
4. Required Python packages (install using `pip install -r requirements.txt`)

### Docker Installation
1. Docker installed on your system
2. No other prerequisites needed - everything is included in the container

## Installation

### Local Installation
1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Docker Installation
1. Clone this repository
2. Build the Docker image:
   ```bash
   docker build -t sync-lpass-bw .
   ```

## Usage

### Local Usage
1. Login to LastPass CLI:
   ```bash
   lpass login <your-email>
   ```

2. Login to Bitwarden CLI:
   ```bash
   bw login <your-email>
   bw unlock
   ```

3. Run the sync script:
   ```bash
   python sync_passwords.py
   ```

### Docker Usage
1. Run the container with mounted volume for logs:
   ```bash
   docker run -it --rm \
     -v $(pwd)/logs:/app/logs \
     sync-lpass-bw
   ```
   The script will prompt you to log in to both LastPass and Bitwarden.

## Features

- Smart synchronization - only syncs entries that exist in LastPass but not in Bitwarden
- Compares entries based on their content (URL, username, password, name, and notes)
- Uses secure hashing to detect differences
- Exports LastPass vault to a temporary CSV file
- Imports only the differences into Bitwarden
- Automatic cleanup of temporary files
- Comprehensive error handling
- Detailed logging (console and file-based)
- Docker support for easy deployment

## Security Notes

- The script creates temporary files during the sync process
- All temporary files are automatically deleted after use
- No passwords are stored permanently on disk
- All operations are performed locally
- Uses blake2b hashing for secure comparison
- When using Docker, credentials are isolated within the container

## Logs

Logs are stored in `sync_passwords.log` with a 1-week rotation and 1-month retention policy. When using Docker, logs are persisted to the host machine through a volume mount.
