import pytest
from unittest.mock import patch, MagicMock, mock_open
import json
from pathlib import Path
from sync_passwords import PasswordSync, PasswordSyncError, VaultEntry

@pytest.fixture
def password_sync():
    return PasswordSync()

@pytest.fixture
def sample_lastpass_csv():
    return """url,username,password,name,notes
https://example.com,user1,pass1,Entry1,note1
https://test.com,user2,pass2,Entry2,note2"""

@pytest.fixture
def sample_bitwarden_json():
    return {
        "items": [
            {
                "type": 1,
                "name": "Entry1",
                "notes": "note1",
                "login": {
                    "uri": "https://example.com",
                    "username": "user1",
                    "password": "pass1"
                }
            }
        ]
    }

def test_vault_entry_equality():
    entry1 = VaultEntry("url1", "user1", "pass1", "name1", "note1")
    entry2 = VaultEntry("url1", "user1", "pass1", "name1", "note1")
    entry3 = VaultEntry("url2", "user2", "pass2", "name2", "note2")
    
    assert entry1 == entry2
    assert entry1 != entry3
    assert len({entry1, entry2}) == 1  # Test hash functionality

@patch('subprocess.run')
def test_check_cli_tools_success(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    sync = PasswordSync()
    sync.check_cli_tools()
    assert mock_run.call_count == 2

@patch('subprocess.run')
def test_check_cli_tools_failure(mock_run):
    mock_run.side_effect = FileNotFoundError()
    sync = PasswordSync()
    with pytest.raises(PasswordSyncError):
        sync.check_cli_tools()

@patch('subprocess.run')
def test_check_lastpass_login_success(mock_run):
    mock_run.return_value = MagicMock(stdout="Logged in as user@example.com")
    sync = PasswordSync()
    sync.check_lastpass_login()
    mock_run.assert_called_once()

@patch('subprocess.run')
@patch.dict('os.environ', {'LASTPASS_USERNAME': 'user', 'LASTPASS_PASSWORD': 'pass'})
def test_check_lastpass_login_needs_login(mock_run):
    mock_run.side_effect = [
        MagicMock(stdout="Not logged in"),
        MagicMock(returncode=0)
    ]
    sync = PasswordSync()
    sync.check_lastpass_login()
    assert mock_run.call_count == 2

@patch('subprocess.run')
def test_check_bitwarden_login_success(mock_run):
    mock_run.return_value = MagicMock(stdout='{"status": "unlocked"}')
    sync = PasswordSync()
    sync.check_bitwarden_login()
    mock_run.assert_called_once()

@patch('subprocess.run')
@patch.dict('os.environ', {'BITWARDEN_USERNAME': 'user', 'BITWARDEN_PASSWORD': 'pass'})
def test_check_bitwarden_login_needs_login(mock_run):
    mock_run.side_effect = [
        MagicMock(stdout='{"status": "locked"}'),
        MagicMock(returncode=0)
    ]
    sync = PasswordSync()
    sync.check_bitwarden_login()
    assert mock_run.call_count == 2

@patch('subprocess.run')
@patch('pandas.read_csv')
def test_get_lastpass_entries(mock_read_csv, mock_run):
    mock_df = MagicMock()
    mock_df.iterrows.return_value = [
        (0, {'url': 'url1', 'username': 'user1', 'password': 'pass1', 'name': 'name1', 'notes': 'note1'})
    ]
    mock_read_csv.return_value = mock_df
    
    sync = PasswordSync()
    entries = sync.get_lastpass_entries()
    assert len(entries) == 1
    entry = entries.pop()
    assert entry.url == 'url1'
    assert entry.username == 'user1'

@patch('subprocess.run')
def test_get_bitwarden_entries(mock_run, sample_bitwarden_json):
    mock_run.return_value = MagicMock(returncode=0)
    sync = PasswordSync()
    with patch('builtins.open', mock_open(read_data=json.dumps(sample_bitwarden_json))):
        entries = sync.get_bitwarden_entries()
        assert len(entries) == 1
        entry = entries.pop()
        assert entry.url == 'https://example.com'
        assert entry.username == 'user1'

def test_find_differences():
    entry1 = VaultEntry("url1", "user1", "pass1", "name1", "note1")
    entry2 = VaultEntry("url2", "user2", "pass2", "name2", "note2")
    
    lastpass_entries = {entry1, entry2}
    bitwarden_entries = {entry1}
    
    sync = PasswordSync()
    differences = sync.find_differences(lastpass_entries, bitwarden_entries)
    assert len(differences) == 1
    assert differences.pop() == entry2

@patch('subprocess.run')
def test_import_to_bitwarden(mock_run):
    mock_run.return_value = MagicMock(returncode=0)
    sync = PasswordSync()
    sync.import_to_bitwarden(Path("test.csv"))
    mock_run.assert_called_once()

def test_prepare_import_csv():
    sync = PasswordSync()
    entries = {VaultEntry("url1", "user1", "pass1", "name1", "note1")}
    import_path = sync.prepare_import_csv(entries)
    assert import_path.exists()
    import_path.unlink()  # Cleanup