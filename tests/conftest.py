import os
import pytest
import tempfile
import shutil
from pathlib import Path

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def sample_pcap():
    """Path to a sample PCAP file for testing."""
    # Check if sample data directory exists
    sample_dir = Path(__file__).parent.parent / "sample_data"
    if not sample_dir.exists():
        pytest.skip("Sample data directory not found")
    
    # Look for sample PCAP files
    pcap_files = list(sample_dir.glob("*.pcap")) + list(sample_dir.glob("*.pcapng"))
    if not pcap_files:
        pytest.skip("No sample PCAP files found")
    
    return str(pcap_files[0])

@pytest.fixture
def mock_command_output(monkeypatch):
    """Mock the run_command function to return predefined output."""
    def _mock_run_command(command, use_cache=True, verbose=False, timeout=300):
        # Return different outputs based on the command
        if "capinfos" in command:
            return "File name: sample.pcap\nFile size: 1000 bytes\nPackets: 100"
        elif "tshark -r" in command and "-Y \"http" in command:
            return "1 192.168.1.1 GET /index.html"
        elif "tshark -r" in command and "-Y \"dns" in command:
            return "1 192.168.1.1 example.com"
        elif "tshark -r" in command and "-Y \"tcp.flags.syn==1" in command:
            return "1 192.168.1.1 192.168.1.2 80"
        else:
            return "Mock output for: " + command
    
    from pcap_analysis.core import command
    monkeypatch.setattr(command, "run_command", _mock_run_command)
    return _mock_run_command
