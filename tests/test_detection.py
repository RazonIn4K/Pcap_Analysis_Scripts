import pytest
import os
from pcap_analysis.detection.web import (
    detect_sql_injection, detect_xss, detect_command_injection,
    detect_directory_traversal, load_custom_signatures, detect_custom_patterns
)
from pcap_analysis.detection.network import (
    detect_port_scan, detect_ddos, detect_syn_flood,
    verify_packets, reconstruct_session, correlate_attacks
)
from pcap_analysis.detection.malware import (
    detect_dns_tunneling, detect_c2_traffic, 
    detect_data_exfiltration, check_known_bad_hosts
)

class TestWebDetection:
    """Tests for web attack detection."""
    
    def test_detect_sql_injection(self, sample_pcap, mock_command_output):
        """Test SQL injection detection."""
        result = detect_sql_injection(sample_pcap)
        assert result is not None
    
    def test_detect_xss(self, sample_pcap, mock_command_output):
        """Test XSS detection."""
        result = detect_xss(sample_pcap)
        assert result is not None
    
    def test_detect_command_injection(self, sample_pcap, mock_command_output):
        """Test command injection detection."""
        result = detect_command_injection(sample_pcap)
        assert result is not None
    
    def test_detect_directory_traversal(self, sample_pcap, mock_command_output):
        """Test directory traversal detection."""
        result = detect_directory_traversal(sample_pcap)
        assert result is not None
    
    def test_load_custom_signatures(self, temp_dir):
        """Test loading custom signatures."""
        # Create a test signature file
        sig_file = os.path.join(temp_dir, "signatures.yaml")
        with open(sig_file, "w") as f:
            f.write("""
            signatures:
              - name: "Test Signature"
                description: "Test signature for unit tests"
                filter: "http.request.uri contains 'test'"
                fields:
                  - frame.number
                  - ip.src
                severity: medium
            """)
        
        signatures = load_custom_signatures(sig_file)
        assert signatures is not None
        assert len(signatures) == 1
        assert signatures[0]["name"] == "Test Signature"
    
    def test_detect_custom_patterns(self, sample_pcap, mock_command_output):
        """Test custom pattern detection."""
        signatures = [
            {
                "name": "Test Signature",
                "description": "Test signature for unit tests",
                "filter": "http.request.uri contains 'test'",
                "fields": ["frame.number", "ip.src"],
                "severity": "medium"
            }
        ]
        
        result = detect_custom_patterns(sample_pcap, signatures)
        assert result is not None

class TestNetworkDetection:
    """Tests for network attack detection."""
    
    def test_detect_port_scan(self, sample_pcap, mock_command_output):
        """Test port scan detection."""
        result = detect_port_scan(sample_pcap)
        assert result is not None
        assert "port_scan" in result
    
    def test_detect_ddos(self, sample_pcap, mock_command_output):
        """Test DDoS detection."""
        result = detect_ddos(sample_pcap)
        assert result is not None
        assert "traffic_volume" in result
    
    def test_detect_syn_flood(self, sample_pcap, mock_command_output):
        """Test SYN flood detection."""
        result = detect_syn_flood(sample_pcap)
        assert result is not None
        assert "syn_flood" in result
    
    def test_correlate_attacks(self, sample_pcap, mock_command_output):
        """Test attack correlation."""
        result = correlate_attacks(sample_pcap)
        assert result is not None
        assert "correlation" in result

class TestMalwareDetection:
    """Tests for malware detection."""
    
    def test_detect_dns_tunneling(self, sample_pcap, mock_command_output):
        """Test DNS tunneling detection."""
        result = detect_dns_tunneling(sample_pcap)
        assert result is not None
    
    def test_detect_c2_traffic(self, sample_pcap, mock_command_output):
        """Test C2 traffic detection."""
        result = detect_c2_traffic(sample_pcap)
        assert result is not None
        assert "unusual_ports" in result
    
    def test_detect_data_exfiltration(self, sample_pcap, mock_command_output):
        """Test data exfiltration detection."""
        result = detect_data_exfiltration(sample_pcap)
        assert result is not None
        assert "large_transfers" in result
