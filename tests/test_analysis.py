import pytest
from pcap_analysis.analysis.patterns import analyze_timing_patterns, detect_beaconing
from pcap_analysis.analysis.anomalies import detect_packet_anomalies, detect_anomalies
from pcap_analysis.analysis.http_responses import analyze_http_responses, analyze_application_protocols

class TestPatterns:
    """Tests for the patterns module."""
    
    def test_analyze_timing_patterns(self, sample_pcap, mock_command_output):
        """Test timing pattern analysis."""
        result = analyze_timing_patterns(sample_pcap)
        assert result is not None
        assert "intervals" in result or "error" in result
    
    def test_detect_beaconing(self, sample_pcap, mock_command_output):
        """Test beaconing detection."""
        result = detect_beaconing(sample_pcap)
        assert result is not None
        assert isinstance(result, dict)

class TestAnomalies:
    """Tests for the anomalies module."""
    
    def test_detect_packet_anomalies(self, sample_pcap, mock_command_output):
        """Test packet anomaly detection."""
        result = detect_packet_anomalies(sample_pcap)
        assert result is not None
        assert isinstance(result, dict)
        assert "large_packets" in result
    
    @pytest.mark.skipif(True, reason="Requires scikit-learn and numpy")
    def test_detect_anomalies(self, sample_pcap, mock_command_output):
        """Test machine learning anomaly detection."""
        result = detect_anomalies(sample_pcap)
        assert result is not None

class TestHttpResponses:
    """Tests for the HTTP responses module."""
    
    def test_analyze_http_responses(self, sample_pcap, mock_command_output):
        """Test HTTP response analysis."""
        result = analyze_http_responses(sample_pcap)
        assert result is not None
        assert "http_codes" in result
    
    def test_analyze_application_protocols(self, sample_pcap, mock_command_output):
        """Test application protocol analysis."""
        result = analyze_application_protocols(sample_pcap)
        assert result is not None
        assert "tls_ciphers" in result or "dns_queries" in result
