import pytest
import os
import json
import yaml
from pcap_analysis.reporting.formatter import (
    format_json, format_yaml, format_csv,
    generate_html_report, generate_visualizations
)

class TestFormatter:
    """Tests for the formatter module."""
    
    @pytest.fixture
    def sample_results(self):
        """Sample analysis results for testing."""
        return {
            "metadata": {
                "pcap_file": "sample.pcap",
                "analysis_time": "2023-01-01T00:00:00"
            },
            "basic_analysis": {
                "file_info": "sample.pcap: 1000 bytes",
                "pcap_summary": "Packets: 100"
            },
            "web_attacks": {
                "sql_injection": "1 192.168.1.1 GET /index.php?id=1'--"
            },
            "network_attacks": {
                "port_scan": "10 192.168.1.1 192.168.1.2 80",
                "correlated_attacks": {
                    "correlation": "5 192.168.1.1",
                    "ip_attack_types": {
                        "192.168.1.1": {
                            "sql_injection": 1,
                            "port_scan": 10
                        }
                    }
                }
            }
        }
    
    def test_format_json(self, temp_dir, sample_results):
        """Test JSON formatting."""
        output_file = os.path.join(temp_dir, "output.json")
        result = format_json(sample_results, output_file)
        
        assert result is not None
        assert os.path.exists(output_file)
        
        # Verify the content
        with open(output_file, "r") as f:
            loaded = json.load(f)
        
        assert loaded["metadata"]["pcap_file"] == "sample.pcap"
        assert "web_attacks" in loaded
    
    def test_format_yaml(self, temp_dir, sample_results):
        """Test YAML formatting."""
        output_file = os.path.join(temp_dir, "output.yaml")
        result = format_yaml(sample_results, output_file)
        
        assert result is not None
        assert os.path.exists(output_file)
        
        # Verify the content
        with open(output_file, "r") as f:
            loaded = yaml.safe_load(f)
        
        assert loaded["metadata"]["pcap_file"] == "sample.pcap"
        assert "web_attacks" in loaded
    
    def test_format_csv(self, temp_dir, sample_results):
        """Test CSV formatting."""
        output_file = os.path.join(temp_dir, "output.csv")
        result = format_csv(sample_results, output_file)
        
        assert result is not None
        assert os.path.exists(output_file)
    
    def test_generate_html_report(self, temp_dir, sample_results):
        """Test HTML report generation."""
        output_file = os.path.join(temp_dir, "output.html")
        result = generate_html_report(sample_results, output_file)
        
        assert result is not None
        assert os.path.exists(output_file)
        
        # Verify the content
        with open(output_file, "r") as f:
            content = f.read()
        
        assert "PCAP Analysis Report" in content
        assert "sample.pcap" in content
        assert "Correlated Attack Sources" in content
    
    @pytest.mark.skipif(True, reason="Requires matplotlib")
    def test_generate_visualizations(self, temp_dir, sample_results):
        """Test visualization generation."""
        # Add required data for visualizations
        sample_results["protocol_stats"] = {
            "TCP": 50,
            "UDP": 30,
            "HTTP": 20
        }
        
        result = generate_visualizations(sample_results, temp_dir)
        assert result is not None
