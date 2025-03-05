import pytest
import os
import tempfile
from pcap_analysis.core.command import run_command, clear_cache
from pcap_analysis.core.config import Config
from pcap_analysis.core.dependencies import check_dependency
from pcap_analysis.core.errors import PcapAnalysisError, CommandError, handle_error

class TestCommand:
    """Tests for the command module."""
    
    def test_run_command_success(self):
        """Test successful command execution."""
        result = run_command("echo 'test'", verbose=True)
        assert result.strip() == "'test'"
    
    def test_run_command_failure(self):
        """Test failed command execution."""
        result = run_command("command_that_does_not_exist", verbose=True)
        assert result is None
    
    def test_command_cache(self):
        """Test command caching."""
        # First call should execute the command
        result1 = run_command("echo 'test'", use_cache=True, verbose=True)
        # Second call should use the cache
        result2 = run_command("echo 'test'", use_cache=True, verbose=True)
        assert result1 == result2
        
        # Clear cache and run again
        clear_cache()
        result3 = run_command("echo 'test'", use_cache=True, verbose=True)
        assert result1 == result3

class TestConfig:
    """Tests for the config module."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = Config()
        assert config.get("output", "directory") == "./output"
        assert config.get("output", "format") == "json"
        assert config.get("output", "visualize") is True
    
    def test_load_from_file(self, temp_dir):
        """Test loading configuration from file."""
        # Create a test config file
        config_file = os.path.join(temp_dir, "config.yaml")
        with open(config_file, "w") as f:
            f.write("""
            output:
              directory: /test/output
              format: html
            """)
        
        # Load config
        config = Config(config_file)
        assert config.get("output", "directory") == "/test/output"
        assert config.get("output", "format") == "html"
        assert config.get("output", "visualize") is True  # Default value
    
    def test_set_and_save(self, temp_dir):
        """Test setting and saving configuration."""
        config = Config()
        
        # Set values
        config.set("output", "directory", "/new/output")
        config.set("output", "format", "csv")
        
        # Save config
        config_file = os.path.join(temp_dir, "config.yaml")
        config.save(config_file)
        
        # Load config again
        config2 = Config(config_file)
        assert config2.get("output", "directory") == "/new/output"
        assert config2.get("output", "format") == "csv"

class TestDependencies:
    """Tests for the dependencies module."""
    
    def test_check_dependency_success(self):
        """Test successful dependency check."""
        # This should pass on most systems
        assert check_dependency("python") is True
    
    def test_check_dependency_failure(self):
        """Test failed dependency check."""
        with pytest.raises(PcapAnalysisError):
            check_dependency("command_that_does_not_exist")

class TestErrors:
    """Tests for the errors module."""
    
    def test_pcap_analysis_error(self):
        """Test PcapAnalysisError."""
        error = PcapAnalysisError("Test error")
        assert str(error) == "Test error (Error code: UNKNOWN_ERROR)"
    
    def test_command_error(self):
        """Test CommandError."""
        error = CommandError("test command", "error output", 1)
        assert "Command failed with exit code 1" in str(error)
    
    def test_handle_error(self):
        """Test error handling."""
        error = PcapAnalysisError("Test error")
        error_code = handle_error(error)
        assert error_code == 1
