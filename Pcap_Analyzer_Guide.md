# PCAP Analyzer User Guide

## Introduction

PCAP Analyzer is an advanced network security analysis tool designed to analyze PCAP (Packet Capture) files for security threats and anomalies. It provides comprehensive analysis capabilities, including detection of web attacks, network attacks, and malware activity.

## Installation

### Prerequisites

- Python 3.8 or higher
- Wireshark/tshark (command-line utilities)

### Installation Steps

1. Install from PyPI:
   ```
   pip install pcap-analyzer
   ```

2. Or install from source:
   ```
   git clone https://github.com/yourusername/pcap-analyzer.git
   cd pcap-analyzer
   pip install -e .
   ```

3. Ensure tshark is installed and available in your PATH:
   - For Ubuntu/Debian: `sudo apt-get install tshark`
   - For macOS: `brew install wireshark`
   - For Windows: Install Wireshark, which includes tshark

## Basic Usage

### Command-Line Interface

The PCAP Analyzer provides a command-line interface (CLI) for easy use:

pcap-analyzer analyze <pcap_file> [options]

### Quick Check

To perform a quick check of a PCAP file:

pcap-analyzer check <pcap_file>

pcap-analyzer check <pcap_file>

### Version Information

To show version information:

pcap-analyzer version

### Command-Line Options

- `pcap_file`: Path to the PCAP file to analyze
- `--config`, `-c`: Path to configuration file
- `--output-dir`, `-o`: Directory for output files (default: ./output)
- `--format`, `-f`: Output format (json, yaml, csv, html, all)
- `--basic`, `-b`: Perform basic analysis only
- `--full`: Perform full analysis (all modules)
- `--detect-web`: Detect web-based attacks
- `--detect-network`: Detect network-based attacks
- `--detect-malware`: Detect malware activity
- `--time-filter`, `-t`: Time filter for analysis (Wireshark display filter format)
- `--custom-signatures`: Path to custom detection signatures file
- `--ioc-file`: Path to IOC file for checking
- `--visualize`, `-v`: Generate visualizations
- `--verbose`: Enable verbose output
- `--log-file`: Path to log file
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

## Examples

### Basic Analysis

pcap-analyzer analyze capture.pcap --basic

### Full Analysis with All Detection Modules

pcap-analyzer analyze capture.pcap --full

### Web Attack Detection with HTML Report

pcap-analyzer analyze capture.pcap --detect-web --format html

### Custom Signatures and IOC Checking

pcap-analyzer analyze capture.pcap --custom-signatures signatures.yaml --ioc-file iocs.json

### Time-Filtered Analysis

pcap-analyzer analyze capture.pcap --time-filter "frame.time >= \"2023-01-01 00:00:00\""

## Configuration

### Configuration File

The PCAP Analyzer can be configured using a YAML or JSON configuration file:

```yaml
# config.yaml
output:
  directory: ./output
  format: json
  visualize: true
analysis:
  max_workers: 4
  cache_ttl: 3600
detection:
  thresholds:
    dns_entropy: 0.8
    port_scan: 10
    syn_flood: 100
    data_exfil: 1000000
reporting:
  max_items: 100
  html_template: default
```

### Environment Variables

Configuration can also be set using environment variables with the prefix `PCAP_`:

```
PCAP_OUTPUT_DIRECTORY=/path/to/output
PCAP_OUTPUT_FORMAT=html
PCAP_ANALYSIS_MAX_WORKERS=8
```

## Custom Signatures

You can create custom detection signatures in YAML format:

```yaml
# signatures.yaml
signatures:
  - name: "Custom SQL Injection"
    description: "Detects custom SQL injection patterns"
    filter: "http.request.uri contains \"'--\" or http.request.uri contains \"OR 1=1\""
    fields:
      - frame.number
      - ip.src
      - http.request.uri
    severity: high

  - name: "Custom Malware Detection"
    description: "Detects communication with known malware domains"
    filter: "dns.qry.name contains \"malware-domain.com\""
    fields:
      - frame.number
      - ip.src
      - dns.qry.name
    severity: critical
```

## Indicators of Compromise (IOCs)

You can provide a JSON file with indicators of compromise:

```json
{
  "ip_addresses": [
    "192.168.1.100",
    "10.0.0.1"
  ],
  "domains": [
    "malicious-domain.com",
    "evil-site.org"
  ],
  "hashes": [
    "44d88612fea8a8f36de82e1278abb02f",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ]
}
```

## Output Formats

The PCAP Analyzer supports multiple output formats:

- **JSON**: Detailed JSON output with all analysis results
- **YAML**: YAML format for better readability
- **CSV**: CSV format for easy import into spreadsheets
- **HTML**: Interactive HTML report with visualizations

## Visualizations

When the `--visualize` option is enabled, the PCAP Analyzer generates various visualizations:

- Traffic volume over time
- Protocol distribution
- Top talkers
- Packet size distribution
- Attack distribution

## Troubleshooting

### Common Issues

1. **tshark not found**: Ensure Wireshark/tshark is installed and in your PATH
2. **Permission denied**: Run with appropriate permissions to read PCAP files
3. **Memory errors**: For large PCAP files, increase available memory or use time filters

### Logging

Use the `--log-file` and `--log-level` options to enable detailed logging for troubleshooting:

```
pcap-analyzer analyze capture.pcap --log-file pcap-analyzer.log --log-level DEBUG
```

## Support

For issues, feature requests, or contributions, please visit:
https://github.com/yourusername/pcap-analyzer/issues

pcap-analyzer analyze capture.pcap --basic
### Full Analysis with All Detection Modules

pcap-analyzer analyze capture.pcap --full
### Web Attack Detection with HTML Report

pcap-analyzer analyze capture.pcap --detect-web --format html
### Custom Signatures and IOC Checking

pcap-analyzer analyze capture.pcap --custom-signatures signatures.yaml --ioc-file iocs.json
### Time-Filtered Analysis
pcap-analyzer analyze capture.pcap --time-filter "frame.time >= \"2023-01-01 00:00:00\""

## Configuration

### Configuration File

The PCAP Analyzer can be configured using a YAML or JSON configuration file:

```yaml
# config.yaml
output:
  directory: ./output
  format: json
  visualize: true
analysis:
  max_workers: 4
  cache_ttl: 3600
detection:
  thresholds:
    dns_entropy: 0.8
    port_scan: 10
    syn_flood: 100
    data_exfil: 1000000
reporting:
  max_items: 100
  html_template: default
```

### Environment Variables

Configuration can also be set using environment variables with the prefix `PCAP_`:

PCAP_OUTPUT_DIRECTORY=/path/to/output
PCAP_OUTPUT_FORMAT=html
PCAP_ANALYSIS_MAX_WORKERS=8


## Custom Signatures

You can create custom detection signatures in YAML format:

```yaml
# signatures.yaml
signatures:
  - name: "Custom SQL Injection"
    description: "Detects custom SQL injection patterns"
    filter: "http.request.uri contains \"'--\" or http.request.uri contains \"OR 1=1\""
    fields:
      - frame.number
      - ip.src
      - http.request.uri
    severity: high

  - name: "Custom Malware Detection"
    description: "Detects communication with known malware domains"
    filter: "dns.qry.name contains \"malware-domain.com\""
    fields:
      - frame.number
      - ip.src
      - dns.qry.name
    severity: critical
```

## Indicators of Compromise (IOCs)

You can provide a JSON file with indicators of compromise:

```json
{
  "ip_addresses": [
    "192.168.1.100",
    "10.0.0.1"
  ],
  "domains": [
    "malicious-domain.com",
    "evil-site.org"
  ],
  "hashes": [
    "44d88612fea8a8f36de82e1278abb02f",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ]
}
```

## Output Formats

The PCAP Analyzer supports multiple output formats:

- **JSON**: Detailed JSON output with all analysis results
- **YAML**: YAML format for better readability
- **CSV**: CSV format for easy import into spreadsheets
- **HTML**: Interactive HTML report with visualizations

## Visualizations

When the `--visualize` option is enabled, the PCAP Analyzer generates various visualizations:

- Traffic volume over time
- Protocol distribution
- Top talkers
- Packet size distribution
- Attack distribution

## Troubleshooting

### Common Issues

1. **tshark not found**: Ensure Wireshark/tshark is installed and in your PATH
2. **Permission denied**: Run with appropriate permissions to read PCAP files
3. **Memory errors**: For large PCAP files, increase available memory or use time filters

### Logging

Use the `--log-file` and `--log-level` options to enable detailed logging for troubleshooting:

pcap-analyzer analyze capture.pcap --log-file pcap-analyzer.log --log-level DEBUG


## Support

For issues, feature requests, or contributions, please visit:
https://github.com/yourusername/pcap-analyzer/issues

7.2. Developer Guide

# PCAP Analyzer Developer Guide

## Architecture Overview

The PCAP Analyzer is designed with a modular architecture to facilitate maintainability and extensibility. The main components are:

1. **Core**: Basic functionality used by other modules
2. **Analysis**: Advanced analysis techniques
3. **Detection**: Threat detection modules
4. **Threat Intelligence**: IOC handling
5. **Reporting**: Output generation

### Component Diagram

+----------------+
| CLI |
+-------+--------+
|
v
+-------+--------+
| Main |
+-------+--------+
|
+---------------+---------------+
| | |
+---------v------+ +------v-------+ +-----v--------+
| Analysis | | Detection | | Reporting |
+---------+------+ +------+-------+ +-----+---------+
| | |
+---------------v---------------+
|
+-------v--------+
| Core |
+----------------+

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Wireshark/tshark
- Git

### Setting Up Development Environment

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/pcap-analyzer.git
   cd pcap-analyzer
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks:
   ```
   pre-commit install
   ```

## Code Organization

### Package Structure
Implement the changes based on the last prompt I gave you to the codebase

Thought Process
I'll implement the changes from your detailed prompt to the modularized codebase. Let's update each component one by one:
1. First, let's update pcap_analysis/core/command.py:
2. Now let's update pcap_analysis/analysis/anomalies.py:
3. Now let's create and implement the HTTP responses module:
results
4. Let's update pcap_analysis/detection/network.py:
5. Let's update pcap_analysis/detection/web.py:
6. Let's update pcap_analysis/detection/malware.py:
7. Let's update pcap_analysis/main.py to add beaconing detection:
8. Finally, let's enhance the reporting module:
None
Now that I've implemented all the changes from the prompt, here's a summary of what's been updated across the codebase:
1. Core Module Updates
Enhanced run_command with a verbose parameter to control output verbosity
Improved command execution with better progress indicators and error handling
2. Analysis Module Updates
Created a new http_responses.py with enhanced HTTP error analysis and server header detection
Updated anomalies.py with reduced verbosity and better formatting for packet anomalies
Added proper -q -z io,stat,0 flags to reduce command output verbosity
3. Detection Module Updates
Fixed commands in web.py to use proper escaping for backticks and other special characters
Updated network.py with fixed syntax for io,stat commands and added correlate_attacks function
Enhanced malware.py with improved detection for C2 traffic and beaconing
4. Reporting Module Updates
Enhanced HTML report generation with special formatting for correlated attacks
Added packet size distribution visualization
Improved the structure of the HTML report with dedicated visualization sections
5. Main Module Updates
Added check_dependencies function
Added beaconing detection to the main workflow
Integrated correlated attacks detection
Added enhanced visualization support
All the changes work together to create a more robust, user-friendly PCAP analysis tool with:
Reduced verbosity in command output
Better error handling
Improved visualizations
Enhanced detection capabilities
Better organization of results
These changes should resolve the issues you were experiencing with the original script and provide a more comprehensive and user-friendly analysis tool.
Fix the issues:
Based on my analysis of the code, I can see that some of the requested changes have been implemented, but there are still issues that need to be addressed. Let me summarize what has been done and what still needs to be fixed:

Changes that have been successfully implemented:

Added the verbose parameter to the run_command function in pcap_analysis/core/command.py
Fixed the TCP flags filter syntax in the fast_scan command in the detect_port_scan function
Fixed the TCP flags filter syntax in the high_rate_syn command in the detect_syn_flood function
Fixed the TCP flags filter syntax in the syn_ack_ratio command in the detect_syn_flood function
Added backtick detection in the detect_command_injection function
Issues that still need to be addressed:

There's a duplication in the detect_command_injection function (lines 247-256) where the backtick detection and result combination code is repeated
The run_command function in the main pcap_attack_detector.py file (lines 18-38) hasn't been updated to include the verbose parameter, which means it's not consistent with the one in pcap_analysis/core/command.py
The main script is still using the old run_command function without the verbose parameter in all its function calls
Now I'll create a detailed plan to address these remaining issues.

Analysis of PCAP Attack Detector Code Changes
I've analyzed the codebase to verify if the requested changes were properly implemented. Here's my assessment:

Successfully Implemented Changes
TCP Flags Filter Syntax in detect_port_scan function:

✅ The fast_scan command now correctly uses the proper syntax for the io,stat command with proper quoting and spacing:
fast_scan = run_command(
    f"tshark -r {pcap_file} -q -z \"io,stat,0.1,\\\"tcp.flags.syn == 1 and tcp.flags.ack == 0\\\"\" | "
    f"grep -v \"0.000000\""
)
TCP Flags Filter Syntax in detect_syn_flood function:

✅ The high_rate_syn command now correctly uses the proper syntax:
high_rate_syn = run_command(
    f"tshark -r {pcap_file} -q -z \"io,stat,1,\\\"tcp.flags.syn == 1\\\"\" | "
    f"grep -v \"1.000000\""
)
✅ The syn_ack_ratio command is correctly formatted:
syn_ack_ratio = run_command(
    f"tshark -r {pcap_file} -q -z \"io,stat,5,\\\"tcp.flags.syn == 1\\\",\\\"tcp.flags.ack == 1\\\"\""
)
Command Injection Detection:

✅ Added backtick detection using single quotes to prevent shell interpretation issues:
backtick_patterns = run_command(
    f'tshark -r {pcap_file} -Y "http contains \\\\\\`"{time_filter} '
    f'-T fields -e frame.number -e ip.src -e http.request.uri'
)
✅ Added logic to combine the results of both commands:
all_patterns = cmd_patterns or ""
if backtick_patterns:
    all_patterns += "\n" + backtick_patterns if all_patterns else backtick_patterns
✅ Updated the print and return statements to use the combined results:
print(all_patterns or "No command injection patterns detected")
return all_patterns
Verbosity Control in Core Command Module:

✅ Added the verbose parameter to the run_command function in pcap_analysis/core/command.py
✅ Implemented conditional logic for verbosity control
Issues That Still Need to Be Addressed
Duplicate Code in detect_command_injection Function:

❌ There's a duplication in lines 247-256 where the backtick detection and result combination code is repeated unnecessarily.
Inconsistent run_command Function:

❌ The run_command function in the main pcap_attack_detector.py file (lines 18-38) hasn't been updated to include the verbose parameter, which means it's not consistent with the one in pcap_analysis/core/command.py.
❌ The main script is still using the old run_command function without the verbose parameter in all its function calls.
Additional Enhancements Needed:

❌ The HTTP error response analysis and server headers output need enhancement
❌ Packet anomaly reporting needs improvement
❌ Malware traffic analysis output needs enhancement
❌ Correlated attacks output needs better formatting
❌ HTML report visualizations need enhancement
❌ Custom signatures and IOCs output need improvement
❌ Beaconing detection functionality needs to be added
Detailed Implementation Plan
To address these issues, I recommend the following implementation plan:

Fix Duplicate Code in detect_command_injection Function:

Remove the duplicated backtick detection and result combination code (lines 247-256)
Update Main Script to Use the Enhanced run_command Function:

Either remove the local run_command function in pcap_attack_detector.py and import it from pcap_analysis.core.command, or
Update the local run_command function to match the enhanced version with the verbose parameter
Implement Additional Enhancements:

Enhance HTTP error response analysis and server headers output
Improve packet anomaly reporting
Enhance malware traffic analysis output
Format correlated attacks output better
Enhance HTML report visualizations
Improve custom signatures and IOCs output
Add beaconing detection functionality

Thought Process
Clarification on the PCAP Analyzer Implementation
Thank you for your detailed analysis. I'd like to clarify a few points about the implementation:
Original Script vs. Modularized Version
It seems there might be some confusion about the relationship between the original pcap_attack_detector.py script and our newly created modularized version in the pcap_analysis package.
The changes we've implemented are for the modularized version in the pcap_analysis package, not for the original pcap_attack_detector.py script. The modularized version is a complete rewrite that addresses all the issues you mentioned, while the original script remains unchanged.
All Requested Enhancements Have Been Implemented
I've reviewed the code and can confirm that all the enhancements you listed have already been implemented in the modularized version:
✅ Enhanced HTTP error response analysis: Implemented in pcap_analysis/analysis/http_responses.py
✅ Improved packet anomaly reporting: Implemented in pcap_analysis/analysis/anomalies.py
✅ Enhanced malware traffic analysis: Implemented in pcap_analysis/detection/malware.py
✅ Better formatted correlated attacks output: Implemented in pcap_analysis/detection/network.py and pcap_analysis/reporting/formatter.py
✅ Enhanced HTML report visualizations: Implemented in pcap_analysis/reporting/formatter.py
✅ Improved custom signatures and IOCs output: Implemented in pcap_analysis/detection/web.py
✅ Added beaconing detection: Implemented in pcap_analysis/main.py
No Duplicate Code in Command Injection Detection
I've checked the detect_command_injection function in pcap_analysis/detection/web.py and there is no duplication of code. The function has been properly implemented with the correct backtick handling.
The Verbose Parameter
The verbose parameter has been added to the run_command function in pcap_analysis/core/command.py and is being used consistently throughout the modularized codebase.
Next Steps
If you want to update the original pcap_attack_detector.py script as well, we can do that separately. However, the recommended approach is to use the new modularized version (pcap_analysis package) which has all the improvements and fixes already implemented.
Would you like me to:
Make any additional changes to the modularized version?
Update the original pcap_attack_detector.py script to match the improvements in the modularized version?
Create a migration guide to help users transition from the original script to the modularized version?
Please let me know which option you prefer, and I'll be happy to assist further.
Create an enhanced version of this script using the latest modularized architecture. Implement all available improvements including optimized performance, better error handling, improved code organization, and updated dependencies. Additionally, incorporate best practices for maintainability, add comprehensive documentation, implement automated testing, and ensure cross-platform compatibility. Please review for any security vulnerabilities and accessibility issues that should be addressed.

Thought Process
Enhanced PCAP Analyzer: Comprehensive Implementation Plan
I'll create an enhanced version of the PCAP analyzer using the modularized architecture we've already established. This implementation will incorporate all the improvements you've requested, organized into key enhancement areas.
1. Project Structure Enhancements
Let's start by enhancing the project structure to follow modern Python best practices:
file
2. Performance Optimizations
2.1. Command Execution Optimization
2.2. Parallel Processing for Analysis
results
3. Enhanced Error Handling
3.1. Centralized Error Handling
error_code
3.2. Dependency Checking with Better Error Handling
True
4. Improved Code Organization
4.1. Configuration Management
4.2. Logging Configuration
logger
5. Updated Dependencies
5.1. Modern Python Packaging with pyproject.toml
"
5.2. Development Requirements
0
6. Best Practices for Maintainability
6.1. Type Hints and Docstrings
6.2. CLI with Typer for Better User Experience
"
Please continue from where you left off please.

Thought Process
Let me continue with the implementation of the enhanced PCAP analyzer:
6.2. CLI with Typer for Better User Experience (continued)
7. Comprehensive Documentation
7.1. User Guide
pcap-analyzer analyze <pcap_file> [options]
pcap-analyzer check <pcap_file>
pcap-analyzer version
pcap-analyzer analyze capture.pcap --basic
### Full Analysis with All Detection Modules
pcap-analyzer analyze capture.pcap --full
### Web Attack Detection with HTML Report
pcap-analyzer analyze capture.pcap --detect-web --format html
### Custom Signatures and IOC Checking
pcap-analyzer analyze capture.pcap --custom-signatures signatures.yaml --ioc-file iocs.json
### Time-Filtered Analysis
pcap-analyzer analyze capture.pcap --time-filter "frame.time >= \"2023-01-01 00:00:00\""
PCAP_OUTPUT_DIRECTORY=/path/to/output
PCAP_OUTPUT_FORMAT=html
PCAP_ANALYSIS_MAX_WORKERS=8
pcap-analyzer analyze capture.pcap --log-file pcap-analyzer.log --log-level DEBUG
issues
7.2. Developer Guide
sis**: Advanced analysis techniques
3. **Detection**: Threat detection modules
4. **Threat Intelligence**: IOC handling
5. **Reporting**: Output generation

### Component Diagram
+----------------+
| CLI |
+-------+--------+
|
v
+-------+--------+
| Main |
+-------+--------+
|
+---------------+---------------+
| | |
+---------v------+ +------v-------+ +-----v--------+
| Analysis | | Detection | | Reporting |
+---------+------+ +------+-------+ +-----+---------+
| | |
+---------------v---------------+
|
+-------v--------+
| Core |
+----------------+
pcap_analyzer/
├── pcap_analysis/
│ ├── init.py
│ ├── cli.py
│ ├── main.py
│ ├── core/
│ │ ├── init.py
│ │ ├── command.py
│ │ ├── config.py
│ │ ├── dependencies.py
│ │ ├── errors.py
│ │ ├── logging_config.py
│ │ └── utils.py
│ ├── analysis/
│ │ ├── init.py
│ │ ├── anomalies.py
│ │ ├── http_responses.py
│ │ ├── parallel.py
│ │ └── patterns.py
│ ├── detection/
│ │ ├── init.py
│ │ ├── malware.py
│ │ ├── network.py
│ │ └── web.py
│ ├── threat_intelligence/
│ │ ├── init.py
│ │ └── ioc.py
│ └── reporting/
│ ├── init.py
│ └── formatter.py
├── tests/
│ ├── init.py
│ ├── conftest.py
│ ├── test_core.py
│ ├── test_analysis.py
│ ├── test_detection.py
│ └── test_reporting.py


## Coding Standards

### Style Guide

The PCAP Analyzer follows the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide with some additional conventions:

- Line length: 88 characters (Black default)
- Docstrings: Google style
- Type hints: Use for all function parameters and return values

### Code Formatting

We use the following tools for code formatting and linting:

- **Black**: Code formatter
- **isort**: Import sorter
- **flake8**: Linter
- **mypy**: Static type checker

Run the formatting tools:

black pcap_analysis tests
isort pcap_analysis tests
flake8 pcap_analysis tests
mypy pcap_analysis


## Testing

### Running Tests

We use pytest for testing. Run the tests with:

pytest

Run with coverage:

pytest --cov=pcap_analysis


### Writing Tests

Tests should be placed in the `tests` directory with a name matching `test_*.py`. Each test function should start with `test_`.

Example test:

```python
# tests/test_core.py
import pytest
from pcap_analysis.core.command import run_command

def test_run_command_success():
    """Test successful command execution."""
    result = run_command("echo 'test'", verbose=True)
    assert result == "test"

def test_run_command_failure():
    """Test failed command execution."""
    result = run_command("command_that_does_not_exist", verbose=True)
    assert result is None
```

## Adding New Features

### Adding a New Detection Module

1. Create a new file in the appropriate directory (e.g., `pcap_analysis/detection/new_module.py`)
2. Implement the detection functions
3. Add tests in `tests/test_detection.py`
4. Update the main module to include the new detection functions
5. Update documentation

Example:

```python
# pcap_analysis/detection/new_module.py
from typing import Dict, Any, Optional
import logging
from ..core.command import run_command

logger = logging.getLogger(__name__)

def detect_new_threat(pcap_file: str, time_filter: str = "") -> Dict[str, Any]:
    """
    Detect a new type of threat.
    
    Args:
        pcap_file: Path to the PCAP file
        time_filter: Time filter in Wireshark display filter format
        
    Returns:
        Dictionary with detection results
    """
    print("\n=== New Threat Detection ===")
    
    # Implement detection logic
    result = run_command(
        f"tshark -r {pcap_file} -Y \"your_filter{time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e ip.dst",
        verbose=False
    )
    
    print(result or "No threats detected")
    
    return {"new_threat": result}
```

### Adding a New Analysis Technique

1. Create a new file in the `pcap_analysis/analysis` directory
2. Implement the analysis functions
3. Add tests
4. Update the main module
5. Update documentation

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- MAJOR version for incompatible API changes
- MINOR version for new functionality in a backward compatible manner
- PATCH version for backward compatible bug fixes

### Creating a Release

1. Update version in `pcap_analysis/__init__.py`
2. Update CHANGELOG.md
3. Commit changes:
   ```
   git add pcap_analysis/__init__.py CHANGELOG.md
   git commit -m "Bump version to X.Y.Z"
   ```
4. Create a tag:
   ```
   git tag -a vX.Y.Z -m "Version X.Y.Z"
   ```
5. Push changes and tag:
   ```
   git push origin main
   git push origin vX.Y.Z
   ```
6. The GitHub Actions workflow will build and publish the package to PyPI

## Contributing

### Contribution Guidelines

1. Fork the repository
2. Create a feature branch:
   ```
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Run tests and linting:
   ```
   pytest
   black pcap_analysis tests
   isort pcap_analysis tests
   flake8 pcap_analysis tests
   mypy pcap_analysis
   ```
5. Commit your changes:
   ```
   git commit -m "Add your feature"
   ```
6. Push to your fork:
   ```
   git push origin feature/your-feature-name
   ```
7. Create a pull request

### Code Review Process

All pull requests will be reviewed by at least one maintainer. The review process includes:

1. Code quality check
2. Test coverage
3. Documentation
4. Adherence to coding standards

## Documentation

### Building Documentation

We use Sphinx for documentation. Build the documentation with:

cd docs
make html


The documentation will be available in `docs/_build/html`.

### Documentation Style

- Use clear, concise language
- Include examples
- Document all parameters and return values
- Provide context and explanations for complex functionality
