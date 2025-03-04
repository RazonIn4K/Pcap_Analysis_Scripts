# PCAP Analyzer

An advanced network security analysis tool for analyzing PCAP files and detecting various security threats and anomalies.

## Features

- **Comprehensive Analysis**: Analyze PCAP files for a wide range of security threats and anomalies
- **Modular Design**: Organized into modules for core functionality, analysis, detection, threat intelligence, and reporting
- **Multiple Detection Methods**: Detect web attacks, network attacks, and malware activity
- **Advanced Analysis Techniques**: Timing pattern analysis, anomaly detection, and more
- **Threat Intelligence Integration**: Load and use indicators of compromise (IOCs) from files or APIs
- **Flexible Output Options**: Generate reports in JSON, YAML, CSV, or HTML formats
- **Visualization Support**: Create visual representations of analysis results

## Installation

### Prerequisites

- Python 3.7 or higher
- Wireshark/tshark (command-line utilities)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/pcap-analyzer.git
   cd pcap-analyzer
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Ensure tshark is installed and available in your PATH:
   - For Ubuntu/Debian: `sudo apt-get install tshark`
   - For macOS: `brew install wireshark`
   - For Windows: Install Wireshark, which includes tshark

## Usage

### Basic Usage

```
python pcap_analyzer.py <pcap_file> [options]
```

### Command-Line Options

- `pcap_file`: Path to the PCAP file to analyze
- `--config`: Path to configuration file
- `--basic`: Perform basic analysis only
- `--full`: Perform full analysis (all modules)
- `--time-filter`: Time filter for analysis (Wireshark display filter format)
- `--detect-web`: Detect web-based attacks
- `--detect-network`: Detect network-based attacks
- `--detect-malware`: Detect malware activity
- `--custom-signatures`: Path to custom detection signatures file
- `--ioc-file`: Path to IOC file for checking
- `--fetch-iocs`: URL to fetch IOCs from
- `--api-key`: API key for IOC service
- `--output-dir`: Directory for output files (default: ./output)
- `--output-format`: Output format (json, yaml, csv, html, all)
- `--visualize`: Generate visualizations

### Examples

Basic analysis of a PCAP file:
```
python pcap_analyzer.py capture.pcap --basic
```

Full analysis with all detection modules:
```
python pcap_analyzer.py capture.pcap --full
```

Detect web attacks and generate HTML report:
```
python pcap_analyzer.py capture.pcap --detect-web --output-format html
```

Use custom signatures and check against IOCs:
```
python pcap_analyzer.py capture.pcap --custom-signatures signatures.yaml --ioc-file iocs.json
```

## Module Structure

- **Core**: Basic functionality used by other modules
  - `command.py`: Functions for running shell commands
  - `config.py`: Configuration management
  - `utils.py`: Utility functions

- **Analysis**: Advanced analysis techniques
  - `patterns.py`: Timing pattern analysis
  - `anomalies.py`: Anomaly detection

- **Detection**: Threat detection modules
  - `web.py`: Web attack detection
  - `network.py`: Network attack detection
  - `malware.py`: Malware activity detection

- **Threat Intelligence**: IOC handling
  - `ioc.py`: Functions for working with indicators of compromise

- **Reporting**: Output generation
  - `formatter.py`: Functions for formatting and visualizing results

## Custom Signatures

You can create custom detection signatures in YAML format:

```yaml
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 