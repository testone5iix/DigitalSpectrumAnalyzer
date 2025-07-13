# Digital Spectrum Analyzer (DSA)

**Version**: 3.0  
**Date**: 2025-07-13  

## Overview
Digital Spectrum Analyzer (DSA) is an advanced forensic tool designed to generate unique device fingerprints based on comprehensive hardware and software characteristics. It is tailored for tracking devices across networks and even after system reformatting, making it a valuable asset for digital forensic investigations and cybercrime analysis.

## Key Features
- **Multi-Platform Support**: Compatible with Windows and Linux systems.
- **Mobile Device Fingerprinting**: Supports Android and iOS devices via USB connections.
- **Light Mode**: Optimized for low-resource systems to ensure accessibility.
- **Tamper Detection**: Includes RAM analysis and comparison mechanisms to detect device tampering.
- **Forensic-Grade Reporting**: Generates reports with SHA-256/RSA digital signatures for integrity verification.
- **Compliance**: Adheres to ISO/IEC 27037 guidelines for digital evidence handling.
- **Chain of Custody**: Maintains tamper-evident logging for forensic accountability.

## Installation

### Prerequisites
- **Python**: Version 3.8 or higher.
- **Operating System**: Windows or Linux (Ubuntu, Debian, or other major distributions).
- **Administrator Privileges**: Required for full functionality (e.g., accessing BIOS, disk, and USB data).
- **External Tools**:
  - **Android**: [Android Debug Bridge (ADB)](https://developer.android.com/studio/command-line/adb) for Android device fingerprinting.
  - **iOS**: [libimobiledevice](https://libimobiledevice.org/) for iOS device fingerprinting.

### Python Dependencies
Install the required Python packages using pip:

```bash
pip install psutil pyudev tabulate cryptography pyyaml paramiko boto3 docker
```

**Note**: On Linux, ensure `pyudev` is installed for USB device detection. For network latency tests, `scapy` is optional but recommended:

```bash
pip install scapy
```

### Setup Instructions
1. Clone the repository:
   ```bash
   git clone [](https://github.com/testone5iix/DigitalSpectrumAnalyzer.git)
   cd digital-spectrum-analyzer
   ```
2. Install Python dependencies as shown above.
3. Ensure ADB and libimobiledevice are installed and accessible in your system PATH for mobile device support.
4. Run the tool with administrator/root privileges for full functionality.

## Usage
The tool is command-line based and supports several operations. Below are examples of common commands:

### Generate a Device Fingerprint
Create a fingerprint for a device and save it to a JSON file:

```bash
python digital_spectrum_analyzer.py --generate --device-id CASE123 --output report.json
```

### Generate a Fingerprint in Light Mode
For low-resource systems, use the `--light-mode` flag to reduce resource consumption:

```bash
python digital_spectrum_analyzer.py --generate --device-id CASE123 --light-mode --output report.json
```

### Fingerprint Mobile Devices
Collect fingerprints from connected Android or iOS devices:

```bash
python digital_spectrum_analyzer.py --mobile --output mobile_report.json
```

### Compare Stored Fingerprints
Compare fingerprints stored in the database to identify similarities or differences:

```bash
python digital_spectrum_analyzer.py --compare
```

### Export a Forensic Report
Export the latest fingerprint for a specific device ID to a JSON file:

```bash
python digital_spectrum_analyzer.py --export --device-id CASE123 --output exported_report.json
```

## Configuration
The tool uses a `dsa_config.yaml` file for customizable settings. If not present, default settings are used. Example configuration:

```yaml
fingerprint:
  cpu_benchmark_iterations: 5000
  disk_test_size_mb: 10
  network_test_count: 5
  memory_test_size_mb: 10
  ram_analysis: true
tamper_detection:
  bios_time_threshold: 3600
  disk_signature_change_threshold: 0.3
  ram_change_threshold: 20
reporting:
  sign_reports: true
```

## Example Outputs

### Sample Fingerprint Report
A generated JSON report might look like this:

```json
{
  "Metadata": {
    "DeviceID": "CASE123",
    "CollectionTime": "2025-07-13T10:30:42Z",
    "Investigator": "user",
    "Platform": "Windows-10-10.0.19041-SP0",
    "Hostname": "DESKTOP-XYZ",
    "SystemBootTime": "2025-07-13T08:00:00"
  },
  "Hardware": {
    "BIOS": {
      "Vendor": "LENOVO",
      "Version": "LENOVO - 1760",
      "ReleaseDate": "2023-05-20",
      "Serial": "XYZ123"
    },
    "CPU": {
      "Model": "Intel64 Family 6",
      "Cores": 4,
      "Threads": 8,
      "Performance": {
        "PrimeCalcTime": 0.1234,
        "FLOPS": 12345678.90
      }
    },
    "Disk": {
      "Model": "Samsung SSD 860 EVO",
      "Serial": "S123456789",
      "WriteSpeed": "500.23 MB/s"
    }
  },
  "Software": {
    "OS": "Windows",
    "OSVersion": "10.0.19041",
    "PythonVersion": "3.11.0",
    "ApplicationResidues": {
      "Chrome": {
        "Path": "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data",
        "Size": "123.45 MB"
      }
    }
  },
  "ForensicIntegrity": {
    "SHA256": "1f05fe93c99b83a5...",
    "VerificationTime": "2025-07-13T10:30:45Z",
    "DigitalSignature": "MIIBIjANBgkqhkiG9w0BAQE..."
  }
}
```

### Sample Comparison Matrix
Running the `--compare` command may produce a table like this:

```
+-----------+---------+---------+
| Device ID | CASE123 | CASE124 |
+-----------+---------+---------+
| CASE123   |    --   |  91.2%  |
| CASE124   |  91.2%  |    --   |
+-----------+---------+---------+
Note: Scores below 85% indicate significantly different devices.
```

## Security Considerations
- **Administrator Privileges**: The tool requires root/admin access to collect hardware data, which may pose security risks if misused.
- **Sensitive Data**: The tool collects sensitive information (e.g., browser cache, USB serials). Ensure reports are stored securely and encrypted if necessary.
- **Private Key Management**: The current implementation generates new private keys for each fingerprint. In production, use secure key storage (e.g., HSM) to maintain forensic integrity.

## Disclaimer
This tool is intended for **research and forensic laboratory use only**. It should not be relied upon as sole legal evidence without expert human analysis. Use at your own risk.

## License
Licensed under the [MIT License](LICENSE). Free to use, modify, and distribute with proper attribution.

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a clear description of your changes.

We encourage contributions to add new features, improve performance, or support additional platforms.

## Contact
For issues or inquiries, please open an issue on the GitHub repository or contact the maintainers at [call me](htps://t.me/venom5iix).
