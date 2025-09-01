# XILLEN Digital Forensics

Advanced digital forensics analysis tool built with Go for comprehensive evidence collection, analysis, and threat detection.

## 🚀 Features

- **File System Analysis**: Comprehensive file system scanning and analysis
- **Hash Analysis**: MD5, SHA1, SHA256 hash calculation and malware detection
- **Timeline Analysis**: Chronological event reconstruction
- **Registry Analysis**: Windows registry entry examination
- **Network Forensics**: Network connection analysis and monitoring
- **Process Analysis**: Running process examination and detection
- **Artifact Collection**: Automated forensic artifact gathering
- **Threat Detection**: Advanced threat identification and classification
- **Multi-threaded Processing**: High-performance concurrent analysis
- **JSON Reporting**: Structured evidence reporting

## 🛠️ Installation

### Prerequisites
- Go 1.21 or higher
- Git

### Build from Source
```bash
git clone https://github.com/BengaminButton/xillen-forensics.git
cd xillen-forensics
go mod tidy
go build -o xillen-forensics main.go
```

### Quick Start
```bash
go run main.go /path/to/analyze
```

## 📋 Usage

### Basic Usage
```bash
./xillen-forensics /home/user/Documents
```

### Custom Output File
```bash
./xillen-forensics /home/user/Documents evidence_report.json
```

### High Performance
```bash
./xillen-forensics /home/user/Documents report.json 20
```

### Windows Analysis
```bash
./xillen-forensics "C:\Users\User\Desktop"
```

## 🎯 Analysis Types

### 1. File System Analysis
- **File Enumeration**: Complete directory traversal
- **File Type Detection**: Automatic file type classification
- **Size Analysis**: Large file identification
- **Timestamp Analysis**: Recent file activity detection
- **Hidden File Detection**: Hidden and system file discovery

### 2. Hash Analysis
- **Multi-algorithm Hashing**: MD5, SHA1, SHA256 support
- **Malware Detection**: Known malware hash database lookup
- **Duplicate Detection**: File deduplication analysis
- **Integrity Verification**: File integrity checking

### 3. Timeline Analysis
- **Chronological Reconstruction**: Event timeline creation
- **Activity Correlation**: Related event identification
- **User Activity Tracking**: User action analysis
- **System Event Logging**: System-level event capture

### 4. Registry Analysis
- **Registry Key Examination**: Windows registry analysis
- **Startup Program Detection**: Autorun program identification
- **System Configuration**: System setting analysis
- **Suspicious Entry Detection**: Malicious registry modification detection

### 5. Network Forensics
- **Connection Analysis**: Active network connection examination
- **Process Correlation**: Network activity to process mapping
- **Protocol Analysis**: Network protocol identification
- **Suspicious Activity Detection**: Anomalous network behavior

### 6. Process Analysis
- **Running Process Enumeration**: Active process identification
- **Command Line Analysis**: Process command line examination
- **User Context**: Process user context analysis
- **Suspicious Process Detection**: Malicious process identification

## 🔍 Forensic Artifacts

### File System Artifacts
- **Recent Documents**: Recently accessed files
- **Temporary Files**: System and application temp files
- **Browser Artifacts**: Web browser data and history
- **Application Data**: Application-specific data files

### System Artifacts
- **Event Logs**: System and application event logs
- **Registry Hives**: Windows registry data
- **Memory Dumps**: System memory analysis
- **Network Logs**: Network activity logs

### User Artifacts
- **User Profiles**: User account information
- **Desktop Items**: Desktop file analysis
- **Recent Items**: Recently accessed items
- **Application Usage**: Application usage patterns

## 🛡️ Threat Detection

### Malware Detection
- **Hash-based Detection**: Known malware hash matching
- **Behavioral Analysis**: Suspicious behavior identification
- **File Signature Analysis**: Malicious file signature detection
- **Process Monitoring**: Malicious process detection

### Suspicious Activity
- **File System Anomalies**: Unusual file system activity
- **Network Anomalies**: Suspicious network connections
- **Registry Modifications**: Unauthorized registry changes
- **Process Anomalies**: Suspicious process behavior

### Risk Assessment
- **Critical Threats**: Immediate security risks
- **High Risk**: Significant security concerns
- **Medium Risk**: Moderate security issues
- **Low Risk**: Minor security observations

## 📊 Output Format

### JSON Report Structure
```json
{
  "target_path": "/path/to/analyze",
  "scan_timestamp": "2024-01-15T14:30:25Z",
  "file_analysis": {
    "total_files": 1250,
    "total_size": 1073741824,
    "file_types": {
      ".txt": 150,
      ".pdf": 75,
      ".jpg": 200
    },
    "suspicious": [
      {
        "path": "/path/suspicious.exe",
        "reason": "Executable in temporary location",
        "risk_level": "High",
        "timestamp": "2024-01-15T14:25:00Z"
      }
    ]
  },
  "hash_analysis": {
    "md5_hashes": {
      "/path/file.exe": "d41d8cd98f00b204e9800998ecf8427e"
    },
    "known_malware": [
      {
        "hash": "d41d8cd98f00b204e9800998ecf8427e",
        "file": "/path/malware.exe",
        "malware": "Trojan.Generic",
        "family": "Unknown",
        "detection": "Hash Match"
      }
    ]
  },
  "timeline": [
    {
      "timestamp": "2024-01-15T14:30:00Z",
      "event": "File Modified",
      "file": "/path/file.txt",
      "action": "Modified",
      "user": "System"
    }
  ],
  "threats": [
    {
      "type": "Malware",
      "severity": "Critical",
      "description": "Known malware detected: Trojan.Generic",
      "file": "/path/malware.exe",
      "timestamp": "2024-01-15T14:30:00Z",
      "ioc": "d41d8cd98f00b204e9800998ecf8427e",
      "remediation": "Quarantine and remove the file immediately"
    }
  ],
  "summary": {
    "total_files": 1250,
    "suspicious_files": 5,
    "threats": 2,
    "artifacts": 15,
    "scan_duration": "Completed",
    "risk_level": "High"
  }
}
```

## 🔧 Configuration

### Environment Variables
```bash
export FORENSICS_THREADS=20
export FORENSICS_TIMEOUT=300
export FORENSICS_OUTPUT_DIR=/forensics/reports
```

### Custom File Type Patterns
Modify the `initializeFileTypes()` function to add custom file type patterns:

```go
xf.FileTypes = map[string][]string{
    "custom": {".custom", ".ext"},
    // Add more patterns
}
```

### Hash Database
Update the `initializeHashDatabase()` function to include additional known malware hashes:

```go
xf.HashDatabase = map[string]string{
    "hash1": "Malware.Family1",
    "hash2": "Malware.Family2",
    // Add more hashes
}
```

## 📈 Performance Features

- **Concurrent Processing**: Multi-threaded file analysis
- **Memory Efficiency**: Optimized memory usage for large datasets
- **Progress Tracking**: Real-time analysis progress
- **Error Handling**: Graceful error recovery
- **Resource Management**: Efficient resource utilization

## 🛡️ Legal Considerations

### Chain of Custody
- Maintain proper evidence handling procedures
- Document all analysis activities
- Preserve original evidence integrity
- Follow legal requirements for evidence collection

### Privacy Compliance
- Respect privacy laws and regulations
- Obtain proper authorization for analysis
- Protect sensitive information
- Follow data protection guidelines

## 🧪 Testing

### Unit Tests
```bash
go test ./...
```

### Integration Tests
```bash
go test -tags=integration ./...
```

### Performance Tests
```bash
go test -bench=. ./...
```

## 📋 Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                XILLEN DIGITAL FORENSICS                     ║
║              Advanced Evidence Analysis Tool                ║
╚══════════════════════════════════════════════════════════════╝

Target: /home/user/Documents
Output: forensics_report.json
Threads: 10
Started: 2024-01-15 14:30:25

🔍 Initializing forensics analysis...
📁 Analyzing file system...
🔧 Analyzing registry...
🌐 Analyzing network connections...
⚙️  Analyzing processes...
📋 Generating forensic artifacts...
⚠️  Detecting threats...
💾 Saving results...

╔══════════════════════════════════════════════════════════════╗
║                        ANALYSIS RESULTS                     ║
╚══════════════════════════════════════════════════════════════╝

📊 File Analysis:
   Total Files: 1250
   Total Size: 1.0 GB
   Suspicious Files: 5
   Recent Files: 25

🔍 Hash Analysis:
   Files Hashed: 150
   Known Malware: 2

⚠️  Threats Detected:
   1. Malware (Critical) - Known malware detected: Trojan.Generic
   2. Suspicious Process (High) - Suspicious process running: malware.exe

📋 Artifacts Found:
   1. File System - Target directory for analysis
   2. Registry - System registry entries
   3. Network - Active network connections

📈 Summary:
   Risk Level: High
   Total Threats: 2
   Artifacts: 15

✅ Analysis completed successfully!
📄 Report saved to: forensics_report.json
⏱️  Analysis completed in: 2m30s
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized forensic analysis purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting any forensic analysis.

## 🔗 Related Projects

- [XILLEN OSINT Framework](../xillen-osint/) - Open source intelligence gathering
- [XILLEN Network Scanner](../xillen-network-scanner/) - Network reconnaissance
- [XILLEN Password Cracker](../xillen-password-cracker/) - Advanced password auditing
- [XILLEN Vulnerability Scanner](../xillen-vuln-scanner/) - Comprehensive vulnerability assessment
- [XILLEN Malware Analyzer](../xillen-malware-analyzer/) - Malware analysis framework
