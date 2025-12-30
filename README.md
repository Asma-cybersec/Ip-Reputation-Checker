# 🔍 IP Reputation Checker - Built by Asma

A Python security tool I built from scratch to check IP threat intelligence using AbuseIPDB API.

## 🎯 What I Built
- **Live API Integration**: Connected to AbuseIPDB's threat intelligence database
- **Real Threat Detection**: Successfully identified Tor exit nodes with 100% accuracy
- **Bulk Processing**: Handles 100+ IPs at once with CSV report generation
- **Interactive CLI**: Professional command-line interface I designed

## 📊 My Real Results
- Detected `185.220.101.34` → **100% malicious** (Tor exit node, 206 abuse reports)
- Verified `8.8.8.8` → **0% clean** (Google DNS infrastructure)
- Processed **100+ IPs** in single batch without crashes
- Identified organizations: Google, Microsoft, Apple, US Department of Defense

## 🛠️ My Technical Implementation
```python
# Key features I implemented:
- API integration with error handling
- IPv4 validation and formatting
- CSV report generation with timestamps
- Rate limiting and timeout management
- Interactive menu system

##How to Use My Tool...
# Clone my project
git clone https://github.com/YOUR-USERNAME/ip-reputation-checker.git

# Install dependencies
pip install -r requirements.txt

# Run my tool
python ip_checker.py

## 👩‍💻 About Me
- Asma , Cybersecurity Student
- Passionate about building practical security tools.

## Future Enhancements Im Considering:

.Add progress bars for large files

.Integrate multiple threat intelligence sources

.Create web interface version

.Add scheduled monitoring capabilities