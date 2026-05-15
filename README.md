# All-in-One Network Forensics Platform

This project turns the proposal into a working Flask-based demo platform for network forensics.

## Included features
- GUI-based interface
- Data ingestion for CSV, TXT, LOG, and PCAP
- Automated attack detection
- Timeline reconstruction
- Attacker profiling
- Session reconstruction
- Credential extraction
- Protocol analysis
- Risk scoring
- Suspicious IP ranking
- Real-time monitoring page with Socket.IO demo events
- HTML report generation
- Optional PDF export with WeasyPrint

## Important notes
- CSV, TXT, and LOG analysis works without extra system drivers.
- PCAP support depends on Scapy and packet-capture support on the local machine.
- PDF export may fail on Windows if WeasyPrint native libraries are missing. The HTML report still works.

## Recommended setup
Use Python 3.12 on Windows.

## Commands
```powershell
cd C:\Users\Hamza\Downloads\project\network_forensics_platform_fixed
py -3.12 -m venv .venv312
.\.venv312\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Open:
`http://127.0.0.1:5000`

## Sample data
Use `samples/sample_logs.csv` for the first test upload.

## Hybrid Threat Intelligence Upgrade

This enhanced version keeps the original project title and all existing functionality, while adding a hybrid analysis layer:

1. Local rule-based forensic detection remains the first layer.
2. IOC extraction identifies IPs, domains, URLs, hashes, emails, user-agents and suspicious payloads.
3. VirusTotal enriches public IPs, domains, URLs and hashes.
4. Hybrid Analysis enriches file hashes and can optionally submit files to a sandbox.
5. The correlation engine produces a unified threat score, confidence level, sophistication level and correlated IOC table.

### Secure API key setup

Copy `.env.example` to `.env` and paste your API keys there:

```powershell
copy .env.example .env
```

Then edit `.env`:

```env
THREAT_INTEL_ENABLED=true
VIRUSTOTAL_API_KEY=your_key_here
HYBRID_ANALYSIS_API_KEY=your_key_here
```

Do not hardcode API keys inside Python files.

### Sandbox privacy note

`HA_AUTO_SUBMIT=false` by default. Keep it disabled if your evidence files are private. Enable it only when you intentionally want to submit uploaded files to Hybrid Analysis.
