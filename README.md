# Phishing Link Analyzer 🔍

A CLI-based tool to analyze URLs for potential phishing indicators. This tool helps identify malicious and suspicious websites by checking against blocklists, detecting brand impersonation, and analyzing suspicious patterns.

## Features ✨

- **URL Validation**: Ensures input is a proper URL format
- **Domain Extraction**: Extracts and analyzes the domain name
- **Real-Time Threat Intelligence**: Queries live threat feeds (OpenPhish, URLhaus)
- **Brand Impersonation Detection**: Identifies lookalike domains that mimic popular brands
- **Character Substitution Detection**: Catches common phishing tricks (e.g., `micros0ft.com`)
- **Suspicious Pattern Analysis**: Detects URL patterns commonly used in phishing
- **Color-Coded Output**: Visual feedback with red/yellow/green indicators
- **Exit Codes**: Machine-readable results for automation
- **Offline Capability**: Works even when threat feeds are unavailable

## Requirements 📋

- Python 3.6+
- `requests` library (install with `pip install requests`)

## Installation 🚀

1. Clone or download the script
2. Install required dependencies:
   ```bash
   pip install requests
   ```
3. Make the script executable (optional):
   ```bash
   chmod +x phishing_checker.py
   ```

## Usage 💻

### Basic Usage

```bash
python phishing_checker.py <URL>
```

### Examples

```bash
# Check a regular website
python phishing_checker.py https://google.com

# Check a suspicious lookalike domain
python phishing_checker.py https://login-micros0ft.com

# Check with explicit --url flag
python phishing_checker.py --url https://example.com

# Protocol is optional (HTTPS will be assumed)
python phishing_checker.py example.com
```

### Sample Output

```
🔍 Analyzing: https://login-micros0ft.com
🌐 Domain: login-micros0ft.com
   🔍 Checking OpenPhish feed...
   🔍 Checking URLhaus...
🚨 Resembles 'microsoft' with character substitution
✅ Not found in threat feeds

⚠️  Additional warnings:
   • Contains suspicious keyword: 'login'

🟡 Verdict: Suspicious
```

For a known malicious domain:
```
🔍 Analyzing: https://known-phishing-site.com
🌐 Domain: known-phishing-site.com
   🔍 Checking OpenPhish feed...
🚨 Found in OpenPhish feed

🔴 Verdict: Malicious
```

## Verdict Categories 🚦

- **🔴 Malicious**: Domain found in known malicious blocklists
- **🟡 Suspicious**: Domain shows phishing indicators (brand impersonation, suspicious patterns)
- **🟢 Clean**: No suspicious indicators detected
- **🔵 Unknown**: Unable to determine (invalid URL, network issues)

## Exit Codes 📊

The tool returns different exit codes for automation:

- `0`: Clean or Unknown
- `1`: Suspicious
- `2`: Malicious
- `130`: Interrupted by user (Ctrl+C)

Example usage in scripts:
```bash
python phishing_checker.py suspicious-site.com
if [ $? -eq 2 ]; then
    echo "Blocking malicious site!"
fi
```

## Detection Methods 🕵️

### 1. Real-Time Threat Intelligence
- **OpenPhish**: Live phishing URL feed (completely free, no registration)
- **URLhaus**: Malware and phishing host database (completely free)
- Local mock blocklist for testing and offline capability
- Graceful fallback when APIs are unavailable

### 2. Brand Impersonation Detection
- Checks for popular brand names in domains
- Detects character substitution attacks (e.g., `0` for `o`)
- Identifies homograph attacks (similar-looking Unicode characters)

### 3. Suspicious Pattern Analysis
- Excessive subdomains
- Suspicious keywords (login, secure, verify, etc.)
- URL shorteners
- IP addresses instead of domain names

## Extending the Tool 🔧

### Adding More Threat Feeds

The tool currently uses free, no-registration APIs. You can easily add more:

```python
def check_virustotal(self, domain: str) -> Tuple[bool, str]:
    # Requires free API key from VirusTotal
    api_key = "your-virustotal-api-key"
    try:
        response = requests.get(f"https://www.virustotal.com/vtapi/v2/url/report", 
                               params={"apikey": api_key, "resource": f"http://{domain}"})
        data = response.json()
        if data.get("positives", 0) > 0:
            return True, f"Detected by {data['positives']}/{data['total']} scanners"
    except requests.RequestException:
        pass
    return False, "Not found in VirusTotal"
```

### Current API Status
- ✅ **OpenPhish**: Active, no setup required
- ✅ **URLhaus**: Active, no setup required  
- 🔧 **VirusTotal**: Requires free API key registration
- 🔧 **URLVoid**: Requires free account registration

## API Integration & Costs 💰

### Currently Active APIs (FREE)
- **OpenPhish** - ✅ No registration, unlimited use
- **URLhaus** - ✅ No registration, reasonable rate limits

### Available Free Tier APIs
- **VirusTotal** - 🆓 4 requests/minute, 500/day (requires free account)
- **URLVoid** - 🆓 100 requests/day (requires free account)
- **PhishTank** - 🆓 Unlimited (requires free account)

### Network Requirements
- Internet connection required for real-time threat intelligence
- Tool works offline using local pattern detection and mock blocklist
- Automatic fallback when APIs are unreachable

## Limitations ⚠️

- **API Dependencies**: Real-time detection requires internet connection
- **Rate Limits**: Free APIs have usage limitations (handled gracefully)
- **Detection Scope**: Limited to URL/domain analysis (no JavaScript execution)
- **False Positives**: May flag legitimate sites with suspicious patterns
- **Coverage**: Not all phishing sites are in public threat feeds

## Contributing 🤝

Feel free to enhance this tool by:
- Adding real threat feed integrations
- Improving detection algorithms
- Adding more suspicious patterns
- Implementing caching for better performance
- Adding configuration file support

## License 📄

This tool is provided as-is for educational and security research purposes.

## Disclaimer ⚖️

This tool is for legitimate security analysis only. Always respect website terms of service and applicable laws when analyzing URLs.