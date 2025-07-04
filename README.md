# Security Scanner 🔒

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)

> **Important**: Before using, replace all API keys in `config_sample.json` and rename to `security_config.json`

A comprehensive security scanning tool with GUI dashboard for Windows systems.

## Features ✨
- Real-time system monitoring
- Malware detection via hash comparison
- VirusTotal API integration
- Network connection analysis
- Startup program monitoring
- Suspicious process detection

## Installation 🛠️

```bash
git clone https://github.com/EndSkiess/security-scanner
cd security-scanner

# Install dependencies
pip install -r requirements.txt

# Copy and configure the sample config
cp config/config_sample.json security_config.json
