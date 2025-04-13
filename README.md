# Automated Vulnerability Scanner

A Python tool that scans networks for open ports, services, and vulnerabilities using Nmap. Built to automate penetration testing tasks with text report generation.

## Features
- Scans targets for open ports and services.
- Supports quick scans (basic port detection) and deep scans (service versions and OS detection).
- Detects vulnerabilities like exposed MySQL, HTTP without HTTPS, and outdated VMware services.
- Generates timestamped text reports for easy analysis.
- Validates target inputs to prevent errors.

## Requirements
- Windows (tested on Windows 10/11)
- Python 3.x
- Nmap (installed and added to PATH)
- Python libraries: `python-nmap`

## Installation
1. Install Python from [python.org](https://www.python.org).
2. Install Nmap from [nmap.org](https://nmap.org).
3. Install the required library:
   ```bash
   pip install python-nmap