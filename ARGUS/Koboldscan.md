# ARGUS Project Execution Report

## 1. Overview
This project demonstrates the deployment and execution of the ARGUS reconnaissance automation tool on a Kali Linux virtual machine.
The tool integrates multiple reconnaissance utilities along with the Anthropic Claude API to automate network enumeration and generate structured PDF reports.
The reports generated will be linked. 

The pipeline performs automated scanning, data aggregation, AI-based analysis, and report generation.

## 2. Environment Setup
The environment was configured on Kali Linux (rolling release).

System preparation steps included:
- Updating system package index via `apt`
- Installing Python virtual environment support (`python3-venv`)
- Creating an isolated Python environment for dependency management

### Virtual environment setup:
```
bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Dependency Installation
Initial Issue

The project initially failed due to a missing Python dependency:
```ModuleNotFoundError: No module named 'anthropic'```
Root Cause
Kali Linux enforces PEP 668 (externally managed Python environment)
System-wide pip installations are blocked
Resolution

A virtual environment was created and used for all Python dependencies.

Commands used:
```
pip install anthropic
pip install -r requirements.txt
```

Installed dependencies:
anthropic (Claude API SDK)
reportlab (PDF generation)
pyyaml (configuration handling)
httpx, pydantic, pillow, and supporting libraries

## 4. API Configuration
The Anthropic API key was configured using environment variables:
```
export ANTHROPIC_API_KEY="myapikey..."
```
This enables authentication with the Claude API for AI-based analysis of reconnaissance data.

## 5. Execution Workflow
The ARGUS tool was executed using:
```python main.py```

Automated pipeline steps:
Target identification
Network reconnaissance using nmap
Subdomain enumeration using subfinder
Web technology detection using whatweb
Vulnerability scanning using nikto
Directory brute forcing using gobuster
Raw data aggregation into JSON
AI analysis using Anthropic Claude API
PDF report generation

## 6. Output Generation
Generated artifacts:
Raw reconnaissance data:
```output/raw_recon.json```

Execution result:
```[+] Report ready: output/recon_report.pdf```

## 7. Issues and Resolutions
Issue 1: Missing anthropic module
Cause: Dependency not installed
Fix: Installed inside virtual environment
Issue 2: pip blocked (externally managed environment)
Cause: Kali Linux PEP 668 enforcement
Fix: Used Python virtual environment (venv)
Issue 3: apt install anthropic failed
Cause: Package not available in Kali repositories
Fix: Installed via pip inside venv

## 8. Conclusion
The ARGUS reconnaissance automation tool was successfully deployed and executed after resolving Python environment and dependency constraints.

The system now provides:

Automated network reconnaissance
AI-assisted analysis via Anthropic Claude
Structured PDF report generation

All components operate correctly within an isolated virtual environment.

## Report
- [Download Recon Report](output/recon_report.pdf)
