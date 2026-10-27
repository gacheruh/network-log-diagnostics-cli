# Automated Network & Log Diagnostics CLI Tool

An enterprise-grade, lightweight Python CLI tool designed for cloud support engineers to instantly parse server diagnostic logs, VPC flow logs, and system traces to identify networking failures, DNS issues, port exhaustion, and packet drops.

## Features Built for Cloud Support
- **Regex Pattern Engine:** Automatically categorizes log lines into specific failure types (DNS, TCP timeouts, port exhaustion, packet drops).
- **Actionable AWS Support Recommendations:** Each detected failure includes precise troubleshooting guidelines aligned with AWS networking best practices (Security Groups, NACLs, Route 53, ENI metrics).
- **Severity Filtering:** Easily filter diagnostics by severity level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

## Quick Start Guide

1. **Install Python Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run Diagnostics on Sample Logs:**
   ```bash
   python diag.py logs/sample_server.log
   ```
3. **Filter by Severity:**
   ```bash
   python diag.py logs/sample_server.log --severity HIGH
   ```
