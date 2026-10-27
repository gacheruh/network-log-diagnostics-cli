import argparse
import re
import sys
from tabulate import tabulate

# Define regex patterns for common cloud & networking failures
PATTERNS = {
    "DNS Resolution Failure": {
        "regex": re.compile(r"DNS resolution failure|lookup failed|Name or service not known", re.IGNORECASE),
        "severity": "HIGH",
        "aws_tip": "Check Amazon Route 53 resolver settings, VPC DNS hostnames/support enabled, or upstream DNS server reachability."
    },
    "Port Exhaustion / High Utilization": {
        "regex": re.compile(r"port exhaustion|ephemeral port utilization|near capacity", re.IGNORECASE),
        "severity": "HIGH",
        "aws_tip": "Review connection reuse (HTTP keep-alive), adjust tcp_fin_timeout, or scale out instances behind an NLB/ALB."
    },
    "Packet Drops / Buffer Overruns": {
        "regex": re.compile(r"packet drop|buffer overrun", re.IGNORECASE),
        "severity": "CRITICAL",
        "aws_tip": "Check ENI network performance metrics in CloudWatch, ensure instance size matches network bandwidth requirements, or inspect security group limits."
    },
    "TCP Handshake / Timeout Failure": {
        "regex": re.compile(r"connection timeout|handshake failed|connection reset by peer|TCP RST", re.IGNORECASE),
        "severity": "MEDIUM",
        "aws_tip": "Inspect Security Groups and Network ACLs (NACLs) for blocked ports, check route tables, or verify target service health."
    }
}

def analyze_log_file(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                for issue_name, info in PATTERNS.items():
                    if info["regex"].search(line):
                        findings.append({
                            "line": line_no,
                            "issue": issue_name,
                            "severity": info["severity"],
                            "message": line,
                            "recommendation": info["aws_tip"]
                        })
    except FileNotFoundError:
        print(f"Error: Log file '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
        
    return findings

def main():
    parser = argparse.ArgumentParser(description="AWS Support Network & Log Diagnostics CLI Tool")
    parser.add_argument("logfile", nargs="?", default="logs/sample_server.log", help="Path to the server or flow log file to analyze")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter findings by minimum severity")
    
    args = parser.parse_args()
    
    print("======================================================================")
    print("           AWS CLOUD SUPPORT: AUTOMATED LOG & NETWORK DIAGNOSTIC      ")
    print("======================================================================\n")
    print(f"Analyzing log file: {args.logfile}...\n")
    
    findings = analyze_log_file(args.logfile)
    
    if not findings:
        print("✅ No network anomalies or failures detected in the log file.")
        return

    table_data = []
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    
    for f in findings:
        if args.severity and severity_order.get(f["severity"], 0) < severity_order.get(args.severity, 0):
            continue
        table_data.append([
            f"Line {f['line']}",
            f['issue'],
            f['severity'],
            f['message'][:60] + "..." if len(f['message']) > 60 else f['message'],
            f['recommendation']
        ])

    if not table_data:
        print("No findings match the specified severity filter.")
        return

    headers = ["Location", "Detected Issue", "Severity", "Log Excerpt", "AWS Support Troubleshooting Tip"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    print(f"\nTotal anomalies identified: {len(table_data)}")

if __name__ == "__main__":
    main()
