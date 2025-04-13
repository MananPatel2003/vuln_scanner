import nmap
import sys
import argparse
import datetime
import socket
import re


def validate_target(target):
    """Validate if the target is a valid IP address or hostname.

    Args:
        target (str): The IP or hostname to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    # Check for valid IP address
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass
    # Check for valid hostname
    if re.match(r'^[a-zA-Z0-9.-]+$', target):
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            pass
    return False


def run_scan(target, output_file, scan_type):
    """Run an Nmap scan on the target and check for vulnerabilities.

    Args:
        target (str): The IP or hostname to scan.
        output_file (str): Path to save the report.
        scan_type (str): Type of scan ('quick' or 'deep').
    """
    # Define known vulnerabilities for detection
    vuln_db = {
    "mysql": {
        "port": 3306,
        "risk": "High",
        "description": "MySQL exposed publicly may allow unauthorized access if not secured."
    },
    "http": {
        "port": 80,
        "risk": "Medium",
        "description": "HTTP on port 80 (no HTTPS) may leak sensitive data."
    },
    "vmware-auth": {
        "port": 902,
        "versions": ["1.10"],
        "risk": "High",
        "description": "VMware Authentication Daemon 1.10 has known vulnerabilities."
    },
    "microsoft-ds": {
        "port": 445,
        "risk": "High",
        "description": "SMB on port 445 may be vulnerable to exploits like EternalBlue if not patched."
    }
}
    
    # Initialize results dictionary for reporting
    results = {}
    
    try:
        # Set up Nmap scanner
        nm = nmap.PortScanner()
        # Choose scan arguments based on type
        scan_args = "-sS" if scan_type == "quick" else "-sS -sV -O"
        print(f"Starting {scan_type} scan on {target}...")
        print("Initializing port scan...")
        nm.scan(target, arguments=scan_args)
        print("Scan completed. Processing results...")
        
        # Parse scan results
        for host in nm.all_hosts():
            results[host] = {
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "protocols": {}
            }
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            # Include OS detection for deep scans
            if scan_type == "deep" and "osclass" in nm[host]:
                results[host]["osclass"] = nm[host]["osclass"]
                print("OS Detection:")
                for os in nm[host]["osclass"]:
                    print(f"  OS: {os['osfamily']} {os['osgen']} (Accuracy: {os['accuracy']}%)")
            # Process protocols and ports
            for proto in nm[host].all_protocols():
                results[host]["protocols"][proto] = {}
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    service = nm[host][proto][port]
                    results[host]["protocols"][proto][port] = {
                        "state": service["state"],
                        "name": service["name"],
                        "product": service["product"],
                        "version": service["version"]
                    }
                    print(f"Port: {port}\tState: {service['state']}\tService: {service['name']} ({service['product']} {service['version']})")
                    # Check vulnerabilities for deep scans
                    if scan_type == "deep":
                        for vuln_service, vuln_info in vuln_db.items():
                            if service["name"] == vuln_service and port == vuln_info["port"]:
                                results[host]["protocols"][proto][port]["vulnerability"] = vuln_info
                                print(f"  [!] Vulnerability: {vuln_info['description']} (Risk: {vuln_info['risk']})")
                            elif service["name"] == vuln_service and "versions" in vuln_info and service["version"] in vuln_info["versions"]:
                                results[host]["protocols"][proto][port]["vulnerability"] = vuln_info
                                print(f"  [!] Vulnerability: {vuln_info['description']} (Risk: {vuln_info['risk']})")
        
        # Generate and save report
        save_text_report(target, results, output_file, scan_type)
    
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)


def save_text_report(target, results, output_file, scan_type):
    """Save scan results and vulnerabilities to a text file.

    Args:
        target (str): The scanned target.
        results (dict): Scan results data.
        output_file (str): Path to save the report.
        scan_type (str): Type of scan performed.
    """
    with open(output_file, 'w') as f:
        f.write(f"Scan Report for {target} ({scan_type} scan)\n")
        f.write(f"Generated: {datetime.datetime.now()}\n")
        f.write("=" * 50 + "\n\n")
        for host, host_data in results.items():
            f.write(f"Host: {host} ({host_data['hostname']})\n")
            f.write(f"State: {host_data['state']}\n")
            if scan_type == "deep" and "osclass" in host_data:
                f.write("OS Detection:\n")
                for os in host_data["osclass"]:
                    f.write(f"  OS: {os['osfamily']} {os['osgen']} (Accuracy: {os['accuracy']}%)\n")
            for proto, proto_data in host_data['protocols'].items():
                f.write(f"Protocol: {proto}\n")
                for port, port_data in proto_data.items():
                    f.write(f"Port: {port}\tState: {port_data['state']}\tService: {port_data['name']} ({port_data['product']} {port_data['version']})\n")
                    if port_data.get('vulnerability'):
                        f.write(f"  [!] Vulnerability: {port_data['vulnerability']['description']} (Risk: {port_data['vulnerability']['risk']})\n")
            f.write("\n")
        f.write("=" * 50 + "\n")
    print(f"Report saved to {output_file}")


if __name__ == "__main__":
    """Main entry point for the vulnerability scanner."""
    # Configure command-line arguments
    parser = argparse.ArgumentParser(description="Automated Vulnerability Scanner using Nmap")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname to scan (e.g., 127.0.0.1)")
    parser.add_argument("-o", "--output", default=f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                       help="Output file for the report (default: scan_report_<timestamp>.txt)")
    parser.add_argument("--scan-type", choices=["quick", "deep"], default="quick",
                       help="Scan type: quick (basic scan) or deep (version and OS detection)")
    args = parser.parse_args()

    # Validate target before scanning
    if not validate_target(args.target):
        print(f"Error: Invalid target '{args.target}'. Please provide a valid IP or hostname.")
        sys.exit(1)

    # Execute the scan
    run_scan(args.target, args.output, args.scan_type)