import os
import re
import logging
from datetime import datetime
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)

class SSHAuditTool:
    def __init__(self, config_file='/etc/ssh/sshd_config'):
        self.config_file = config_file
        self.config = self.parse_config()
        self.report = []

    def parse_config(self):
        """Parse SSH configuration file to extract settings."""
        if not os.path.exists(self.config_file):
            logging.error(f"Configuration file not found: {self.config_file}")
            return {}

        config = {}
        with open(self.config_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    match = re.match(r'(\w+)\s+(.+)', line)
                    if match:
                        key, value = match.groups()
                        config[key] = value.strip()
        return config

    def run_audit(self):
        """Run the SSH audit."""
        self.check_security()
        self.check_compliance()
        self.check_vulnerabilities()
        self.generate_report()

    def check_security(self):
        """Perform security checks on SSH configuration."""
        # Example checks
        if self.config.get('PermitRootLogin', 'yes').lower() == 'yes':
            self.report.append("Security Check: PermitRootLogin should be 'no'")
        
        if self.config.get('PasswordAuthentication', 'yes').lower() == 'yes':
            self.report.append("Security Check: PasswordAuthentication should be 'no'")
        
        if 'Ciphers' in self.config:
            weak_ciphers = ['arcfour', 'rc4', '3des', 'blowfish', 'md5']
            if any(weak in self.config['Ciphers'].lower() for weak in weak_ciphers):
                self.report.append("Security Check: Weak ciphers detected in Ciphers setting.")

    def check_compliance(self):
        """Check compliance against standards."""
        # Example compliance checks
        if self.config.get('PermitRootLogin', 'yes').lower() == 'yes':
            self.report.append("Compliance Check: Direct root login is enabled, which is non-compliant.")
        
        if self.config.get('PasswordAuthentication', 'yes').lower() == 'yes':
            self.report.append("Compliance Check: Password authentication is enabled, which is non-compliant; consider using key-based authentication.")
        
        if self.config.get('UsePAM', 'no').lower() != 'yes':
            self.report.append("Compliance Check: UsePAM should be enabled for better authentication management.")
        
        if 'MaxAuthTries' in self.config and int(self.config['MaxAuthTries']) > 3:
            self.report.append("Compliance Check: MaxAuthTries should be set to 3 or fewer to mitigate brute-force attacks.")

    def check_vulnerabilities(self):
        """Check for known SSH vulnerabilities."""
        # Known vulnerabilities to check for
        vulnerabilities = {
            "Heartbleed": "Ensure that OpenSSL versions 1.0.1 to 1.0.1f are not in use; these are vulnerable to Heartbleed.",
            "Shellshock": "Ensure that Bash versions prior to 4.3 are not in use; these are vulnerable to Shellshock."
        }

        # Placeholder for the installed OpenSSL and Bash versions check
        # In a real implementation, you could use subprocess to get version info
        installed_openssl_version = "3.0.15"  # Placeholder for OpenSSL version check
        installed_bash_version = "5.0"  # Placeholder for Bash version check

        # Check for Heartbleed vulnerability
        if installed_openssl_version in ["1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", "1.0.1f"]:
            self.report.append(f"Vulnerability Check: {vulnerabilities['Heartbleed']}")

        # Check for Shellshock vulnerability
        if installed_bash_version < "4.3":
            self.report.append(f"Vulnerability Check: {vulnerabilities['Shellshock']}")

    def generate_report(self):
        """Generate and save the audit report."""
        report_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>SSH Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>SSH Audit Report</h1>
            <table>
                <tr>
                    <th>Findings</th>
                </tr>
        """
        for finding in self.report:
            report_content += f"<tr><td>{finding}</td></tr>"

        report_content += """
            </table>
        </body>
        </html>
        """

        report_file_path = f"SSH_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_file_path, 'w') as report_file:
            report_file.write(report_content)

        logging.info(f"Report generated: {report_file_path}")

# Example of running the audit tool
if __name__ == "__main__":
    ssh_audit_tool = SSHAuditTool()
    ssh_audit_tool.run_audit()
