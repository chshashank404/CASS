import subprocess
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PowerShellAuditTool:
    def __init__(self):
        # MITRE ATT&CK Techniques Mapping
        self.mitre_techniques = {
            "Get-Command": "T1059.001 - PowerShell commands used for execution.",
            "Invoke-Expression": "T1059.001 - Potentially malicious command execution.",
            "Invoke-WebRequest": "T1071.001 - Web Service for command and control.",
            "New-Object": "T1059.001 - Instantiates .NET objects for execution.",
            "Start-Process": "T1059.001 - Executes programs and scripts.",
            "Get-Process": "T1016 - Data from process listing may indicate suspicious activity.",
            "Set-ExecutionPolicy": "T1047 - Changes the execution policy to allow script execution.",
            "Add-Type": "T1059.001 - Adds .NET types to PowerShell scripts.",
            "Invoke-Item": "T1059.001 - Executes files, potentially malicious.",
            "Get-EventLog": "T1045 - Queries event logs, potentially for enumeration.",
            "Set-ItemProperty": "T1060 - Modifies properties of items, could be for persistence.",
            "Export-Clixml": "T1007 - Exfiltrates data in XML format.",
            "Import-Clixml": "T1007 - Imports data potentially for unauthorized use.",
            "Get-Content": "T1005 - Reads files, potentially for sensitive data exfiltration.",
            "Read-Host": "T1056.001 - Captures user input, could be used for credential harvesting.",
            "Test-Connection": "T1016 - Network reconnaissance tool.",
            "Get-WmiObject": "T1047 - Queries WMI data, often for enumeration.",
            "Invoke-Command": "T1071.001 - Executes commands on remote systems.",
            "Get-CimInstance": "T1047 - Queries CIM data, often for enumeration.",
            "Find-PsResource": "T1071.001 - Finds and retrieves PowerShell modules from the internet.",
            "Remove-Item": "T1070.001 - Deletes files, potentially used for obfuscation.",
            "Set-Alias": "T1036.003 - Creates an alias to obfuscate command execution.",
            "ForEach-Object": "T1059.001 - Loops through objects and executes commands.",
            "Out-File": "T1047 - Redirects output to a file, could be for persistence.",
            "Stop-Process": "T1070.001 - Terminates processes, potentially malicious.",
            "Get-LocalUser": "T1069 - Enumerates local user accounts.",
            "Get-ADUser": "T1069 - Enumerates Active Directory users.",
            "New-LocalUser": "T1136 - Creates local user accounts, could be used for persistence.",
        }

    def run_audit(self):
        print("Running Audit...")
        results = []

        # Run each audit module
        audit_methods = [
            self.test_execution_policy,
            self.test_logging_audit,
            self.test_remote_powershell,
            self.test_powershell_version,
            self.test_system_hardening,
            self.test_jea_compliance,
            self.test_anti_malware,
            self.test_amsi_audit,
            self.test_forensic_trace,
            self.test_user_profile,
            self.test_lateral_movement,
            self.test_privilege_escalation,
            self.test_ad_integration,
            self.test_network_configuration,
            self.test_user_account_security,
            self.test_application_whitelisting,
            self.test_patch_management,
            self.test_logging_and_monitoring,
            self.test_firewall_status,
            self.test_usb_storage,
            self.capture_powershell_activities
        ]

        for method in audit_methods:
            results.append(method())

        # Generate report in HTML format
        report_file_html = self.generate_html_report(results)

        # Display results
        print("Audit Complete!")
        print(f"Report generated: {report_file_html}")

    def capture_powershell_activities(self):
        try:
            command_history = subprocess.check_output(
                ["powershell", "-Command", "Get-History | Select-Object -ExpandProperty CommandLine"]
            ).strip().decode()
            findings = []

            for command in command_history.splitlines():
                technique = self.mitre_techniques.get(command)
                if technique:
                    findings.append(f"Suspicious Command Detected: {command} - {technique}")

            return "\n".join(findings) if findings else "No suspicious PowerShell commands detected."
        except Exception as e:
            return f"Error capturing PowerShell activities: {str(e)}"

    def test_execution_policy(self):
        return self.run_powershell_command("Get-ExecutionPolicy")

    def test_logging_audit(self):
        script_block_logging = self.run_powershell_command(
            "Get-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging'"
        )
        module_logging = self.run_powershell_command(
            "Get-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging'"
        )

        script_block_status = "Enabled" if "EnableScriptBlockLogging" in script_block_logging else "Disabled"
        module_logging_status = "Enabled" if "EnableModuleLogging" in module_logging else "Disabled"

        return f"Script Block Logging: {script_block_status}, Module Logging: {module_logging_status}"

    def test_remote_powershell(self):
        remoting_config = self.run_powershell_command("Get-WinRMService")
        return "Remote PowerShell: Secure Configuration" if "AllowRemoteShellAccess" in remoting_config else "Remote PowerShell: Insecure Configuration"

    def test_powershell_version(self):
        version = int(self.run_powershell_command("$PSVersionTable.PSVersion.Major"))
        return "PowerShell Version: Compliant" if version >= 5 else "PowerShell Version: Non-Compliant"

    def test_system_hardening(self):
        signing_required = self.run_powershell_command("Get-ExecutionPolicy -List | Where-Object { $_.Scope -eq 'LocalMachine' }")
        return "System Hardening: Secure (Scripts require signing)" if "AllSigned" in signing_required else "System Hardening: Insecure (Scripts may not require signing)"

    def test_jea_compliance(self):
        jea_config = self.run_powershell_command("Get-PSSessionConfiguration | Where-Object { $_.Name -eq 'JEA' }")
        return "JEA Compliance: Configured" if jea_config else "JEA Compliance: Not Configured"

    def test_anti_malware(self):
        anti_malware_status = self.run_powershell_command("Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring")
        return "Anti-malware: Enabled" if anti_malware_status == "False" else "Anti-malware: Disabled"

    def test_amsi_audit(self):
        amsi_status = self.run_powershell_command("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\AMSI'")
        return "AMSI: Enabled" if "Enable" in amsi_status else "AMSI: Disabled"

    def test_forensic_trace(self):
        forensic_log_status = self.run_powershell_command("Get-WinEvent -LogName 'Windows PowerShell' -MaxEvents 1")
        return "Forensic Trace: Present" if forensic_log_status else "Forensic Trace: Absent"

    def test_user_profile(self):
        user_profile = self.run_powershell_command("[System.Security.Principal.WindowsIdentity]::GetCurrent().Name")
        return f"User Profile: {user_profile}"

    def test_lateral_movement(self):
        lateral_movement_status = self.run_powershell_command("Get-LocalGroupMember -Group 'Administrators'")
        return f"Lateral Movement Risk: Check Group Members - {lateral_movement_status}"

    def test_privilege_escalation(self):
        privilege_status = self.run_powershell_command("Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true }")
        return f"Privilege Escalation Risk: {privilege_status if privilege_status else 'No Risk Detected'}"

    def test_ad_integration(self):
        ad_status = self.run_powershell_command("Get-ADDomain")
        return "AD Integration: Active" if ad_status else "AD Integration: Inactive"

    def test_network_configuration(self):
        network_config = self.run_powershell_command("Get-NetFirewallProfile")
        return f"Network Configuration: {network_config}"

    def test_user_account_security(self):
        user_accounts = self.run_powershell_command("Get-LocalUser")
        return f"User Account Security: {user_accounts}"

    def test_application_whitelisting(self):
        applocker_policy = self.run_powershell_command("Get-AppLockerPolicy -Effective")
        return "Application Whitelisting: Active" if applocker_policy else "Application Whitelisting: Inactive"

    def test_patch_management(self):
        patch_status = self.run_powershell_command("Get-WindowsUpdate")
        return "Patch Management: Up to date" if patch_status else "Patch Management: Updates available"

    def test_logging_and_monitoring(self):
        monitoring_status = self.run_powershell_command("Get-WinEvent -LogName 'Security' -MaxEvents 5")
        return "Logging and Monitoring: Active" if monitoring_status else "Logging and Monitoring: Inactive"

    def test_firewall_status(self):
        firewall_status = self.run_powershell_command("Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'True' }")
        return "Firewall Status: Enabled" if firewall_status else "Firewall Status: Disabled"

    def test_usb_storage(self):
        usb_storage_status = self.run_powershell_command("Get-PnpDevice -Class 'USB'")
        return "USB Storage: Detected" if usb_storage_status else "USB Storage: Not Detected"

    def run_powershell_command(self, command):
        try:
            output = subprocess.check_output(["powershell", "-Command", command], stderr=subprocess.STDOUT)
            return output.decode().strip()
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {command}, Error: {e.output.decode().strip()}")
            return f"Error running command: {command}"

    def generate_html_report(self, results):
        report_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>PowerShell Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
                .long-text {{ cursor: pointer; color: blue; }}
            </style>
        </head>
        <body>
            <h1>PowerShell Audit Report</h1>
            <table>
                <tr>
                    <th>Audit Module</th>
                    <th>Findings</th>
                </tr>
        """
        
        for result in results:
            audit_module = result.split(":")[0]
            findings = result.split(":")[1] if ":" in result else "No findings"
            report_content += f"""
            <tr>
                <td>{audit_module}</td>
                <td class="long-text" onclick="toggleText(this)">{findings.strip()}</td>
                <td style="display: none;">{findings.strip()}</td>
            </tr>
            """

        report_content += """
        </table>
        <script>
            function toggleText(element) {
                const hiddenText = element.nextElementSibling;
                if (hiddenText.style.display === 'none') {
                    hiddenText.style.display = 'block';
                } else {
                    hiddenText.style.display = 'none';
                }
            }
        </script>
    </body>
    </html>
    """
        
        report_file_path = f"PowerShell_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_file_path, 'w') as report_file:
            report_file.write(report_content)

        return report_file_path

# Example of running the audit tool
if __name__ == "__main__":
    audit_tool = PowerShellAuditTool()
    audit_tool.run_audit()
