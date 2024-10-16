import platform
import psutil
import subprocess
import logging
import html

# Setup logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_antivirus_installed():
    # Check if antivirus is installed (example for Windows)
    if platform.system().lower() == 'windows':
        antivirus_processes = ['avp.exe', 'msmpeng.exe', 'avg.exe']
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in antivirus_processes:
                return True
    return False

def check_firewall_status():
    # Check if the firewall is enabled (Windows example)
    if platform.system().lower() == 'windows':
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
        return 'State ON' in result.stdout
    return True  # Assume true for non-Windows systems

def check_software_updates():
    # Check if the OS and applications are up-to-date
    if platform.system().lower() == 'windows':
        result = subprocess.run(['powershell', 'Get-WindowsUpdate'], capture_output=True, text=True)
        return 'No updates available' in result.stdout
    return True  # Assume true for simplicity

def check_disk_encryption():
    # Check for full-disk encryption (Windows example)
    if platform.system().lower() == 'windows':
        result = subprocess.run(['manage-bde', '-status'], capture_output=True, text=True)
        return 'Protection Status: On' in result.stdout
    return False

def check_patch_status():
    # Verify if OS and applications are patched
    if platform.system().lower() == 'windows':
        result = subprocess.run(['powershell', 'Get-HotFix'], capture_output=True, text=True)
        return 'No hotfixes' not in result.stdout  # If no hotfixes are listed, it's unpatched
    return True  # Assume true for simplicity

def check_usb_restrictions():
    # Simplified check for USB restrictions
    if platform.system().lower() == 'windows':
        result = subprocess.run(['reg', 'query', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{36FC9E60-C465-11CF-8058-044556003C01}'], capture_output=True, text=True)
        return 'Allow' not in result.stdout  # If "Allow" is not found, restrictions are enforced
    return True  # Assume true for non-Windows systems for simplicity

def generate_html_report(assessment_result):
    html_report = f"""
    <html>
    <head><title>Endpoint Security Report</title></head>
    <body>
        <h1>Endpoint Security Assessment Report</h1>
        <h2>Hostname: {assessment_result['hostname']}</h2>
        <h2>IP Address: {assessment_result['ip']}</h2>
        <h2>Operating System: {assessment_result['os']}</h2>
        <h2>CPU Usage: {assessment_result['cpu_usage']}%</h2>
        <h2>Memory Usage: {assessment_result['memory_usage']}%</h2>
        <h2>Disk Usage: {assessment_result['disk_usage']}%</h2>
        <h2>Users: {", ".join(assessment_result['users'])}</h2>
        <h2>Findings:</h2>
        <table border="1">
            <tr>
                <th>Feature</th>
                <th>Status</th>
            </tr>
            <tr><td>Antivirus Installed</td><td>{'Yes' if assessment_result['antivirus_installed'] else 'No'}</td></tr>
            <tr><td>Firewall Status</td><td>{'Enabled' if assessment_result['firewall_status'] else 'Disabled'}</td></tr>
            <tr><td>Software Updates</td><td>{'Up-to-date' if assessment_result['software_updates'] else 'Outdated'}</td></tr>
            <tr><td>Disk Encryption</td><td>{'Enabled' if assessment_result['disk_encryption'] else 'Disabled'}</td></tr>
            <tr><td>USB Restrictions</td><td>{'Enforced' if assessment_result['usb_restrictions'] else 'Not enforced'}</td></tr>
            <tr><td>Patch Status</td><td>{'Patched' if assessment_result['patch_status'] else 'Unpatched'}</td></tr>
        </table>
        <h2>Compliance Status</h2>
        <p>{assessment_result['compliance_status']}</p>
    </body>
    </html>
    """
    return html_report

def main():
    logging.info("Starting endpoint security assessment...")

    # Gather system information
    hostname = platform.node()
    ip_address = psutil.net_if_addrs()['Ethernet'][0].address  # Adjust as necessary for your environment
    operating_system = platform.system() + ' ' + platform.version()
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    users = [u.name for u in psutil.users()]

    # Perform checks
    antivirus_installed = check_antivirus_installed()
    firewall_status = check_firewall_status()
    software_updates = check_software_updates()
    disk_encryption = check_disk_encryption()
    usb_restrictions = check_usb_restrictions()
    patch_status = check_patch_status()

    # Generate findings
    findings = []
    if not antivirus_installed:
        findings.append("No antivirus installed.")
    if not disk_encryption:
        findings.append("Disk encryption not enabled.")
    if not usb_restrictions:
        findings.append("USB restrictions not enforced.")

    # Compliance status (example logic)
    compliance_status = "Complies with CIS and NIST recommendations." if antivirus_installed and disk_encryption else "Does not comply with CIS and NIST recommendations."

    # Prepare assessment result
    assessment_result = {
        'hostname': hostname,
        'ip': ip_address,
        'os': operating_system,
        'cpu_usage': cpu_usage,
        'memory_usage': memory_usage,
        'disk_usage': disk_usage,
        'users': users,
        'antivirus_installed': antivirus_installed,
        'firewall_status': firewall_status,
        'software_updates': software_updates,
        'disk_encryption': disk_encryption,
        'usb_restrictions': usb_restrictions,
        'patch_status': patch_status,
        'compliance_status': compliance_status,
        'findings': findings,
    }

    # Generate HTML report
    html_report = generate_html_report(assessment_result)

    # Save the report to an HTML file
    with open("endpoint_security_report.html", "w") as report_file:
        report_file.write(html_report)

    logging.info("Endpoint security assessment completed. Report saved as 'endpoint_security_report.html'.")

if __name__ == "__main__":
    main()
