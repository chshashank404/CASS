import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import scapy.all as scapy
import nmap
import os
import threading
import socket
from netaddr import IPNetwork, IPAddress

class WiFiSecurityAudit:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Audit Module")

        self.essid = None
        self.bssid = None
        self.ip_range = None
        
        self.create_widgets()
        
    def create_widgets(self):
        # Start Button
        self.start_button = ttk.Button(self.root, text="Start Audit", command=self.start_audit)
        self.start_button.grid(row=0, column=0, columnspan=2, pady=20)
        
        # Output Textbox with Scrollbar
        self.output_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=20, width=80)
        self.output_text.grid(row=1, column=0, columnspan=2, padx=10, pady=5)
    
    def start_audit(self):
        # Clear the output text box
        self.output_text.delete(1.0, tk.END)
        
        # Run the audit in a separate thread to keep the UI responsive
        audit_thread = threading.Thread(target=self.run_audit)
        audit_thread.start()
    
    def run_audit(self):
        self.output_text.insert(tk.END, "Detecting network interface...\n")
        interface = self.detect_interface()
        if not interface:
            self.output_text.insert(tk.END, "No network interface found.\n")
            return

        self.output_text.insert(tk.END, f"Using interface: {interface}\n")

        self.output_text.insert(tk.END, "Discovering IP range...\n")
        self.ip_range = self.get_ip_range()
        self.output_text.insert(tk.END, f"IP Range: {self.ip_range}\n")

        self.output_text.insert(tk.END, "Starting Network Mapping...\n")
        devices = self.network_scan(self.ip_range)
        self.output_text.insert(tk.END, "Network Mapping Complete.\n\n")
        
        self.output_text.insert(tk.END, "Starting Vulnerability Assessment...\n")
        for device in devices:
            scan_data = self.vulnerability_scan(device['ip'])
            for data in scan_data:
                self.output_text.insert(tk.END, f"Host: {data['host']}, Port: {data['port']}, State: {data['state']}, Service: {data['name']}, Version: {data['version']}\n")
        self.output_text.insert(tk.END, "Vulnerability Assessment Complete.\n\n")
        
        self.output_text.insert(tk.END, "Starting Penetration Testing...\n")
        self.run_aircrack(self.essid, self.bssid)
        self.output_text.insert(tk.END, "Penetration Testing Complete.\n")

    def detect_interface(self):
        interfaces = scapy.get_if_list()
        for iface in interfaces:
            if "Wi-Fi" in iface or "wlan" in iface:
                return iface
        return None
    
    def get_ip_range(self):
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_network = IPNetwork(local_ip + '/24')
        return str(ip_network.network) + '/' + str(ip_network.prefixlen)

    def network_scan(self, ip_range):
        arp = scapy.ARP(pdst=ip_range)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = scapy.srp(packet, timeout=3, verbose=0)[0]
        devices = []
        for sent, received in result:
            device_info = f"IP: {received.psrc}, MAC: {received.hwsrc}\n"
            self.output_text.insert(tk.END, device_info)
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        return devices
    
    def vulnerability_scan(self, ip):
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sV')
        scan_data = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    scan_data.append({
                        'host': host,
                        'port': port,
                        'state': nm[host][proto][port]['state'],
                        'name': nm[host][proto][port]['name'],
                        'version': nm[host][proto][port]['version']
                    })
        return scan_data
    
    def run_aircrack(self, essid, bssid):
        command = f"aircrack-ng -a2 -b {bssid} -e {essid} capture_file.cap"
        os.system(command)

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiSecurityAudit(root)
    root.mainloop()
