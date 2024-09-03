import tkinter as tk
from tkinter import ttk, filedialog
import subprocess
import shlex
import os
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def run_nmap_scan():
    ip_address = ip_entry.get().strip()
    save_path = save_path_entry.get().strip()
    output_filename = output_filename_entry.get().strip()
    
    if not is_valid_ip(ip_address):
        result_label.config(text="Error: Invalid IP address")
        return
    
    if not os.path.isdir(save_path):
        result_label.config(text="Error: Please select a valid directory")
        return
    
    if not output_filename:
        output_filename = "nmap_scan.txt"
    
    # Disable scan button during the scan
    scan_button.config(state=tk.DISABLED)
    
    # Configure progress bar
    progress_bar.config(mode='indeterminate')
    progress_bar.start()

    # Specify the full path to the Nmap executable
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"  # Replace with the actual path to nmap.exe
    output_file = os.path.join(save_path, output_filename)
    
    # Securely construct Nmap command
    nmap_command = f'"{nmap_path}" {shlex.quote(ip_address)} -oN {shlex.quote(output_file)}'
    
    try:
        # Execute the Nmap command
        result = subprocess.run(nmap_command, shell=True, check=True, capture_output=True, text=True)
        result_label.config(text=f"Scan completed successfully. Results saved to {output_file}")
        display_network_diagram(ip_address, output_file)
    except subprocess.CalledProcessError as e:
        result_label.config(text=f"Error: Nmap command failed.\n{e.stderr}")
    except Exception as e:
        result_label.config(text=f"Error: {e}")
    finally:
        # Reset UI
        scan_button.config(state=tk.NORMAL)
        progress_bar.stop()
        progress_bar.config(mode='determinate', value=0)

def is_valid_ip(ip):
    # Basic IPv4 validation
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

def display_network_diagram(ip_address, output_file):
    G = nx.Graph()
    
    # Add the scanned IP address as the central node
    G.add_node(ip_address)
    
    # Extract open ports from the Nmap output file
    with open(output_file, 'r') as file:
        for line in file:
            if "/tcp" in line and "open" in line:
                port = line.split('/')[0]
                G.add_node(port)
                G.add_edge(ip_address, port)
    
    # Draw the network diagram
    fig, ax = plt.subplots()
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, ax=ax, node_size=500, node_color='lightblue', font_size=10, font_weight='bold')
    
    # Display the graph in the Nmap window
    canvas = FigureCanvasTkAgg(fig, master=nmap_window)
    canvas.draw()
    canvas.get_tk_widget().grid(row=4, column=0, padx=10, pady=10, sticky='nsew')

def open_nmap_scanner():
    global nmap_window, ip_entry, save_path_entry, output_filename_entry, result_label, scan_button, progress_bar

    # Create the Nmap window
    nmap_window = tk.Toplevel(root)
    nmap_window.title("Nmap Network Scanner")
    nmap_window.geometry("1000x800")  # Set initial size, adjust as needed

    # Hide the main window
    root.withdraw()

    # Create a frame for inputs
    input_frame = ttk.Frame(nmap_window, padding="20")
    input_frame.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')

    # Center the input frame
    nmap_window.grid_columnconfigure(0, weight=1)

    # IP Address
    tk.Label(input_frame, text="IP Address:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
    ip_entry = tk.Entry(input_frame)
    ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky='ew')

    # Save Path
    tk.Label(input_frame, text="Save Path:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
    save_path_entry = tk.Entry(input_frame)
    save_path_entry.grid(row=1, column=1, padx=10, pady=10, sticky='ew')

    tk.Button(input_frame, text="Browse", command=lambda: save_path_entry.insert(tk.END, filedialog.askdirectory())).grid(row=1, column=2, padx=10, pady=10, sticky='ew')

    # Output Filename
    tk.Label(input_frame, text="Output Filename:").grid(row=2, column=0, padx=10, pady=10, sticky='e')
    output_filename_entry = tk.Entry(input_frame)
    output_filename_entry.grid(row=2, column=1, padx=10, pady=10, sticky='ew')

    # Center the input_frame grid columns
    input_frame.grid_columnconfigure(0, weight=1)
    input_frame.grid_columnconfigure(1, weight=1)
    input_frame.grid_columnconfigure(2, weight=1)

    # Scan button
    scan_button = tk.Button(nmap_window, text="Scan", command=run_nmap_scan)
    scan_button.grid(row=1, column=0, padx=10, pady=10, sticky='ew')

    # Output Label
    result_label = tk.Label(nmap_window, text="")
    result_label.grid(row=2, column=0, padx=10, pady=10, sticky='ew')

    # Progress bar
    progress_bar = ttk.Progressbar(nmap_window, orient='horizontal', mode='determinate')
    progress_bar.grid(row=3, column=0, padx=10, pady=10, sticky='ew')

    # Back Button
    back_button = tk.Button(nmap_window, text="Back to Main", command=go_back_to_main)
    back_button.grid(row=0, column=0, padx=10, pady=10, sticky='nw')

    # Close Button
    close_button = tk.Button(nmap_window, text="Close", command=nmap_window.destroy)
    close_button.grid(row=0, column=1, padx=10, pady=10, sticky='ne')

def go_back_to_main():
    global nmap_window
    # Destroy the Nmap window and show the main window
    nmap_window.destroy()
    root.deiconify()

def placeholder1():
    placeholder_window = tk.Toplevel(root)
    placeholder_window.title("Placeholder 1")
    tk.Label(placeholder_window, text="Functionality for Placeholder 1").pack(padx=20, pady=20)

def placeholder2():
    placeholder_window = tk.Toplevel(root)
    placeholder_window.title("Placeholder 2")
    tk.Label(placeholder_window, text="Functionality for Placeholder 2").pack(padx=20, pady=20)

def placeholder3():
    placeholder_window = tk.Toplevel(root)
    placeholder_window.title("Placeholder 3")
    tk.Label(placeholder_window, text="Functionality for Placeholder 3").pack(padx=20, pady=20)

# Create the main Tkinter window
root = tk.Tk()
root.title("Main Application")
root.geometry("800x600")  # Set initial size, adjust as needed

# Top label
top_label = tk.Label(root, text="THREAT INTELLIGENCE SYSTEM", font=("Arial", 24), fg="blue")
top_label.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

# Create the main frame
main_frame = ttk.Frame(root, padding="20")
main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Create four buttons linking to different functions
button1 = tk.Button(main_frame, text="Nmap Scanner", command=open_nmap_scanner, width=20, height=2)
button1.grid(row=0, column=0, padx=10, pady=10, sticky='nsew')

button2 = tk.Button(main_frame, text="Placeholder 1", command=placeholder1, width=20, height=2)
button2.grid(row=0, column=1, padx=10, pady=10, sticky='nsew')

button3 = tk.Button(main_frame, text="Placeholder 2", command=placeholder2, width=20, height=2)
button3.grid(row=1, column=0, padx=10, pady=10, sticky='nsew')

button4 = tk.Button(main_frame, text="Placeholder 3", command=placeholder3, width=20, height=2)
button4.grid(row=1, column=1, padx=10, pady=10, sticky='nsew')

# Configure grid layout for the main frame
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=1)
main_frame.grid_rowconfigure(0, weight=1)
main_frame.grid_rowconfigure(1, weight=1)

# Run the Tkinter main loop
root.mainloop()
