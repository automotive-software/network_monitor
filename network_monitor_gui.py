import os
import psutil
import signal
import sys
import tkinter as tk
from tkinter import ttk

class NetworkMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Monitor")
        
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True)

        self.interface_frame = tk.Frame(self.notebook)
        self.ip_frame = tk.Frame(self.notebook)
        
        self.notebook.add(self.interface_frame, text='Interface')
        self.notebook.add(self.ip_frame, text='IP')

        self.interface_label = tk.Label(self.interface_frame, text="Interface:")
        self.interface_label.pack(pady=5)

        self.interface_entry = tk.Entry(self.interface_frame)
        self.interface_entry.pack(pady=5)

        self.interface_button = tk.Button(self.interface_frame, text="Monitor Interface", command=self.monitor_interface)
        self.interface_button.pack(pady=5)

        self.interface_text = tk.Text(self.interface_frame, height=10, width=40)
        self.interface_text.pack(fill='both', expand=True)

        self.ip_label = tk.Label(self.ip_frame, text="IP Address:")
        self.ip_label.pack(pady=5)

        self.ip_entry = tk.Entry(self.ip_frame)
        self.ip_entry.pack(pady=5)

        self.ip_button = tk.Button(self.ip_frame, text="Monitor IP", command=self.monitor_ip)
        self.ip_button.pack(pady=5)

        self.ip_text = tk.Text(self.ip_frame, height=10, width=40)
        self.ip_text.pack(fill='both', expand=True)

        self.excluded_pids = [os.getpid()]
        signal.signal(signal.SIGINT, self.signal_handler)

    def get_processes_for_interface(self, interface):
        processes = []
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.laddr and conn.laddr[1] == interface:
                process = psutil.Process(conn.pid)
                if process.pid not in self.excluded_pids:
                    processes.append(process)
        return processes

    def get_processes_for_ip(self, ip_address):
        processes = []
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if (conn.laddr and conn.laddr.ip == ip_address) or (conn.raddr and conn.raddr.ip == ip_address):
                process = psutil.Process(conn.pid)
                if process.pid not in self.excluded_pids:
                    processes.append(process)
        return processes

    def check_processes_for_interface(self, interface):
        processes = self.get_processes_for_interface(interface)
        if processes:
            self.interface_text.delete('1.0', tk.END)
            self.interface_text.insert(tk.END, "Processes accessing interface {}:\n".format(interface))
            for process in processes:
                self.interface_text.insert(tk.END, "PID: {}, Name: {}\n".format(process.pid, process.name()))
        else:
            self.interface_text.delete('1.0', tk.END)
            self.interface_text.insert(tk.END, "No processes accessing interface {} found.".format(interface))

    def check_processes_for_ip(self, ip_address):
        processes = self.get_processes_for_ip(ip_address)
        if processes:
            self.ip_text.delete('1.0', tk.END)
            self.ip_text.insert(tk.END, "Processes accessing IP {}:\n".format(ip_address))
            for process in processes:
                self.ip_text.insert(tk.END, "PID: {}, Name: {}\n".format(process.pid, process.name()))
        else:
            self.ip_text.delete('1.0', tk.END)
            self.ip_text.insert(tk.END, "No processes accessing IP {} found.".format(ip_address))

    def monitor_interface(self):
        interface = self.interface_entry.get()
        self.check_processes_for_interface(interface)

    def monitor_ip(self):
        ip_address = self.ip_entry.get()
        self.check_processes_for_ip(ip_address)

    def signal_handler(self, sig, frame):
        print("Terminating the script...")
        self.destroy()

if __name__ == "__main__":
    app = NetworkMonitorApp()
    app.mainloop()
