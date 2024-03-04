import os
import psutil
import signal
import sys

def get_processes_for_interface(interface, excluded_pids=[]):
    processes = []
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if conn.laddr and conn.laddr[1] == interface:
            process = psutil.Process(conn.pid)
            if process.pid not in excluded_pids:
                processes.append(process)
    return processes

def get_processes_for_ip(ip_address, excluded_pids=[]):
    processes = []
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if (conn.laddr and conn.laddr.ip == ip_address) or (conn.raddr and conn.raddr.ip == ip_address):
            process = psutil.Process(conn.pid)
            if process.pid not in excluded_pids:
                processes.append(process)
    return processes

def check_processes_for_interface(interface, excluded_pids=[]):
    processes = get_processes_for_interface(interface, excluded_pids)
    if processes:
        print("Processes accessing interface {}:".format(interface))
        for process in processes:
            print("PID: {}, Name: {}".format(process.pid, process.name()))
    else:
        print("\rNo processes accessing interface {} found.".format(interface), end="", flush=True)

def check_processes_for_ip(ip_address, excluded_pids=[]):
    processes = get_processes_for_ip(ip_address, excluded_pids)
    if processes:
        print("Processes accessing IP {}:".format(ip_address))
        for process in processes:
            print("PID: {}, Name: {}".format(process.pid, process.name()))
    else:
        print("\rNo processes accessing IP {} found.".format(ip_address), end="", flush=True)

def signal_handler(sig, frame):
    print("Terminating the script...")
    sys.exit(0)
 
def main():
    interface = "my_network_interface"  # Specify the Ethernet interface
    ip_address = "192.168.178.35"  # Specify the IP address to monitor
    excluded_pids = [os.getpid()]  # Exclude the PID of the current Python script
    
    signal.signal(signal.SIGINT, signal_handler)
    
    while True:
        check_processes_for_interface(interface, excluded_pids)
        check_processes_for_ip(ip_address, excluded_pids)

if __name__ == "__main__":
    main()
