
import os
import socket
import hashlib
import subprocess
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1

def show_banner():
    print(r"""
████████╗███████╗ █████╗ ██████╗ 
██╔════╝██╔════╝██╔══██╗██╔══██╗
█████╗  █████╗  ███████║██████╔╝
██╔══╝  ██╔══╝  ██╔══██║██╔══██╗
██║     ███████╗██║  ██║██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
                                
    Ethical Hacking Toolkit - By Ordinaryfeb
    """)

def network_scanner(target_ip):
    print("\n[+] Scanning for active devices...")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("\nActive Devices:")
    print("-" * 37)
    print("IP Address".ljust(16) + "MAC Address")
    print("-" * 37)
    for device in devices:
        print(f"{device['ip']}".ljust(16) + f"{device['mac']}")

def port_scanner(target_ip, start_port, end_port):
    print(f"\n[+] Scanning ports {start_port}-{end_port} on {target_ip}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port} is open")
            open_ports.append(port)
        sock.close()
    return open_ports

def wifi_analyzer():
    print("\n[+] Scanning nearby Wi-Fi networks...")
    try:
        result = subprocess.run(["iwlist", "wlan0", "scan"], capture_output=True, text=True)
        print(result.stdout if result.stdout else "Run with sudo or check Wi-Fi interface!")
    except:
        print("Error: Install 'iwlist' or check permissions.")

def hash_cracker(hash_value, wordlist="/usr/share/wordlists/rockyou.txt"):
    print(f"\n[+] Cracking hash: {hash_value}...")
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            for word in f:
                word = word.strip()
                if hashlib.md5(word.encode()).hexdigest() == hash_value:
                    print(f"Found MD5 Password: {word}")
                    return
                if hashlib.sha1(word.encode()).hexdigest() == hash_value:
                    print(f"Found SHA-1 Password: {word}")
                    return
        print("Password not found in wordlist.")
    except FileNotFoundError:
        print("Wordlist not found. Default: /usr/share/wordlists/rockyou.txt")

def ping_sweep(target_ip):
    print(f"\n[+] Ping sweeping {target_ip}...")
    packet = IP(dst=target_ip)/ICMP()
    reply = sr1(packet, timeout=2, verbose=0)
    if reply:
        print(f"{target_ip} is online!")
    else:
        print(f"{target_ip} is offline or blocking ICMP.")

def main():
    show_banner()
    while True:
        print("\n[1] Network Scanner (ARP)")
        print("[2] Port Scanner (TCP)")
        print("[3] Wi-Fi Analyzer (iwlist)")
        print("[4] Hash Cracker (MD5/SHA-1)")
        print("[5] Ping Sweep (ICMP)")
        print("[6] Exit")
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            target = input("Enter IP range (e.g., 192.168.1.0/24): ")
            network_scanner(target)
        elif choice == "2":
            target = input("Enter target IP: ")
            start = int(input("Start port: "))
            end = int(input("End port: "))
            port_scanner(target, start, end)
        elif choice == "3":
            wifi_analyzer()
        elif choice == "4":
            hash_val = input("Enter hash: ")
            hash_cracker(hash_val)
        elif choice == "5":
            target = input("Enter target IP or range (e.g., 192.168.1.1): ")
            ping_sweep(target)
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid option!")

if __name__ == "__main__":
    main()