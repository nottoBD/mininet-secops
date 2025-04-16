#!/usr/bin/env python3
"""
DMZ Network Port Scanner
------------------------

This module implements a comprehensive port scanning tool designed for the DMZ segment
of a segmented network topology with trusted LAN and DMZ zones. The scanner performs
both TCP and UDP scanning to discover active services in the DMZ network.

The script is designed to work with the provided network topology which consists of:
- Trusted LAN (10.1.0.0/24): Contains workstations (ws2, ws3)
- DMZ (10.12.0.0/24): Contains service servers (http, dns, ntp, ftp)
- Two routers (r1, r2) connecting these networks
- Internet connectivity through r2

By default, this targets the DMZ servers at 10.12.0.10 (HTTP), 10.12.0.20 (DNS),
10.12.0.30 (NTP), and 10.12.0.40 (FTP), scanning commonly used TCP and UDP ports.

Usage:
    python3 main.py [--full]

    --full: Scan all 65535 TCP ports instead of just the first 1000
"""

from queue import Queue
from scapy.all import *
import argparse

target_hosts = ["10.12.0.10", "10.12.0.20", "10.12.0.30", "10.12.0.40"]
tcp_port_range = (1, 1000)
udp_ports = [123, 5353]
num_threads = 100


def get_banner(sock):
    """
    Attempt to retrieve a service banner from an open socket connection.

    Many services send an initial banner when a connection is established, which
    can provide valuable information about the service type and version. This is
    particularly useful for identifying specific services in the DMZ such as
    FTP (21), SSH (22), and HTTP (80).

    Args:
        sock (socket): An already connected socket object

    Returns:
        str: The banner string if available, or an empty string if no banner
             is received or an error occurs
    """
    try:
        sock.settimeout(2)
        return sock.recv(1024).decode().strip()
    except:
        return ""


def tcp_scan(host, port_queue):
    """
    Perform TCP port scanning using a thread-based approach.

    This function processes a queue of ports to scan for a given host, checking
    if each port is open and attempting to identify the running service. For the
    DMZ hosts in our topology, this typically identifies services like:
    - HTTP (80) on the web server (10.12.0.10)
    - DNS (5353) on the DNS server (10.12.0.20)
    - FTP (21) on the FTP server (10.12.0.40)

    Args:
        host (str): The target host IP address to scan
        port_queue (Queue): A queue of port numbers to scan
    """
    while not port_queue.empty():
        port = port_queue.get()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((host, port)) == 0:
                    banner = get_banner(s)
                    service = identify_service(port, banner)
                    print(f"[+] {host}:{port}/tcp open - {service}")
                    enumerate_service(host, port, banner)
        except Exception as e:
            pass
        finally:
            port_queue.task_done()


def identify_service(port, banner):
    """
    Identify a service based on its port number and banner information.

    This function uses common port mappings relevant to our network topology
    to identify services running in the DMZ. It maps standard ports to their
    expected services, with a fallback to using banner information if available.

    In our topology, this helps identify critical DMZ services:
    - Web server (HTTP on port 80)
    - DNS server (mDNS on port 5353)
    - NTP server (NTP on port 123)
    - FTP server (FTP on port 21)

    Args:
        port (int): The port number to identify
        banner (str): The service banner, if available

    Returns:
        str: The identified service name or "Unknown" if not identifiable
    """
    services = {
        21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP",
        53: "DNS", 123: "NTP", 443: "HTTPS", 5353: "mDNS"
    }
    return services.get(port, banner or "Unknown")


def enumerate_service(host, port, banner):
    """
    Perform additional enumeration for specific identified services.

    For certain services in our DMZ, this function attempts to gather more
    detailed information by sending service-specific queries:
    - For HTTP (port 80): Retrieves HTTP headers from the web server
    - For FTP (port 21): Displays the FTP server banner
    - For DNS (port 5353): Performs a DNS query for exemple.com

    This provides deeper insight into the specific configurations and versions
    of services running in the DMZ segment.

    Args:
        host (str): The target host IP address
        port (int): The open port number
        banner (str): The service banner, if available
    """
    try:
        if port == 80:
            with socket.socket() as s:
                s.connect((host, port))
                s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
                print(f"   HTTP Header: {s.recv(1024).decode().splitlines()[0]}")
        elif port == 21:
            print(f"   FTP Banner: {banner}")
        elif port == 5353 or port == 53:
            dns_query(host, port)
    except:
        pass


def dns_query(host, port):
    """
    Perform a DNS query to enumerate a DNS server.

    This function sends a DNS query for example.com to a DNS server in the DMZ
    and displays the response. In our topology, this is particularly relevant
    for the DNS server at 10.12.0.20, which serves both standard multicast DNS (port 5353).

    Args:
        host (str): The target DNS server IP address
        port (int): The DNS server port (typically 53 or 5353)
    """
    pkt = IP(dst=host) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname="exemple.com"))
    ans = sr1(pkt, timeout=2, verbose=0)
    if ans and DNSRR in ans:
        for rr in ans.an:
            if rr.type == 1:
                print(f"   DNS Response: example.com -> {rr.rdata}")


def udp_scan(host):
    """
    Perform UDP port scanning for specific services.

    This function targets specific UDP services known to exist in our DMZ:
    - NTP on port 123 (the NTP server at 10.12.0.30)
    - DNS on port 5353 (the DNS server at 10.12.0.20)

    Unlike the TCP scanner, this function uses service-specific packets to 
    elicit responses from UDP services, which is more reliable than blind UDP
    scanning as it generates recognizable responses.

    Args:
        host (str): The target host IP address to scan
    """
    ntp_pkt = IP(dst=host) / UDP(dport=123) / NTP(version=4)
    ans = sr1(ntp_pkt, timeout=2, verbose=0)
    if ans and NTP in ans:
        print(f"[+] {host}:123/udp open - NTP (v{ans[NTP].version}, stratum {ans[NTP].stratum})")

    for port in [53, 5353]:
        dns_pkt = IP(dst=host) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname="exemple.com"))
        ans = sr1(dns_pkt, timeout=2, verbose=0)
        if ans and DNS in ans:
            print(f"[+] {host}:{port}/udp open - DNS")


def main():
    """
    Main execution function for the DMZ port scanner.

    This function orchestrates the scanning workflow:
    1. Parse command-line arguments (allowing for full port scan mode)
    2. For each target host in the DMZ, perform:
       - TCP port scanning with multiple threads for efficiency
       - UDP scanning for specific services (NTP, DNS)
    3. Report timing information for each scan phase

    The scanner focuses on the DMZ services in our network topology, testing
    for expected services on each host. The results can be used to verify
    proper service operation and identify unexpected open ports that might
    indicate security issues.
    """
    parser = argparse.ArgumentParser(description="DMZ Port Scanner")
    parser.add_argument("--full", action="store_true", help="Scan all 65535 TCP ports")
    args = parser.parse_args()

    """
    Configure scanning range based on command-line arguments

    By default, only the first 1000 TCP ports are scanned for efficiency.
    With the --full flag, all 65535 TCP ports are scanned, which provides
    more thorough coverage but takes significantly longer to complete.
    """
    if args.full:
        global tcp_port_range
        tcp_port_range = (1, 65535)

    for host in target_hosts:
        print(f"\nScanning {host}")

        """
        Perform TCP port scanning with multiple threads

        The multi-threaded approach significantly increases scanning speed.
        Each thread takes a port number from the shared queue and tests
        if that port is open on the target host.
        """
        start_time = time.time()
        queue = Queue()
        for port in range(tcp_port_range[0], tcp_port_range[1] + 1):
            queue.put(port)

        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=tcp_scan, args=(host, queue))
            t.start()
            threads.append(t)

        queue.join()
        print(f"TCP scan completed in {time.time() - start_time:.2f}s")

        """
        Perform UDP port scanning for specific services

        UDP scanning is more targeted than TCP scanning, focusing only on
        ports known to run important services in our DMZ, such as DNS (5353)
        and NTP (123).
        """
        start_time = time.time()
        udp_scan(host)
        print(f"UDP scan completed in {time.time() - start_time:.2f}s")


if __name__ == "__main__":
    main()
