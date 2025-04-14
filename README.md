# ARP Cache Poisoning Attack and Protection Test Procedure

This document provides step-by-step instructions for testing both the ARP cache poisoning attack and its protection mechanism in the mininet environment.

---


## Table of Contents
- [Prerequisites](#prerequisites)
- [0. General Setup](#0-general-setup)
- **[1. ARP Cache Poisoning](#1-arp-cache-poisoning)**
  - [1.1 Test Attack (Before Protection)](#11-test-attack-before-protection)
  - [1.2 Reset and Apply Protection](#12-reset-and-apply-protection)
  - [1.3 Test Attack With Protection](#13-test-attack-with-protection)
  - [1.4 Deploy Complete Protection](#14-deploy-complete-protection)
  - [1.5 Test Attack After Timeout Period](#15-test-attack-after-timeout-period)
  - [1.6 Traffic Inspection](#16-traffic-inspection)

---

## 0. General Setup

```bash
# Make the script executable
chmod u+x run_deploy 

# Update or Build the network
./run_deploy 
```
The **run_deploy** script clears and redeploy the complete Mininet environment. If required It will update attack scripts, protection scripts, the network topology file (topo.py), and Python dependencies from requirements.txt.

The script provides the ability to enact protections  once in the Mininet environment. 
```bash
source /home/student-linfo2347/mininet/protections/organic/run_organic_protections.py
 ```
The three organic rulefiles enforce the lab’s basic protection policies through stateful filtering:

    DMZ servers can't initiate a connection, only respond to an established connection.

    Workstations can open any connection anywhere and return traffic is permitted.

    Internet can initiate new connections only to the DMZ, while workstations can access the Internet, and bidirectional established traffic is permitted.

    The rules do not block ICMP (ping is allowed implicitly by connection tracking), address application-layer attacks, or prevent IP spoofing beyond the specified policies, focusing solely on network-layer controls as required.

## 1. ARP Cache Poisoning
The implemented ARP cache poisoning defenses include rate limiting (8 requests and 5 replies per minute) on all the network segments (workstations, routers, and DMZ servers), detection of router impersonation attempts, and temporary blocking of suspicious MAC addresses exhibiting abnormal ARP behavior. Despite these safeguards, there are significant limitations: inability to take advantage of static ARP entries due to MAC randomization in mininet, vulnerability to patient attackers who can wait between attempts, lack of authentication against a trusted MAC-IP database, and lack of correlation between observed ARP traffic and actual network topology. The solution does not negate a number of key attack channels like low-volume stealth poisoning, distributed poisoning from multiple sources, passive probing after successful poisoning, and is devoid of any mechanism to verify whether a successful MITM attack is already in progress or recover automatically compromised ARP tables.
```bash
Copy

# Check initial ARP table state (should be empty)
ws3 arp -n

# Ping gateway to establish legitimate ARP entry
ws3 ping -c 3 10.1.0.1

# Verify ARP table now has the gateway entry
ws3 arp -n
```
### 1.1. Test Attack (Before Protection)
```bash
# Start a background tcpdump on ws2 to capture traffic
ws2 sudo tcpdump -i ws2-eth0 -n -w /tmp/attack_capture.pcap &

# Run the attack with explicit parameters
ws2 cd /home/student-linfo2347/mininet/attacks/arp_cache_poisoning/ && python3 main.py --target 10.1.0.3 --gateway 10.1.0.1 --interval 0.5 &

# Enable IP forwarding on the attacker
ws2 sysctl -w net.ipv4.ip_forward=1

# Verify ARP poisoning was successful (should show ws2's MAC)
ws3 arp -n

# Test traffic redirection through attacker (should show ICMP Redirect messages)
ws3 ping -c 3 10.12.0.10

# Stop background processes
ws2 pkill -f "python3 main.py"
ws2 pkill -f "tcpdump"
```

### 1.2. Reset and Apply Protection
```bash
# Clean up ARP tables
ws3 arp -d 10.1.0.1
ws3 arp -d 10.1.0.2

# Ping to re-establish legitimate ARP entry
ws3 ping -c 1 10.1.0.1
ws3 arp -n

# Apply protection to workstations
ws3 sudo nft -f /home/student-linfo2347/mininet/protections/arp_cache_poisoning/firewall_wsx.nft
ws2 sudo nft -f /home/student-linfo2347/mininet/protections/arp_cache_poisoning/firewall_wsx.nft

# Verify firewall rules are loaded
ws3 sudo nft list ruleset
```

### 1.3. Test Attack With Protection
```bash
# Try attack again - should be limited by rate limiter
ws2 cd /home/student-linfo2347/mininet/attacks/arp_cache_poisoning/ && python3 main.py --target 10.1.0.3 --gateway 10.1.0.1 &

# Verify ARP table remains unchanged (legitimate gateway MAC)
ws3 arp -n

# Verify ping still works directly (should not see ICMP Redirects)
ws3 ping -c 3 10.12.0.10

# Check counter values in firewall
ws3 sudo nft list ruleset | grep -A 2 "counter"

# Stop attack
ws2 pkill -f "python3 main.py"
```

### 1.4. Deploy Complete Protection
```bash
# Deploy full protection to all hosts
source /home/student-linfo2347/mininet/protections/arp_cache_poisoning/run_arp_protections.py

# Verify network connectivity with protection
pingall
```

### 1.5. Test Attack After Timeout Period
```bash 
# Wait for rate limit timer to expire
sleep 60

# Try new attack
ws2 cd /home/student-linfo2347/mininet/attacks/arp_cache_poisoning/ && python3 main.py --target 10.1.0.3 --gateway 10.1.0.1 &

# Verify single ARP request allowed but no poisoning
ws3 arp -n

# Kill the attack again
ws2 pkill -f "python3 main.py"
```

### 1.6. Traffic Inspection and pingall Results
```bash
# Outside mininet, examine the tcpdump capture
tcpdump -n -r /tmp/attack_capture.pcap | head -20
```
| From\To | Default State | With Organic Protection | With Organic + ARP Protection |
|---------|---------------|-------------------------|-------------------------------|
| **dns**   | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **ftp**   | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **http**  | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **internet**| ✓✓✓✓✓✓✓✓ | ✓✓✓✓❌✓❌❌ | ✓✓✓✓❌✓❌❌ |
| **ntp**   | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **r1**    | ✓✓✓✓✓✓✓✓ | ✓✓✓❌✓✓✓✓ | ✓✓✓❌✓✓✓✓ |
| **r2**    | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓❌❌ | ✓✓✓✓✓✓❌❌ |
| **ws2**   | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓✓✓ | ❌❌❌❌✓✓✓✓ |
| **ws3**   | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓✓✓ |
| **% Drop**| 0% (0/72) | 52% (38/72) | 58% (42/72) |



