### 1.0. Initial Assessment
```bash
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

# Enable IP forwarding on the attacker
ws2 sysctl -w net.ipv4.ip_forward=1

# Run the attack with explicit parameters
ws2 python3 mininet/attacks/arp_cache_poisoning/main.py --target 10.1.0.3 --gateway 10.1.0.1 --interval 0.5 &

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
ws3 sudo nft -f mininet/protections/arp_cache_poisoning/ws_arp_protection.nft
ws2 sudo nft -f mininet/protections/arp_cache_poisoning/ws_arp_protection.nft

# Verify firewall rules are loaded
ws3 sudo nft list ruleset
```

### 1.3. Test Attack With Protection
```bash
# Try attack again - should be limited by rate limiter
ws2 python3 mininet/attacks/arp_cache_poisoning/main.py --target 10.1.0.3 --gateway 10.1.0.1 &

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
source mininet/protections/arp_cache_poisoning/run_arp_protections.py

# Verify network connectivity with protection
pingall
```

### 1.5. Test Attack After Timeout Period
```bash 
# Wait for rate limit timer to expire
sleep 60

# Try new attack
ws2 python3 mininet/attacks/arp_cache_poisoning/main.py --target 10.1.0.3 --gateway 10.1.0.1 &

# Verify single ARP request allowed but no poisoning
ws3 arp -n

# Kill the attack again
ws2 pkill -f "python3 main.py"
```

### 1.6. Traffic Inspection and pingall Results
```bash
# Outside mininet, examine the tcpdump capture
tcpdump -n -r /tmp/attack_capture.pcap
```

Our defense against ARP cache poisoning incorporates a deliberately low rate limit (5/minute) on R2, creating an asymmetric connectivity model. When ws2 was used as the attack host, it led to additional scrutiny, while ws3 exhausted the available ARP quota first.

The pingall results prove our defense against ARP spoofing attacks with respect to connectivity, showing the necessity of finely tuned and granular defense in production environments.

| From\To | Default State | With Organic Protection | With Organic + ARP Protection |
|---------|---------------|-------------------------|-------------------------------|
| **dns**   | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **ftp**   | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **http**  | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **ntp**   | ✓✓✓✓✓✓✓✓ | ❌❌❌❌❌❌❌❌ | ❌❌❌❌❌❌❌❌ |
| **ws2**   | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓✓✓ | ❌❌❌❌✓✓✓✓ |
| **ws3**   | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓✓✓ |
| **r1**    | ✓✓✓✓✓✓✓✓ | ✓✓✓❌✓✓✓✓ | ✓✓✓❌✓✓✓✓ |
| **r2**    | ✓✓✓✓✓✓✓✓ | ✓✓✓✓✓✓❌❌ | ✓✓✓✓✓✓❌❌ |
| **internet**| ✓✓✓✓✓✓✓✓ | ✓✓✓✓❌✓❌❌ | ✓✓✓✓❌✓❌❌ |
| **% Drop**| 0% (0/72) | 52% (38/72) | 58% (42/72) |

