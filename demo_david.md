# ARP Cache Poisoning Demonstration Guide

## No Protection Scenario  
**Objective:** Demonstrate successful ARP cache poisoning attack  

1. **Initial Verification (Victim: `ws3`)**
```bash  
ws3 ping -c 3 10.1.0.1 
ws3 arp -n               
```
2. **Attacker Setup (ws2)**  
```bash 
ws2 sysctl -w net.ipv4.ip_forward=1
```
3. **Launch Attack (ws2)**  
```bash
ws2 python3 mininet/attacks/arp_cache_poisoning/main.py --target 10.1.0.3 --gateway 10.1.0.1   
```
4. **Verify Poisoning (Victim: ws3)**

- Attacker's MAC should appear for both gateway and workstation in victim ARP table
```bash
ws3 arp -n  
```
5. **Test MITM (Victim: ws3)**  
```bash 
ws3 ping -c 10 10.12.0.10 
```

## Protection Scenario  
**Objective:** Demonstrate effective ARP spoofing protection  

1. **Apply Protection Rules (All Workstations and their gateway)**  
```bash 
r1 sudo nft -f mininet/protections/arp_cache_poisoning/r1_arp_protection.nft
r2 sudo nft -f mininet/protections/arp_cache_poisoning/r2_arp_protection.nft
ws3 sudo nft -f mininet/protections/arp_cache_poisoning/ws_arp_protection.nft
ws2 sudo nft -f mininet/protections/arp_cache_poisoning/ws_arp_protection.nft
```
2. **Verify Rules**  
```bash  
ws3 sudo nft list ruleset
```

3. **Launch Attack (ws2)**  
```bash  
ws2 python3 mininet/attacks/arp_cache_poisoning/main.py --target 10.1.0.3 --gateway 10.1.0.1
```
4. **Test Protection (Victim: ws3)**  
- Shows 100% packet loss
```bash  
ws3 ping -c 3 10.12.0.10
```

### Il drop les packets qui se font passer pour la gateway avec une addresse MAC différente que celle hardcodée 
### Il y a aussi l'ARP request rate limiting
### Et enfin le Reply Rate Limiting

---
*RESTART*


*SHOW SLIDES*

---

# Port Scan Demonstration Guide

## No Protection Scenario  


### 2.0 Initial Assessment
```bash
# Test FTP server
internet curl ftp://10.12.0.40/README
# Test NTP server
internet ntpdate -q 10.12.0.30
# Test mDNS server
internet dig @10.12.0.20 -p 5353 example.com
```

### 2.1 Initial Scan (Before Protection)
```bash
# Run port scan attack
internet python3 mininet/attacks/network_port_scan/main.py
```

### 2.2 Apply Basic Protections
```bash
# Deploy protections on gateway router
r2 sudo nft -f mininet/protections/network_port_scan/r2_port_scan_protection.nft
```

### 2.3 Attack (After Protection)
```bash
# Run port scan attack
internet python3 mininet/attacks/network_port_scan/main.py
```

### 2.3. Traffic Inspection
```bash
# Examine blacklisted IPs
r2 nft list set inet filter blacklist
```