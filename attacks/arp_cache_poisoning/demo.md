# ARP Cache Poisoning Demonstration Guide

## No Protection Scenario  
**Objective:** Demonstrate successful ARP cache poisoning attack  

1. **Initial Verification (Victim: `ws3`)**  

- Verify gateway connectivity 

- Show original ARP table
```bash  
ws3 ping -c 3 10.1.0.1 
ws3 arp -n               
```
2. **Attacker Setup (ws2)**  

- Enable MITM forwarding  
```bash 
ws2 sysctl -w net.ipv4.ip_forward=1
```
3. **Launch Attack (ws2)**  
```bash
ws2 python3 mininet/attacks/arp_cache_poisoning/main.py --target 10.1.0.3 --gateway 10.1.0.1   
```
4. **Verify Poisoning (Victim: ws3)**


- Attacker's MAC should appear for both gateway and workstation   
```bash
ws3 arp -n  
```
5. **Test MITM (Victim: ws3)**  
```bash 
ws3 ping -c 3 10.12.0.10 
```
*RESTART*

*RESTART*

*RESTART*

## Protection Scenario  
**Objective:** Demonstrate effective ARP spoofing protection  

1. **Apply Protection Rules (All Workstations)**  
```bash  
ws3 sudo nft -f mininet/protections/arp_cache_poisoning/ws_arp_protection.nft  
ws2 sudo nft -f mininet/protections/arp_cache_poisoning/ws_arp_protection.nft  
```
2. **Verify Rules**  
```bash  
ws3 sudo nft list ruleset
```
3**Attacker Setup (ws2)**  

- Enable MITM forwarding  
```bash 
ws2 sysctl -w net.ipv4.ip_forward=1
```
4. **Launch Attack (ws2)**  
```bash  
ws2 python3 mininet/attacks/arp_cache_poisoning/main.py --target 10.1.0.3 --gateway 10.1.0.1
```
5. **Test Protection (Victim: ws3)**  
- Shows 100% packet loss
```bash  
ws3 ping -c 3 10.12.0.10
```

# Il drop les packets qui se font passer pour la gateway avec une addresse MAC différente que celle hardcodée 
# Il y a aussi l'ARP request rate limiting
# Et enfin le Reply Rate Limiting