
## Table of Contents
- [i. General Setup](#i-general-setup)
- [ii. Organic Enterprise Protections](#ii-organic-enterprise-protections)
- **[1. ARP Cache Poisoning](#1-arp-cache-poisoning)**
  - [1.1 Attack ](#11-attack)
  - [1.2 Protections](#12-protections)


---

## i. General Setup

```bash
cd $HOME/LINFO2347
git clone git@github.com:nottoBD/mininet-secops.git
chmod mininet-secops/u+x run_deploy 
./mininet-secops/run_deploy 
```
The **run_deploy** script clears and redeploy the complete Mininet environment. If required It will update attack scripts, protection scripts, the network topology file (topo.py).

The script provides the ability to enact protections  once in the Mininet environment. 
```bash
source /home/student-linfo2347/mininet/protections/organic/run_organic_protections.py
 ```

## ii. Organic Enterprise Protections
**ii.1. DMZ Server Restrictions**
* **Implementation:** DMZ hosts (`dmz_organic_protection.nft`) have an `output` chain policy of `drop`, only allowing `established/related` traffic.
* **Effect:**
   * DMZ servers cannot initiate new connections (TCP/UDP/ICMP)
   * Only permit responses to connections initiated by others
   * Example: HTTP server can respond to workstation requests, but cannot make outbound requests

**ii.2. Workstation Permissions**
* **Router R1 Rules (`r1_organic_protection.nft`):**
```nftables
iifname "r1-eth0" ip saddr 10.1.0.0/24 ct state new accept  # Allow new outbound
iifname "r1-eth12" ip daddr 10.1.0.0/24 ct state established,related accept  # Allow returns
```
* **Router R2 Rules (`r2_organic_protection.nft`):**
```nftables
iifname "r2-eth12" ip saddr 10.1.0.0/24 ct state new accept  # Workstation→Internet
iifname "r2-eth12" ip saddr 10.12.0.0/24 ip daddr 10.1.0.0/24 ct state established,related accept  # DMZ→WS returns
```
* **Effect:**
   * Workstations can initiate connections to any network
   * Return traffic permitted through both routers

**ii.3. Internet Restrictions**
* **Router R2 Rules (`r1_organic_protection.nft`):**
```nftables
iifname "r2-eth0" ip saddr 10.2.0.0/24 ip daddr 10.12.0.0/24 ct state new accept  # New→DMZ only
iifname "r2-eth0" ip saddr 10.2.0.0/24 ip daddr 10.1.0.0/24 ct state established,related accept  # Returns→WS
```
* **Effect:**
   * Internet hosts can only establish new connections to DMZ (10.12.0.0/24)
   * Workstation-initiated Internet connections are permitted via r2-eth12 rule
   * Bidirectional established traffic allowed

---

## 1. ARP Cache Poisoning

### 1.1 Attack
1. **Target Selection**:  
   - Focuses on the trusted LAN (10.1.0.0/24), specifically workstation `ws3` (10.1.0.3) and gateway `r1` (10.1.0.1).  
   - Rationale: Compromising this pair intercepts **all traffic** from `ws3` to the DMZ (HTTP/DNS servers) and the internet via `r2`.

2. **MAC Discovery**:  
   - Uses `scapy` to broadcast ARP requests (e.g., `resolve_mac("10.1.0.1")`) to map IPs to MACs.  
   - Limitations:  
     - Fails if defenses block ARP requests (e.g., workstation rate limits of **8 requests/minute**).  
     - Invalidates if static MAC bindings (e.g., R1's `trusted_mappings`) are enforced.

3. **ARP Spoofing**:  
   - Sends forged ARP replies to both `ws3` and `r1` at 1-second intervals:  
     - Tells `ws3`: "10.1.0.1 (r1)" → Attacker's MAC.  
     - Tells `r1`: "10.1.0.3 (ws3)" → Attacker's MAC.  
   - Tools: `poison_arp_cache()` in Python/scapy.  
   - Limitations:  
     - **DMZ rules** drop unsolicited replies (non-broadcast `daddr` ≠ `ff:ff:ff:ff:ff:ff`).  
     - **R1's `trusted_mappings`** discard replies with mismatched IP-MAC pairs (e.g., spoofed `r1-eth0` MAC ≠ `00:00:00:00:01:00`).  

4. **Traffic Interception**:  
   - After successful poisoning, attacker becomes MITM for:  
     - **DMZ-bound traffic** (e.g., HTTP requests to 10.12.0.10).  
     - **Internet-bound traffic** via `r2` (10.2.0.1).  
   - Limitations:  
     - **Workstation rules** block replies from MACs marked as suspicious (e.g., `WSX-ROUTER-IMPERSONATION` logs/drops mismatched gateway MACs).  
     - **R2's suspicious_hosts** set blocks MACs exceeding reply rate limits (5/minute).  

5. **Persistence**:  
   - Continuous ARP reply flooding to maintain poisoned caches.  
   - Defeated by:  
     - **Rate limits**: DMZ (3 replies/minute), R1 (5 replies/minute), workstations (10 replies/minute).  
     - **Logging**: All rules log flood attempts (e.g., `DMZ-ARP-REPLY-FLOOD`), alerting admins.  

**Topology-Specific Constraints**:  
- Attacker **must reside in the trusted LAN** (e.g., `ws2`) to send Layer 2 ARP packets.  
- Cannot poison DMZ servers (10.12.0.10/20/30/40) due to:  
  - **DMZ router MAC validation** (e.g., 10.12.0.1 → 00:00:00:00:01:12).  
  - **R2's router impersonation detection** (blocks spoofed 10.12.0.2 MACs).
  - 

### 1.2 Protections
1. **DMZ Protections (`dmz_arp_protection.nft`):**  
   - **Static MAC Bindings**:  
     - Enforces fixed IP-MAC pairs for routers (e.g., 10.12.0.1 → 00:00:00:00:01:12).  
     - Neutralizes spoofed ARP replies claiming to be `r1`/`r2`.  
   - **Unsolicited Reply Blocking**:  
     - Drops replies not sent to broadcast MAC (`ff:ff:ff:ff:ff:ff`).  
   - **Rate Limiting**:  
     - Requests: 5/minute per source, preventing ARP floods.  
     - Replies: 3/minute, limiting poisoning speed.  

2. **Router R1 Protections (`r1_arp_protection.nft`):**  
   - **Trusted Mappings Table**:  
     - Hardcodes valid IP-MAC pairs (e.g., 10.1.0.1 → 00:00:00:00:01:00).  
     - Immediate drop of mismatched replies (e.g., spoofed gateway MAC).  
   - **Rate Limits**:  
     - 5 requests/minute and 5 replies/minute per MAC, hindering sustained attacks.  

3. **Router R2 Protections (`r2_arp_protection.nft`):**  
   - **Suspicious Host List**:  
     - Time-based bans (10m) for MACs sending invalid replies (e.g., impersonating 10.12.0.2).  
   - **Router Impersonation Detection**:  
     - Logs/drops replies claiming to be R2’s IP (10.12.0.2) with wrong MACs.  

4. **Workstation Protections (`wsx_arp_protection.nft`):**  
   - **Gateway MAC Validation**:  
     - Drops replies claiming `10.1.0.1` with non-00:00:00:00:01:00 MACs.  
   - **Intra-Subnet Rate Limits**:  
     - Allows 10 ARP replies/minute from 10.1.0.0/24, limiting MITM viability.  

**Residual Risks**:  
- **Static Mapping Maintenance**: Manual updates required if MACs change (e.g., hardware replacement).  
- **Encrypted Traffic**: Protections don’t mitigate decryption of intercepted TLS/SSH traffic.  
- **Trusted LAN Compromise**: Attackers on `ws2` can still target `ws3` until rate limits trigger drops.  

**Efficacy Metrics**:  
- **Poisoning Attempts**: Blocked within 1–5 packets (static mappings + rate limits).  
- **Detection**: Logs provide forensic trails (e.g., `R1-ARP-SPOOF` entries).  


---
