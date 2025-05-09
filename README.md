
## Table of Contents
- [i. General Setup](#i-general-setup)
- [ii. Organic Enterprise Protections](#ii-organic-enterprise-protections)
- **[1. ARP Cache Poisoning](#1-arp-cache-poisoning)**
  - [1.1 Attack ](#11-attack)
  - [1.2 Protections](#12-protections)
- **[2. Network Port Scan](#2-network-port-scan)**
  - [2.1 Attack ](#21-attack)
  - [2.2 Protections](#22-protections)

---
GitHub source: https://github.com/nottoBD/mininet-secops

## i. General Setup

```bash
cd $HOME/LINFO2347
git clone git@github.com:nottoBD/mininet-secops.git
chmod u+x mininet-secops/run_deploy 
./mininet-secops/run_deploy 
```
The **run_deploy** script clears and redeploy the complete Mininet environment. If required It will update attack scripts, protection scripts, the network topology file (topo.py).

The script provides the ability to enact protections  once in the Mininet environment. 
```bash
source /home/student-linfo2347/mininet/protections/organic/run_organic_protections.py
 ```

## ii. Organic Enterprise Protections
![Mininet Topology](mininet_topology.png)

**ii.1. DMZ Server Restrictions**
* **Implementation:** DMZ hosts (`dmz_organic_protection.nft`) have an `output` chain policy of `drop`, only allowing `established/related` traffic.
* **Effect:**
   * DMZ servers cannot initiate new connections (TCP/UDP/ICMP)
   * Only permit responses to connections initiated by others

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
*see walkthrough at: [attacks/arp_cache_poisoning/execution_example.md](attacks/arp_cache_poisoning/execution_example.md)*
### 1.1 Attack
#### Target Selection
- **Focus**: LAN hosts `ws3` (10.1.0.3) and gateway `r1` (10.1.0.1).  
- **Goal**: Intercept traffic between `ws3` and DMZ/internet via MITM.

#### MAC Discovery
- **Method**: Scapy ARP broadcasts to map IP-MAC pairs.  
- **Blocked By**:  
  - Workstation rate limits (8 ARP requests/minute).  
  - Static MAC bindings on `r1`.

#### ARP Spoofing
- **Execution**: Forged replies sent to `ws3` and `r1` (1/second).  
- **Blocked By**:  
  - `r1`’s trusted mappings (fixed IP-MAC pairs).  
  - DMZ rules enforcing static MAC bindings for routers, rate limiting replies.

#### Traffic Interception
- **Success Criteria**: Poisoned ARP caches enable MITM for:  
  - DMZ traffic (HTTP/DNS to 10.12.0.10/20).  
  - Internet traffic via `r2` (10.2.0.1).  
- **Blocked By**:  
  - Workstation gateway MAC validation (00:00:00:00:01:00).  
  - `r2`’s suspicious MAC bans (5 replies/minute).

#### Persistence
- **Method**: Continuous ARP reply flooding.  
- **Mitigation**: Rate limits:  
  - DMZ: 3 replies/minute.  
  - `r1`: 5 replies/minute.  
  - Workstations: 10 replies/minute.  

#### Constraints
- Attacker must reside in LAN (e.g., `ws2`).  
- DMZ servers (10.12.0.10-40) immune due to:  
  - Static router MAC validation (e.g., 10.12.0.1 → `00:00:00:00:01:12`).  
  - `r2`’s impersonation detection (blocks spoofed 10.12.0.2 MACs).
  

### 1.2 Protections
#### DMZ (`dmz_arp_protection.nft`)
- **Static MAC Bindings**:  
  - Enforce 10.12.0.1 → `00:00:00:00:01:12`, 10.12.0.2 → `00:00:00:00:02:12`.  
- **Unsolicited Reply Blocking**: Drop non-broadcast replies.  
- **Rate Limits**:  
  - 5 requests/minute per source.  
  - 3 replies/minute.  

#### Router R1 (`r1_arp_protection.nft`)
- **Trusted Mappings**:  
  - 10.1.0.1 → `00:00:00:00:01:00`, 10.12.0.1 → `00:00:00:00:01:12`.  
- **Rate Limits**: 5 requests/replies per minute.  

#### Router R2 (`r2_arp_protection.nft`)
- **Suspicious Host List**:  
  - 10-minute bans for MACs spoofing 10.12.0.2.  
- **Logging**: Records impersonation attempts.  

#### Workstations (`ws_arp_protection.nft`)
- **Gateway Validation**: Drops replies for 10.1.0.1 with non-`00:00:00:00:01:00` MAC.  
- **Rate Limits**: 10 intra-subnet replies/minute.  


### Residual Risks
- **Manual Maintenance**: Static mappings require updates if MACs change.  
- **Encrypted Traffic**: Protections don’t prevent decryption of intercepted TLS/SSH.  
- **Trusted LAN Attacks**: `ws2` can target `ws3` until rate limits trigger.  

### Efficacy Metrics
- **Blocking**: Poisoning attempts blocked within 1–5 packets.  
- **Detection**: Logs record events (e.g., `R1-ARP-SPOOF`, `R2-IMPERSONATION`).  

---

## 2. Network Port Scan
*see walkthrough at: [attacks/network_port_scan/execution_example.md](attacks/network_port_scan/execution_example.md)*
## 2.1 Attack

**Target Selection**
* **Focus**: DMZ servers at 10.12.0.10 (HTTP), 10.12.0.20 (DNS), 10.12.0.30 (NTP), and 10.12.0.40 (FTP).
* **Goal**: Discover active services and vulnerabilities in the DMZ network segment.

**Scanning Techniques**
* **TCP Connect Scan**: Multi-threaded (100 threads) scan establishes full connections to detect open ports.
* **Scope**: Default range of 1-1000 ports (expandable to all 65535 ports with `--full` flag).
* **Service Enumeration**: Retrieves service banners, HTTP headers, and DNS data.
* **UDP Targeting**: Tests specific UDP services (DNS on 53/5353, NTP on 123).

**Attack Execution**
* **MAC/IP Discovery**: No prerequisite ARP poisoning needed; direct scanning.
* **Rate Management**: No built-in scan rate limiting in attack script.
* **Service Fingerprinting**:
  * HTTP (80): Extracts headers from web server (10.12.0.10)
  * DNS (5353): Performs queries for "exemple.com" (10.12.0.20)
  * NTP (123): Extracts version and stratum info (10.12.0.30)
  * FTP (21): Captures service banner (10.12.0.40)

**Constraints**
* **Attacker Position**: Attack effectiveness depends on location:
  * From workstation LAN: Limited by router r1's forward policy.
  * From Internet: Restricted by r2's rate limiting and blacklisting.
  * From DMZ itself: Constrained by server output filtering.

## 2.2 Protections

**Router R1 (`r1_port_scan_protection.nft`)**
* **Default Policy**: DROP for all forwarded traffic.
* **Workstation Access**:
  * Allows 10.1.0.0/24 hosts to initiate connections to any destination.
* **Response Filtering**:
  * Only allows DMZ/Internet to respond to established workstation connections.
  * Blocks new inbound connections to workstations.
* **Weaknesses**:
  * No rate limiting for outbound connection attempts.
  * No explicit port scan detection mechanisms.

**Router R2 (`r2_port_scan_protection.nft`)**
* **Blacklist Mechanism**:
  * Dynamic IP blacklist with 30-minute timeout.
  * Logs and blocks all traffic from blacklisted sources.
* **Rate Limiting Triggers**:
  * TCP: >5 SYN packets/second (burst 10)
  * UDP: >5 packets/second (burst 5)
* **Connection Rules**:
  * Allows workstations to initiate connections to any destination.
  * Permits Internet hosts to connect to DMZ servers.
  * Restricts DMZ servers to only responding to established connections.
  * Routes DMZ-to-workstation traffic via R1.

**DMZ Servers (`dmz_port_scan_protection.nft`)**
* **Output Restrictions**:
  * Only permits established/related connections to specific networks.
  * Destinations limited to workstations, Internet, and router IPs.
* **Default Policies**:
  * ACCEPT for input (relies on router filtering)
  * DROP for forward and output.
* **Weaknesses**:
  * No input filtering to prevent scan detection.
  * No host-based rate limiting.

---