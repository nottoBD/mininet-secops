### Initial Assessment
```bash
#Verify that the DNS and NTP services on DMZ servers are running:
http netstat -tulpn | grep -E ':21|:22|:53|:80|:123|:5353'
dns netstat -tulpn | grep -E ':21|:22|:53|:80|:123|:5353'
ntp netstat -tulpn | grep -E ':21|:22|:53|:80|:123|:5353'
ftp netstat -tulpn | grep -E ':21|:22|:53|:80|:123|:5353'

#Test the accessibility of all exposed DMZ services:
# Test HTTP server
internet curl -v http://10.12.0.10

# Test FTP server
internet curl ftp://10.12.0.40/README

# Test NTP server
internet ntpdate -q 10.12.0.30

# Test DNS server (on non-standard port 5353)
internet dig @10.12.0.20 -p 5353 example.com

#Start a packet capture on the DMZ switch interface:
s2 sudo tcpdump -i s2-eth1 -n port 123 or port 5353 -w /tmp/reflected_ddos_capture.pcap &
```

We used the Scapy library  to construct DNS and NTP packets, with the victim’s IP address set as the spoofed source IP. This enables us to perform a reflected DDoS attack , where responses from DNS and NTP servers are redirected to the target. 

To efficiently execute the attack at scale, we employ Python’s concurrent.futures.ThreadPoolExecutor, managing a pool of up to 1000 worker threads . This allows for high concurrency, enabling thousands of spoofed requests to be sent simultaneously. 

Each thread is assigned either the dns_ddos or ntp_ddos function, depending on the protocol being used. These functions send malicious requests to open DNS or NTP servers, triggering amplified responses directed at the target. 

The script submits each function call to the thread pool using executor.submit(). If any thread returns a valid result (i.e., not None), the program terminates the executor early, logs the elapsed time, and exits gracefully.
 
# Launch the attack and the protection
```bash
#Launch the attack from the internet host
xterm internet
cd mininet/attacks/reflected_ddos/
python3 main.py

# launch the protection :
source mininet/protections/organic/run_organic_protections.py
source mininet/protections/reflected_ddos/run_reflected_ddos_protections.py
```


### Protection Analysis
```bash
#On r2 (Internet-facing router):
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ip protocol udp ip daddr {10.12.0.20, 10.12.0.30} iif "r2-eth0" jump protect_services
    }

    chain protect_services {
        udp dport 5353 limit rate 3/second burst 5 packets accept
        udp dport 123 limit rate 3/second burst 5 packets accept
    }
}
#Purpose : Rate limits incoming UDP traffic to DNS and NTP services.
#Effectiveness :
#Limits reflection-based traffic from external sources.
#Prevents bandwidth saturation and service overload

#On DMZ (http, dns, ntp, ftp):
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        ip protocol udp ip daddr {10.12.0.20, 10.12.0.30} ip saddr != {10.2.0.0/24} drop
    }
}

#Purpose : Drops UDP packets from non-trusted networks.
#Effectiveness :
#Prevents unsolicited DNS/NTP replies from reaching the servers.
#Reduces risk of being used as amplification targets.
         
```

### Validation of Protection
Measure Response Time Before and After Attack 
```bash
ws2 time curl -o /dev/null -s -w "%{time_total}\n" http://10.12.0.10
```
Result : 
```bash
Before Attack : 0m0.017s
After Attack : 0m0.574s
After Protection : 0m0.020s
```