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
#On DMZ (http, dns, ntp, ftp):
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        ip protocol udp ip daddr {10.12.0.20, 10.12.0.30} ip saddr != {10.2.0.0/24} drop
    }
}
```