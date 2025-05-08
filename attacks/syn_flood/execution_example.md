# Check if the necessary services are running on the target server
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
# Launch the attack
```bash
#Open a new terminal window for the attacker.
xterm internet
#Navigate to attack directory
cd mininet/attacks/syn_flood/
#Run the attack script
python3 main.py

```
# Validation of the attack
```bash
#In a separate host (ws2 for example), we measured the time for getting a response from the http server withe the command:
ws2 time curl -o /dev/null -s http://10.12.0.10

#then we look to have this result
Before SYN Flooding 
real    0m0.023s
user    0m0.000s
sys     0m0.010s

After SYN Flooding 
real    0m0.305s
user    0m0.000s
sys     0m0.008s

```
# Apply Protection Against SYN Flood
```bash
#Run protection script
source mininet/protections/syn_flood/run_syn_flood_protections.py
```
# Protection Analysis
```bash
#nftables Protection Rules
table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;
        tcp flags syn tcp flags == syn counter jump syn_flood_protection
    }

    chain syn_flood_protection {
        ct state new limit rate 3/second burst 5 packets counter accept
        counter drop
    }
}

#    Limits new TCP connections to 3 per second , with bursts up to 5 packets
#    Drops excessive connection attempts
#    Protects against resource exhaustion due to half-open connections

 #To confirm that the network connectivity was functioning as expected, the pingall command was executed. The output matched the basic enterprise network protection, indicating that the network connectivity was not affected by the protection.    

```

# Validation of the protection
```bash
#To validate our protection, we measured the time for getting a response from the http server and we compared it with the time before the attack. We can see that it is pretty much the same.
ws2 time curl -o /dev/null -s http://10.12.0.10

real    0m0.023s
user    0m0.000s
sys     0m0.007s


```