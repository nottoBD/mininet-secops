"""
Custom topology for the LINFO2347 - Computer System Security course.

Mimics a small enterprise network, with 2 workstations in a trusted LAN,
and service-providing servers in a DMZ LAN.

Adapted from https://stackoverflow.com/questions/46595423/mininet-how-to-create-a-topology-with-two-routers-and-their-respective-hosts
"""

import os
import time
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.examples.linuxrouter import LinuxRouter
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class TopoSecu(Topo):
    """
    Custom Mininet topology
    """

    def build(self):

        # Add 2 routers in two different subnets
        r1 = self.addHost('r1', cls=LinuxRouter, ip=None)  # Workstation LAN router
        r2 = self.addHost('r2', cls=LinuxRouter, ip=None)  # Internet router

        # Add 2 switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add router-switch links in the same subnet
        self.addLink(s1, r1, intfName2='r1-eth0', params2={'ip': '10.1.0.1/24'})
        self.addLink(s2, r1, intfName2='r1-eth12', params2={'ip': '10.12.0.1/24'})
        self.addLink(s2, r2, intfName2='r2-eth12', params2={'ip': '10.12.0.2/24'})

        # Add outside host
        internet = self.addHost(name='internet', ip='10.2.0.2/24', defaultRoute='via 10.2.0.1')
        self.addLink(internet, r2, intfName2='r2-eth0', params2={'ip': '10.2.0.1/24'})

        # Adding hosts specifying the default route
        ws2 = self.addHost(name='ws2', ip='10.1.0.2/24', defaultRoute='via 10.1.0.1')
        ws3 = self.addHost(name='ws3', ip='10.1.0.3/24', defaultRoute='via 10.1.0.1')
        httpServer = self.addHost(name='http', ip='10.12.0.10/24', defaultRoute='via 10.12.0.2')
        dnsServer = self.addHost(name='dns', ip='10.12.0.20/24', defaultRoute='via 10.12.0.2')
        ntpServer = self.addHost(name='ntp', ip='10.12.0.30/24', defaultRoute='via 10.12.0.2')
        ftpServer = self.addHost(name='ftp', ip='10.12.0.40/24', defaultRoute='via 10.12.0.2')

        # Add host-switch links
        self.addLink(ws2, s1)
        self.addLink(ws3, s1)
        self.addLink(httpServer, s2)
        self.addLink(dnsServer, s2)
        self.addLink(ntpServer, s2)
        self.addLink(ftpServer, s2)


topos = {
    "secu": ( lambda: TopoSecu() )
}


def add_routes(net):
    ### STATIC ROUTES ###
    info(net['r1'].cmd("ip route add 10.2.0.0/24 via 10.12.0.2 dev r1-eth12"))
    info(net['r2'].cmd("ip route add 10.1.0.0/24 via 10.12.0.1 dev r2-eth12"))


def start_services(net: Mininet) -> None:
    """Start services on servers."""
    # Kill existing processes
    for host in ['http', 'dns', 'ntp', 'ftp']:
        net[host].cmd("pkill -9 apache2 python3 dnsmasq ntpd vsftpd 2>/dev/null")

    # HTTP server - use Python's simple HTTP server instead of Apache
    net['http'].cmd("mkdir -p /tmp/www")
    net['http'].cmd("echo 'This index was hardcoded from within topo.py' > /tmp/www/index.html")
    net['http'].cmd("cd /tmp/www && python3 -m http.server 80 &")

    #BUG: dnsmasq DNS server
    net['dns'].cmd("pkill -9 dnsmasq")
    net['dns'].cmd("echo 'listen-address=10.12.0.20' > /tmp/dnsmasq.conf")
    net['dns'].cmd("echo 'bind-interfaces' >> /tmp/dnsmasq.conf")
    net['dns'].cmd("echo 'port=5353' >> /tmp/dnsmasq.conf")
    net['dns'].cmd("echo 'server=8.8.8.8' >> /tmp/dnsmasq.conf")
    net['dns'].cmd("echo 'address=/example.com/10.12.0.10' >> /tmp/dnsmasq.conf")
    net['dns'].cmd("dnsmasq -C /tmp/dnsmasq.conf --no-daemon &")

    # NTP server
    net['ntp'].cmd("mkdir /var/log/ntpsec/")
    net['ntp'].cmd("echo 'server 127.127.1.0 prefer' > /tmp/ntp.conf")
    net['ntp'].cmd("echo 'fudge 127.127.1.0 stratum 1' >> /tmp/ntp.conf")
    net['ntp'].cmd("ntpd -g -n -c /tmp/ntp.conf &")

    # FTP server
    net['ftp'].cmd("mkdir -p /srv/ftp")
    net['ftp'].cmd("echo 'This README was hardcoded from within topo.py' > /srv/ftp/README")
    net['ftp'].cmd("echo 'listen=YES\nanonymous_enable=YES\nanon_root=/srv/ftp' > /tmp/vsftpd.conf")
    net['ftp'].cmd("vsftpd /tmp/vsftpd.conf &")
    # Block unwanted services on other hosts
    for host in ['http', 'ftp', 'dns', 'ntp']:
        net[host].cmd("iptables -A INPUT -p udp --dport 53 -j DROP")
        if host != 'ntp':
            net[host].cmd("iptables -A INPUT -p udp --dport 123 -j DROP")
        if host != 'dns':
            net[host].cmd("iptables -A INPUT -p udp --dport 5353 -j DROP")

    # Enable IP forwarding on routers
    net['r1'].cmd("sysctl -w net.ipv4.ip_forward=1")
    net['r2'].cmd("sysctl -w net.ipv4.ip_forward=1")

    # SSH server
    for host in ['http', 'dns', 'ntp', 'ftp']:
        info(net[host].cmd("mkdir -p /var/run/sshd"))
        info(net[host].cmd("/usr/sbin/sshd 2>/dev/null &"))


def stop_services(net: Mininet) -> None:
    """
    Stop services on servers.
    :param net: Mininet network
    """
    # Apache2 HTTP server
    info(net['http'].cmd("killall apache2"))
    # dnsmasq DNS server
    info(net['dns'].cmd("killall dnsmasq"))
    # OpenNTPd NTP server
    info(net['ntp'].cmd("killall ntpd"))
    # FTP server
    info(net['ftp'].cmd("killall vsftpd"))


def run():
    topo = TopoSecu()
    net = Mininet(topo=topo)

    add_routes(net)
    stop_services(net)
    time.sleep(1)
    start_services(net)

    net.start()
    CLI(net)
    stop_services(net)
    net.stop()


def ping_all():
    topo = TopoSecu()
    net = Mininet(topo=topo)

    add_routes(net)
    stop_services(net)
    start_services(net)

    net.start()
    net.pingAll()
    stop_services(net)
    net.stop()


if __name__ == '__main__':
    os.system("sudo apt-get install -y apache2 dnsmasq ntp vsftpd openssh-server ntpdate")
    setLogLevel('info')
    run()
