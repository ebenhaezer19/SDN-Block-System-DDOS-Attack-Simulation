#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
import time
import sys

class DDoSTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)
        
        # Add hosts and switches
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        
        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)
        self.addLink(s1, s2)
        
def start_attack():
    topo = DDoSTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    
    print("*** Dumping host connections")
    dumpNodeConnections(net.hosts)
    
    print("*** Testing network connectivity")
    net.pingAll()
    
    print("*** Starting DDoS attack simulation")
    h1 = net.get('h1')
    h2 = net.get('h2')
    
    # Start ping flood attack from h1 to h2
    print("*** Starting ping flood attack from h1 to h2")
    h1.cmd('ping -f 10.0.0.2 &')
    
    # Wait for a while to observe the attack
    time.sleep(10)
    
    # Stop the attack
    h1.cmd('killall ping')
    
    print("*** Attack simulation completed")
    
    # Clean up
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_attack() 