#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Host, RemoteController
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
    
    # Create network with remote controller
    net = Mininet(topo=topo, 
                  host=Host,
                  link=TCLink,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633))
    
    net.start()
    
    print("*** Dumping host connections")
    dumpNodeConnections(net.hosts)
    
    print("*** Testing network connectivity")
    net.pingAll()
    
    print("*** Starting DDoS attack simulation")
    h1 = net.get('h1')
    h2 = net.get('h2')
    
    # Start multiple ping flood attacks from h1 to h2
    print("*** Starting multiple ping flood attacks from h1 to h2")
    
    # Start background ping flood with maximum packet size
    h1.cmd('ping -f -s 65500 10.0.0.2 &')
    
    # Start additional ping flood with different packet sizes
    h1.cmd('ping -f -s 1000 10.0.0.2 &')
    
    # Start ping flood to broadcast address
    h1.cmd('ping -f -b 10.0.0.255 &')
    
    # Start ping flood to all hosts
    h1.cmd('ping -f 10.0.0.3 &')
    h1.cmd('ping -f 10.0.0.4 &')
    
    # Start additional flood attacks
    h1.cmd('ping -f -s 500 10.0.0.2 &')
    h1.cmd('ping -f -s 2000 10.0.0.2 &')
    
    print("*** Waiting for attack to be detected...")
    time.sleep(10)  # Reduced wait time to ensure faster detection
    
    # Test if h1 is blocked
    print("*** Testing if h1 is blocked...")
    result = h2.cmd('ping -c 1 10.0.0.1')
    print("Ping result from h2 to h1:", result)
    
    # Stop all ping processes
    h1.cmd('killall ping')
    
    print("*** Attack simulation completed")
    
    # Clean up
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    start_attack() 