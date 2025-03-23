# SDN DDoS Attack Detection and Mitigation System

A Software-Defined Networking (SDN) system that detects and mitigates DDoS attacks using Mininet and Ryu Controller. The system monitors network traffic in real-time and automatically blocks sources that exhibit suspicious behavior.

## Features

- Real-time DDoS attack detection
- Automatic source blocking
- Traffic monitoring and statistics
- Detailed attack reporting
- Support for multiple attack types
- Easy-to-use simulation environment

## Prerequisites

- Kali Linux (or any Linux distribution)
- Python 3.x
- Docker
- Mininet
- Open vSwitch (OVS)

## Installation

1. Install required packages:
```bash
sudo apt update
sudo apt install mininet openvswitch-switch docker.io -y
```

2. Start and enable services:
```bash
sudo systemctl start openvswitch-switch
sudo systemctl enable openvswitch-switch
sudo systemctl start docker
sudo systemctl enable docker
```

3. Clone this repository:
```bash
git clone <repository-url>
cd SDN-Block-System-DDOS-Attack-Simulation
```

## Project Structure

```
.
├── ddos_detector.py    # Ryu Controller application for DDoS detection
├── mininet_attack.py   # Mininet topology and attack simulation
├── Dockerfile         # Docker configuration for Ryu Controller
└── README.md          # This file
```

## Usage

### 1. Start Ryu Controller

First, ensure no process is using port 6633:
```bash
sudo fuser -k 6633/tcp
```

Build and run the Ryu Controller with DDoS detection:
```bash
sudo docker build -t ryu-ddos .
sudo docker run --rm -it -p 6633:6633 ryu-ddos
```

### 2. Run Attack Simulation

In a new terminal, run the Mininet simulation:
```bash
sudo python mininet_attack.py
```

The simulation will:
1. Create a network topology with 4 hosts and 2 switches
2. Test network connectivity
3. Simulate DDoS attacks from h1 to other hosts
4. Demonstrate automatic blocking of attack sources

### 3. Monitor Results

Watch the Ryu Controller output for:
- Traffic statistics
- Attack detection alerts
- Blocking actions
- Detailed attack reports

## Attack Detection Parameters

- Threshold: 5 packets per second
- Detection interval: 1 second
- Blocking duration: Until manual reset

## Attack Statistics

The system provides detailed statistics for each detected attack:
- Source MAC address
- Peak traffic rate
- Total dropped packets
- Blocking timestamp
- Attack duration

## Troubleshooting

1. If Ryu Controller fails to start:
```bash
sudo systemctl restart docker
sudo docker ps  # Check if container is running
```

2. If Mininet can't connect to controller:
```bash
sudo netstat -tulnp | grep 6633  # Verify port is listening
```

3. If switches aren't connecting:
```bash
sudo ovs-vsctl show  # Check OVS status
```

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OpenFlow Protocol
- Mininet Project
- Ryu SDN Framework
- Open vSwitch 