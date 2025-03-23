from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import time
import logging

class DDoSDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(DDoSDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}
        self.packet_count = {}
        self.last_check = {}
        self.threshold = 5  # Menurunkan threshold menjadi 5 paket per detik
        self.logger.setLevel(logging.INFO)
        self.blocked_sources = set()
        self.attack_detected = False
        self.dropped_packets = {}  # Menambahkan counter untuk paket yang di-drop
        self.attack_stats = {}  # Statistik serangan
        self.start_time = time.time()
        
    def print_attack_stats(self):
        """Print statistik serangan"""
        current_time = time.time()
        duration = current_time - self.start_time
        
        self.logger.info("\n=== DDoS Attack Statistics ===")
        self.logger.info("Duration: %.2f seconds", duration)
        self.logger.info("Total blocked sources: %d", len(self.blocked_sources))
        
        for mac, stats in self.attack_stats.items():
            self.logger.info("\nSource: %s", mac)
            self.logger.info("  - Peak traffic: %d packets/sec", stats['peak_traffic'])
            self.logger.info("  - Total dropped packets: %d", self.dropped_packets.get(mac, 0))
            self.logger.info("  - Blocked at: %s", time.strftime('%Y-%m-%d %H:%M:%S', 
                                                               time.localtime(stats['block_time'])))
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.logger.info("Switch %s connected", datapath.id)
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)
        
    def block_source(self, datapath, src_mac, parser, packets_per_sec):
        """Block all traffic from a source MAC address"""
        # Block incoming traffic
        match = parser.OFPMatch(eth_src=src_mac)
        actions = []  # Drop packets
        self.add_flow(datapath, 2, match, actions)
        
        # Block outgoing traffic
        match = parser.OFPMatch(eth_dst=src_mac)
        self.add_flow(datapath, 2, match, actions)
        
        # Block broadcast traffic
        broadcast_match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff')
        self.add_flow(datapath, 2, broadcast_match, actions)
        
        self.logger.warning("BLOCKING ALL TRAFFIC FOR MAC: %s", src_mac)
        self.dropped_packets[src_mac] = 0  # Initialize dropped packets counter
        
        # Update attack statistics
        self.attack_stats[src_mac] = {
            'peak_traffic': packets_per_sec,
            'block_time': time.time()
        }
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
            
        dst = eth.dst
        src = eth.src
        
        # Check if source is blocked and count dropped packets
        if src in self.blocked_sources:
            self.dropped_packets[src] = self.dropped_packets.get(src, 0) + 1
            if self.dropped_packets[src] % 10 == 0:  # Log every 10 dropped packets
                self.logger.warning("Dropped %d packets from blocked source %s", 
                                  self.dropped_packets[src], src)
            return
            
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.packet_count.setdefault(dpid, {})
        self.last_check.setdefault(dpid, {})
        
        # Update packet count for source
        if src not in self.packet_count[dpid]:
            self.packet_count[dpid][src] = 0
            self.last_check[dpid][src] = time.time()
            
        current_time = time.time()
        time_diff = current_time - self.last_check[dpid][src]
        
        if time_diff >= 1.0:  # Check every second
            packets_per_sec = self.packet_count[dpid][src]
            self.logger.info("Traffic from %s: %d packets/sec (threshold: %d)", 
                           src, packets_per_sec, self.threshold)
            
            if packets_per_sec > self.threshold:
                # DDoS detected - block the source
                self.logger.warning("DDoS attack detected from %s on switch %s (packets/sec: %d)", 
                                  src, dpid, packets_per_sec)
                self.block_source(datapath, src, parser, packets_per_sec)
                self.blocked_sources.add(src)
                self.attack_detected = True
                self.logger.warning("Blocking all traffic from %s", src)
                
                # Print updated statistics
                self.print_attack_stats()
            
            # Reset counters
            self.packet_count[dpid][src] = 0
            self.last_check[dpid][src] = current_time
            
        self.packet_count[dpid][src] += 1
        
        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
            
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
                
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out) 