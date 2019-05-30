import argparse
import os
import sys
import time
from scapy.all import *

class BfdEcho:
    """ object holds a router's BFD output, and the BFD return echo 
        There is some state ambiguity, such that, the current packet
        analysis may start with the echo packet, not the initial BFD
        packet.  in the event the echo and initial packets are confused,
        the time measurements will be incorrect."""

    def __init__(self, ts1, mac_src1, mac_dst1):
        """ initializing the object assumes the packet details are coming
        from the initial BFD packet, not the echo packet"""
        self.ts1  = ts1
        self.src1 = mac_src1
        self.dst1 = mac_dst1
        self.ts2  = 0.0 
        self.src2 = "" 
        self.dst2 = "" 

    def addecho(self, ts2, mac_src2, mac_dst2):
        """ this call assumes the packet information is the echo and the object exists """
        self.ts2  = ts2 
        self.src2 = mac_src2
        self.dst2 = mac_dst2

    def delta(self):
        """ the call calculates the time it takes to send a BFD packet, transit the link,
        be recived by the destination mac router and echo'ed off the dataplane and transit 
        the link """
        return (self.ts2-self.ts1)

    def dump(self):
        """ a troubleshooting call """
        return (self.ts1, self.src1, self.dst1, self.ts2, self.src2, self.dst2)


""" dictionary variables """
events = {}
lastts = {}
jitters = {}

""" code loops through the pcap file, looking for BFD port 3785 packets.
    code assumes the first BFD packet is the initiator packet and the second
    packet is the BFD echo.  furthermore the algorithm does not currently 
    support a router, having BFD sessions with multiple router end-points
    the algorithm returns two timing variables, of interest:
    delta: the BFD down and back timing
    jitter: the measure of a router's ability, to periodically send the BFD """

print("router_IP", "router_mac_sender", "router_mac_echoer", "ts", "delta", "jitter")

#for (pkt, pkt_metadata,) in RawPcapReader('BFD-capture.pcap'):
for pkt in PcapReader('BFD-capture.pcap'):
    eth_ts    = pkt[Ether].time
    eth_src   = pkt[Ether].src
    eth_dst   = pkt[Ether].dst
    eth_type  = pkt[Ether].type
    ip_src    = pkt[IP].src
    ip_dst    = pkt[IP].dst
    ip_ttl    = pkt[IP].ttl
    udp_sport = pkt[UDP].sport
    udp_dport = pkt[UDP].dport
    #st = pkt.fields['subtype']


    if udp_dport == 3785:
        src = eth_src
        dst = eth_dst

        if ip_src in events:
            """ this is the echo packet processing - it outputs all the timing 
            and destroys the object, waiting for the next BFD iniator """
            events[ip_src].addecho(eth_ts, eth_src, eth_dst)
            delta = events[ip_src].ts2 - events[ip_src].ts1
            print (ip_src, events[ip_src].src1, events[ip_src].src2, eth_ts, end='' )
            print (" %2.9f"% (delta), end='' )
            print (" %2.9f"% (jitters[ip_src]), )
            #print (events[ip_src].dump())
            del events[ip_src]
        else:
            """ this is the BFD iniating packet processing, holding the packet details
            till this packets echo response hits the wire """
            events[ip_src] = BfdEcho(eth_ts, eth_src, eth_dst) 
            try:
                jitters[ip_src] = eth_ts - lastts[ip_src] 
                lastts[ip_src] = eth_ts
            except KeyError:
                jitters[ip_src] = 0.0
                lastts[ip_src] = eth_ts


    #print( pkt[0].summary() )
    #print( pkt[1].summary() )
    #print( pkt[2].summary() )

#ls()
#print("Ether:", Ether)
#ls(Ether)
#print("IP:")
#ls(IP)
#print("UDP:")
#ls(UDP)
