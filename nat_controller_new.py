from ryu.base import app_manager

from ryu.controller import ofp_event

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER

from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3



from ryu.lib import hub

from ryu.lib.packet import ether_types

from ryu.lib.packet import packet

from ryu.lib.packet import ethernet

from ryu.lib.packet import arp

from ryu.lib.packet import ipv4

from ryu.lib.packet import icmp



import time

import IPy



class NATServer(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]



    def __init__(self, *args, **kwargs):

        super(NATServer, self).__init__(*args, **kwargs)

        self.ip_inside = '192.168.0.0/24'

        self.ip_outside = '192.168.1.0/24'

        self.arp_table = {}

        self.nat_translation = {}

        self.mac_to_port = {}

        self.nat_port = {1:'outside',

            2:'inside'}



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)

    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,

            ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)



    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(

            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:

            mod = parser.OFPFlowMod(datapath=datapath,

                buffer_id=buffer_id, priority=priority,

                match=match, instructions=inst)

        else:

            mod = parser.OFPFlowMod(datapath=datapath,

                priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)

    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:

            self.logger.debug("packet truncated: only %s of %s bytes",

                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg

        datapath = msg.datapath

        dpid = datapath.id

        if dpid != 1:

            return

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst

        src = eth.src

        data = None

        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:

            out_port = self.mac_to_port[dpid][dst]

        else:

            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

            self.add_flow(datapath, 1, match, actions)        

        

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,

                                  in_port=in_port, actions=actions, data=msg.data)

        datapath.send_msg(out)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)

    def _packet_in_handler_router(self, ev):

	msg = ev.msg

        datapath = msg.datapath

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        dpid = datapath.id

        if dpid != 2:

            return

        port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth_req = pkt.get_protocols(ethernet.ethernet)[0]

        arp_req = pkt.get_protocol(arp.arp)

        icmp_req = pkt.get_protocol(icmp.icmp)

	ipv4_re = pkt.get_protocol(ipv4.ipv4)

	src_ip = ipv4_req.src



	dst_ip = ipv4_req.dst

        if dst_ip not in self.ip_inside