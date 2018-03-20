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

        self.ip_inside = IPy.IP('192.168.0.0/24')

        self.ip_outside = IPy.IP('192.168.1.0/24')

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

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:

            out_port = self.mac_to_port[dpid][dst]

        else:

            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]



	if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

            # verify if we have a valid buffer_id, if yes avoid to send both

            # flow_mod & packet_out

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                self.add_flow(datapath, 1, match, actions, msg.buffer_id)

                return

            else:

                self.add_flow(datapath, 1, match, actions)

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:

            data = msg.data



        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,

                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)

	



#        if out_port != ofproto.OFPP_FLOOD:

 #           match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

  #          self.add_flow(datapath, 1, match, actions)        

#	self.logger.info("before filling out\n")        

 #       out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)

#	self.logger.info("before filling out_1\n")

 #       datapath.send_msg(out)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)

    def _packet_in_handler_router(self, ev):

	msg = ev.msg

        datapath = msg.datapath

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        dpid = datapath.id

        if dpid != 2:

            return

	#self.logger.info("inside nat packet handler\n")

        port = msg.match['in_port']

	self.logger.info("inside nat packet handler, port is %s\n", port)

        pkt = packet.Packet(msg.data)

        eth_req = pkt.get_protocols(ethernet.ethernet)[0]

        arp_req = pkt.get_protocol(arp.arp)

        icmp_req = pkt.get_protocol(icmp.icmp)

	ipv4_req = pkt.get_protocol(ipv4.ipv4)

	src_ip = ipv4_req.src

	dst_ip = ipv4_req.dst



        if src_ip in self.ip_inside and dst_ip in self.ip_inside:

	    return

	if arp_req:

            self.arp_handler(datapath, port, arp_req)

        elif icmp_req:

            self.icmp_handler(datapath, port, pkt)

        return



    def arp_handler(self, dp, port, arp_req):

        if arp_req.dst_ip not in self.ip_inside \

                and arp_req.dst_ip not in self.ip_outside:

            return

        if arp_req.opcode == arp.ARP_REQUEST:                

            rep = packet.Packet()

            eth_rep = ethernet.ethernet(

                ethertype=ether_types.ETH_TYPE_ARP,

                dst=arp_req.src_mac, src=dp.ports[port].hw_addr)



            #if self.nat_port[port] == 'outside':

             #   _src_ip = self.ip_outside

           # elif self.nat_port[port] == 'inside':

            #    _src_ip = self.ip_inside

           # else:

            #    raise 'bad ip address'

            arp_rep = arp.arp(

                opcode=arp.ARP_REPLY,

                src_mac=dp.ports[port].hw_addr, src_ip=arp_req.dst_ip,

                dst_mac=arp_req.src_mac, dst_ip=arp_req.src_ip)

            self.arp_table[arp_rep.src_ip] = arp_rep.src_mac

            self.arp_table[arp_rep.dst_ip] = src_mac

            rep.add_protocol(eth_rep)

            rep.add_protocol(arp_rep)

            self.send_packet(dp, port, rep)

        return



    def icmp_handler(self, dp, in_port, pkt_req):

        eth_req = pkt_req.get_protocols(ethernet.ethernet)[0]

        ipv4_req = pkt_req.get_protocol(ipv4.ipv4)

        icmp_req = pkt_req.get_protocol(icmp.icmp)

        # if icmp_req.type != icmp.ICMP_ECHO_REQUEST:

        #     return

        nat_src_ip = ipv4_req.src

        nat_port = icmp_req.data.id

	self.logger.info("nat_port is %s and nat_src_ip is %s and in_port is %s\n", nat_port, nat_src_ip, in_port)

        if icmp_req.type == icmp.ICMP_ECHO_REQUEST:

	    self.logger.info("it's an ICMP echo request packet\n")

            self.nat_translation[nat_port] = nat_src_ip

        if self.nat_port[in_port] == 'inside':

            # ip nat inside

            ipv4_req.src = self.ip_outside

            for port in self.nat_port:

                if self.nat_port[port] == 'outside':

                    out_port = port

	    self.logger.info("out_port is %s\n", out_port)

            src_mac = dp.ports[out_port].hw_addr

            if ipv4_req.dst in self.arp_table:

                dst_mac = self.arp_table[ipv4_req.dst]

            else:

                # dst_mac = 'aa:bb:cc:dd:ee:11'

                eth_rep = ethernet.ethernet(

                    ethertype=ether_types.ETH_TYPE_ARP,

                    dst='ff:ff:ff:ff:ff:ff',

                    src=src_mac)

                arp_rep = arp.arp(

                    opcode=arp.ARP_REQUEST,

                    dst_ip='192.168.1.1',

                    dst_mac='00:00:00:00:00:00',

                    src_ip=self.ip_outside,

                    src_mac=src_mac)

                rep = packet.Packet()

                rep.add_protocol(eth_rep)

                rep.add_protocol(arp_rep)

                self.send_packet(dp, out_port, rep)

              #  try:

               #     dst_mac = self.arp_table[ipv4_req.dst]

              #  except KeyError:

               #     return

            eth_rep = ethernet.ethernet(

                ethertype=eth_req.ethertype,

                dst=dst_mac, src=src_mac)

            rep = packet.Packet()

            rep.add_protocol(eth_rep)

            rep.add_protocol(ipv4_req)

            rep.add_protocol(icmp_req)

            self.send_packet(dp, out_port, rep)

        elif self.nat_port[in_port] == 'outside':

            # ip nat outside

            nat_port = icmp_req.data.id

            dst_ip = self.nat_translation[nat_port]

	    self.logger.info("dstt_ip is %s\n", dst_ip)

            src_ip = ipv4_req.src

	    self.logger.info("srcc_ip is %s\n", src_ip)

            dst_mac = self.arp_table[dst_ip]

            src_mac = self.arp_table[src_ip]

            eth_rep = ethernet.ethernet(

                ethertype=eth_req.ethertype,

                dst=dst_mac, src=src_mac)

            ipv4_req.dst = dst_ip

            rep = packet.Packet()

            rep.add_protocol(eth_rep)

            rep.add_protocol(ipv4_req)

            rep.add_protocol(icmp_req)

            for port in self.nat_port:

                if self.nat_port[port] == 'inside':

                    out_port = port

            self.send_packet(dp, out_port, rep)

        else:

            raise

    

    def send_packet(self, datapath, port, pkt):

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        pkt.serialize()

        # self.logger.info("packet-out %s" % (pkt,))

        data = pkt.data

        actions = [parser.OFPActionOutput(port=port)]

        out = parser.OFPPacketOut(datapath=datapath,

            buffer_id=ofproto.OFP_NO_BUFFER,

            in_port=ofproto.OFPP_CONTROLLER,

            actions=actions, data=data)

        datapath.send_msg(out)