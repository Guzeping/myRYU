from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp

broadcast_mac = "88:88:88:88:88:88"  # special MAC to sent arp_request by controller
broadcast_ip = '10.10.10.10'  # special IP to sent arp_request by controller


class ARP_proxy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARP_proxy, self).__init__(*args, **kwargs)
        self.mac2Port = {}
        self.ip2mac = {}
        self.dpid2datapath = {}  # dpid->datapath
        self.request_queue = {}  # record arp request:{requested IP:{askIP:askIPtoDPid}} .e.g.{"10.0.0.2":{"10.0.0.1":"1","10.0.0.3","2"}}
        #                          "10.0.0.3":{"10.0.0.4","3"}}

    def encapsulate_ARP_reply(self, src_mac, src_ip, dst_mac, dst_ip):
        ARP = packet.Packet()
        ARP.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac,
                                           ethertype=ether_types.ETH_TYPE_ARP))
        ARP.add_protocol(arp.arp_ip(arp.ARP_REPLY, src_mac=src_mac,
                                    src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        ARP.serialize()
        return ARP

    def encapsulate_ARP_request(self, src_mac, src_ip, dst_ip):
        ARP = packet.Packet()
        ARP.add_protocol(ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=src_mac,
                                           ethertype=ether_types.ETH_TYPE_ARP))
        ARP.add_protocol(arp.arp_ip(arp.ARP_REQUEST, src_mac=src_mac,
                                    src_ip=src_ip, dst_mac="ff:ff:ff:ff:ff:ff", dst_ip=dst_ip))
        ARP.serialize()
        return ARP

    def add_flow(self, datapath, priority, match, actions, table_id=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath, table_id=table_id, priority=priority,
                                    buffer_id=buffer_id,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath, table_id=table_id, priority=priority, match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    def find_dpid_and_port_by_mac(self, mac):
        for dpid in self.mac2Port:
            if mac in self.mac2Port[dpid]:
                return dpid, self.mac2Port[dpid][mac]

    def printMac2Port(self, dpid):
        self.logger.info("dpid=%d" % dpid)
        for mac, port in self.mac2Port[dpid].items():
            self.logger.info("mac=%s port=%d" % (mac, port))
        self.logger.info("")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # set default= packetIn
        # drop IPV6,UDP
        # ARP packetIn
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.dpid2datapath[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 0xff11)]
        self.logger.info("add default flow entry to switch:%s. default=packetIn", datapath.id)
        self.add_flow(datapath, 0, match, actions)

        # drop IPV6
        match_filter1 = parser.OFPMatch(eth_type=0x86dd)
        actions_filter1 = []
        self.logger.info("add default flow entry to switch:%s. drop IPV6", datapath.id)
        self.add_flow(datapath, 10, match_filter1, actions_filter1)

        # drop UDP      problem!!
        match_filter2 = parser.OFPMatch(eth_type=0x0800, ip_proto=17)  ##slove the question  . to filter udp,
        # must not only indicate the udp(ip_proto=17)
        # but also indicate the IPV4(eth=0x0800)
        actions_filter2 = []
        self.logger.info("add default flow entry to switch:%s. drop UDP", datapath.id)
        self.add_flow(datapath, 10, match_filter2, actions_filter2)

        # packetIN ARP
        match_filter3 = parser.OFPMatch(eth_type=0x0806)
        actions_filter3 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 0xff11)]
        self.logger.info("add default flow entry to switch:%s. ARP packetIn", datapath.id)
        self.add_flow(datapath, 10, match_filter3, actions_filter3)

        # drop special dl_src=broadcast_mac
        match_filter4 = parser.OFPMatch(eth_src=broadcast_mac)
        actions_filter4 = []
        self.logger.info("add default flow entry to switch:%s. drop broadcast_mac", datapath.id)
        self.add_flow(datapath, 11, match_filter4, actions_filter4)

        self.logger.info("")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = ev.msg.match['in_port']

        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # mac learning
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac2Port.setdefault(dpid, {})
        self.logger.info("\npacket in dpid:%s src:%s dst:%s in_port:%s ", dpid, src, dst, in_port)

        self.mac2Port[dpid][src] = in_port
        self.logger.info("set mac:%s to dpid:%s port:%s", src, dpid, in_port)
        self.logger.info("Current mac2Port for this switch")
        self.printMac2Port(dpid)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # ARP handler
            self.logger.info("  handling arp!")
            arp_packet = pkt.get_protocol(arp.arp)
            src_ip = arp_packet.src_ip
            src_mac = arp_packet.src_mac
            self.ip2mac[src_ip] = src_mac
            self.logger.info("  Current ip2mac:")
            for key, value in self.ip2mac.items():
                self.logger.info("  %s->%s", key, value)
            self.logger.info("")
            # arp_request
            if arp_packet.opcode == arp.ARP_REQUEST:
                self.logger.info("      handling arp_request!")
                dst_ip = arp_packet.dst_ip

                # hit the cache
                if dst_ip in self.ip2mac:
                    # encapsulate and ARP reply and sent
                    self.logger.info("      hit cache!")
                    dst_mac = self.ip2mac[dst_ip]
                    arp_reply = self.encapsulate_ARP_reply(src_mac=dst_mac, src_ip=dst_ip,
                                                           dst_mac=src_mac, dst_ip=src_ip)

                    self.logger.info("      encapsulate ARP reply and sent!\n")
                    actions = [parser.OFPActionOutput(in_port, 0)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER,
                                              actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)

                # miss the cache
                else:
                    # append request to request_queue
                    self.logger.info("      miss cache,broadcast!")
                    if dst_ip in self.request_queue.keys():

                        self.request_queue[dst_ip].setdefault(src_ip, dpid)
                    else:
                        self.request_queue.setdefault(dst_ip, {src_ip: dpid})
                        # flood
                        arp_request = self.encapsulate_ARP_request(src_mac=broadcast_mac,
                                                                   src_ip=broadcast_ip,
                                                                   dst_ip=dst_ip)
                        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD, 0)]
                        for sw_dpid in self.dpid2datapath:
                            self.logger.info("      broadcast to dpid:%s", sw_dpid)
                            out = parser.OFPPacketOut(datapath=self.dpid2datapath[sw_dpid],
                                                      buffer_id=self.dpid2datapath[sw_dpid].ofproto.OFP_NO_BUFFER,
                                                      in_port=self.dpid2datapath[sw_dpid].ofproto.OFPP_CONTROLLER,
                                                      actions=actions, data=arp_request.data)
                            self.dpid2datapath[sw_dpid].send_msg(out)

                    # print request_queue
                    self.logger.info("      request_queue:")
                    for arp_request_Ip in self.request_queue:
                        self.logger.info("      request_ip:%s ->", arp_request_Ip)
                        for key, value in self.request_queue[arp_request_Ip].items():
                            self.logger.info("          %s in dpid %s", key, value)
                    self.logger.info("")

            # arp_reply
            elif arp_packet.opcode == arp.ARP_REPLY:
                self.logger.info("      handling arp_reply!")
                # find information of pending_ip and encapsulate the arp_reply and sent to the respective port of switch
                # for pending_ip in self.request_queue[src_ip]:
                while self.request_queue[src_ip].__len__() != 0:
                    # find information of pending_ip:
                    pending_ip, pending_dpid = self.request_queue[src_ip].popitem()
                    pending_mac = self.ip2mac[pending_ip]
                    pending_port = self.mac2Port[pending_dpid][pending_mac]
                    self.logger.info(
                        "      find  pending_ip:%s, pending_mac:%s in dpid :%s in port:%s for requested_ip:%s",
                        pending_ip, pending_mac, pending_dpid, pending_port, src_ip)

                    arp_reply = self.encapsulate_ARP_reply(src_mac=src_mac, src_ip=src_ip,
                                                           dst_mac=pending_mac, dst_ip=pending_ip)

                    # encapsulate the arp_reply and sent to the respective port of switch
                    self.logger.info("      encapsulate ARP reply and sent to dpid:%s port:%s!\n", pending_dpid,
                                     pending_port)
                    actions = [self.dpid2datapath[pending_dpid].ofproto_parser.OFPActionOutput(pending_port, 0)]
                    out = self.dpid2datapath[pending_dpid].ofproto_parser.OFPPacketOut(
                            datapath=self.dpid2datapath[pending_dpid],
                            buffer_id=self.dpid2datapath[pending_dpid].ofproto.OFP_NO_BUFFER,
                            in_port=self.dpid2datapath[pending_dpid].ofproto.OFPP_CONTROLLER,
                            actions=actions, data=arp_reply.data)
                    self.dpid2datapath[pending_dpid].send_msg(out)

                self.request_queue.pop(src_ip)
            return

        if dst in self.mac2Port[dpid]:
            out_put = self.mac2Port[dpid][dst]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(out_put)]
            self.logger.info("add flow to dpid:%s,in_port=%s,dl_dst=%s,ouput=%s",
                             dpid, in_port, dst, out_put)
            self.add_flow(datapath=datapath, priority=1, match=match,
                          actions=actions)

        elif dst == "ff:ff:ff:ff:ff:ff":
            return
        else:
            out_put = ofproto.OFPP_FLOOD
            self.logger.info("flood!")
        actions = [parser.OFPActionOutput(out_put)]

        data = None
        if ev.msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = ev.msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ev.msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
