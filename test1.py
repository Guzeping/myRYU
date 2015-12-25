from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types,arp


class ARP_proxy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARP_proxy, self).__init__(*args, **kwargs)
        self.mac2Port = {}
        self.ip2mac = {}
        self.switches={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # set default= packetIn
        # drop IPV6,UDP
        # ARP packetIn
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.switches[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,0xff11)]
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
        match3 = parser.OFPMatch(eth_type=0x0806)
        actions3 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,0xff11)]
        self.logger.info("add default flow entry to switch:%s. ARP packetIn", datapath.id)
        self.add_flow(datapath, 10, match3, actions3)

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

    def printMac2Port(self, dpid):
        self.logger.info("dpid=%d" % dpid)
        for mac, port in self.mac2Port[dpid].items():
            self.logger.info("mac=%s port=%d" % (mac, port))

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
        self.logger.info("packet in dpid:%s src:%s dst:%s in_port:%s", dpid, src, dst, in_port)

        self.mac2Port[dpid][src] = in_port
        self.logger.info("add mac:%s to port:%s", src, in_port)
        self.logger.info("Current mac2Port for this switch")
        self.printMac2Port(dpid)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # ARP handler
            self.logger.info("handling arp!")
            header_list = dict((p.protocol_name, p)for p in pkt.protocols )#if type(p) != str)
            arp_packet =header_list[arp]



            return

        if dst in self.mac2Port[dpid]:
            out_put = self.mac2Port[dpid][dst]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(out_put)]
            self.add_flow(datapath=datapath, priority=1, match=match,
                          actions=actions)

        elif dst == "ff:ff:ff:ff:ff:ff":
            return
        else:
            out_put = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_put)]

        data = None
        if ev.msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = ev.msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ev.msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
