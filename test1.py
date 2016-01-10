from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.topology import switches
from ryu.lib import hub




class Switch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'switches': switches.Switches}

    def __init__(self, switches, *args, **kwargs):
        super(Switch13, self).__init__(*args, **kwargs)
        self.switches = switches
        self.mac2Port = {}
        self.links=self.switches.links
        self.dps=self.switches.dps

        self.threads = []
       # self.threads.extend([hub.spawn(self._link_monitor), ])

    # def _link_monitor(self):
    #     while (self.is_active):
    #         if self.links != self.dp_tracker.links.keys():
    #             self.dps = self.dp_tracker.dps
    #             self.links = self.dp_tracker.links.keys()
    #         hub.sleep(1)

    def get_graph(self):
        graph_cap = {}
        graph_port = {}
        for dpid in self.dps.keys():
            for link in self.links:
                if link.src.dpid == dpid:
                    graph_cap.setdefault(dpid, {})
                    graph_port.setdefault(dpid, {})
                    neighbor = link.dst.dpid
                    capacity = link.dst.curr_speed
                    graph_cap[dpid][neighbor] = capacity
                    graph_port[dpid][neighbor] = link.src.port_no
        return graph_cap, graph_port

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          0xff11
                                          )]
        self.logger.info("add default flow entry to switch:%s!", datapath.id)
        self.add_flow(datapath, 0, match, actions)

        # drop IPV6
        match_filter1 = parser.OFPMatch(eth_type=0x86dd)
        actions_filter1 = []
        self.add_flow(datapath, 1, match_filter1, actions_filter1)

        # drop UDP      problem!!
        match_filter2 = parser.OFPMatch(eth_type=0x0800, ip_proto=17)  ##slove the question  . to filter udp,
        # must not only indicate the udp(ip_proto=17)
        # but also indicate the IPV4(eth=0x0800)
        actions_filter2 = []
        self.add_flow(datapath, 1, match_filter2, actions_filter2)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath, priority=priority,
                                    buffer_id=buffer_id,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath, priority=priority, match=match,
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

        for dpid1 in self.dps.keys():
            self.logger.info("this is test ! dpid:%s  ",dpid1)

        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac2Port.setdefault(dpid, {})
        self.logger.info("packet in dpid:%s src:%s dst:%s in_port:%s", dpid, src, dst, in_port)

        self.mac2Port[dpid][src] = in_port
        self.logger.info("add mac:%s to port:%s", src, in_port)
        self.logger.info("Current mac2Port for this switch")
        self.printMac2Port(dpid)

        if dst in self.mac2Port[dpid]:
            out_put = self.mac2Port[dpid][dst]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            actions = [parser.OFPActionOutput(out_put)]
            self.add_flow(datapath=datapath, priority=1, match=match,
                          actions=actions)

        else:
            out_put = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_put)]

        data = None
        if ev.msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = ev.msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ev.msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
