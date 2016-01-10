from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link


# this class is to get the topology of the net
class PP_network_awareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PP_network_awareness, self).__init__(*args, **kwargs)

        # [switches]
        self.switches = []
        # links : {(src_dpid,dst_dpid):(src_port,dst_dpid)}
        self.links = {}

        # dpid-> (port num)
        self.switch2port = {}
        # interior port: dpid-> port num (interior)    important!
        self.interior_port = {}
        # dpid->port num (access: link to host directly)
        self.access_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    def create_switch2port(self, sw_list):
        for sw in sw_list:
            self.switch2port.setdefault(sw.dp.id, set())
            self.interior_port.setdefault(sw.dp.id, set())
            self.access_port.setdefault(sw.dp.id, set())
            for port in sw.ports:
                self.switch2port[sw.dp.id].add(port.port_no)

    def create_interior_port(self, link_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.interior_port[src.dpid].add(src.port_no)
            self.interior_port[dst.dpid].add(dst.port_no)
            self.interior_port[dst.dpid].add(dst.port_no)

    def create_access_port(self):
        for dpid in self.switch2port.keys():
            self.access_port[dpid] = self.switch2port[dpid] - self.interior_port[dpid]

    @set_ev_cls(events)
    def get_topology(self, ev):
        self.switches = get_switch(self, None)
        self.links = get_link(self, None) #todo: get no link!!!!
        self.logger.info(self.links)
        self.create_switch2port(self.switches)
        self.create_interior_port(self.links)
        self.create_access_port()
        # test:print
        self.logger.info("print switch2port:")
        for key, value in self.switch2port.items():
            self.logger.info("dpid:%s,ports:%s", key, value)
        self.logger.info("print interior_port:")
        for key, value in self.interior_port.items():
            self.logger.info("dpid:%s,ports:%s", key, value)
        self.logger.info("print access_port:")
        for key, value in self.access_port.items():
            self.logger.info("dpid:%s,ports:%s", key, value)
