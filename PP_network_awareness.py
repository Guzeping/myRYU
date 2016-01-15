from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host

sleep_time = 10


# this class is to get the topology of the net
class PP_network_awareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PP_network_awareness, self).__init__(*args, **kwargs)

        # [switches]
        self.switches = []
        # links : {(src_dpid,dst_dpid):(src_port,dst_port)}
        self.links = {}

        # dpid-> set(port num)
        self.switch2port = {}
        # interior port: dpid-> set(port num) (interior)    important!
        self.interior_port = {}
        # dpid->set(port num) (access: link to host directly)
        self.access_port = {}

        # switches connection matrix
        self.dp_map = {}

        # self.discover_thread = hub.spawn(self._discover)

    def dijkstra(self, src_dpid, dst_dpid):
        # init
        if src_dpid == dst_dpid:
            return [src_dpid]
        distances = self.dp_map[src_dpid]
        finish = [src_dpid]
        pre = {src_dpid: src_dpid}
        for dst in distances:
            if distances[dst] < float("inf"):
                pre[dst] = src_dpid

        while dst_dpid not in finish:
            current = None
            min_dis = float("inf")
            # choose current
            for dst in distances:
                if dst not in finish and distances[dst] < min_dis:
                    current = dst
                    min_dis = distances[dst]
            finish.append(current)
            # update distances and pre
            for dst in distances:
                if dst not in finish and distances[dst] > distances[current] + self.dp_map[current][dst]:
                    distances[dst] = distances[current] + self.dp_map[current][dst]
                    pre[dst] = current

        # find path have problem!
        last = dst_dpid
        path = []
        while last != src_dpid:
            path.append(last)
            last = pre[last]
        path.append(src_dpid)
        path.reverse()
        return path

    def find_shortest_path(self, map, src, dst):  # find the shortest path from host_src to dst_src
        src_dpid = self.hosts[src].port.dpid
        dst_dpid = self.hosts[dst].port.dpid
        path = self.dijkstra(src_dpid, dst_dpid)
        return path

    # def _discover(self):
    #     while True:
    #         hub.sleep(sleep_time)
    #         self.get_topology(None)

    # @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # def switch_features_handler(self, ev):
    #     datapath = ev.msg.datapath
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser
    #     msg = ev.msg
    #     self.logger.info("switch:%s connected", datapath.id)
    #
    #     # install table-miss flow entry
    #     match = parser.OFPMatch()
    #     actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
    #                                       ofproto.OFPCML_NO_BUFFER)]
    #     self.add_flow(datapath, 0, match, actions)
    #
    # def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
    #     ofproto = dp.ofproto
    #     parser = dp.ofproto_parser
    #
    #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
    #                                          actions)]
    #
    #     mod = parser.OFPFlowMod(datapath=dp, priority=p,
    #                             idle_timeout=idle_timeout,
    #                             hard_timeout=hard_timeout,
    #                             match=match, instructions=inst)
    #     dp.send_msg(mod)

    def create_switch2port(self, sw_list):
        for sw in sw_list:
            self.switch2port.setdefault(sw.dp.id, set())
            self.interior_port.setdefault(sw.dp.id, set())
            self.access_port.setdefault(sw.dp.id, set())
            for port in sw.ports:
                self.switch2port[sw.dp.id].add(port.port_no)

    def create_link(self, link_list):
        self.links.clear()
        for link in link_list:
            src = link.src
            dst = link.dst
            self.links.setdefault((src.dpid, dst.dpid), (src.port_no, dst.port_no))

    def create_interior_port(self, link_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.interior_port[src.dpid].add(src.port_no)
            self.interior_port[dst.dpid].add(dst.port_no)

    def create_access_port(self):
        for dpid in self.switch2port.keys():
            self.access_port[dpid] = self.switch2port[dpid] - self.interior_port[dpid]

    def get_graph(self):
        for sw_src in self.switches:
            self.dp_map.setdefault(sw_src.dp.id, {})
            for sw_dst in self.switches:
                if (sw_src.dp.id, sw_dst.dp.id) in self.links.keys():
                    self.dp_map[sw_src.dp.id][sw_dst.dp.id] = 1
                else:
                    self.dp_map[sw_src.dp.id][sw_dst.dp.id] = float("inf")

    def print_map(self):
        print("--------------------topo map--------------------")
        print("%10s") % ("switch"),
        for sw_src in self.switches:
            print "%10s" % sw_src.dp.id,
        print
        for sw_src in self.switches:
            print"%10s" % sw_src.dp.id,
            for sw_dst in self.switches:
                print "%10.0f" % self.dp_map[sw_src.dp.id][sw_dst.dp.id],
            print

    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    @set_ev_cls(events)
    def get_topology(self, ev):
        print"------------------start------------------"
        self.switches = get_switch(self, None)
        self.create_switch2port(self.switches)
        link_list = get_link(self, None)  # two way
        self.create_link(link_list)
        self.create_interior_port(link_list)
        self.create_access_port()
        self.get_graph()

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

        self.logger.info("print map:")
        self.print_map()


