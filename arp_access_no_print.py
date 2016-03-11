from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.topology import event
import time
import PP_network_awareness

broadcast_mac = "88:88:88:88:88:88"  # special MAC to sent arp_request by controller
broadcast_ip = '10.10.10.10'  # special IP to sent arp_request by controller
enable_time = 10000
expired_time = 20000
# todo:delete the print and logger,decrease the time,install one direct path

class Host(object):
    def __init__(self, dpid, port_no, mac):
        self.dpid = dpid
        self.port_no = port_no
        self.mac = mac
        self.ipv4 = []


class Host_info(object):
    def __init__(self, mac, ip):
        self.ip = ip
        self.mac = mac
        self.stamp = time.time()
        self.enabled = True

    def is_enable(self):
        if self.enabled == True and time.time() - self.stamp <= enable_time:
            self.stamp = time.time()
            return True
        else:
            return False

    def is_expired(self):
        if self.enabled == False and time.time() - self.stamp >= expired_time:
            return True
        else:
            return False

    def update_stamp(self):
        self.stamp = time.time()
        self.enabled = True


class ARP_proxy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]
    _CONTEXTS = {"PP_network_awareness": PP_network_awareness.PP_network_awareness}

    def __init__(self, *args, **kwargs):
        super(ARP_proxy, self).__init__(*args, **kwargs)
        self.PP_network_awareness = kwargs["PP_network_awareness"]
        # links : {(src_dpid,dst_dpid):(src_port,dst_port)}
        self.links = self.PP_network_awareness.links

        # dpid->set(port num) (access: link to host directly)
        self.access_port = self.PP_network_awareness.access_port

        # switches connection matrix
        self.dp_map = self.PP_network_awareness.dp_map
        # mac->host
        self.hosts = {}

        # ip->host_info
        self.ip2host_info = {}

        self.dpid2dp = {}  # dpid->datapath
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

    def arp_request_handler(self, arp_packet):
        # self.logger.info("      handling arp_request!")

        # init
        src_ip = arp_packet.src_ip
        src_mac = arp_packet.src_mac
        src_dpid = self.hosts[src_mac].dpid
        in_port = self.hosts[src_mac].port_no
        datapath = self.dpid2dp[src_dpid]
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dst_ip = arp_packet.dst_ip

        # hit the cache
        if dst_ip in self.ip2host_info:
            # self.logger.info("      hit cache!")
            dst_mac = self.ip2host_info[dst_ip].mac
            if self.ip2host_info[dst_ip].is_enable():
                #  host_info enabled! encapsulate and ARP reply and sent
                # self.logger.info("      the cache enbaled!")
                arp_reply = self.encapsulate_ARP_reply(src_mac=dst_mac, src_ip=dst_ip,
                                                       dst_mac=src_mac, dst_ip=src_ip)

                # self.logger.info("      encapsulate ARP reply and sent!\n")
                actions = [parser.OFPActionOutput(in_port, 0)]
                out = parser.OFPPacketOut(datapath=self.dpid2dp[src_dpid],
                                          buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER,
                                          actions=actions, data=arp_reply.data)
                # install path
                # print"      install path"
                path = self.find_shortest_path(src_mac, dst_mac)
                self.install_path_flow(src_mac, dst_mac, path)

                path.reverse()
                self.install_path_flow(dst_mac, src_mac, path)
                # print"      install finish"
                time.sleep(0.005)
                datapath.send_msg(out)
            else:
                if self.ip2host_info[dst_ip].is_expired():
                    # expired
                    # self.logger.info("      cache is expired,delete ip:%s ,broadcast!", dst_ip)
                    if dst_ip in self.request_queue.keys():
                        self.request_queue[dst_ip].setdefault(src_ip, src_dpid)
                    else:
                        self.request_queue.setdefault(dst_ip, {src_ip: src_dpid})
                    # flood
                    for sw_dpid in self.dpid2dp:
                            # print "      broadcast to dpid:%s to port:" % sw_dpid,
                            arp_request = self.encapsulate_ARP_request(src_mac=src_mac,
                                                                       src_ip=src_ip,
                                                                       dst_ip=dst_ip)
                            actions = []
                            for access_port in self.access_port[sw_dpid]:
                                actions.append(parser.OFPActionOutput(access_port, 0))
                                # print "%d" % access_port,
                            out = parser.OFPPacketOut(datapath=self.dpid2dp[sw_dpid],
                                                      buffer_id=self.dpid2dp[sw_dpid].ofproto.OFP_NO_BUFFER,
                                                      in_port=self.dpid2dp[sw_dpid].ofproto.OFPP_CONTROLLER,
                                                      actions=actions, data=arp_request.data)
                            self.dpid2dp[sw_dpid].send_msg(out)
                            # print

                    self.ip2host_info.pop(dst_ip)  # delete the dst_ip
                else:
                    # disabled
                    self.ip2host_info[dst_ip].enabled = False
                    # self.logger.info("          the cache disabled,sent request to the requested host")
                    if dst_ip in self.request_queue.keys():
                        self.request_queue[dst_ip].setdefault(src_ip, src_dpid)
                    else:
                        self.request_queue.setdefault(dst_ip, {src_ip: src_dpid})
                        dst_port = self.hosts[dst_mac].port_no
                        dst_dpid = self.hosts[dst_mac].dpid
                        actions = [parser.OFPActionOutput(dst_port, 0)]
                        # print "          mac:", dst_mac
                        # print "          dpid:%s,port:%s" % (dst_dpid, dst_port)
                        arp_request = self.encapsulate_ARP_request(src_mac=src_mac,
                                                                   src_ip=src_ip,
                                                                   dst_ip=dst_ip)
                        out = parser.OFPPacketOut(datapath=self.dpid2dp[dst_dpid],
                                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                                  in_port=ofproto.OFPP_CONTROLLER,
                                                  actions=actions, data=arp_request.data)
                        self.dpid2dp[dst_dpid].send_msg(out)
                # print request_queue
                # self.logger.info("      request_queue:")
                # for arp_request_Ip in self.request_queue:
                #     self.logger.info("      request_ip:%s ->", arp_request_Ip)
                #     for key, value in self.request_queue[arp_request_Ip].items():
                #         self.logger.info("          %s in dpid %s", key, value)
                # self.logger.info("")

        # miss the cache
        else:
            # append request to request_queue
            # self.logger.info("      miss cache,broadcast!")
            if dst_ip in self.request_queue.keys():
                self.request_queue[dst_ip].setdefault(src_ip, src_dpid)
            else:
                self.request_queue.setdefault(dst_ip, {src_ip: src_dpid})
                        # flood
                for sw_dpid in self.dpid2dp:
                    # print "      broadcast to dpid:%s to port:" % sw_dpid,
                    arp_request = self.encapsulate_ARP_request(src_mac=src_mac,
                                                               src_ip=src_ip,
                                                               dst_ip=dst_ip)
                    actions = []
                    for access_port in self.access_port[sw_dpid]:
                        actions.append(parser.OFPActionOutput(access_port, 0))
                        # print "%d" % access_port,
                    out = parser.OFPPacketOut(datapath=self.dpid2dp[sw_dpid],
                                              buffer_id=self.dpid2dp[sw_dpid].ofproto.OFP_NO_BUFFER,
                                              in_port=self.dpid2dp[sw_dpid].ofproto.OFPP_CONTROLLER,
                                              actions=actions, data=arp_request.data)
                    self.dpid2dp[sw_dpid].send_msg(out)
                    # print


            # print request_queue
            # self.logger.info("      request_queue:")
            # for arp_request_Ip in self.request_queue:
            #     self.logger.info("      request_ip:%s ->", arp_request_Ip)
            #     for key, value in self.request_queue[arp_request_Ip].items():
            #         self.logger.info("          %s in dpid %s", key, value)
            # self.logger.info("")
            # time.sleep(0.005)

    def arp_reply_handler(self, arp_packet):
        src_ip = arp_packet.src_ip
        src_mac = arp_packet.src_mac
        src_dpid = self.hosts[src_mac].dpid
        # self.logger.info("      handling arp_reply!")
        # find information of pending_ip and encapsulate the arp_reply and sent to the respective port of switch
        # for pending_ip in self.request_queue[src_ip]:
        while self.request_queue[src_ip].__len__() != 0:
            # find information of pending_ip:
            pending_ip, pending_dpid = self.request_queue[src_ip].popitem()
            pending_mac = self.ip2host_info[pending_ip].mac
            pending_port = self.hosts[pending_mac].port_no
            # self.logger.info("      find  pending_ip:%s, pending_mac:%s in dpid :%s in port:%s for requested_ip:%s",
            #                  pending_ip, pending_mac, pending_dpid, pending_port, src_ip)

            arp_reply = self.encapsulate_ARP_reply(src_mac=src_mac, src_ip=src_ip,
                                                   dst_mac=pending_mac, dst_ip=pending_ip)

            # encapsulate the arp_reply and sent to the respective port of switch

            actions = [self.dpid2dp[pending_dpid].ofproto_parser.OFPActionOutput(pending_port, 0)]
            out = self.dpid2dp[pending_dpid].ofproto_parser.OFPPacketOut(
                    datapath=self.dpid2dp[pending_dpid],
                    buffer_id=self.dpid2dp[pending_dpid].ofproto.OFP_NO_BUFFER,
                    in_port=self.dpid2dp[pending_dpid].ofproto.OFPP_CONTROLLER,
                    actions=actions, data=arp_reply.data)

            # self.logger.info("      install flow from %s to %s", pending_mac, src_mac)
            # print"      install path..."
            path = self.dijkstra(pending_dpid, src_dpid)
            self.install_path_flow(pending_mac, src_mac, path)
            path.reverse()
            self.install_path_flow(src_mac, pending_mac, path)
            # print"      install finish!"
            time.sleep(0.005)
            # self.logger.info("      encapsulate ARP reply and sent to dpid:%s port:%s!\n", pending_dpid,
            #                  pending_port)
            self.dpid2dp[pending_dpid].send_msg(out)

        self.request_queue.pop(src_ip)

    def dijkstra(self, src_dpid, dst_dpid):
        # init
        if src_dpid == dst_dpid:
            return [src_dpid]
        distances = self.dp_map[src_dpid].copy()
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

        # find path
        last = dst_dpid
        path = []
        while last != src_dpid:
            path.append(last)
            last = pre[last]
        path.append(src_dpid)
        path.reverse()
        return path

    def find_shortest_path(self, src, dst):  # find the shortest path from host_src to dst_src
        src_dpid = self.hosts[src].dpid
        dst_dpid = self.hosts[dst].dpid
        path = self.dijkstra(src_dpid, dst_dpid)
        return path

    def _install_one_path_flow(self, dpid, src_mac, dst_mac, output):
        dp = self.dpid2dp[dpid]
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(output)]
        # self.logger.info("install flow to %s, match:dl_src=%s,dl_src=%s,output=%s",
        #                  dpid, src_mac, dst_mac, output)
        self.add_flow(dp, 9, match, actions)
        return

    def install_path_flow(self, src_mac, dst_mac, path):
        for i in range(len(path)):
            if i == len(path) - 1:  # for the access switch
                output = self.hosts[dst_mac].port_no
                dpid = path[i]
                self._install_one_path_flow(dpid, src_mac, dst_mac, output)
                return

            dpid = path[i]
            dst_dpid = path[i + 1]
            output = self.links[(dpid, dst_dpid)][0]
            self._install_one_path_flow(dpid, src_mac, dst_mac, output)

    def encapsulate_ARP_request(self, src_mac, src_ip, dst_ip):
        ARP = packet.Packet()
        ARP.add_protocol(ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=src_mac,
                                           ethertype=ether_types.ETH_TYPE_ARP))
        ARP.add_protocol(arp.arp_ip(arp.ARP_REQUEST, src_mac=src_mac,
                                    src_ip=src_ip, dst_mac="ff:ff:ff:ff:ff:ff", dst_ip=dst_ip))
        ARP.serialize()
        return ARP

    def ip_register(self, pkt):
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        host_mac = eth.src

        # arp packet, update ip address
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocols(arp.arp)[0]
            host_ip = arp_pkt.src_ip
            if host_ip in self.ip2host_info and self.ip2host_info[host_ip].mac == host_mac:
                # the ip'mac have been recorded, then update the stamp
                self.ip2host_info[host_ip].update_stamp()
            else:
                # the ip's mac have changed or haven't been recorded, then set the host_info to this ip
                self.ip2host_info.setdefault(host_ip, Host_info(host_mac, host_ip))

        # ipv4 packet, update ipv4 address
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            host_ip = ipv4_pkt.src
            if host_ip in self.ip2host_info:
                self.ip2host_info[host_ip].update_stamp()
            else:
                self.ip2host_info.setdefault(host_ip, Host_info(host_mac, host_ip))

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # set default= packetIn
        # drop IPV6,UDP
        # ARP packetIn
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.dpid2dp[datapath.id] = datapath

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
        match_filter2 = parser.OFPMatch(eth_type=0x0800, ip_proto=17)  # solve the question  . to filter udp,
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

        if in_port in self.access_port[dpid]:
            # host learning
            self.ip_register(pkt)
            self.hosts[src] = Host(dpid, in_port, src)

        # self.logger.info("\npacket in dpid:%s src:%s dst:%s in_port:%s ", dpid, src, dst, in_port)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            # ARP handler
            # self.logger.info("  handling arp!")
            arp_packet = pkt.get_protocol(arp.arp)

            # print arp_table
            # self.logger.info("  Current arp_table:")
            # self.logger.info("     ip          mac          enabled")
            # for key, value in self.ip2host_info.items():
            #     value.is_enable()
                # self.logger.info("  %s->%s  %s", key, value.mac, value.enabled)
            # self.logger.info("")

            # arp_request
            if arp_packet.opcode == arp.ARP_REQUEST:
                self.arp_request_handler(arp_packet)

            # arp_reply
            elif arp_packet.opcode == arp.ARP_REPLY:
                self.arp_reply_handler(arp_packet)

        return
