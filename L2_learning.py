# -*- coding: utf-8 -*-
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin


class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)  # 继承函数
        self.mac_to_port = {}  # MAC端口对应的dict，具体结构mac_to_port={dpid1:{mac1:port1,mac2:port2,...},
        #              dpid2: {mac1:port1,mac2:port2,},...

    def addFlow(self, datapath, in_port, dst, actions):

        # 添加流表项，datapath为交换机与控制器的连接，in_port为输入的端口，dst为目的MAC，action为行动

        ofproto = datapath.ofproto  # 连接的协议类型 这里应该是openflow1.0

        match = datapath.ofproto_parser.OFPMatch(in_port=in_port,
                                                 dl_dst=haddr_to_bin(dst))  # 匹配，设置流表项的匹配规则，这里是匹配输入端口和目的MAC

        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, cookie=0,
                                                 # 构造flowmode包，包括header，match，mode（包括command等），actions
                                                 command=ofproto.OFPFC_ADD,
                                                 flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)  # 发送flowmode

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)  # 每次controller收到packetIn时就会调用下下面的函数，第二个参数指出交换机的状态
    def packet_in_handler(self, ev):
        msg = ev.msg  # 获得packetIn的数据结构
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            self.addFlow(datapath, msg.in_port, dst, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:  # 如果交换机不支持缓存，则把整个网包全部发送给控制器，这是控制器许
            data = msg.data  # 这是控制器发送packetOut时需要把网包发回。故"data=msg.data"

        out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
        datapath.send_msg(out)

        @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
        def port_status_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto

            if msg.reason == ofp.OFPPR_ADD:
                reason = 'ADD'
            elif msg.reason == ofp.OFPPR_DELETE:
                reason = 'DELETE'
            elif msg.reason == ofp.OFPPR_MODIFY:
                reason = 'MODIFY'
            else:
                reason = 'unknown'

            self.logger.debug('OFPPortStatus received: reason=%s desc=%s',
                              reason, msg.desc)
