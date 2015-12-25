from mininet.topo import Topo

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

"""this is a tree topo,depth=2,fanout=3"""
fanout = 2


class MyTopo(Topo):
    def addMultiHost(self, n=2):
        for i in xrange(n):
            self.host_list.append(self.addHost("h%s" % (i + 1)))

    def addMultiSwitch(self, n=1):
        for i in xrange(n):
            self.switch_list.append(self.addSwitch("s%s" % (i + 1)))

    def __init__(self):

        Topo.__init__(self)
        hostNumPer=fanout
        switchNum=fanout
        self.host_list = []
        self.switch_list = []
        hostNum = hostNumPer * switchNum
        self.addMultiHost(hostNum)
        self.addMultiSwitch(switchNum + 1)  # "+1"because there is a aggregated switch
        # link switches to aggregated switch
        for i in xrange(switchNum):
            self.addLink(self.switch_list[i], self.switch_list[switchNum])

        # link host to switch
        for i in xrange(switchNum):
            for j in xrange(hostNumPer):
                self.addLink(self.host_list[i * hostNumPer + j], self.switch_list[i])


    # def build(self, hostNumPer=fanout, switchNum=fanout):
    #     self.host_list = []
    #     self.switch_list = []
    #     hostNum = hostNumPer * switchNum
    #     self.addMultiHost(hostNum)
    #     self.addMultiSwitch(switchNum + 1)  # "+1"because there is a aggregated switch
    #     # link switches to aggregated switch
    #     for i in xrange(switchNum):
    #         self.addLink(self.switch_list[i], self.switch_list[switchNum])
    #
    #     # link host to switch
    #     for i in xrange(switchNum):
    #         for j in xrange(hostNumPer):
    #             self.addLink(self.host_list[i * hostNumPer + j], self.switch_list[i])

topos = {'mytopo': (lambda: MyTopo())}