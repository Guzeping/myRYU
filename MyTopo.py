#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel


class MyTopo(Topo):
    "My Topology example."

    def addMultiHost(self, n=2):
        for i in xrange(n):
            self.host_list.append(self.addHost("h%s" % (i + 1)))

    def addMultiSwitch(self, n=1):
        for i in xrange(n):
            self.switch_list.append(self.addSwitch("s%s" % (i + 1)))

    def build(self, hostNumPer=3, switchNum=3):
        self.host_list = []
        self.switch_list = []
        hostNum=hostNumPer*switchNum
        self.addMultiHost(hostNum)
        self.addMultiSwitch(switchNum)
        # link switch to switch
        # for i in xrange(switchNum):
        #     for j in xrange(switchNum):
        #         if i < j:
        #             self.addLink(self.switch_list[i], self.switch_list[j])

        # link host to switch
        for i in xrange(switchNum):
            for j in xrange(hostNumPer):
                self.addLink(self.host_list[i * hostNumPer + j], self.switch_list[i])


def simpleTest():
    """Create and test a simple network"""
    topo = MyTopo(hostNumPer=4, switchNum=3)
    net = Mininet(topo)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")
    net.pingAll()
    net.stop()

if __name__=="__main__":
    setLogLevel("info")
    simpleTest()
