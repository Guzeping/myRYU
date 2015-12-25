from mininet.topo import Topo


class MyTopo(Topo):
    "Simple topology example."

    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)
        hostNumPer = 4
        switchNum = 3
        self.host_list = []
        self.switch_list = []
        hostNum = hostNumPer * switchNum
        self.addMultiHost(hostNum)
        self.addMultiSwitch(switchNum)
        # link switch to switch
        for i in xrange(switchNum):
            for j in xrange(switchNum):
                if i < j:
                    self.addLink(self.switch_list[i], self.switch_list[j])
        # link host to switch
        for i in xrange(switchNum):
            for j in xrange(hostNumPer):
                self.addLink(self.host_list[i * hostNumPer + j], self.switch_list[i])

    def addMultiHost(self, n=2):
        for i in xrange(n):
            self.host_list.append(self.addHost("h%s" % (i + 1)))

    def addMultiSwitch(self, n=1):
        for i in xrange(n):
            self.switch_list.append(self.addSwitch("s%s" % (i + 1)))


topos = {'mytopo': (lambda: MyTopo())}
