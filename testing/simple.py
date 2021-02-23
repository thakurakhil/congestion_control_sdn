from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import Link
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm
from functools import partial
from mininet.log import setLogLevel
from mininet.node import OVSSwitch


class MyTopo( Topo ):
    def __init__( self ):
        "Create custom topo."
        Topo.__init__( self )
        h1 = self.addHost('h1', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', mac='00:00:00:00:00:02')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)


def ofp_version(switch, protocols):
    # protocols_str = ','.join(protocols)
    command = 'ovs-vsctl set bridge %s protocols=%s' % (switch, protocols)
    # print command
    # print command.split(' ')
    switch.cmd(command)


if '__main__' == __name__:
    setLogLevel('info')
    topo = MyTopo()
    switch = partial(OVSSwitch, protocols='OpenFlow15')
    controller = RemoteController('c1', ip='127.0.0.1', port=6633)
    #net = Mininet(topo=topo, autoStaticArp=True, autoSetMacs=True)
    net = Mininet(topo=topo, autoSetMacs=True, controller=controller, switch=switch)
    #c0 = net.addController('Ryu', controller=RemoteController, ip='127.0.0.1', protocols='OpenFlow13', port=6633)
    net.start()
    # net.start()
    s1, s2 = net.get('s1', 's2')

    #ofp_version(s1, 'OpenFlow13')
    #ofp_version(s2, 'OpenFlow13')
    CLI(net)
    net.stop()