""" Custom topology

host--switch--host

"""

from mininet.topo import Topo
from mininet.net import Mininet

class MyTopo (Topo):

	def __init__(self) :

		Topo.__init__(self)

		h1 = self.addHost('h1', ip="192.168.1.2/24",defaultRoute='via 192.168.1.1')
		h2 = self.addHost('h2', ip="10.0.0.2/24", defaultRoute='via 10.0.0.69')
		switch = self.addSwitch('s1')

		self.addLink(h1, switch)
		self.addLink(switch, h2)

topos = { 'mytopo': (lambda: MyTopo()) }
