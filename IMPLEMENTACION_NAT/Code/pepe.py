#!/usr/bin/env python

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import packet_utils
from ryu.lib.packet.packet import Packet
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.base import app_manager
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac
from ryu.lib import hub
from ryu.lib.mac import haddr_to_bin
from ryu.ofproto import ether
from ryu.ofproto import inet
from netaddr.ip import IPNetwork
from netaddr.ip import IPAddress
import random

class NAT(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs): #Inicializamos las variables
        super(NAT, self).__init__(*args, **kwargs)

        self.ports_to_ips = [('192.168.1.1','255.255.255.0','00:00:00:00:00:50'),
                             ('10.0.0.69','255.255.255.0','00:00:00:00:00:60')]

        self.tablaEnrutamiento = [('192.168.1.0','255.255.255.0',1,None),
                                  ('10.0.0.0','255.255.255.0',2,None)]

        self.tablaNat = []
        self.tablaNat_Icmp = []
        self.arp_cache = {}
        self.queue={}
        self.used_ports = []

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        if buffer_id:
             mod = parser.OFPFlowMod(datapath=datapath,
                                     buffer_id=buffer_id,
                                     priority=priority,
                                     match=match,
                                     instructions=inst,
                                     idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout)
        else:
             mod = parser.OFPFlowMod(datapath=datapath,
                                     priority=priority,
                                     match=match,
                                     instructions=inst,
                                     idle_timeout=idle_timeout,
                                     hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def event_switch_enter_handler(self, ev):
        msg =ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        self.add_flow(datapath=dp, priority=0, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']

        if (eth.ethertype == ether.ETH_TYPE_ARP):
            print "Paquete ARP"
            self.receive_arp(datapath, pkt, in_port)

        elif (eth.ethertype == ether.ETH_TYPE_IP):
            ip = pkt.get_protocol(ipv4.ipv4)

            self.arp_cache.setdefault(in_port, {})
            self.arp_cache[in_port][ip.src]=eth.src

            self.forward(msg)

    def receive_arp(self,datapath, packet, in_port):
        a = packet.get_protocol(arp.arp)

        if a.opcode==1: # Request
            print "Request"
            self.arp_reply(a.src_ip, a.src_mac, in_port,  datapath)
            print self.arp_cache

        elif a.opcode==2: # Reply
            print "Reply"
            self.arp_cache.setdefault(in_port, {})
            self.arp_cache[in_port][a.src_ip] = a.src_mac

            # Sacamos de cola y procesamos los forward
            self.queue.setdefault(in_port,{})
            self.queue[in_port].setdefault(a.src_ip, [])
            for msg in self.queue[in_port][a.src_ip]:
                self.set_forward_rules(msg, in_port)

            self.queue[in_port][a.src_ip] = []

    def arp_reply(self,ip,mac, port, datapath):
        mac_dst = self.ports_to_ips[port-1][2]
        ip_dst = self.ports_to_ips[port-1][0]

        e = ethernet.ethernet(dst=mac,
                              src=mac_dst,
                              ethertype=ether.ETH_TYPE_ARP)

        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                    src_mac=mac_dst, src_ip=ip_dst,
                    dst_mac=mac, dst_ip=ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        self.send_packet(datapath, port, p)


    def arp_request(self,ip, port, datapath):
        mac_dst = self.ports_to_ips[port-1][2]
        ip_dst = self.ports_to_ips[port-1][0]
        e = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff',
            src=mac_dst,
            ethertype=ether.ETH_TYPE_ARP)

        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=1,
            src_mac=mac_dst, src_ip=ip_dst,
            dst_mac='00:00:00:00:00:00', dst_ip=ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)

        self.send_packet(datapath, port, p)

    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def decide_port(self, port):
        if port==1:
            return 2
        else:
            return 1

    def tabla_nat_exist_public_icmp(self,cabecera_ip):
        Tmp=None

        for em in self.tablaNat_Icmp:
            if em[2] == cabecera_ip.src:
                Tmp=em

        if Tmp == None:
            self.tablaNat_Icmp.append([cabecera_ip.src,self.ports_to_ips[1][0],cabecera_ip.dst])
            Tmp=self.tablaNat_Icmp[-1]

        return Tmp

    def tabla_nat_exist_public(self,cabecera_ip,cabecera_protocol):
        Tmp=None

        for em in self.tablaNat:
            if cabecera_protocol.dst_port == em[3]:
                Tmp=em

        return Tmp

    def tabla_nat_exist(self,cabecera_ip,cabecera_protocol):
        Tmp=None

        for em in self.tablaNat:
            if ((cabecera_ip.src == em[0]) and (cabecera_protocol.src_port == em[1])):
                Tmp=em

        for em in self.tablaNat:
            if cabecera_protocol.dst_port == em[3]:
                Tmp=em

        if Tmp == None:
            nuevo_puerto = random.randint(5000,5010)
            while nuevo_puerto in self.used_ports:
                nuevo_puerto = random.randint(5000,5010)
            print "PUERTO A INSERTAR: ", nuevo_puerto
            self.used_ports.append(nuevo_puerto)

            self.tablaNat.append([cabecera_ip.src,cabecera_protocol.src_port,self.ports_to_ips[1][0],nuevo_puerto])
            return self.tablaNat[-1]

        return Tmp

    def set_forward_rules(self,msg,port):

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt=packet.Packet(msg.data)
        eth=pkt.get_protocol(ethernet.ethernet)
        ip=pkt.get_protocol(ipv4.ipv4)

        cabecera_tcp = pkt.get_protocol(tcp.tcp)
        cabecera_udp = pkt.get_protocol(udp.udp)

        in_port = msg.match['in_port']

        if cabecera_tcp: #Se trata de un paquete TCP
            R_Nat = self.tabla_nat_exist(ip,cabecera_tcp)
            print "TCP"

            if in_port != 2: #Proviene de la red privada
                print "PROVIENE DE LA RED PRIVADA"
                print R_Nat

                match = datapath.ofproto_parser.OFPMatch(eth_src=eth.src,
                                                         eth_type=ether.ETH_TYPE_IP,
                                                         ip_proto=inet.IPPROTO_TCP,
                                                         ipv4_dst=ip.dst,
                                                         tcp_dst=cabecera_tcp.dst_port,
                                                         tcp_src=cabecera_tcp.src_port)
                actions = [
                    datapath.ofproto_parser.OFPActionSetField(tcp_src=R_Nat[3]),
                    datapath.ofproto_parser.OFPActionSetField(ipv4_src=R_Nat[2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self.ports_to_ips[port-1][2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=self.arp_cache[port][ip.dst]),
                    datapath.ofproto_parser.OFPActionOutput(port)
                    ]
                print " - Se ha modificado el puerto de origen por: ", R_Nat[3]
                print " - Se ha modificado la ip de origen por:", R_Nat[2]
                print " - Se ha modificado la MAC de origen por: ", self.ports_to_ips[port-1][2]
                print " - Se ha lanzado por la interfaz: ", port
                print " - Se ha modificado la MAC de destino por: ", self.arp_cache[port][ip.dst]

            else:
                print "PROVIENE DE LA RED PUBLICA"
                match = datapath.ofproto_parser.OFPMatch(eth_src=eth.src,
                                                         eth_type=ether.ETH_TYPE_IP,
                                                         ip_proto=inet.IPPROTO_TCP,
                                                         ipv4_dst=R_Nat[2],
                                                         tcp_dst=R_Nat[3])
                actions = [
                    datapath.ofproto_parser.OFPActionSetField(tcp_dst=R_Nat[1]),
                    datapath.ofproto_parser.OFPActionSetField(ipv4_dst=R_Nat[0]),
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self.ports_to_ips[port-1][2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=self.arp_cache[port][R_Nat[0]]),
                    datapath.ofproto_parser.OFPActionOutput(port)
                    ]
                print " - Se ha modificado el puerto de destino por: ", R_Nat[1]
                print " - Se ha modificado la ip de destino por: ", R_Nat[0]
                print " - Se ha modificado la MAC de origen por: ", self.ports_to_ips[port-1][2]
                print " - Se ha lanzado por la interfaz: ", (port)
                print " - Se ha modificado la MAC de destino por: ", self.arp_cache[port][R_Nat[0]]

        elif cabecera_udp: #Se trata de un paquete UDP
            R_Nat = self.tabla_nat_exist(cabecera_ip,cabecera_udp)
            print "UDP"

            if in_port != 2: #Proviene de la red privada
                print "PROVIENE DE LA RED PRIVADA"
                match = datapath.ofproto_parser.OFPMatch(eth_src=eth.src,
                                                         eth_type=ether.ETH_TYPE_IP,
                                                         ip_proto=inet.IPPROTO_UDP,
                                                         ipv4_dst=ip.dst,
                                                         udp_dst=cabecera_udp.dst_port,
                                                         udp_src=cabecera_udp.src_port)
                actions = [
                    datapath.ofproto_parser.OFPActionSetField(udp_src=R_Nat[3]),
                    datapath.ofproto_parser.OFPActionSetField(ipv4_src=R_Nat[2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self.ports_to_ips[port-1][2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=self.arp_cache[port][ip.dst]),
                    datapath.ofproto_parser.OFPActionOutput(port)
                    ]
                print " - Se ha modificado el puerto de origen por: ", R_Nat[3]
                print " - Se ha modificado la ip de origen por:", R_Nat[2]
                print " - Se ha modificado la MAC de origen por: ", self.ports_to_ips[port-1][2]
                print " - Se ha lanzado por la interfaz: ", port
                print " - Se ha modificado la MAC de destino por: ", self.arp_cache[port][ip.dst]

            else:
                print "PROVIENE DE LA RED PUBLICA"
                match = datapath.ofproto_parser.OFPMatch(eth_src=eth.src,
                                                         eth_type=ether.ETH_TYPE_IP,
                                                         ip_proto=inet.IPPROTO_UDP,
                                                         ipv4_dst=R_Nat[2],
                                                         udp_dst=R_Nat[3])
                actions = [
                    datapath.ofproto_parser.OFPActionSetField(udp_dst=R_Nat[1]),
                    datapath.ofproto_parser.OFPActionSetField(ipv4_dst=R_Nat[0]),
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self.ports_to_ips[port-1][2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=self.arp_cache[port][R_Nat[0]]),
                    datapath.ofproto_parser.OFPActionOutput(port)
                    ]
                print " - Se ha modificado el puerto de destino por: ", R_Nat[1]
                print " - Se ha modificado la ip de destino por: ", R_Nat[0]
                print " - Se ha modificado la MAC de origen por: ", self.ports_to_ips[port-1][2]
                print " - Se ha lanzado por la interfaz: ", (port)
                print " - Se ha modificado la MAC de destino por: ", self.arp_cache[port][R_Nat[0]]

        else:
            print "ICMP"
            R_Nat = self.tabla_nat_exist_public_icmp(ip)

            if in_port != 2: #Proviene de la red privada
                print "PROVIENE DE LA RED PRIVADA"

                match = datapath.ofproto_parser.OFPMatch(eth_src=eth.src,
                                                         eth_type=ether.ETH_TYPE_IP,
                                                         ip_proto=inet.IPPROTO_ICMP,
                                                         ipv4_dst=ip.dst)
                actions = [
                    datapath.ofproto_parser.OFPActionSetField(ipv4_src=R_Nat[1]),
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self.ports_to_ips[port-1][2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=self.arp_cache[port][ip.dst]),
                    datapath.ofproto_parser.OFPActionOutput(port)
                    ]
                print " - Se ha modificado la ip de origen por:", R_Nat[1]
                print " - Se ha modificado la MAC de origen por: ", self.ports_to_ips[port-1][2]
                print " - Se ha lanzado por la interfaz: ", port
                print " - Se ha modificado la MAC de destino por: ", self.arp_cache[port][ip.dst]

            else:
                print "PROVIENE DE LA RED PUBLICA"
                match = datapath.ofproto_parser.OFPMatch(eth_src=eth.src,
                                                         eth_type=ether.ETH_TYPE_IP,
                                                         ip_proto=inet.IPPROTO_ICMP,
                                                         ipv4_dst=R_Nat[1])
                actions = [
                    datapath.ofproto_parser.OFPActionSetField(ipv4_dst=R_Nat[0]),
                    datapath.ofproto_parser.OFPActionSetField(eth_src=self.ports_to_ips[port-1][2]),
                    datapath.ofproto_parser.OFPActionSetField(eth_dst=self.arp_cache[port][R_Nat[0]]),
                    datapath.ofproto_parser.OFPActionOutput(port)
                    ]
                print " - Se ha modificado la ip de destino por: ", R_Nat[0]
                print " - Se ha modificado la MAC de origen por: ", self.ports_to_ips[port-1][2]
                print " - Se ha lanzado por la interfaz: ", (port)
                print " - Se ha modificado la MAC de destino por: ", self.arp_cache[port][R_Nat[0]]

        self.add_flow(datapath=datapath, priority=1, match=match, actions=actions, buffer_id=msg.buffer_id)

    def forward(self, msg):
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        in_port = msg.match['in_port']
        port = self.decide_port(in_port)
        R_Nat=None

        if in_port == 1:
            ip_dst=ip.dst
        else:
            cabecera_tcp = pkt.get_protocol(tcp.tcp)
            cabecera_udp = pkt.get_protocol(udp.udp)
            pkt_icmp = pkt.get_protocol(icmp.icmp)

            if cabecera_tcp:
                R_Nat = self.tabla_nat_exist_public(ip,cabecera_tcp)
                print R_Nat
                ip_dst=R_Nat[0]
            elif cabecera_udp:
                R_Nat = self.tabla_nat_exist_public(ip,cabecera_udp)
                ip_dst=R_Nat[0]
            else:
                R_Nat = self.tabla_nat_exist_public_icmp(ip)
                ip_dst=R_Nat[0]

            if R_Nat == None:
                ip_dst=ip.dst

        self.arp_cache.setdefault(port, {})
        if ip_dst in self.arp_cache[port].keys():
            print "Sale"
            self.set_forward_rules(msg, port)
        else:
            print "Cola"
            print self.arp_cache
            self.arp_request(ip_dst,port,datapath)
            self.queue.setdefault(port,{})
            self.queue[port].setdefault(ip,[])
            self.queue[port][ip].append(msg)
