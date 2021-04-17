# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import matplotlib.pyplot as plt
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,  DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.ofproto import ofproto_v1_5_parser
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_4_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from operator import attrgetter
from ryu.lib import hub

from ryu.topology.api import get_switch, get_link
from ryu.topology import event, switches 
import networkx as nx

from ryu import utils
# Check https://osrg.github.io/ryu-book/en/html/traffic_monitor.html
# 1414bb8be75b83033d6b721e8600f674da719307

# workaround for statsreply of OF15 as suggested by https://www.mail-archive.com/ryu-devel@lists.sourceforge.net/msg14569.html

class OFPFlowStatsReply(ofproto_v1_5_parser.OFPMultipartReply,
                        ofproto_v1_4_parser.OFPFlowStatsReply):
    pass


ofproto_v1_5_parser.OFPMultipartReply._STATS_MSG_TYPES[
    # Note: not OFPMP_FLOW_STATS(=17), use OFPMP_FLOW_DESC(=1)
    ofproto_v1_5.OFPMP_FLOW_DESC] = OFPFlowStatsReply




class SimpleSwitch15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #below two are from simple monitor
        self.datapaths = {}
        self.query_interval = 2
        
        ###################################################
        #self.monitor_thread = hub.spawn(self._monitor)####
        ###################################################

        self.rate_limited_switches = []
        self.switch_interfaces = ["s1-eth3", "s2-eth3", "s3-eth1", "s3-eth2", "s3-eth3", "s4-eth1", "s4-eth2",
                                          "s5-eth1", "s5-eth2", "s5-eth3", "s6-eth3", "s7-eth3"]
        self.switch_dpids = {0x1: "s1", 0x2: "s2", 0x3: "s3", 0x4: "s4", 0x5: "s5", 0x6: "s6", 0x7: "s7"}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.nodes = {}
        self.links = {}
        self.no_of_nodes = 0
        self.no_of_links = 0
        self.i=0

        self.link_to_port = {}                 # {(src_dpid,dst_dpid):(src_port,dst_port),}
        self.access_table = {}                # {(sw,port):(ip, mac),}
        self.switch_port_table = {}      # {dpid:set(port_num,),}
        self.access_ports = {}                # {dpid:set(port_num,),}
        self.interior_ports = {}              # {dpid:set(port_num,),}
        self.switches = []                         # self.switches = [dpid,]
        self.shortest_paths = {}            # {dpid:{dpid:[[path],],},}
        self.pre_link_to_port = {}
        self.pre_access_table = {}
        self.graph = nx.DiGraph()
        # Get initiation delay.
        self.initiation_delay = 20
        self.start_time = time.time()
        self.discover_thread = hub.spawn(self._discover)


    def _discover(self):
        self.get_topology(None)
        #i = 0
        #while True:
        #    self.show_topology()
        #    if i == 2:   # Reload topology every 20 seconds.
        #        self.get_topology(None)
        #        i = 0
        #    hub.sleep(setting.DISCOVERY_PERIOD)
        #    i = i + 1


    # Handy function that lists all attributes in the given object
    def ls(self,obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    # Convert from byte count delta to bitrate
    def bitrate(self, bytes):
        return bytes * 8.0 / (self.query_interval * 1024)


    @set_ev_cls(events)
    def get_topology(self, ev):
        """
            Get topology info and calculate shortest paths.
            Note: In looped network, we should get the topology
            20 or 30 seconds after the network went up.
        """
        present_time = time.time()
        if present_time - self.start_time < self.initiation_delay:
            return

        self.logger.info("[GET NETWORK TOPOLOGY]")
        switch_list = get_switch(self.topology_api_app, None)
        self.create_port_map(switch_list)
        self.switches = [sw.dp.id for sw in switch_list]
        links = get_link(self.topology_api_app, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.graph = self.get_graph(self.link_to_port.keys())
        self.shortest_paths = self.all_k_shortest_paths(
            self.graph, weight='weight', k=4)

    def create_port_map(self, switch_list):
        """
            Create interior_port table and access_port table.
        """
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            # switch_port_table is equal to interior_ports plus access_ports.
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())
            for port in sw.ports:
                # switch_port_table = {dpid:set(port_num,),}
                self.switch_port_table[dpid].add(port.port_no)

    def create_interior_links(self, link_list):
        """
            Get links' srouce port to dst port  from link_list.
            link_to_port = {(src_dpid,dst_dpid):(src_port,dst_port),}
        """
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            # Find the access ports and interior ports.
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    def create_access_ports(self):
        """
            Get ports without link into access_ports.
        """
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            # That comes the access port of the switch.
            self.access_ports[sw] = all_port_table - interior_port

    def get_graph(self, link_list):
        """
            Get Adjacency matrix from link_to_port.
        """
        _graph = self.graph.copy()
        for src in self.switches:
            for dst in self.switches:
                if src == dst:
                    _graph.add_edge(src, dst, weight=0)
                elif (src, dst) in link_list:
                    _graph.add_edge(src, dst, weight=1)
                else:
                    pass
        return _graph

    def k_shortest_paths(self, graph, src, dst, weight='weight', k=5):
        """
            Creat K shortest paths from src to dst.
            generator produces lists of simple paths, in order from shortest to longest.
        """
        generator = nx.shortest_simple_paths(graph, source=src, target=dst, weight=weight)
        shortest_paths = []
        try:
            for path in generator:
                if k <= 0:
                    break
                shortest_paths.append(path)
                k -= 1
            return shortest_paths
        except:
            self.logger.debug("No path between %s and %s" % (src, dst))

    def all_k_shortest_paths(self, graph, weight='weight', k=5):
        """
            Creat all K shortest paths between datapaths.
            Note: We get shortest paths for bandwidth-sensitive
            traffic from bandwidth-sensitive switches.
        """
        _graph = graph.copy()
        paths = {}
        # Find k shortest paths in graph.
        for src in _graph.nodes():
            paths.setdefault(src, {src: [[src] for i in xrange(k)]})
            for dst in _graph.nodes():
                if src == dst:
                    continue
                paths[src].setdefault(dst, [])
                paths[src][dst] = self.k_shortest_paths(_graph, src, dst, weight=weight, k=k)
        return paths



    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """when the Datapath state becomes MAIN_DISPATCHER, 
        that switch is registered as the monitor target and when it becomes DEAD_DISPATCHER, 
        the registration is deleted."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.query_interval)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofp = ofproto_v1_4
        ofp_parser = ofproto_v1_4_parser
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(in_port=1)
        cookie = cookie_mask = 0
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                         ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         cookie, cookie_mask,
                                         match)
        datapath.send_msg(req)

        #req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        #datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s',
                          msg.type, msg.code, utils.hex_array(msg.data))

    # Applies ingress restriction to a high bw switch/port
    def apply_rate_limiting(self, switch, in_port, out_port, eth_dst, rate):
        c_rate = int(ceil(rate))
        switch_id = switch + "-eth" + str(in_port) + str(out_port) + str(eth_dst)
        ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=10", "ingress_policing_rate=5000"
        if not switch_id in self.rate_limited_switches:
            self.rate_limited_switches.append(switch_id)
            print "\n\n------------------- \n", "rate limiting ", switch_id, "\n-------------------"
            subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(in_port), ingressPolicingBurst])
            subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(in_port), ingressPolicingRate])

    # Removes ingress restriction to a high bw switch/port
    def revoke_rate_limiting(self, switch, in_port, out_port, eth_dst, rate):
        switch_id = switch + "-eth" + str(in_port) + str(out_port) + str(eth_dst)
        ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=0", "ingress_policing_rate=0"
        if switch_id in self.rate_limited_switches:
            self.rate_limited_switches.remove(switch_id)
            print "\n\n------------------- \n", "undo rate limiting ", switch_id, "\n-------------------"
            subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(in_port), ingressPolicingBurst])
            subprocess.call(["sudo", "ovs-vsctl", "set", "interface", switch + "-eth" + str(in_port), ingressPolicingRate])


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        ingress_policing_rate :
        the maximum rate (in Kbps) that this VM should be allowed to send
        
        ingress_policing_burst :
        a parameter to the policing algorithm to indicate the 
        maximum amount of data (in Kb) that this interface can send beyond the policing rate.
        """
        """
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

        """
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'importance=%d cookie=%d packet_count=%d '
                         'byte_count=%d match=%s instructions=%s' %
                         (stat.table_id,
                          stat.duration_sec, stat.duration_nsec,
                          stat.priority,
                          stat.idle_timeout, stat.hard_timeout,
                          stat.flags, stat.importance,
                          stat.cookie, stat.packet_count, stat.byte_count,
                          stat.match, stat.instructions))
        self.logger.debug('FlowStats: %s', flows)
        """
        body = ev.msg.body
        dpid = int(ev.msg.datapath.id)
        if CONF.topo == 'simple':
            switch = self.simple_dpids[dpid]
            switch_interfaces = self.simple_switch_interfaces
        elif CONF.topo == 'datacenter':
            switch = self.complex_dpids[dpid]
            switch_interfaces = self.complex_switch_interfaces
        print "-------------- Flow stats for switch", switch, "---------------"

        # Iterate through all statistics reported for the flow
        for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[0].port
            eth_dst = stat.match['eth_dst']

            # Check if we have a previous byte count reading for this flow
            # and calculate bandwith usage over the last polling interval
            key = (dpid, in_port, eth_dst, out_port)
            rate = 0
            if key in self.flow_byte_counts:
                cnt = self.flow_byte_counts[key]
                rate = self.bitrate(stat.byte_count - cnt)

            self.flow_byte_counts[key] = stat.byte_count
            print "In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (in_port, eth_dst, out_port, rate)

            switch_id = switch + "-eth" + str(in_port)
            if rate > self.bw_threshold:
                if not switch_id in switch_interfaces:
                    self.apply_rate_limiting(switch, in_port, out_port, eth_dst, rate)
            elif rate < self.bw_min:
                if not switch_id in switch_interfaces:
                    self.revoke_rate_limiting(switch, in_port, out_port, eth_dst, rate)
        """

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)


    #this is a features reply message that was sent from switch upron feature request by the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # @set_ev_cls(event.EventSwitchEnter)
    # def get_topology_data(self, ev):
    #     switch_list = get_switch(self.topology_api_app, None)   
    #     switches=[switch.dp.id for switch in switch_list]
    #     self.net.add_nodes_from(switches)
         
    #     #print "**********List of switches"
    #     #for switch in switch_list:
    #     #self.ls(switch)
    #     #print switch
    #     #self.nodes[self.no_of_nodes] = switch
    #     #self.no_of_nodes += 1
    
    #     links_list = get_link(self.topology_api_app, None)
    #     #print links_list
    #     links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
    #     #print links
    #     self.net.add_edges_from(links)
    #     links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
    #     #print links
    #     self.net.add_edges_from(links)
    #     print "**********List of links"
    #     print self.net.edges()
    #     #for link in links_list:
    #     #print link.dst
    #         #print link.src
    #         #print "Novo link"
    #     #self.no_of_links += 1
      
        
    #     #print "@@@@@@@@@@@@@@@@@Printing both arrays@@@@@@@@@@@@@@@"
    #     #for node in self.nodes:    
    #     #    print self.nodes[node]
    #     #for link in self.links:
    #     #    print self.links[link]
    #     #print self.no_of_nodes
    #     #print self.no_of_links

    #     #@set_ev_cls(event.EventLinkAdd)
    #     #def get_links(self, ev):
    #     #print "################Something##############"
    #     #print ev.link.src, ev.link.dst

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out


    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port of dst host.
            access_table = {(sw,port):(ip, mac),}
        """
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:   # Use the IP address only, not the MAC address. (hmc)
                        dst_port = key[1]
                        return dst_port
        return None

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
            link_to_port = {(src_dpid,dst_dpid):(src_port,dst_port),}
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("Link from dpid:%s to dpid:%s is not in links" %
             (src_dpid, dst_dpid))
            return None

            
    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
            flow_info = (eth_type, src_ip, dst_ip, in_port)
            or
            flow_info = (eth_type, src_ip, dst_ip, in_port, ip_proto, Flag, L4_port)
        """
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))
        if len(flow_info) == 7:
            if flow_info[-3] == 6:
                if flow_info[-2] == 'src':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=6, tcp_src=flow_info[-1])
                elif flow_info[-2] == 'dst':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=6, tcp_dst=flow_info[-1])
                else:
                    pass
            elif flow_info[-3] == 17:
                if flow_info[-2] == 'src':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=17, udp_src=flow_info[-1])
                elif flow_info[-2] == 'dst':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=17, udp_dst=flow_info[-1])
                else:
                    pass
        elif len(flow_info) == 4:
            match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
        else:
            pass

        self.add_flow(datapath, 30, match, actions,
                      idle_timeout=5, hard_timeout=10)

    def install_flow(self, datapaths, link_to_port, path, flow_info, buffer_id, data=None):
        '''
            Install flow entries for datapaths.
            path=[dpid1, dpid2, ...]
            flow_info = (eth_type, src_ip, dst_ip, in_port)
            or
            flow_info = (eth_type, src_ip, dst_ip, in_port, ip_proto, Flag, L4_port)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL

        # Install flow entry for intermediate datapaths.
        for i in range(1, (len(path) - 1) / 2):
            port = self.get_port_pair_from_link(link_to_port, path[i-1], path[i])
            port_next = self.get_port_pair_from_link(link_to_port, path[i], path[i+1])
            if port and port_next:
                src_port, dst_port = port[1], port_next[0]
                datapath = datapaths[path[i]]
                self.send_flow_mod(datapath, flow_info, src_port, dst_port)

        #  Install flow entry for the first datapath.
        port_pair = self.get_port_pair_from_link(link_to_port, path[0], path[1])
        if port_pair is None:
            self.logger.info("Port not found in first hop.")
            return
        out_port = port_pair[0]
        self.send_flow_mod(first_dp, flow_info, in_port, out_port)
        # Send packet_out to the first datapath.
        self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)



    def flood(self, msg):
        """
            Flood packet to the access ports which have no record of host.
            access_ports = {dpid:set(port_num,),}
            access_table = {(sw,port):(ip, mac),}
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding packet to access port")


    def register_access_info(self, dpid, in_port, ip, mac):
        """
            Register access host info into access table.
        """
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        # https://ryu.readthedocs.io/en/latest/ofproto_v1_5_ref.html#ryu.ofproto.ofproto_v1_5_parser.OFPMatch

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if isinstance(arp_pkt, arp.arp):
            arp_src_ip = arp_pkt.src_ip
            mac = arp_pkt.src_mac
            # Record the access infomation.
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)
            self.logger.debug("ARP processing")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        elif isinstance(ip_pkt, ipv4.ipv4):
            ip_src_ip = ip_pkt.src
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            mac = eth.src
            # Record the access infomation.
            self.register_access_info(datapath.id, in_port, ip_src_ip, mac)
            self.logger.debug("IPV4 processing")
            if len(pkt.get_protocols(ethernet.ethernet)):
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)
        else:
            pass

        # if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        #     # ignore lldp packet
        #     return
        # dst = eth.dst
        # src = eth.src

        # dpid = datapath.id
        # self.mac_to_port.setdefault(dpid, {})

        # #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # # learn a mac address to avoid FLOOD next time.
        # self.mac_to_port[dpid][src] = in_port
        # print "SETTING == datapath : " + str(dpid) + "  src : " + str(src) + "  in_port : " + str(in_port)
        
        # if src not in self.net:
        #     self.net.add_node(src)
        #     self.net.add_edge(dpid,src,{'port':msg.in_port})
        #     self.net.add_edge(src,dpid)

        # if dst in self.net:
        #     #out_port = self.mac_to_port[dpid][dst]
        #     #print "im here with out_port : " + str(out_port) + "\n"
        #     #print self.mac_to_port
        #     path=nx.shortest_path(self.net,src,dst)   
        #     next=path[path.index(dpid)+1]
        #     out_port=self.net[dpid][next]['port']
        # else:
        #     out_port = ofproto.OFPP_FLOOD
        #     #print "flooding goes brrr..."

        # actions = [parser.OFPActionOutput(out_port)]

        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        #     print "NOTFLOOD : datapath : " + str(dpid) + "  src : " + str(src) + "  in_port : " + str(in_port) + "  dst : " + str(dst) + "  out_port : " + str(out_port) + " " 
        #     self.add_flow(datapath, 1, match, actions)

        
        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data
        # match = parser.OFPMatch(in_port=in_port)
        # out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, match=match, actions=actions, data=data)
        # #print "FLOOD : datapath : " + str(dpid) + "  in_port : " + str(in_port) + "  dst : " + str(dst) + "  out_port : " + str(out_port) + " " 
        # datapath.send_msg(out)

        # #if msg.reason == ofproto.TABLE_MISS:
        # #    reason = 'TABLE MISS'
        # #elif msg.reason == ofproto.OFPR_APPLY_ACTION:
        # #    reason = 'APPLY ACTION'
        # #elif msg.reason == ofproto.OFPR_INVALID_TTL:
        # #    reason = 'INVALID TTL'
        # #elif msg.reason == ofproto.OFPR_ACTION_SET:
        # #    reason = 'ACTION SET'
        # #elif msg.reason == ofproto.OFPR_GROUP:
        # #    reason = 'GROUP'
        # #elif msg.reason == ofproto.OFPR_PACKET_OUT:
        # #    reason = 'PACKET OUT'
        # #else:
        # reason = 'unknown'
        # #if str(out_port) != "4294967291":
        # #    print "datapath : " + str(dpid) + "  in_port : " + str(in_port) + "  dst : " + str(dst) + "  out_port : " + str(out_port) + " " 
        # #self.logger.debug('OFPPacketIn received: '
        # #             'buffer_id=%x total_len=%d reason=%s '
        # #              'table_id=%d cookie=%d match=%s data=%s dst=%s  src=%s',
        # #              msg.buffer_id, msg.total_len, reason,
        # #              msg.table_id, msg.cookie, msg.match,
        # #              utils.hex_array(msg.data), dst, src)

    def get_host_location(self, host_ip):
        """
            Get host location info ((datapath, port)) according to the host ip.
            self.access_table = {(sw,port):(ip, mac),}
        """
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.info("%s location is not found." % host_ip)
        return None

    def get_L4_info(self, tcp_pkt, udp_pkt, ip_proto, L4_port, Flag):
        """
            Get ip_proto and L4 port number.
        """
        if tcp_pkt:
            ip_proto = 6
            if tcp_pkt.src_port:
                L4_port = tcp_pkt.src_port
                Flag = 'src'
            elif tcp_pkt.dst_port:
                L4_port = tcp_pkt.dst_port
                Flag = 'dst'
            else:
                pass
        elif udp_pkt:
            ip_proto = 17
            if udp_pkt.src_port:
                L4_port = udp_pkt.src_port
                Flag = 'src'
            elif udp_pkt.dst_port:
                L4_port = udp_pkt.dst_port
                Flag = 'dst'
            else:
                pass
        else:
            pass
        return (ip_proto, L4_port, Flag)

    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None
        src_location = self.get_host_location(src)   # src_location = (dpid, port)
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None
        dst_location = self.get_host_location(dst)   # dst_location = (dpid, port)
        if dst_location:
            dst_sw = dst_location[0]
        if src_sw and dst_sw:
            return src_sw, dst_sw
        else:
            return None


    def arp_forwarding(self, msg, src_ip, dst_ip):
        """
            Send ARP packet to the destination host if the dst host record
            is existed, else flow it to the unknow access port.
            result = (datapath, port)
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto

        result = self.get_host_location(dst_ip)
        if result:
            # Host has been recorded in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Deliver ARP packet to knew host")
        else:
            # Flood is not good.
            self.flood(msg)


    def get_path(self, src, dst, weight):
        """
            Get shortest path from network_awareness module.
            generator (nx.shortest_simple_paths( )) produces
            lists of simple paths, in order from shortest to longest.
        """
        shortest_paths = self.shortest_paths
        # Create bandwidth-sensitive datapath graph.
        graph = self.graph

        if weight == self.WEIGHT_MODEL['hop']:
            return shortest_paths.get(src).get(dst)[0]
        elif weight == self.WEIGHT_MODEL['bw']:
            # Because all paths will be calculated when we call self.monitor.get_best_path_by_bw,
            # so we just need to call it once in a period, and then, we can get path directly.
            # If path is existed just return it, else calculate and return it.
            try:
                path = self.monitor.best_paths.get(src).get(dst)
                return path
            except:
                result = self.monitor.get_best_path_by_bw(graph, shortest_paths)
                # result = (capabilities, best_paths)
                paths = result[1]
                best_path = paths.get(src).get(dst)
                return best_path
        else:
            pass

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            Calculate shortest forwarding path and Install them into datapaths.
            flow_info = (eth_type, src_ip, dst_ip, in_port)
            or
            flow_info = (eth_type, ip_src, ip_dst, in_port, ip_proto, Flag, L4_port)
        """
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        ip_proto = None
        L4_port = None
        Flag = None
        # Get ip_proto and L4 port number.
        ip_proto, L4_port, Flag = self.get_L4_info(tcp_pkt, udp_pkt, ip_proto, L4_port, Flag)
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)   # result = (src_sw, dst_sw)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # Path has already been calculated, just get it.
                path = self.get_path(src_sw, dst_sw, weight=self.weight)
                if ip_proto and L4_port and Flag:
                    if ip_proto == 6:
                        L4_Proto = 'TCP'
                    elif ip_proto == 17:
                        L4_Proto = 'UDP'
                    else:
                        pass
                    self.logger.info("[PATH]%s<-->%s(%s Port:%d): %s" % (ip_src, ip_dst, L4_Proto, L4_port, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port, ip_proto, Flag, L4_port)
                else:
                    self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port)
                # Install flow entries to datapaths along the path.
                self.install_flow(self.datapaths,
                                  self.awareness.link_to_port,
                                  path, flow_info, msg.buffer_id, msg.data)
        else:
            # Flood is not good.
            self.flood(msg)


    def show_topology(self):
        if self.pre_link_to_port != self.link_to_port and setting.TOSHOW:
            # It means the link_to_port table has changed.
            _graph = self.graph.copy()
            print "\n---------------------Link Port---------------------"
            print '%6s' % ('switch'),
            for node in sorted([node for node in _graph.nodes()], key=lambda node: node):
                print '%6d' % node,
            print
            for node1 in sorted([node for node in _graph.nodes()], key=lambda node: node):
                print '%6d' % node1,
                for node2 in sorted([node for node in _graph.nodes()], key=lambda node: node):
                    if (node1, node2) in self.link_to_port.keys():
                        print '%6s' % str(self.link_to_port[(node1, node2)]),
                    else:
                        print '%6s' % '/',
                print
            print
            self.pre_link_to_port = self.link_to_port.copy()

        if self.pre_access_table != self.access_table and setting.TOSHOW:
            # It means the access_table has changed.
            print "\n----------------Access Host-------------------"
            print '%10s' % 'switch', '%10s' % 'port', '%22s' % 'Host'
            if not self.access_table.keys():
                print "    NO found host"
            else:
                for sw in sorted(self.access_table.keys()):
                    print '%10d' % sw[0], '%10d      ' % sw[1], self.access_table[sw]
            print
            self.pre_access_table = self.access_table.copy()