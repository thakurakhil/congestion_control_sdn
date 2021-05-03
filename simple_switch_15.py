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
from __future__ import division

import matplotlib.pyplot as plt
import array
import time
import copy

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,  DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
#from ryu.ofproto import ofproto_v1_5
#from ryu.ofproto import ofproto_v1_5_parser
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_4_parser
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from operator import attrgetter
from ryu.lib import hub

from ryu.topology.api import get_switch, get_link
from ryu.topology import event, switches 
import networkx as nx

from ryu import utils
from threading import Timer

# Check https://osrg.github.io/ryu-book/en/html/traffic_monitor.html
# 1414bb8be75b83033d6b721e8600f674da719307

# workaround for statsreply of OF15 as suggested by https://www.mail-archive.com/ryu-devel@lists.sourceforge.net/msg14569.html

#class OFPFlowStatsReply(ofproto_v1_5_parser.OFPMultipartReply,
#                        ofproto_v1_4_parser.OFPFlowStatsReply):
#   pass


#ofproto_v1_5_parser.OFPMultipartReply._STATS_MSG_TYPES[
    # Note: not OFPMP_FLOW_STATS(=17), use OFPMP_FLOW_DESC(=1)
#    ofproto_v1_5.OFPMP_FLOW_DESC] = OFPFlowStatsReply


MAX_CAPACITY = 800
THRESH_CAP = 500

class SimpleSwitch15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]
    WEIGHT_MODEL = {'hop': 'weight', 'bw': 'bw'}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #below two are from simple monitor
        self.datapaths = {}
        self.query_interval = 2
        
        #self.monitor_thread = hub.spawn(self._monitor)

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
        self.initiation_delay = 10
        self.initiation_delay_route = 70
        self.start_time = time.time()
        self.discover_thread = hub.spawn(self._discover)

        self.weight = self.WEIGHT_MODEL['bw']

        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.stats = {}
        self.port_features = {}
        self.free_bandwidth = {}   # self.free_bandwidth = {dpid:{port_no:free_bw,},} unit:Kbit/s
        #self.awareness = lookup_service_brick('awareness')
        #self.graph = None
        self.capabilities = None
        self.best_paths = None
        self.flagitty = 1
        # Start to green thread to monitor traffic and calculating
        # free bandwidth of links respectively.
        self.monitor_thread = hub.spawn(self._monitorTraffic)
        self.save_freebandwidth_thread = hub.spawn(self._save_bw_graph)
        #t = Timer(30.0 + 8.0 + 15.0 , self._reroute)
        #t.start()


    def _reroute(self):
        present_time = time.time()
        self.trigger_bw_red_sw1()
        hub.sleep(100000000000000)
        return
    def _monitorTraffic(self):
        """
            Main entry method of monitoring traffic.
        """
        while self.weight == 'bw':
            self.stats['flow'] = {}
            self.stats['port'] = {}
            for dp in self.datapaths.values():
                self.port_features.setdefault(dp.id, {})
                self._request_stats(dp)
                # Refresh data.
                self.capabilities = None
                self.best_paths = None
            hub.sleep(5)
            if self.stats['flow'] or self.stats['port']:
                self.show_stat('flow')
                self.show_stat('port')
                hub.sleep(1)

    def _save_bw_graph(self):
        """
            Save bandwidth data into networkx graph object.
        """
        while self.weight == 'bw':
            self.graph = self.create_bw_graph(self.free_bandwidth)
            self.logger.debug("save free bandwidth in graph")
            hub.sleep(5)
    
    def show_topology(self):
        self.logger.info("inside show topology")
        if self.pre_link_to_port != self.link_to_port:
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

        if self.pre_access_table != self.access_table:
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

    def _discover(self):
        #self.show_topology()
        #self.get_topology(None)
        temp = 0
        while True:
            print("im here")
            self.show_topology()
            if temp == 2:   # Reload topology every 20 seconds.
                self.get_topology(None)
                temp = 0
            hub.sleep(10)
            temp = temp + 1


    def create_bw_graph(self, bw_dict):
        """
            Save bandwidth data into networkx graph object.
        """
        try:
            graph = self.graph
            link_to_port = self.link_to_port
            for link in link_to_port:
                (src_dpid, dst_dpid) = link
                (src_port, dst_port) = link_to_port[link]
                if src_dpid in bw_dict and dst_dpid in bw_dict:
                    bw_src = bw_dict[src_dpid][src_port]
                    bw_dst = bw_dict[dst_dpid][dst_port]
                    bandwidth = min(bw_src, bw_dst)
                    # Add key:value pair of bandwidth into graph.
                    if graph.has_edge(src_dpid, dst_dpid):
                        graph[src_dpid][dst_dpid]['bandwidth'] = bandwidth
                    else:
                        graph.add_edge(src_dpid, dst_dpid)
                        graph[src_dpid][dst_dpid]['bandwidth'] = bandwidth
                else:
                    if graph.has_edge(src_dpid, dst_dpid):
                        graph[src_dpid][dst_dpid]['bandwidth'] = 0
                    else:
                        graph.add_edge(src_dpid, dst_dpid)
                        graph[src_dpid][dst_dpid]['bandwidth'] = 0
            return graph
        except:
            self.logger.info("Create bw graph exception")
            #if self.awareness is None:
            #    self.awareness = lookup_service_brick('awareness')
            return self.graph

    # Handy function that lists all attributes in the given object
    def ls(self,obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    # Convert from byte count delta to bitrate
    def bitrate(self, bytes):
        return bytes * 8.0 / (self.query_interval * 1024)
    
    def _save_freebandwidth(self, dpid, port_no, speed):
        """
            Calculate free bandwidth of port and Save it.
            port_feature = (config, state, p.curr_speed)
            self.port_features[dpid][p.port_no] = port_feature
            self.free_bandwidth = {dpid:{port_no:free_bw,},}
        """
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = 800   # The true bandwidth of link, instead of 'curr_speed'.
            free_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = free_bw
            if(dpid == 3 and port_no == 1):
                print(free_bw)
            #if(free_bw <= MAX_CAPACITY - THRESH_CAP):
                #self.trigger_bw_red(dpid, port_no)
                #self.trigger_bw_red_sw1()
        else:
            self.logger.info("Port is Down")

    def trigger_bw_red_sw1(self):
        #3 is the in_port
        print("~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~trigger~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~")
        flow_info = (2048, "10.1.1.1", "10.1.4.1", 3)
        priority = 80
        path = [1, 5, 6, 8, 4]
        ofproto = ofproto_v1_4
        self.install_flow(self.datapaths,
                                   self.link_to_port,
                                   path, flow_info, ofproto.OFP_NO_BUFFER,priority, None)
        return

    def _save_stats(self, _dict, key, value, length=5):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)
        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0

    def _get_free_bw(self, capacity, speed):
        # freebw: Kbit/s
        return max(capacity - speed * 8 / 1000.0, 0)

    def _get_time(self, sec, nsec):
        return sec + nsec / 1000000000.0

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    ### to do op4 parser

    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        #self.logger.info('send stats request: %016x', datapath.id)
        #ofp = ofproto_v1_4
        ofproto = datapath.ofproto
        #ofp_parser = ofproto_v1_4_parser
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        #req = parser.OFPQueueStatsRequest(datapath, 0, ofproto.OFPP_ANY,ofproto.OFPQ_ALL)
        #datapath.send_msg(req)

    def get_min_bw_of_links(self, graph, path, min_bw):
        """
            Getting bandwidth of path. Actually, the mininum bandwidth
            of links is the path's bandwith, because it is the bottleneck of path.
        """
        _len = len(path)
        if _len > 1:
            minimal_band_width = min_bw
            for i in xrange(_len-1):
                pre, curr = path[i], path[i+1]
                if 'bandwidth' in graph[pre][curr]:
                    bw = graph[pre][curr]['bandwidth']
                    minimal_band_width = min(bw, minimal_band_width)
                else:
                    continue
            return minimal_band_width
        else:
            return min_bw

    def get_best_path_by_bw(self, graph, paths):
        """
            Get best path by comparing paths.
            Note: This function is called in EFattree module.
        """
        capabilities = {}
        best_paths = copy.deepcopy(paths)

        for src in paths:
            for dst in paths[src]:
                if src == dst:
                    best_paths[src][src] = [src]
                    capabilities.setdefault(src, {src: MAX_CAPACITY})
                    capabilities[src][src] = MAX_CAPACITY
                else:
                    max_bw_of_paths = 0
                    best_path = paths[src][dst][0]
                    for path in paths[src][dst]:
                        min_bw = MAX_CAPACITY
                        min_bw = self.get_min_bw_of_links(graph, path, min_bw)
                        if min_bw > max_bw_of_paths:
                            max_bw_of_paths = min_bw
                            best_path = path
                    best_paths[src][dst] = best_path
                    capabilities.setdefault(src, {dst: max_bw_of_paths})
                    capabilities[src][dst] = max_bw_of_paths

        # self.capabilities and self.best_paths have no actual utility in this module.
        self.capabilities = capabilities
        self.best_paths = best_paths
        return capabilities, best_paths


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
        #print(links)
        self.create_interior_links(links)
        self.create_access_ports()
        self.graph = self.get_graph(self.link_to_port.keys())
        self.shortest_paths = self.all_k_shortest_paths(
            self.graph, weight='weight', k=4)
        #print("shortest paths array :: ")
        #print self.shortest_paths
        self.logger.info("[DONE NETWORK TOPOLOGY]")
    
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
        #print("switch port table ::  ") 
        #print(self.switch_port_table)

    def create_interior_links(self, link_list):
        """
            Get links' srouce port to dst port  from link_list.
            link_to_port = {(src_dpid,dst_dpid):(src_port,dst_port),}
        """
        #print(link_list)
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            # Find the access ports and interior ports.
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)
        #print("interior link ports ::  ") 
        #print(self.link_to_port)
    

    def create_access_ports(self):
        """
            Get ports without link into access_ports.
        """
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            # That comes the access port of the switch.
            self.access_ports[sw] = all_port_table - interior_port
        #print("access port table ::  ") 
        #print(self.access_ports)


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
            self.logger.info("No path between %s and %s" % (src, dst))

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
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    # def _monitor(self):
    #     while True:
    #         for dp in self.datapaths.values():
    #             self._request_stats(dp)
    #         hub.sleep(self.query_interval)

    

    @set_ev_cls(ofp_event.EventOFPErrorMsg,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
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


    # @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    # def _flow_stats_reply_handler(self, ev):
    #     """
    #     ingress_policing_rate :
    #     the maximum rate (in Kbps) that this VM should be allowed to send
        
    #     ingress_policing_burst :
    #     a parameter to the policing algorithm to indicate the 
    #     maximum amount of data (in Kb) that this interface can send beyond the policing rate.
    #     """
    #     """
    #     body = ev.msg.body

    #     self.logger.info('datapath         '
    #                      'in-port  eth-dst           '
    #                      'out-port packets  bytes')
    #     self.logger.info('---------------- '
    #                      '-------- ----------------- '
    #                      '-------- -------- --------')
    #     for stat in sorted([flow for flow in body if flow.priority == 1],
    #                        key=lambda flow: (flow.match['in_port'],
    #                                          flow.match['eth_dst'])):
    #         self.logger.info('%016x %8x %17s %8x %8d %8d',
    #                          ev.msg.datapath.id,
    #                          stat.match['in_port'], stat.match['eth_dst'],
    #                          stat.instructions[0].actions[0].port,
    #                          stat.packet_count, stat.byte_count)

    #     """
    #     flows = []
    #     for stat in ev.msg.body:
    #         flows.append('table_id=%s '
    #                      'duration_sec=%d duration_nsec=%d '
    #                      'priority=%d '
    #                      'idle_timeout=%d hard_timeout=%d flags=0x%04x '
    #                      'importance=%d cookie=%d packet_count=%d '
    #                      'byte_count=%d match=%s instructions=%s' %
    #                      (stat.table_id,
    #                       stat.duration_sec, stat.duration_nsec,
    #                       stat.priority,
    #                       stat.idle_timeout, stat.hard_timeout,
    #                       stat.flags, stat.importance,
    #                       stat.cookie, stat.packet_count, stat.byte_count,
    #                       stat.match, stat.instructions))
    #     self.logger.debug('FlowStats: %s', flows)
    #     """
    #     body = ev.msg.body
    #     dpid = int(ev.msg.datapath.id)
    #     if CONF.topo == 'simple':
    #         switch = self.simple_dpids[dpid]
    #         switch_interfaces = self.simple_switch_interfaces
    #     elif CONF.topo == 'datacenter':
    #         switch = self.complex_dpids[dpid]
    #         switch_interfaces = self.complex_switch_interfaces
    #     print "-------------- Flow stats for switch", switch, "---------------"

    #     # Iterate through all statistics reported for the flow
    #     for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
    #         in_port = stat.match['in_port']
    #         out_port = stat.instructions[0].actions[0].port
    #         eth_dst = stat.match['eth_dst']

    #         # Check if we have a previous byte count reading for this flow
    #         # and calculate bandwith usage over the last polling interval
    #         key = (dpid, in_port, eth_dst, out_port)
    #         rate = 0
    #         if key in self.flow_byte_counts:
    #             cnt = self.flow_byte_counts[key]
    #             rate = self.bitrate(stat.byte_count - cnt)

    #         self.flow_byte_counts[key] = stat.byte_count
    #         print "In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (in_port, eth_dst, out_port, rate)

    #         switch_id = switch + "-eth" + str(in_port)
    #         if rate > self.bw_threshold:
    #             if not switch_id in switch_interfaces:
    #                 self.apply_rate_limiting(switch, in_port, out_port, eth_dst, rate)
    #         elif rate < self.bw_min:
    #             if not switch_id in switch_interfaces:
    #                 self.revoke_rate_limiting(switch, in_port, out_port, eth_dst, rate)
    #     """

    @set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
    def queue_stats_reply_handler(self, ev):
        queues = []
        #print(ev.msg.body)
        for stat in ev.msg.body:
            queues.append('port_no=%d queue_id=%d '
                          'tx_bytes=%d tx_packets=%d tx_errors=%d '
                          'duration_sec=%d duration_nsec=%d'
                          'properties=%s' %
                          (stat.port_no, stat.queue_id,
                           stat.tx_bytes, stat.tx_packets))
        #self.logger.info('*****QueueStats****: %s', queues)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply information into self.flow_stats.
            Calculate flow speed and Save it.
            (old) self.flow_stats = {dpid:{(in_port, ipv4_dst, out-port):[(packet_count, byte_count, duration_sec,  duration_nsec),],},}
            (old) self.flow_speed = {dpid:{(in_port, ipv4_dst, out-port):[speed,],},}
            (new) self.flow_stats = {dpid:{(priority, ipv4_src, ipv4_dst):[(packet_count, byte_count, duration_sec,  duration_nsec),],},}
            (new) self.flow_speed = {dpid:{(priority, ipv4_src, ipv4_dst):[speed,],},}
            Because the proactive flow entrys don't have 'in_port' and 'out-port' field.
            Note: table-miss, LLDP and ARP flow entries are not what we need, just filter them.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        for stat in sorted([flow for flow in body if ((flow.priority not in [0, 65535]) and (flow.match.get('ipv4_src')) and (flow.match.get('ipv4_dst')))],
                           key=lambda flow: (flow.priority, flow.match.get('ipv4_src'), flow.match.get('ipv4_dst'))):
            key = (stat.priority, stat.match.get('ipv4_src'), stat.match.get('ipv4_dst'))
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed and Save it.
            pre = 0
            period = 5
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)
            self._save_stats(self.flow_speed[dpid], key, speed, 5)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        # body = ev.msg.body

        # self.logger.info('datapath         port     '
        #                  'rx-pkts  rx-bytes rx-error '
        #                  'tx-pkts  tx-bytes tx-error')
        # self.logger.info('---------------- -------- '
        #                  '-------- -------- -------- '
        #                  '-------- -------- --------')
        # for stat in sorted(body, key=attrgetter('port_no')):
        #     self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
        #                      ev.msg.datapath.id, stat.port_no,
        #                      stat.rx_packets, stat.rx_bytes, stat.rx_errors,
        #                      stat.tx_packets, stat.tx_bytes, stat.tx_errors)
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_4.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)
                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed and Save it.
                pre = 0
                period = 5
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    # Calculate only the tx_bytes, not the rx_bytes. (hmc)
                    pre = tmp[-2][0]
                    period = self._get_period(tmp[-1][3], tmp[-1][4], tmp[-2][3], tmp[-2][4])
                speed = self._get_speed(self.port_stats[key][-1][0], pre, period)
                self._save_stats(self.port_speed, key, speed, 5)
                self._save_freebandwidth(dpid, port_no, speed)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.properties[0].curr, p.properties[0].advertised,
                          p.properties[0].supported, p.properties[0].peer, p.properties[0].curr_speed,
                          p.properties[0].max_speed))

            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            # Recording data.
            port_feature = (config, state, p.properties[0].curr_speed)
            self.port_features[dpid][p.port_no] = port_feature

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
            Handle the port status changed event.
        """
        msg = ev.msg
        ofproto = msg.datapath.ofproto
        reason = msg.reason
        dpid = msg.datapath.id
        port_no = msg.desc.port_no

        reason_dict = {ofproto.OFPPR_ADD: "added",
                       ofproto.OFPPR_DELETE: "deleted",
                       ofproto.OFPPR_MODIFY: "modified", }

        if reason in reason_dict:
            print "switch%d: port %s %s" % (dpid, reason_dict[reason], port_no)
        else:
            print "switch%d: Illeagal port state %s %s" % (dpid, port_no, reason)



    #this is a features reply message that was sent from switch upron feature request by the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("switch:%s connected", datapath.id)

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


    def send_flow_mod(self, datapath, flow_info, src_port, dst_port, priority=30):
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

        self.add_flow(datapath, priority, match, actions,
                      idle_timeout=0, hard_timeout=0)

    def install_flow(self, datapaths, link_to_port, path, flow_info, buffer_id, priority=30, data=None):
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
        dst_ip = flow_info[2]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        hops = len(path)

        # Install flow entry for intermediate datapaths.
        for i in range(1, ((len(path) - 1) )):
            port = self.get_port_pair_from_link(link_to_port, path[i-1], path[i])
            port_next = self.get_port_pair_from_link(link_to_port, path[i], path[i+1])
            if port and port_next:
                src_port, dst_port = port[1], port_next[0]
                datapath = datapaths[path[i]]
                self.send_flow_mod(datapath, flow_info, src_port, dst_port, priority)

        #  Install flow entry for the first datapath.
        port_pair = self.get_port_pair_from_link(link_to_port, path[0], path[1])
        if port_pair is None:
            self.logger.info("Port not found in first hop.")
            return
        out_port = port_pair[0]
        self.send_flow_mod(first_dp, flow_info, in_port, out_port, priority)

        # #  Install flow entry for the last datapath.
        # port_pair = self.get_port_pair_from_link(link_to_port, path[0], path[1])
        # if port_pair is None:
        #     self.logger.info("Port not found in first hop.")
        #     return
        # out_port = port_pair[0]
        # self.send_flow_mod(first_dp, flow_info, in_port, out_port)
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
        self.logger.info("Flooding packet to access port")


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
                self.logger.info("Registering access info")
                print("dpid - " + str(dpid) + " , in_port - " + str(in_port) + " :: ip - " + str(ip) + " , mac - " + str(mac))
                return

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,)
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
        #pkt1 = packet.Packet(array.array('B', msg.data))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        #if eth.ethertype == ether_types.ETH_TYPE_LLDP:
             # ignore lldp packet
        #     return
        #self.register_access_info(datapath.id, in_port, ip_src_ip, mac)
        #for p in pkt1.protocols:
        #    print(p)
        #self.logger.info("Packet processing")
        #self.logger.info("packet in %s %s %s %s", datapath.id, eth.src, eth.dst, in_port)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            mac = arp_pkt.src_mac
            # Record the access infomation.
            self.logger.info("ARP processing")
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)
            
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        elif ip_pkt:
            ip_src_ip = ip_pkt.src
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            mac = eth.src
            # Record the access infomation.
            self.logger.info("IPV4 processing")
            self.register_access_info(datapath.id, in_port, ip_src_ip, mac)
            
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
            self.logger.log("Deliver ARP packet to know host")
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
        #print shortest_paths
        # Create bandwidth-sensitive datapath graph.
        graph = self.graph

        if weight == self.WEIGHT_MODEL['hop']:
            return shortest_paths.get(src).get(dst)[0]
        elif weight == self.WEIGHT_MODEL['bw']:
            # Because all paths will be calculated when we call self.monitor.get_best_path_by_bw,
            # so we just need to call it once in a period, and then, we can get path directly.
            # If path is existed just return it, else calculate and return it.
            try:
                path = self.best_paths.get(src).get(dst)
                return path
            except:
                result = self.get_best_path_by_bw(graph, shortest_paths)
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
                    if(ip_src == '10.1.1.1' and ip_dst == '10.1.4.1'):
                        path = [1, 2, 3, 4]
                    elif(ip_dst == '10.1.1.1' and ip_src == '10.1.4.1'):
                        path = [4, 3, 2, 1]
                    self.logger.info("[PATH] switch : %s :: %s<-->%s(%s Port:%d): %s" % (datapath.id, ip_src, ip_dst, L4_Proto, L4_port, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port, ip_proto, Flag, L4_port)
                else:
                    if(ip_src == '10.1.1.1' and ip_dst == '10.1.4.1'):
                        path = [1, 2, 3, 4]
                    elif(ip_dst == '10.1.1.1' and ip_src == '10.1.4.1'):
                        path = [4, 3, 2, 1]
                    
                    self.logger.info("[PATH] switch : %s :: %s<-->%s: %s" % (datapath.id, ip_src, ip_dst, path))
                    flow_info = (eth_type, ip_src, ip_dst, in_port)
                    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    print("eth_type : %s ::: buffer_id : %s" % (eth_type, msg.buffer_id))
                    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                # Install flow entries to datapaths along the path.
                self.install_flow(self.datapaths,
                                  self.link_to_port,
                                  path, flow_info, msg.buffer_id, 30, msg.data)
        else:
            # Flood is not good.
            self.flood(msg)


    

    def show_stat(self, _type):
        '''
            Show statistics information according to data type.
            _type: 'port' / 'flow'
        '''
        return

        bodys = self.stats[_type]
        if _type == 'flow':
            print('\ndatapath  '
                'priority        ip_src        ip_dst  '
                '  packets        bytes  flow-speed(Kb/s)')
            print('--------  '
                '--------  ------------  ------------  '
                '---------  -----------  ----------------')
            for dpid in sorted(bodys.keys()):

                for stat in sorted([flow for flow in bodys[dpid] if ((flow.priority not in [0, 65535]) and (flow.match.get('ipv4_src')) and (flow.match.get('ipv4_dst')))],
                           key=lambda flow: (flow.priority, flow.match.get('ipv4_src'), flow.match.get('ipv4_dst'))):
                    print('%8d  %8s  %12s  %12s  %9d  %11d  %16.1f' % (
                        dpid,
                        stat.priority, stat.match.get('ipv4_src'), stat.match.get('ipv4_dst'),
                        stat.packet_count, stat.byte_count,
                        abs(self.flow_speed[dpid][(stat.priority, stat.match.get('ipv4_src'), stat.match.get('ipv4_dst'))][-1])*8/1000.0))
            print

        if _type == 'port':
            print('\ndatapath  port '
                '   rx-pkts     rx-bytes ''   tx-pkts     tx-bytes '
                ' port-bw(Kb/s)  port-speed(b/s)  port-freebw(Kb/s) '
                ' port-state  link-state')
            print('--------  ----  '
                '---------  -----------  ''---------  -----------  '
                '-------------  ---------------  -----------------  '
                '----------  ----------')
            _format = '%8d  %4x  %9d  %11d  %9d  %11d  %13d  %15.1f  %17.1f  %10s  %10s'
            for dpid in sorted(bodys.keys()):
                for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
                    if stat.port_no != ofproto_v1_4.OFPP_LOCAL:
                        print(_format % (
                            dpid, stat.port_no,
                            stat.rx_packets, stat.rx_bytes,
                            stat.tx_packets, stat.tx_bytes,
                            10000,
                            abs(self.port_speed[(dpid, stat.port_no)][-1] * 8),
                            self.free_bandwidth[dpid][stat.port_no],
                            self.port_features[dpid][stat.port_no][0],
                            self.port_features[dpid][stat.port_no][1]))
            print
