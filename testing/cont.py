import networkx as nx
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.topology import event, switches
from ryu.topology.api import get_link, get_switch, get_host
from ryu.app.ofctl.api import get_datapath
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

DEFAULT_FLOW_PRIORITY = 32767
DEFAULT_BUCKET_WEIGHT = 0

#https://github.com/Yi-Tseng/SDN-Work/blob/cb0e6d8680bfb625b7735089a19aac73fc262693/FastFailover/ff.py

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.hosts = {}
        self.net = nx.DiGraph()
        self.topology_api_app = self
        self.mac_to_gid = {}
        self.num_groups = 1

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev):
        from ryu import utils
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x message=%s', msg.type, msg.code, utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # install default groups
        for gid in range(1, 3):
            gmod = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_FF, gid, [])
            datapath.send_msg(gmod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def find_hosts(self, dst):
        all_hosts = get_host(self, None)
        for host in all_hosts:
            src = host.mac
            dpid = host.port.dpid
            in_port = host.port.port_no
            self.hosts[src] = (dpid, in_port)

            if src not in self.mac_to_gid:
                self.mac_to_gid[src] = self.num_groups
                gid = self.num_groups
                self.logger.info("mac: %s, gid: %d", src, gid)
                self.num_groups += 1
        return (dst in self.hosts)

    def get_nx_graph(self):
        links = get_link(self, None)
        for link in links:
            src = link.src
            dst = link.dst
            self.net.add_edge(src.dpid, dst.dpid, src_port=src.port_no, dst_port=dst.port_no)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        _dbg_hosts = ['00:00:00:00:00:01', '00:00:00:00:00:02']
        if src not in _dbg_hosts or dst not in _dbg_hosts:
            return

        if dst not in self.hosts:
            isvalid = self.find_hosts(dst)
            if isvalid is False:
                return

        dst_dpid, dst_port = self.hosts[dst]
        all_paths = nx.all_shortest_paths(self.net, dpid, dst_dpid)
        if not all_paths:
            self.get_nx_graph()
            all_paths = nx.all_shortest_paths(self.net, dpid, dst_dpid)

        '''
        to_install:
        for example, topology like
            /2\ /5\
        h1-1   4   7-h2
            \3/ \6/
        all path from h1 to h2
        [1, 2, 4, 5, 7]
        [1, 2, 4, 6, 7]
        [1, 3, 4, 5, 7]
        [1, 3, 4, 6, 7]
        data of to_install will be:
        {
            1: [2, 3],
            2: [4],
            3: [4],
            4: [5, 6],
            5: [7],
            6: [7],
            7: []
        }
        '''

        install = {}
        for path in all_paths:
            for i in range(len(path)):
                install.setdefault(path[i], set())
                if path[i] == dst_dpid:
                    continue
                else:
                    install[path[i]].add(path[i + 1])
        self.logger.info(install)

        dst_gid = self.mac_to_gid.get(dst, -1)
        if dst_gid == -1:
            return

        dst_match = parser.OFPMatch(eth_dst=dst)
        dst_actions = [parser.OFPActionGroup(group_id=dst_gid)]

        for dpid, next_dpid_list in install.items():
            dp = get_datapath(self.topology_api_app, dpid)
            if dpid == dst_dpid:
                actions = [parser.OFPActionOutput(port=dst_port)]
                buckets = [parser.OFPBucket(DEFAULT_BUCKET_WEIGHT, dst_port, dst_gid, actions)]
                gmod = parser.OFPGroupMod(dp, ofproto.OFPGC_MODIFY, ofproto.OFPGT_FF, dst_gid, buckets)
                dp.send_msg(gmod)
                self.add_flow(dp, DEFAULT_FLOW_PRIORITY, dst_match, dst_actions)

            else:
                buckets = []
                for next_dpid in next_dpid_list:
                    out_port = self.net.edge[dpid][next_dpid]['src_port']
                    actions = [parser.OFPActionOutput(port=out_port)]
                    buckets.append(parser.OFPBucket(DEFAULT_BUCKET_WEIGHT, out_port, dst_gid, actions))
                gmod = parser.OFPGroupMod(dp, ofproto.OFPGC_MODIFY, ofproto.OFPGT_FF, dst_gid, buckets)
                dp.send_msg(gmod)
                self.add_flow(dp, DEFAULT_FLOW_PRIORITY, dst_match, dst_actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=dst_actions, data=data)
        datapath.send_msg(out)

    #An event class to notify connect/disconnect of a switch.
    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def on_dp_change(self, ev):
        if ev.enter:
            switch_list = get_switch(self.topology_api_app, None)
            switches = [switch.dp.id for switch in switch_list]
            self.net.add_nodes_from(switches)

            links = get_link(self, None)
            for link in links:
                src = link.src
                dst = link.dst
                self.net.add_edge(src.dpid, dst.dpid, src_port=src.port_no, dst_port=dst.port_no)

            print "**********List of links"
            print self.net.edges()