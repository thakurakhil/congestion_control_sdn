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


    # Convert from byte count delta to bitrate
    def bitrate(self, bytes):
        return bytes * 8.0 / (self.query_interval * 1024)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        print "SETTING == datapath : " + str(dpid) + "  src : " + str(src) + "  in_port : " + str(in_port)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            #print "im here with out_port : " + str(out_port) + "\n"
            #print self.mac_to_port
        else:
            out_port = ofproto.OFPP_FLOOD
            #print "flooding goes brrr..."

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            print "NOTFLOOD : datapath : " + str(dpid) + "  src : " + str(src) + "  in_port : " + str(in_port) + "  dst : " + str(dst) + "  out_port : " + str(out_port) + " " 
            self.add_flow(datapath, 1, match, actions)

        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        match = parser.OFPMatch(in_port=in_port)
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, match=match, actions=actions, data=data)
        #print "FLOOD : datapath : " + str(dpid) + "  in_port : " + str(in_port) + "  dst : " + str(dst) + "  out_port : " + str(out_port) + " " 
        datapath.send_msg(out)

        #if msg.reason == ofproto.TABLE_MISS:
        #    reason = 'TABLE MISS'
        #elif msg.reason == ofproto.OFPR_APPLY_ACTION:
        #    reason = 'APPLY ACTION'
        #elif msg.reason == ofproto.OFPR_INVALID_TTL:
        #    reason = 'INVALID TTL'
        #elif msg.reason == ofproto.OFPR_ACTION_SET:
        #    reason = 'ACTION SET'
        #elif msg.reason == ofproto.OFPR_GROUP:
        #    reason = 'GROUP'
        #elif msg.reason == ofproto.OFPR_PACKET_OUT:
        #    reason = 'PACKET OUT'
        #else:
        reason = 'unknown'
        #if str(out_port) != "4294967291":
        #    print "datapath : " + str(dpid) + "  in_port : " + str(in_port) + "  dst : " + str(dst) + "  out_port : " + str(out_port) + " " 
        #self.logger.debug('OFPPacketIn received: '
        #             'buffer_id=%x total_len=%d reason=%s '
        #              'table_id=%d cookie=%d match=%s data=%s dst=%s  src=%s',
        #              msg.buffer_id, msg.total_len, reason,
        #              msg.table_id, msg.cookie, msg.match,
        #              utils.hex_array(msg.data), dst, src)
