#!/usr/bin/env python

from subprocess import Popen, PIPE
import re
from time import sleep, time
from argparse import ArgumentParser

from functools import partial
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg
from mininet.node import CPULimitedHost, RemoteController, OVSSwitch, OVSController
from mininet.link import TCLink
from mininet.util import irange, custom, quietRun, dumpNetConnections
from mininet.cli import CLI
from mininet.util import dumpNodeConnections

from numpy import std

from multiprocessing import Process

from monitor import monitor_qlen, monitor_bbr, capture_packets, filter_packets
import termcolor as T

import json
import math
import os
import sched
import socket
import sys

import threading


parser = ArgumentParser(description="Swimming")


parser.add_argument('--dir', '-d',
                    help="Directory to store outputs",
                    default="./resultsNew")
parser.add_argument('--time', '-t',
                    help="Duration (sec) to run each experiment",
                    type=int,
                    default=90)
parser.add_argument('--cport', '-c',
                    help="Controller Port (default:6633)",
                    type=int,
                    default=6633)


args = parser.parse_args()

queue_length = 500
def runner(popen, noproc=False):
    def run_fn(command, background=False, daemon=True):
        #print "runnin the command : {}".format(command)
        if noproc:
            p = popen(command, shell=True)
            if not background:
                return p.wait()
        def start_command():
            popen(command, shell=True).wait()
        proc = Process(target=start_command)
        proc.daemon = daemon
        proc.start()
        if not background:
            proc.join()
        return proc
    return run_fn



class ExperimentTopo(Topo):
    def __init__(self):
        # Add default members to class
        super(ExperimentTopo, self).__init__()

        switch_config = {
            #'enable_ecn': args.ecn,
            #'use_hfsc': args.use_hfsc,
            #min-rate=10000000000 10 Gbps
            'max_queue_size': queue_length
        }

        switch_lconfig1  = {
            'bw':    800,
            'delay': '0.2ms',
            'max_queue_size': queue_length
        }
        switch_lconfig2  = {
            'bw':    800,
            'delay': '0.2ms',
            'max_queue_size': queue_length
        }
        switch_lconfig3  = {
            'bw':    800,
            'delay': '0.2ms',
            'max_queue_size': queue_length
        }
        switch_lconfig4  = {
            'bw':    800,
            'delay': '0.2ms',
            'max_queue_size': queue_length
        }
        link_lconfig1 = {
            'bw':    1000,
            'delay': '1ms',
            'max_queue_size': queue_length
        }
        link_lconfig2 = {
            'bw':    1000,
            'delay': '1ms',
            'max_queue_size': queue_length
        }
        link_lconfig3 = {
            'bw':    1000,
            'delay': '1ms',
            'max_queue_size': queue_length
        }
        link_lconfig4 = {
            'bw':    1000,
            'delay': '1ms',
            'max_queue_size': queue_length
        }
        link_lconfig5 = {
            'bw':    1000,
            'delay': '1ms',
            'max_queue_size': queue_length
        }
        

        """Configure the port and set its properties.
           bw: bandwidth in Mb/s (e.g. '10m')
           delay: transmit delay (e.g. '1ms' )
           jitter: jitter (e.g. '1ms')
           loss: loss (e.g. '1%' )
           gro: enable GRO (False)
           txo: enable transmit checksum offload (True)
           rxo: enable receive checksum offload (True)
           speedup: experimental switch-side bw option
           use_hfsc: use HFSC scheduling
           use_tbf: use TBF scheduling
           latency_ms: TBF latency parameter
           enable_ecn: enable ECN (False)
           enable_red: enable RED (False)
           max_queue_size: queue limit parameter for netem in packets length


            bw: bandwidth in Mbps (e.g. 10) with HTB by default
            use_hfsc: use HFSC scheduling instead of HTB for shaping
            use_tbf: use TBF scheduling instead of HTB for shaping
            latency_ms: TBF latency parameter
            enable_ecn: enable ECN by adding a RED qdisc after shaping (False)
            enable_red: enable RED after shaping (False)
            speedup: experimental switch-side bw option (switches-only)
            delay: transmit delay (e.g. '1ms') with netem
            jitter: jitter (e.g. '1ms') with netem
            loss: loss (e.g. '1%'' ) with netem
            max_queue_size: queue limit parameter for the netem qdisc
            gro: enable GRO (False)
            txo: enable transmit checksum offload (True)
            rxo: enable receive checksum offload (True)

           """



        # Just create a partial topology for the experiment to save resources
        self.addSwitch('sw1', dpid='0000000000000001', **switch_config)
        self.addSwitch('sw2', dpid='0000000000000002', **switch_config)
        self.addSwitch('sw3', dpid='0000000000000003', **switch_config)
        self.addSwitch('sw4', dpid='0000000000000004', **switch_config)
        self.addSwitch('sw5', dpid='0000000000000005', **switch_config)
        self.addSwitch('sw6', dpid='0000000000000006', **switch_config)
        self.addSwitch('sw7', dpid='0000000000000007', **switch_config)
        self.addSwitch('sw8', dpid='0000000000000008', **switch_config)
        self.addSwitch('sw9', dpid='0000000000000009', **switch_config)
        self.addSwitch('sw10', dpid='000000000000000A', **switch_config)


        # Connect the switches together
        self.addLink('sw1', 'sw2', **switch_lconfig1)
        self.addLink('sw2', 'sw3', **switch_lconfig4)
        self.addLink('sw3', 'sw4', **switch_lconfig1)
        self.addLink('sw1', 'sw5', **switch_lconfig1)
        self.addLink('sw5', 'sw6', **switch_lconfig2)
        self.addLink('sw6', 'sw8', **switch_lconfig2)
        self.addLink('sw8', 'sw4', **switch_lconfig2)
        self.addLink('sw5', 'sw7', **switch_lconfig3)
        self.addLink('sw7', 'sw9', **switch_lconfig3)
        self.addLink('sw9', 'sw10', **switch_lconfig3)
        self.addLink('sw10', 'sw4', **switch_lconfig3)

        # the 7 hosts
        host_format = 'h{:02x}{:02x}{:02x}'
        
        self.addHost('h010101', ip='10.1.1.1', mac='00:00:00:01:01:01')
        self.addLink('sw1', 'h010101', **link_lconfig1)

        self.addHost('h010201', ip='10.1.2.1', mac='00:00:00:01:02:01')
        self.addLink('sw2', 'h010201', **link_lconfig2)
        self.addHost('h010202', ip='10.1.2.2', mac='00:00:00:01:02:02')
        self.addLink('sw2', 'h010202', **link_lconfig2)
        self.addHost('h010203', ip='10.1.2.3', mac='00:00:00:01:02:03')
        self.addLink('sw2', 'h010203', **link_lconfig2)

        self.addHost('h010301', ip='10.1.3.1', mac='00:00:00:01:03:01')
        self.addLink('sw7', 'h010301', **link_lconfig3)
        self.addHost('h010302', ip='10.1.3.2', mac='00:00:00:01:03:02')
        self.addLink('sw7', 'h010302', **link_lconfig3)

        self.addHost('h010401', ip='10.1.4.1', mac='00:00:00:01:04:01')
        self.addLink('sw4', 'h010401', **link_lconfig4)

        self.addHost('h010501', ip='10.1.5.1', mac='00:00:00:01:05:01')
        self.addLink('sw3', 'h010501', **link_lconfig5)


class DCTopo(Topo):
    def __init__(self):
        # Add default members to class
        super(DCTopo, self).__init__()

        tor_lconfig  = {
            'bw':    1000
            # 'delay': '0.1ms'
        }
        agg_lconfig  = {
            'bw':    1000,
            'delay': '0.2ms'
        }
        core_lconfig = {
            'bw':    1000,
            'delay': '1ms'
        }
        switch_config = {
            #'enable_ecn': args.ecn,
            #'use_hfsc': args.use_hfsc,
            'max_queue_size': 60
        }

        """Configure the port and set its properties.
           bw: bandwidth in b/s (e.g. '10m')
           delay: transmit delay (e.g. '1ms' )
           jitter: jitter (e.g. '1ms')
           loss: loss (e.g. '1%' )
           gro: enable GRO (False)
           txo: enable transmit checksum offload (True)
           rxo: enable receive checksum offload (True)
           speedup: experimental switch-side bw option
           use_hfsc: use HFSC scheduling
           use_tbf: use TBF scheduling
           latency_ms: TBF latency parameter
           enable_ecn: enable ECN (False)
           enable_red: enable RED (False)
           max_queue_size: queue limit parameter for netem in packets length"""

        # Just create a partial topology for the experiment to save resources
        self.addSwitch('core', dpid='0000000000000001', **switch_config)
        self.addSwitch('agg1', dpid='0000000000000002', **switch_config)
        self.addSwitch('agg2', dpid='0000000000000003', **switch_config)
        self.addSwitch('tor1', dpid='0000000000000004', **switch_config)
        self.addSwitch('tor2', dpid='0000000000000005', **switch_config)
        self.addSwitch('tor3', dpid='0000000000000006', **switch_config)

        # Connect the switches together
        self.addLink('core', 'agg1', **core_lconfig)
        self.addLink('core', 'agg2', **core_lconfig)
        self.addLink('agg1', 'tor1', **agg_lconfig)
        self.addLink('agg1', 'tor2', **agg_lconfig)
        self.addLink('agg2', 'tor3', **agg_lconfig)

        # the 10 hosts under the same ToR
        host_format = 'h{:02x}{:02x}{:02x}'
        for i in range(2):
            hostname = host_format.format(1, 1, i+1)
            #in the format of h01010i
            self.addHost(hostname, ip='10.1.1.{}'.format(i+1), mac='00:00:00:01:01:{:02X}'.format(i+1)) # AggId.TorId.HostId
            self.addLink('tor1', hostname, **tor_lconfig)

        # one host under same agg different tor
        hostname = host_format.format(1, 2, 1)
        #in the format of h010201
        self.addHost(hostname, ip='10.1.2.1', mac='00:00:00:01:02:01')
        self.addLink('tor2', hostname, **tor_lconfig)

        # one host under different agg
        hostname = host_format.format(2, 1, 1)
        #in the format of h020101
        self.addHost(hostname, ip='10.2.1.1', mac='00:00:00:02:01:01')
        self.addLink('tor3', hostname, **tor_lconfig)    

def insert_flow_cmd(switch, ip, in_port, dst_port):
    cmd_arp = "ovs-ofctl add-flow %s -O OpenFlow14 \
                'table=0,idle_timeout=0,hard_timeout=0,priority=10,arp, \
                nw_dst=%s,in_port=%d,actions=output:%d'" % (switch, ip, in_port, dst_port)
    os.system(cmd_arp)

    cmd_ip = "ovs-ofctl add-flow %s -O OpenFlow14 \
                'table=0,idle_timeout=0,hard_timeout=0,priority=10,ip, \
                nw_dst=%s,in_port=%d,actions=output:%d'" % (switch, ip, in_port, dst_port)
    os.system(cmd_ip)
    return

def insert_queue_cmd(interface, packet_length):
    cmd_queue = "sudo ifconfig %s txqueuelen %d" % (interface, packet_length)
    os.system(cmd_queue)

    return

def install_proactive_flows(net, topo):
    #switch sw1
    insert_flow_cmd("sw1", "10.1.1.1", 1, 3)
    insert_flow_cmd("sw1", "10.1.1.1", 2, 3)

    #switch sw2
    insert_flow_cmd("sw2", "10.1.2.1", 1, 3)
    insert_flow_cmd("sw2", "10.1.2.1", 2, 3)
    insert_flow_cmd("sw2", "10.1.2.1", 4, 3)
    insert_flow_cmd("sw2", "10.1.2.1", 5, 3)
    insert_flow_cmd("sw2", "10.1.2.2", 1, 4)
    insert_flow_cmd("sw2", "10.1.2.2", 2, 4)
    insert_flow_cmd("sw2", "10.1.2.2", 3, 4)
    insert_flow_cmd("sw2", "10.1.2.2", 5, 4)
    insert_flow_cmd("sw2", "10.1.2.3", 1, 5)
    insert_flow_cmd("sw2", "10.1.2.3", 2, 5)
    insert_flow_cmd("sw2", "10.1.2.3", 3, 5)
    insert_flow_cmd("sw2", "10.1.2.3", 4, 5)

    # switch sw3
    insert_flow_cmd("sw3", "10.1.5.1", 1, 3)
    insert_flow_cmd("sw3", "10.1.5.1", 2, 3)

    #switch sw7
    insert_flow_cmd("sw7", "10.1.3.1", 1, 3)
    insert_flow_cmd("sw7", "10.1.3.1", 2, 3)
    insert_flow_cmd("sw7", "10.1.3.1", 4, 3)
    insert_flow_cmd("sw7", "10.1.3.2", 1, 4)
    insert_flow_cmd("sw7", "10.1.3.2", 2, 4)
    insert_flow_cmd("sw7", "10.1.3.2", 3, 4)

    #switch sw4
    insert_flow_cmd("sw4", "10.1.4.1", 1, 4)
    insert_flow_cmd("sw4", "10.1.4.1", 2, 4)
    insert_flow_cmd("sw4", "10.1.4.1", 3, 4)

    # insert_queue_cmd("sw2-eth2", queue_length)

#specific monitor for bbr parameters obtained from comand ss
def start_bbrmon(dst, interval_sec=0.1, outfile="bbr.txt", runner=None):
    monitor = Process(target=monitor_bbr,
                      args=(dst, interval_sec, outfile, runner))
    monitor.start()
    return monitor

def start_queuemon(iface, interval_sec=0.1):
    monitor = Process(target=monitor_qlen,
                      args=(iface, 1.0))
    monitor.start()
    return 

def iperf_bbr_mon(net, i, port):
    mon = start_bbrmon("%s:%s" % (net.get("h020101").IP(), port),
                       outfile= "%s/bbr%s.txt" %(args.dir, i),
                       runner=net.get("h010102").popen)
    return mon



def start_capture(outfile="capture.dmp", interface=""):
    monitor = Process(target=filter_packets,
                      args=(interface, outfile))
    monitor.start()
    return monitor

def start_side_flows_thread(net, num_flows, time_btwn_flows, flow_type, cong,
                pre_flow_action=None, flow_monitor=None):
    monitor = Process(target=start_side_flows,
                      args=(net, num_flows, time_btwn_flows, flow_type, cong,
                            pre_flow_action, flow_monitor))
    monitor.start()
    return monitor

def filter_capture(filter_pattern, infile="capture.dmp", outfile="filtered.dmp"):
    monitor = Process(target=filter_packets,
                      args=("-r {} {}".format(infile, filter_pattern), outfile))
    monitor.start()
    return monitor


# Display a countdown to the user to show time remaining.
def display_countdown(nseconds):
    start_time = time()
    while True:
        sleep(5)
        now = time()
        delta = now - start_time
        if delta >= nseconds:
            break
        print "%.1fs left..." % (nseconds - delta)


def netperf_commands(index, h1, h2, port, cong, duration, outdir, delay=0):
    # -H [ip]: remote host
    # -p [port]: port of netserver
    # -s [time]: time to sleep
    # -l [seconds]: duration
    # -- -s [size]: sender TCP buffer
    # -- -P [port]: port of data flow
    # -- -K [cong]: congestion control protocol
    window = ''
    client = "netperf -H {} -s {} -p 12563 -l {} -- {} -K {} -P {} > {}".format(
        h2.IP(), delay, duration, window, cong, port,
        "{}/netperf{}.txt".format(outdir, index)
    )
    runner(h1.popen, noproc=False)(client, background=True)
    #h1['runner'](client, background=True)

def netperf_setup(h1, h2):
    server = "killall netserver;netserver -p 12563;"
    runner(h2.popen, noproc=False)(server)
    #sleep(5)
    #h2['runner'](server)


def iperf_setup(h1, h2, ports):
    #runner(h2.popen, noproc=False)("killall iperf3")
    #h2.popen("killall iperf3",shell=True)
    #h2['runner']("killall iperf3")
    #sleep(1) # make sure ports can be reused
    for port in ports:
        # -s: server
        # -p [port]: port
        # -f m: format in megabits
        # -i 1: measure every second
        # -1: one-off (one connection then exit)
        cmd = "iperf3 -s -p {} -f m -i 1 -1".format(port)
        h2.popen(cmd,shell=True)
        #runner(h2.popen, noproc=False)(cmd,background=True)
        #h2['runner'](cmd, background=True)
    sleep(min(10, len(ports))) # make sure all the servers start

def iperf_commands(index, h1, h2, port, cong, duration, outdir, delay=0):
    # -c [ip]: remote host
    # -w [size]: TCP buffer size
    # -C: congestion control
    # -t [seconds]: duration
    # -p [port]: port
    # -f m: format in megabits
    # -i 1: measure every second
    window = ''
    client = "iperf3 -c {} -f m -i 1 -p {} {} -C {} -t {} > {}".format(
        h2.IP(), port, window, cong, duration, "{}/iperf_{}_{}.txt".format(outdir, cong, index)
    )
    #runner(h1.popen, noproc=False)(client, background=True)
    h1.popen(client, shell=True)
    #h1['runner'](client, background=True)

def start_side_flows(net, num_flows, time_btwn_flows, flow_type, cong,
                pre_flow_action=None, flow_monitor=None):
    h21 = net.get("h010201")
    h22 = net.get("h010202")
    h23 = net.get("h010203")
    h51 = net.get("h010501")

    print "Starting {} side flows...".format(cong)
    flows = []
    base_port = 2345

    if flow_type == 'netperf':
        netperf_setup(h21, h51)
        flow_commands = netperf_commands
    else:
        h51.popen("killall iperf3",shell=True)
        sleep(1)
        iperf_setup(h21, h51, [base_port + 0 for i in range(num_flows)])
        iperf_setup(h22, h51, [base_port + 1 for i in range(num_flows)])
        iperf_setup(h23, h51, [base_port + 2 for i in range(num_flows)])
        flow_commands = iperf_commands

    
    def start_side_flow(i):
        if pre_flow_action is not None:
            pre_flow_action(net, i, base_port + i) #check here when increasing number of flows
        flow_commands(1, h21, h51, base_port + 0, cong[i],
                      args.time - time_btwn_flows * i,
                      args.dir, delay=i*time_btwn_flows)
        flow_commands(2, h22, h51, base_port + 1, cong[i],
                      args.time - time_btwn_flows * i,
                      args.dir, delay=i*time_btwn_flows)
        flow_commands(3, h23, h51, base_port + 2, cong[i],
                      args.time - time_btwn_flows * i,
                      args.dir, delay=i*time_btwn_flows)
        
    #s.enter(delay, priority, action, argument=(), kwargs={})
    s = sched.scheduler(time, sleep)
    for i in range(num_flows):
        if flow_type == 'iperf':
            s.enter(i * time_btwn_flows, 1, start_side_flow, [i])
        else:
            s.enter(0, i, start_side_flow, [i])
    s.run()
    return

def start_flows(net, num_flows, time_btwn_flows, flow_type, cong,
                pre_flow_action=None, flow_monitor=None):
    h1 = net.get("h010101")
    h2 = net.get("h010401")
    #h2 = net.get("h020101")

    print "Starting {} flows...".format(cong)
    flows = []
    base_port = 2345

    if flow_type == 'netperf':
        netperf_setup(h1, h2)
        flow_commands = netperf_commands
    else:
        h2.popen("killall iperf3",shell=True)
        sleep(1)
        iperf_setup(h1, h2, [base_port + i for i in range(num_flows)])
        flow_commands = iperf_commands

    
    def start_flow(i):
        if pre_flow_action is not None:
            pre_flow_action(net, i, base_port + i) #check here when increasing number of flows
        flow_commands(0, h1, h2, base_port + i, cong[i],
                      args.time - time_btwn_flows * i,
                      args.dir, delay=i*time_btwn_flows)
        flow = {
            'index': i,
            'send_filter': 'src {} and dst {} and dst port {}'.format(h1.IP(), h2.IP(),
                                                                      base_port + i),
            'receive_filter': 'src {} and dst {} and src port {}'.format(h2.IP(), h1.IP(),
                                                                         base_port + i),
            'monitor': None
        }
        flow['filter'] = '"({}) or ({})"'.format(flow['send_filter'], flow['receive_filter'])
        if flow_monitor:
            flow['monitor'] = flow_monitor(net, i, base_port + i)
        flows.append(flow)
    #s.enter(delay, priority, action, argument=(), kwargs={})
    s = sched.scheduler(time, sleep)
    for i in range(num_flows):
        if flow_type == 'iperf':
            s.enter(i * time_btwn_flows, 1, start_flow, [i])
        else:
            s.enter(0, i, start_flow, [i])
    s.run()
    return flows


def plot_graphs():
    return


def main():
	# Start the controller
    #controller_proc = subprocess.Popen([CONTROLLER_PATH], stderr=subprocess.PIPE)
    #time.sleep(3)

	#creating a mininet network
    controller = RemoteController('c1', ip='127.0.0.1', port=args.cport)
    #topo = DCTopo()
    topo = ExperimentTopo()

    switch = partial(OVSSwitch, protocols='OpenFlow14')
    net = Mininet(topo=topo, link=TCLink, autoSetMacs=True, autoStaticArp=True, controller=controller, switch=switch)
    #net = Mininet(topo=topo, link=TCLink, autoSetMacs=True, switch=switch, controller = controller)
    #net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, switch=switch, autoStaticArp=True)
    #c0 = net.addController('Ryu', controller=RemoteController, ip='127.0.0.1', protocols='OpenFlow13', port=6633)

    # Start the network
    insert_queue_cmd("sw2-eth2", queue_length)
    net.start()
    
    install_proactive_flows(net, topo)
    dumpNodeConnections(net.hosts) #diagnostic thing
    #net.pingAll()
    display_countdown(30)
    
    n_iperf_flows = 1
    time_btwn_flows = 0
    #flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["pcc"], pre_flow_action=None)
    #flows = None

    cap = start_capture("{}/capture_pcc.dmp".format(args.dir), "-i sw1-eth3")
    
    cap2 = start_capture("{}/capture_pcc_sw2.dmp".format(args.dir), "-i sw2-eth2")
    #start_queuemon("sw2-eth2")
    side_flows_thread = start_side_flows_thread(net, n_iperf_flows, time_btwn_flows, "iperf", ["pcc"], pre_flow_action=None)
    #side_flows_thread = threading.Thread(target = start_side_flows, (net, n_iperf_flows, time_btwn_flows, "iperf", ["pcc"], pre_flow_action=None) )
    #side_flows_thread.start()
    #side_flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["pcc"], pre_flow_action=None)


    flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["pcc"], pre_flow_action=None)
    display_countdown(args.time + 5)
    Popen("killall tcpdump", shell=True)
    cap.join()
    cap2.join()
    #que.join()
    
    main_send_filter = "src 10.1.1.1 and dst 10.1.4.1 and dst port 2345"
    main_receive_filter = "src 10.1.4.1 and dst 10.1.1.1 and src port 2345"
    main_filter = '"({}) or ({})"'.format(main_send_filter, main_receive_filter)
    print "Filtering PCC flow of 1 and 4..."
    filter_capture(main_filter,
                   "{}/capture_pcc.dmp".format(args.dir), "{}/flow_pcc_1.dmp".format(args.dir)) 

    side_send_filter1 = "src 10.1.2.1 and dst 10.1.5.1 and dst port 2345"
    side_receive_filter1 = "src 10.1.5.1 and dst 10.1.2.1 and src port 2345"
    side_filter1 = '"({}) or ({})"'.format(side_send_filter1, side_receive_filter1)
    
    display_countdown(5)
    
    print "Filtering PCC flow of 21 and 5..."
    filter_capture(side_filter1,
                   "{}/capture_pcc_sw2.dmp".format(args.dir), "{}/flow_pcc_21.dmp".format(args.dir)) 

    side_send_filter2 = "src 10.1.2.2 and dst 10.1.5.1 and dst port 2346"
    side_receive_filter2 = "src 10.1.5.1 and dst 10.1.2.2 and src port 2346"
    side_filter2 = '"({}) or ({})"'.format(side_send_filter2, side_receive_filter2)
    
    display_countdown(5)
    
    print "Filtering PCC flow of 22 and 5..."
    filter_capture(side_filter2,
                   "{}/capture_pcc_sw2.dmp".format(args.dir), "{}/flow_pcc_22.dmp".format(args.dir))

    side_send_filter3 = "src 10.1.2.3 and dst 10.1.5.1 and dst port 2347"
    side_receive_filter3 = "src 10.1.5.1 and dst 10.1.2.3 and src port 2347"
    side_filter3 = '"({}) or ({})"'.format(side_send_filter3, side_receive_filter3)
    
    display_countdown(5)
    
    print "Filtering PCC flow of 23 and 5..."
    filter_capture(side_filter3,
                   "{}/capture_pcc_sw2.dmp".format(args.dir), "{}/flow_pcc_23.dmp".format(args.dir))

    
    side_filter4 = '"({}) or ({}) or ({}) or ({}) or ({}) or ({}) or ({}) or ({})"'.format(
                                                        main_send_filter, main_receive_filter,
                                                        side_send_filter1, side_receive_filter1, 
                                                        side_send_filter2, side_receive_filter2,
                                                        side_send_filter3, side_receive_filter3)
    
    display_countdown(5)
    
    # print "Filtering PCC flow of * and 5..."
    # filter_capture(side_filter4,
    #                "{}/capture_pcc_sw2.dmp".format(args.dir), "{}/flow_pcc_5.dmp".format(args.dir)) 

    # display_countdown(5)

     
    # n_iperf_flows = 1
    # time_btwn_flows = 0

    # cap = start_capture("{}/capture_cubic.dmp".format(args.dir), "")
    # flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["cubic"], pre_flow_action=None)
    # display_countdown(args.time + 5)
    # Popen("killall tcpdump", shell=True)
    # cap.join()

    # for flow in flows:
    #     if flow['filter']:
    #         print "Filtering cubic flow {}...".format(flow['index'])
    #         filter_capture(flow['filter'],
    #                        "{}/capture_cubic.dmp".format(args.dir),
    #                        "{}/flow_cubic_{}.dmp".format(args.dir, flow['index'])) 
    #     if flow['monitor'] is not None:
    #         flow['monitor'].terminate()

    # #filter_capture(flows[0]['filter'],"{}/capture_cubic.dmp".format(args.dir),"{}/flow_cubic.dmp".format(args.dir))
    

    # n_iperf_flows = 1
    # time_btwn_flows = 0

    # cap = start_capture("{}/capture_bbr.dmp".format(args.dir))
    # flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["bbr"], pre_flow_action=None,flow_monitor=iperf_bbr_mon)
    # display_countdown(args.time + 5)
    # Popen("killall tcpdump", shell=True)
    # cap.join()
    
    # for flow in flows:
    #     if flow['filter']:
    #         print "Filtering BBR flow {}...".format(flow['index'])
    #         filter_capture(flow['filter'],
    #                        "{}/capture_bbr.dmp".format(args.dir),
    #                        "{}/flow_bbr_{}.dmp".format(args.dir, flow['index'])) 
    #     if flow['monitor'] is not None:
    #         flow['monitor'].terminate()

    #filter_capture(flows[0]['filter'],"{}/capture_bbr.dmp".format(args.dir),"{}/flow_bbr.dmp".format(args.dir))
    
    

    #filter_capture(flows[0]['filter'],"{}/capture_pcc.dmp".format(args.dir),"{}/flow_pcc.dmp".format(args.dir))
                

    # trigger a pingAllFull to solve the ARP and the delay associated
    #CLI(net)
    # Stop mininet
    net.stop()

    #plot_graphs()
    # Kill the controller process
    #controller_proc.terminate();

    # restore TCP parameters
    #disable_tcp_ecn()

    # Get the output from the controller
    #controller_stdout, controller_stderr = controller_proc.communicate()
    #print controller_stdout
    

if __name__ == '__main__':
    main()


