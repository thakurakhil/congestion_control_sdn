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


parser = ArgumentParser(description="Swimming")


parser.add_argument('--dir', '-d',
                    help="Directory to store outputs",
                    default="./results")
parser.add_argument('--time', '-t',
                    help="Duration (sec) to run the experiment",
                    type=int,
                    default=10)
parser.add_argument('--cport', '-c',
                    help="Controller Port (default:6633)",
                    type=int,
                    default=6633)


args = parser.parse_args()


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
            'max_queue_size': 60
        }

        switch_lconfig1  = {
            'bw':    1000,
            'delay': '0.2ms'
        }
        switch_lconfig2  = {
            'bw':    1000,
            'delay': '0.2ms'
        }
        switch_lconfig3  = {
            'bw':    1000,
            'delay': '0.2ms'
        }
        link_lconfig1 = {
            'bw':    1000,
            'delay': '1ms'
        }
        link_lconfig2 = {
            'bw':    1000,
            'delay': '1ms'
        }
        link_lconfig3 = {
            'bw':    1000,
            'delay': '1ms'
        }
        link_lconfig4 = {
            'bw':    1000,
            'delay': '1ms'
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
        self.addSwitch('s1', dpid='0000000000000001', **switch_config)
        self.addSwitch('s2', dpid='0000000000000002', **switch_config)
        self.addSwitch('s3', dpid='0000000000000003', **switch_config)
        self.addSwitch('s4', dpid='0000000000000004', **switch_config)
        self.addSwitch('s5', dpid='0000000000000005', **switch_config)
        self.addSwitch('s6', dpid='0000000000000006', **switch_config)
        self.addSwitch('s7', dpid='0000000000000007', **switch_config)

        # Connect the switches together
        self.addLink('s1', 's2', **switch_lconfig1)
        self.addLink('s2', 's3', **switch_lconfig1)
        self.addLink('s3', 's4', **switch_lconfig1)
        self.addLink('s1', 's5', **switch_lconfig1)
        self.addLink('s5', 's6', **switch_lconfig2)
        self.addLink('s6', 's4', **switch_lconfig2)
        self.addLink('s5', 's7', **switch_lconfig3)
        self.addLink('s7', 's4', **switch_lconfig3)

        # the 7 hosts
        host_format = 'h{:02x}{:02x}{:02x}'
        
        self.addHost('h010101', ip='10.1.1.1', mac='00:00:00:01:01:01')
        self.addLink('s1', 'h010101', **link_lconfig1)

        self.addHost('h010201', ip='10.1.2.1', mac='00:00:00:01:02:01')
        self.addLink('s2', 'h010201', **link_lconfig2)
        self.addHost('h010202', ip='10.1.2.2', mac='00:00:00:01:02:02')
        self.addLink('s2', 'h010202', **link_lconfig2)
        self.addHost('h010203', ip='10.1.2.3', mac='00:00:00:01:02:03')
        self.addLink('s2', 'h010203', **link_lconfig2)

        self.addHost('h010301', ip='10.1.3.1', mac='00:00:00:01:03:01')
        self.addLink('s7', 'h010301', **link_lconfig3)
        self.addHost('h010302', ip='10.1.3.2', mac='00:00:00:01:03:02')
        self.addLink('s7', 'h010302', **link_lconfig3)

        self.addHost('h010401', ip='10.1.4.1', mac='00:00:00:01:04:01')
        self.addLink('s4', 'h010401', **link_lconfig4)


    def DCTopo(self):
        # Add default members to class
        super(ExperimentTopo, self).__init__()

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

#specific monitor for bbr parameters obtained from comand ss
def start_bbrmon(dst, interval_sec=0.1, outfile="bbr.txt", runner=None):
    monitor = Process(target=monitor_bbr,
                      args=(dst, interval_sec, outfile, runner))
    monitor.start()
    return monitor

def iperf_bbr_mon(net, i, port):
    mon = start_bbrmon("%s:%s" % (net.get("h020101").IP(), port),
                       outfile= "%s/bbr%s.txt" %(args.dir, i),
                       runner=net.get("h010102").popen)
    return mon



def start_capture(outfile="capture.dmp", interface=""):
    monitor = Process(target=filter_packets,
                      args=("", outfile))
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
        if delta > nseconds:
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
    h2.popen("killall iperf3",shell=True)
    #h2['runner']("killall iperf3")
    sleep(1) # make sure ports can be reused
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

def start_flows(net, num_flows, time_btwn_flows, flow_type, cong,
                pre_flow_action=None, flow_monitor=None):
    h1 = net.get("h010101")
    h2 = net.get("h010401")

    print "Starting {} flows...".format(cong)
    flows = []
    base_port = 2345

    if flow_type == 'netperf':
        netperf_setup(h1, h2)
        flow_commands = netperf_commands
    else:
        iperf_setup(h1, h2, [base_port + i for i in range(num_flows)])
        flow_commands = iperf_commands

    
    def start_flow(i):
        if pre_flow_action is not None:
            pre_flow_action(net, i, base_port + i) #check here when increasing number of flows
        flow_commands(i, h1, h2, base_port + i, cong[i],
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
    topo = ExperimentTopo()
    switch = partial(OVSSwitch, protocols='OpenFlow15')
    net = Mininet(topo=topo, link=TCLink, autoSetMacs=True, autoStaticArp=True, controller=controller, switch=switch)
    #net = Mininet(topo=topo, link=TCLink, autoSetMacs=True, switch=switch, controller = controller)
    #net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink, switch=switch, autoStaticArp=True)
    #c0 = net.addController('Ryu', controller=RemoteController, ip='127.0.0.1', protocols='OpenFlow13', port=6633)

    # Start the network
    net.start()
    
    dumpNodeConnections(net.hosts) #diagnostic thing
    net.pingAll()


    n_iperf_flows = 1
    time_btwn_flows = 0
    flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["pcc"], pre_flow_action=None)
    flows = None

    """
    cap = start_capture("{}/capture_pcc.dmp".format(args.dir))
    flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["pcc"], pre_flow_action=None)
    display_countdown(args.time + 5)
    Popen("killall tcpdump", shell=True)
    cap.join()
    
    for flow in flows:
        if flow['filter']:
            print "Filtering PCC flow {}...".format(flow['index'])
            filter_capture(flow['filter'],
                           "{}/capture_pcc.dmp".format(args.dir),
                           "{}/flow_pcc_{}.dmp".format(args.dir, flow['index'])) 
        if flow['monitor'] is not None:
            flow['monitor'].terminate()

     
    n_iperf_flows = 1
    time_btwn_flows = 0

    cap = start_capture("{}/capture_cubic.dmp".format(args.dir), "")
    flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["cubic"], pre_flow_action=None)
    display_countdown(args.time + 5)
    Popen("killall tcpdump", shell=True)
    cap.join()

    for flow in flows:
        if flow['filter']:
            print "Filtering cubic flow {}...".format(flow['index'])
            filter_capture(flow['filter'],
                           "{}/capture_cubic.dmp".format(args.dir),
                           "{}/flow_cubic_{}.dmp".format(args.dir, flow['index'])) 
        if flow['monitor'] is not None:
            flow['monitor'].terminate()

    #filter_capture(flows[0]['filter'],"{}/capture_cubic.dmp".format(args.dir),"{}/flow_cubic.dmp".format(args.dir))
    

    n_iperf_flows = 1
    time_btwn_flows = 0

    cap = start_capture("{}/capture_bbr.dmp".format(args.dir))
    flows = start_flows(net, n_iperf_flows, time_btwn_flows, "iperf", ["bbr"], pre_flow_action=None,flow_monitor=iperf_bbr_mon)
    display_countdown(args.time + 5)
    Popen("killall tcpdump", shell=True)
    cap.join()
    
    for flow in flows:
        if flow['filter']:
            print "Filtering BBR flow {}...".format(flow['index'])
            filter_capture(flow['filter'],
                           "{}/capture_bbr.dmp".format(args.dir),
                           "{}/flow_bbr_{}.dmp".format(args.dir, flow['index'])) 
        if flow['monitor'] is not None:
            flow['monitor'].terminate()

    #filter_capture(flows[0]['filter'],"{}/capture_bbr.dmp".format(args.dir),"{}/flow_bbr.dmp".format(args.dir))
    
    

    #filter_capture(flows[0]['filter'],"{}/capture_pcc.dmp".format(args.dir),"{}/flow_pcc.dmp".format(args.dir))
    """            

    # trigger a pingAllFull to solve the ARP and the delay associated
    CLI(net)
    # Stop mininet
    #net.stop()

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


