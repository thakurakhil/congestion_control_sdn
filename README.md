# congestion_control_sdn

System configuration:
Ubuntu 18.04.1 LTS
(Open vSwitch) 2.15.90
DB Schema 8.2.0


uname -a
git clone git://github.com/mininet/mininet 
mininet/util/install.sh -a 
sudo apt-get install -y python-termcolor
sudo apt-get install -y python-matplotlib

##################################################################
####-----------installing openvswitch----##########################

kill `cd /usr/local/var/run/openvswitch && cat ovsdb-server.pid ovs-vswitchd.pid`
git clone https://github.com/openvswitch/ovs.git
#git checkout v2.7.0
#git checkout origin/branch-2.7
git checkout master
git pull

sudo apt-get install -y libssl autoconf libtool
cd ovs/
./boot.sh
./configure --with-linux=/lib/modules/$(uname -r)/build
make
sudo make install
sudo make moudles_install

config_file="/etc/depmod.d/openvswitch.conf"
 for module in datapath/linux/*.ko; do
  modname="$(basename ${module})"
  echo "override ${modname%.ko} * extra" >> "$config_file"
  echo "override ${modname%.ko} * weak-updates" >> "$config_file"
  done
 depmod -a

/sbin/modprobe openvswitch

check if openvswitch is listed:   /sbin/lsmod | grep openvswitch

mkdir -p /usr/local/etc/openvswitch
ovsdb-tool create /usr/local/etc/openvswitch/conf.db \
    vswitchd/vswitch.ovsschema

mkdir -p /usr/local/var/run/openvswitch
mkdir -p /usr/local/var/log/openvswitch


ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --private-key=db:Open_vSwitch,SSL,private_key \
    --certificate=db:Open_vSwitch,SSL,certificate \
    --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
    --pidfile --detach --log-file


ovs-vsctl --no-wait init

ovs-vswitchd --pidfile --detach --log-file

####################################################################

pip install ryu

#################

wget http://downloads.es.net/pub/iperf/iperf-3.0.11.tar.gz
tar -xvf iperf-3.0.11.tar.gz
cd iperf-3.0.11
./configure
make
sudo make install
sudo ldconfig /usr/local/lib

#########################

wget http://launchpadlibrarian.net/306560390/iproute2_4.9.0-1ubuntu1_amd64.deb
sudo dpkg -i iproute2_4.9.0-1ubuntu1_amd64.deb

##################

sudo apt-get install -y tcptrace
sudo apt-get install -y unzip
wget https://github.com/hgn/captcp/archive/master.zip
unzip master.zip
cd captcp-master
sudo make install
sudo apt-get install -y python-pip
pip install dpkt

##########################

sudo apt-get install -y netperf
ssh-keygen -f $HOME/.ssh/id_rsa -t rsa -N ''

##############################3
##############################

./mounting.sh


cat /proc/sys/net/ipv4/tcp_congestion_control  
cat /proc/sys/net/ipv4/tcp_available_congestion_control

wget https://github.com/PCCproject/PCC-Kernel/archive/master.zip
unzip master.zip
cd PCC-Kernel/src
sudo make
sudo insmod tcp_pcc.ko



sudo mn -c
// ryu-manager controller.py
//default port is 6633
//yes/simple_switch_15.py
ryu-manager --observe-links simple_switch_15.py --ofp-tcp-listen-port 6633 --verbose
// ****observe-links is mandatory****
sudo python swim2.py

sudo ovs-vsctl set s1 protocols=OpenFlow15
ovs-appctl fdb/show s1
ovs-ofctl show s1 --protocols=OpenFlow15
ovs-ofctl dump-flows s1

ovs-vsctl list Bridge
ovs-vsctl list Port
ovs-vsctl list Interface


./plot_graphs.sh


grep tcpdump /sys/kernel/security/apparmor/profiles #You need to switch from 'enforcement' mode to 'complain' mode on 'tcpdump'

sudo aa-complain /usr/sbin/tcpdump            #for tcpdump operation nor permited





#####---follow the instructions below to remove openvswitch---#####

pkgs=`dpkg --get-selections | grep openvswitch | awk '{ print $1;}'`
echo $pkgs

sudo DEBIAN_FRONTEND=noninteractive apt-get -y -q remove $pkgs

    if scripts=`ls /etc/init.d/*openvswitch* 2>/dev/null`; then
        echo $scripts
        for s in $scripts; do
            s=$(basename $s)
            echo SCRIPT $s
            sudo service $s stop
            sudo rm -f /etc/init.d/$s
            sudo update-rc.d -f $s remove
        done
    fi
    echo "Done removing OVS"




ip link del s2-eth1;ip link del s1-eth1;ip link del s1-eth1;ip link del s2-eth1;ip link del s5-eth1;ip link del s1-eth2;ip link del s1-eth2;ip link del s5-eth1;ip link del s3-eth1;ip link del s2-eth2;ip link del s2-eth2;ip link del s3-eth1;ip link del s4-eth1;ip link del s3-eth2;ip link del s3-eth2;ip link del s4-eth1;ip link del s6-eth1;ip link del s5-eth2;ip link del s5-eth2;ip link del s6-eth1;ip link del s7-eth1;ip link del s5-eth3;ip link del s5-eth3;ip link del s7-eth1;ip link del s4-eth2;ip link del s6-eth2;ip link del s6-eth2;ip link del s4-eth2;ip link del s4-eth3;ip link del s7-eth2;ip link del s7-eth2;ip link del s4-eth3 
