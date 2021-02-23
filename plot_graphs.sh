#!/bin/bash

n_iperf_flows=1
n_iperf_flows=$n_iperf_flows-1
results="./results"
oldpwd=$PWD

cd $results

for (( i = 0; i <= $n_iperf_flows; i++ )) 
do

echo "retriving bbr rtt for flow no:$(($i+1))..."
tshark -2 -r ./flow_bbr_$i.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./bbr_rtt_$i.txt

echo "retriving cubic rtt for flow no:$(($i+1))..."
tshark -2 -r ./flow_cubic_$i.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./cubic_rtt_$i.txt

echo "retriving pcc rtt for flow no:$(($i+1))..."
tshark -2 -r ./flow_pcc_$i.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./pcc_rtt_$i.txt

echo "retriving bbr throughput for flow no:$(($i+1))..."
captcp throughput -u Mbit --stdio flow_bbr_$i.dmp > captcp_bbr_$i.txt
awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_bbr_$i.txt > captcp-csv_bbr_$i.txt

echo "retriving cubic throughput for flow no:$(($i+1))..."
captcp throughput -u Mbit --stdio flow_cubic_$i.dmp > captcp_cubic_$i.txt
awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_cubic_$i.txt > captcp-csv_cubic_$i.txt

echo "retriving pcc throughput for flow no:$(($i+1))..."
captcp throughput -u Mbit --stdio flow_pcc_$i.dmp > captcp_pcc_$i.txt
awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_pcc_$i.txt > captcp-csv_pcc_$i.txt

echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./bbr_rtt_$i.txt ./cubic_rtt_$i.txt ./pcc_rtt_$i.txt --xlimit 8 -o ./rtt_$i.png

python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_bbr_$i.txt ./captcp-csv_cubic_$i.txt ./captcp-csv_pcc_$i.txt -o ./throughput_$1.png


done

echo "plotting throughput graphs.."
python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_bbr* -o ./throughput_bbr.png
python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_cubic* -o ./throughput_cubic.png
python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_pcc* -o ./throughput_pcc.png


cd $oldpwd

echo "done.."

