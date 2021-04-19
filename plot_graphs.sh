#!/bin/bash

n_iperf_flows=1
n_iperf_flows=$n_iperf_flows-1
results="./resultsNew"
oldpwd=$PWD

cd $results

# for (( i = 0; i <= $n_iperf_flows; i++ )) 
# do

# echo "retriving bbr rtt for flow no:$(($i+1))..."
# tshark -2 -r ./flow_bbr_$i.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./bbr_rtt_$i.txt

# echo "retriving cubic rtt for flow no:$(($i+1))..."
# tshark -2 -r ./flow_cubic_$i.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./cubic_rtt_$i.txt

# echo "retriving pcc rtt for flow no:$(($i+1))..."
# tshark -2 -r ./flow_pcc_$i.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./pcc_rtt_$i.txt

# echo "retriving pcc rtt for flow_pcc_1..."
# tshark -2 -r ./flow_pcc_1.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./pcc_rtt_1.txt
# echo "retriving pcc rtt for flow_pcc_21..."
# tshark -2 -r ./flow_pcc_21.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./pcc_rtt_21.txt
# echo "retriving pcc rtt for flow_pcc_22..."
# tshark -2 -r ./flow_pcc_22.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./pcc_rtt_22.txt
# echo "retriving pcc rtt for flow_pcc_23..."
# tshark -2 -r ./flow_pcc_23.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./pcc_rtt_23.txt
# echo "retriving pcc rtt for flow_pcc_5..."
# tshark -2 -r ./flow_pcc_5.dmp -R 'tcp.stream eq 1 && tcp.analysis.ack_rtt'  -e frame.time_relative -e tcp.analysis.ack_rtt -Tfields -E separator=, > ./pcc_rtt_5.txt

# echo "retriving bbr throughput for flow no:$(($i+1))..."
# captcp throughput -u Mbit --stdio flow_bbr_$i.dmp > captcp_bbr_$i.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_bbr_$i.txt > captcp-csv_bbr_$i.txt

# echo "retriving cubic throughput for flow no:$(($i+1))..."
# captcp throughput -u Mbit --stdio flow_cubic_$i.dmp > captcp_cubic_$i.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_cubic_$i.txt > captcp-csv_cubic_$i.txt

# echo "retriving pcc throughput for flow no:$(($i+1))..."
# captcp throughput -u Mbit --stdio flow_pcc_$i.dmp > captcp_pcc_$i.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_pcc_$i.txt > captcp-csv_pcc_$i.txt


# echo "retriving pcc throughput for flow_pcc_1..."
# captcp throughput -u Mbit --stdio flow_pcc_1.dmp > captcp_pcc_1.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_pcc_1.txt > captcp-csv_pcc_1.txt

# echo "retriving pcc throughput for flow_pcc_21..."
# captcp throughput -u Mbit --stdio flow_pcc_21.dmp > captcp_pcc_21.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_pcc_21.txt > captcp-csv_pcc_21.txt

# echo "retriving pcc throughput for flow_pcc_22..."
# captcp throughput -u Mbit --stdio flow_pcc_22.dmp > captcp_pcc_22.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_pcc_22.txt > captcp-csv_pcc_22.txt

# echo "retriving pcc throughput for flow_pcc_23..."
# captcp throughput -u Mbit --stdio flow_pcc_23.dmp > captcp_pcc_23.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_pcc_23.txt > captcp-csv_pcc_23.txt

# echo "retriving pcc throughput for flow_pcc_5..."
# captcp throughput -u Mbit --stdio flow_pcc_5.dmp > captcp_pcc_5.txt
# awk "{print (\$1+$i*2-1)(\",\")(\$2) }" < captcp_pcc_5.txt > captcp-csv_pcc_5.txt


echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt ./pcc_rtt_5.txt --xlimit 8 -o ./rtt_1.png

python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_pcc_1.txt ./captcp-csv_pcc_21.txt ./captcp-csv_pcc_22.txt ./captcp-csv_pcc_23.txt ./captcp-csv_pcc_5.txt -o ./throughput_1.png


#done

# echo "plotting throughput graphs.."
# python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_bbr* -o ./throughput_bbr.png
# python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_cubic* -o ./throughput_cubic.png
# python $oldpwd/plot_throughput.py --xlimit 50 -f ./captcp-csv_pcc* -o ./throughput_pcc.png


cd $oldpwd

echo "done.."

