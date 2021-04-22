#!/bin/bash

n_iperf_flows=1
n_iperf_flows=$n_iperf_flows-1
#results="./Bigresults/new/all3"
#results="./Bigresults/old/all1"
#results="./resultsNew"
results="./Bigresults/queue/cmp"
oldpwd=$PWD

cd $results

# echo "plotting rtt graphs.."
# python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt -t "cmp of RTT -- without the model -- queue size : 500" -l h11 h21 h22 h23 -o ./rtt_all_without_500.png
# echo "plotting throughput graphs.."
# python $oldpwd/plot_throughput.py  -f ./captcp-csv_pcc_1.txt ./captcp-csv_pcc_21.txt ./captcp-csv_pcc_22.txt ./captcp-csv_pcc_23.txt  -t "cmp of throughput -- without the model -- queue size : 500" -l h11 h21 h22 h23  -o ./throughput_all_without_500.png
# echo "plotting rates graphs.."
# python $oldpwd/plot_rates_iperf.py  -f ./iperf_csv_pcc_0.txt ./iperf_csv_pcc_1.txt ./iperf_csv_pcc_2.txt ./iperf_csv_pcc_3.txt -t "cmp of rates -- without the model -- queue size : 500" -l h11 h21 h22 h23 -o ./rates_all_without_500.png

python $oldpwd/plot_rates_iperf.py  -f ../1000/with/iperf_csv_pcc_0.txt ../750/with/iperf_csv_pcc_0.txt ../500/with/iperf_csv_pcc_0.txt -t "cmp of rates of h11 wrt. queue sizes -- with the model" -l 1000 750 500 -o ./rates_h11_with.png

# python $oldpwd/plot_throughput.py  -f ./captcp-csv_pcc_1.txt ../../old/all1/captcp-csv_pcc_1.txt -t "cmp of throughtput of h11 -- with vs without" -o ./throughput_1v1.png
# python $oldpwd/plot_throughput.py  -f ./captcp-csv_pcc_5.txt ../../old/all1/captcp-csv_pcc_5.txt -t "cmp of throughput of sw5 -- with vs without" -o ./throughput_5v5.png
# python $oldpwd/plot_ping.py  -f ../1000/without/pcc_rtt_1.txt ../750/without/pcc_rtt_1.txt ../500/without/pcc_rtt_1.txt -t "cmp of RTT of h11 wrt. queue sizes-- without the model" -l 1000 750 500 -o ./rtt_h11_without.png


cd $oldpwd

echo "done.."
