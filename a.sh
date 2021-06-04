#!/bin/bash

n_iperf_flows=1
n_iperf_flows=$n_iperf_flows-1
#results_with="./Bigresults/new/all3"
#results_without="./Bigresults/old/all1"
finalresults="./resultsNew"
results_without="./Bigresults/queue/1000/without"
results_with="./Bigresults/queue/1000/with"
results_reno="./Bigresults/queue/cmp/reno"
results_cubic="./Bigresults/queue/cmp/cubic"
results_without_750="./Bigresults/queue/750/without"
results_with_750="./Bigresults/queue/750/with"
results_without_500="./Bigresults/queue/500/without"
results_with_500="./Bigresults/queue/500/with"

oldpwd=$PWD


cd $results_cubic

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f $oldpwd/$results_with/iperf_csv_pcc_0.txt ./iperf_csv_cubic_0.txt -t "" -l "our model" "cubic" -o $oldpwd/$finalresults/rates_all_cubicVpcc_h11_1.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f $oldpwd/$results_with/pcc_rtt_1.txt ./cubic_rtt_1.txt -t "" -l "our model" "cubic" -o $oldpwd/$finalresults/rtt_all_cubicVpcc_h11_1.png


cd $oldpwd

#cd $oldpwd

echo "done.."

