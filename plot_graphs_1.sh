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

# #for (( i = 0; i <= $n_iperf_flows; i++ )) 
# #do
# i=0



# ##plotting without our model 8000

# ##rates
cd $results_without

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f ./iperf_csv_pcc_0.txt ./iperf_csv_pcc_1.txt ./iperf_csv_pcc_2.txt ./iperf_csv_pcc_3.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rates_all_without_pcc_8000.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rtt_all_without_pcc_8000.png

cd $oldpwd

##plotting with our model 8000

cd $results_with

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f ./iperf_csv_pcc_0.txt ./iperf_csv_pcc_1.txt ./iperf_csv_pcc_2.txt ./iperf_csv_pcc_3.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rates_all_with_8000.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rtt_all_with_8000.png


cd $oldpwd


cd $results_reno

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f $oldpwd/$results_with/iperf_csv_pcc_0.txt ./iperf_csv_reno_0.txt -t "" -l "our model" "reno" -o $oldpwd/$finalresults/rates_all_renoVpcc_h11.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f $oldpwd/$results_with/pcc_rtt_1.txt ./reno_rtt_1.txt -t "" -l "our model" "reno" -o $oldpwd/$finalresults/rtt_all_renoVpcc_h11.png


cd $oldpwd


cd $results_cubic

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f $oldpwd/$results_with/iperf_csv_pcc_0.txt ./iperf_csv_cubic_0.txt -t "" -l "our model" "cubic" -o $oldpwd/$finalresults/rates_all_cubicVpcc_h11.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f $oldpwd/$results_with/pcc_rtt_1.txt ./cubic_rtt_1.txt -t "" -l "our model" "cubic" -o $oldpwd/$finalresults/rtt_all_cubicVpcc_h11.png


cd $oldpwd

cd $results_without_750

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f ./iperf_csv_pcc_0.txt ./iperf_csv_pcc_1.txt ./iperf_csv_pcc_2.txt ./iperf_csv_pcc_3.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rates_all_without_6000.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rtt_all_without_6000.png

cd $oldpwd


cd $results_with_750

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f ./iperf_csv_pcc_0.txt ./iperf_csv_pcc_1.txt ./iperf_csv_pcc_2.txt ./iperf_csv_pcc_3.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rates_all_with_6000.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rtt_all_with_6000.png


cd $oldpwd

cd $results_without_500


echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f ./iperf_csv_pcc_0.txt ./iperf_csv_pcc_1.txt ./iperf_csv_pcc_2.txt ./iperf_csv_pcc_3.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rates_all_without_4500.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rtt_all_without_4500.png

cd $oldpwd


cd $results_with_500

echo "plotting rates graphs.."
python $oldpwd/plot_rates_iperf.py  -f ./iperf_csv_pcc_0.txt ./iperf_csv_pcc_1.txt ./iperf_csv_pcc_2.txt ./iperf_csv_pcc_3.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rates_all_with_4500.png
echo "plotting rtt graphs.."
python $oldpwd/plot_ping.py -f ./pcc_rtt_1.txt ./pcc_rtt_21.txt ./pcc_rtt_22.txt ./pcc_rtt_23.txt -t "" -l h11 h21 h22 h23 -o $oldpwd/$finalresults/rtt_all_with_4500.png


cd $oldpwd




#cd $oldpwd

echo "done.."

