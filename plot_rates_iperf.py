'''
Plot queue occupancy over time
'''
from helper import *
import plot_defaults

from matplotlib.ticker import LinearLocator
from pylab import figure


parser = argparse.ArgumentParser()
parser.add_argument('--files', '-f',
                    help="Throughput timeseries output to one plot",
                    required=True,
                    action="store",
                    nargs='+',
                    dest="files")

parser.add_argument('--legend', '-l',
                    help="Legend to use if there are multiple plots.  File names used as default.",
                    action="store",
                    nargs="+",
                    default=None,
                    dest="legend")

parser.add_argument('--out', '-o',
                    help="Output png file for the plot.",
                    default=None, # Will show the plot
                    dest="out")

parser.add_argument('--labels',
                    help="Labels for x-axis if summarising; defaults to file names",
                    required=False,
                    default=[],
                    nargs="+",
                    dest="labels")

parser.add_argument('--xlimit',
                    help="Upper limit of x axis, data after ignored",
                    type=float,
                    default=600)

parser.add_argument('--title', '-t',
                    help="Title of the graph",
                    type=str,
                    default="")

parser.add_argument('--every',
                    help="If the plot has a lot of data points, plot one of every EVERY (x,y) point (default 1).",
                    default=1,
                    type=int)

args = parser.parse_args()

if args.legend is None:
    args.legend = []
    for file in args.files:
        name = "new"
        if file == "./iperf_csv_pcc_0.txt":
            name = "h11"
        elif file == "./iperf_csv_pcc_1.txt":
            name = "h21"
        elif file == "./iperf_csv_pcc_2.txt":
            name = "h22"
        elif file == "./iperf_csv_pcc_3.txt":
            name = "h23"
        args.legend.append(name)

to_plot=[]
def get_style(i):
    if i == 0:
        return {'color': 'red'}
    if i == 1:
        return {'color': 'blue'}
    if i == 2:
        return {'color': 'green'}
    else:
        return {'color': 'orange'}

m.rc('figure', figsize=(32, 12))
fig = figure()
ax = fig.add_subplot(111)
time_btwn_flows = 2.0
for i, f in enumerate(args.files):
    data = read_list(f)
    xaxis = map(float, col(0, data))
    throughput = map(float, col(1, data))
    throughput = [t for j, t in enumerate(throughput)
                  if xaxis[j] <= args.xlimit]
    xaxis = [x for x in xaxis if x <= args.xlimit]

    ax.plot(xaxis, throughput, label=args.legend[i], lw=2, **get_style(i))
    ax.xaxis.set_major_locator(LinearLocator(6))
    ax.set_title(args.title)
    ax.set_xticks([0,10,20,30,40,50,60,70,80,90,100])

if args.legend is not None:
	plt.legend()
plt.ylabel("Rate (Mbits)")
plt.grid(True)
plt.xlabel("Seconds")
plt.tight_layout()

if args.out:
    print 'saving to', args.out
    plt.savefig(args.out)
else:
    plt.show()
