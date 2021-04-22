'''
Plot ping RTTs over time
'''
from helper import *
import plot_defaults

from matplotlib.ticker import LinearLocator
from pylab import figure

parser = argparse.ArgumentParser()
parser.add_argument('--files', '-f',
                    help="Ping output files to plot",
                    required=True,
                    action="store",
                    nargs='+')

parser.add_argument('--xlimit',
                    help="Upper limit of x axis, data after ignored",
                    type=float,
                    default=600)

parser.add_argument('--legend', '-l',
                    help="Legend to use if there are multiple plots.  File names used as default.",
                    action="store",
                    nargs="+",
                    default=None,
                    dest="legend")

parser.add_argument('--title', '-t',
                    help="Title of the graph",
                    type=str,
                    default="")

parser.add_argument('--out', '-o',
                    help="Output png file for the plot.",
                    default=None) # Will show the plot

args = parser.parse_args()

if args.legend is None:
    args.legend = []
    for file in args.files:
        name = "h11"
        if args.files[i] == "./pcc_rtt_1.txt":
            name = "new"
        elif args.files[i] == "./pcc_rtt_21.txt":
            name = "h21"
        elif args.files[i] == "./pcc_rtt_22.txt":
            name = "h22"
        elif args.files[i] == "./pcc_rtt_23.txt":
            name = "h23"
        elif args.files[i] == "./pcc_rtt_5.txt":
            name = "sw5"
        args.legend.append(name)

m.rc('figure', figsize=(32, 12))
fig = figure()
ax = fig.add_subplot(111)
for i, f in enumerate(args.files):
    data = read_list(f)
    xaxis = map(float, col(0, data)) #time in seconds
    rtts = map(float, col(1, data))  #rtt
    xaxis = [x - xaxis[0] for x in xaxis] #making time relative
    rtts = [r * 1000 for j, r in enumerate(rtts)  #rtt in ms
            if xaxis[j] <= args.xlimit]
    xaxis = [x for x in xaxis if x <= args.xlimit]
    
    
    
    ax.plot(xaxis, rtts, lw=2, label=args.legend[i])
    plt.legend()
    ax.xaxis.set_major_locator(LinearLocator(5))
    ax.set_title(args.title)
    ax.set_xticks([0,10,20,30,40,50,60,70,80,90,100])
    #ax.set_xtickslabels()

plt.ylabel("RTT (ms)")
plt.xlabel("Seconds")
plt.grid(True)
plt.tight_layout()

if args.out:
    plt.savefig(args.out)
else:
    plt.show()
