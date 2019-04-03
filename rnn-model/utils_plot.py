import os
import math
import random
import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.pyplot import figure
from matplotlib.widgets import Slider, Button, RadioButtons
from matplotlib.patches import Arrow

#defaults to rcParams["figure.figsize"] = [6.4, 4.8]

#########   Prediction   ##########

def plot_distribution(final_acc, overall_mean_acc, save_dir, show=False):
    fig = plt.gcf()
    fig.set_size_inches(8,6)
    ax = plt.gca()
    ax.set_ylim(0.0, 1.0)
    plt.plot(final_acc, '|')
    plt.title('Dist of mean cosine similarity for true packets')
    plt.xlabel('Traffic #')
    plt.ylabel('Mean Cosine Similarity')
    plt.axhline(y=round(overall_mean_acc,5), color='r', linestyle='-')
    plt.text(0.05, round(overall_mean_acc,5)-0.025, '{:.5f}'.format(overall_mean_acc), color='r', fontweight='bold', horizontalalignment='left', verticalalignment='top', transform=ax.transAxes)
    plt.savefig(os.path.join(save_dir, 'acc-traffic'))
    if show:
        plt.show()
    plt.clf()

def plot_mse_for_dim(mse_dim, dim_name, save_dir, show=False):
    fig = plt.gcf()
    fig.set_size_inches(25,18)
    plt.bar(np.arange(len(mse_dim)), mse_dim, tick_label=dim_name)
    plt.xticks(rotation='vertical', fontsize=6)
    plt.title('Overall MSE score for each dimension')
    plt.xlabel('Dimension')
    plt.ylabel('Mean Squared Error')
    plt.savefig(os.path.join(save_dir, 'mse-dim'))
    if show:
        plt.show()
    plt.clf()

def plot_mse_for_dim_for_outliers(pcap_filename, mean_acc, mse_dim, typename, save_dir, show=False):
    n = len(pcap_filename)
    col = 5
    row = math.ceil(n/col)
    fig, ax = plt.subplots(nrows=row, ncols=col)
    plt.subplots_adjust(wspace=0.5)
    fig.set_size_inches(25, 18)
    for i in range(n):
        ax[i//col,i%col].bar(np.arange(len(mse_dim[i])), mse_dim[i])
        ax[i//col,i%col].set_title(str(pcap_filename[i])+'\nAcc: '+str(mean_acc[i]), fontsize=10)
    fig.suptitle('MSE score for each dimension for {} {} outlier'.format(typename, n), fontsize=24)
    plt.savefig(os.path.join(save_dir, 'outlier({}{})'.format(typename,n)))
    if show:
        plt.show()
    plt.clf()

def plot_summary_for_sampled_traffic(pcap_filename, mse_dim, dim_name, mean_acc, packetwise_acc, 
                                predict_for_top5_dim, true_for_top5_dim, top5dim, 
                                predict_for_bottom5_dim, true_for_bottom5_dim, bottom5dim,
                                save_dir, show=False, trough_marker=False):
    fig=plt.gcf()
    fig.set_size_inches(25,18)
    fig.suptitle('Summary Stats for {}\nAcc: {}'.format(pcap_filename, mean_acc))
    
    gs = mpl.gridspec.GridSpec(4,5)
    gs.update(hspace=0.3)

    # ax1 = plt.subplot2grid((4,5), (0,0), colspan=5)
    ax1 = plt.subplot(gs[0,:])
    ax1.bar(np.arange(len(mse_dim)), mse_dim)
    ax1.set_xlabel('Feature #')
    ax1.set_ylabel('MSE score')
    ax1.set_title('MSE score for each dimension')
    
    ax2 = plt.subplot(gs[1,:])
    ax2.plot(packetwise_acc)
    if trough_marker:
        percentile25_acc = np.percentile(packetwise_acc, 25)
        for i,packet_acc in enumerate(packetwise_acc.tolist()):
            if packet_acc<percentile25_acc:
                ax2.plot(i, packet_acc, 'ro-')
                ax2.text(i, (packet_acc-0.05), i+1, fontsize=9, horizontalalignment='center')
    ax2.set_xlabel('Packet #')
    ax2.set_ylabel('Cosine similarity score')
    ax2.set_title('Cosine similarity for each packet')

    for i in range(5):
        # ax_top = plt.subplot2grid((4,5), (2,i))
        ax_top = plt.subplot(gs[2,i])
        ax_top.plot(predict_for_top5_dim[:,i], label='Predict')
        ax_top.plot(true_for_top5_dim[:,i], label='True')
        ax_top.set_title('{} (T)'.format(dim_name[top5dim[i]]))

        # ax_bottom = plt.subplot2grid((4,5), (3,i))
        ax_bottom = plt.subplot(gs[3,i])
        ax_bottom.plot(predict_for_bottom5_dim[:,i], label='Predict')
        ax_bottom.plot(true_for_bottom5_dim[:,i], label='True')
        ax_bottom.set_title('{} (B)'.format(dim_name[bottom5dim[i]]))
    handles,labels = ax_top.get_legend_handles_labels()
    fig.legend(handles, labels, loc=(0.85,0.05))
    plt.savefig(os.path.join(save_dir, '{}.png'.format(pcap_filename)))
    if show:
        plt.show()
    plt.clf()

def plot_mse_for_dim(mse_dim, dim_name, save_dir, show=False):
    fig = plt.gcf()
    fig.set_size_inches(25,18)
    plt.bar(np.arange(len(mse_dim)), mse_dim, tick_label=dim_name)
    plt.xticks(rotation='vertical', fontsize=6)
    plt.title('Overall MSE score for each dimension')
    plt.xlabel('Dimension')
    plt.ylabel('Mean Squared Error')
    plt.savefig(os.path.join(save_dir, 'mse-dim'))
    if show:
        plt.show()
    plt.clf()

def plot_interactive_summary_for_sampled_traffic(pcap_filenames, mean_acc, pktwise_acc, pkwise_sqerr, dim_names,
                                                    predict, true,
                                                    save_dir, show=False):

    def plot_graph():
        fig.suptitle('{}\nAcc: {}'.format(pcap_filenames[pointer], mean_acc[pointer]))
        ax[0].plot([i+1 for i in range(len(pktwise_acc[pointer]))], pktwise_acc[pointer])
        for i, pkt_acc in enumerate(pktwise_acc[pointer]):
            ax[0].plot(i+1, pkt_acc, 'ro', picker=5)
            ax[0].text(i+1, (pkt_acc-0.05), i+1, fontsize=9, horizontalalignment='center')
        ax[1].clear()
        fig.canvas.draw_idle()

    pointer = 0
    fig, ax = plt.subplots(nrows=2, ncols=1)
    ax2 = ax[1].twinx()
    fig.set_size_inches(25,18)
    plot_graph()

    def on_pick(event):
        print(round(event.mouseevent.xdata))
        print(round(event.mouseevent.ydata))
        # Create an arrow on top of the selected point
        print('patches', ax[0].patches)
        if len(ax[0].patches)!=0:
            ax[0].patches[0].remove()
        arrow = Arrow(round(event.mouseevent.xdata), event.mouseevent.ydata-0.11, 0, 0.05, width=0.1, color='red')
        a = ax[0].add_patch(arrow)
        fig.canvas.draw_idle()

        # Plot a new graph
        ax[1].clear()
        ax2.clear()
        ndim = len(dim_names)
        index = [i for i in range(ndim)]
        bar_width = 0.3
        opacity = 0.5
        packet_num = int(round(event.mouseevent.xdata))-1
        ax[1].bar(index, predict[pointer,packet_num,:], bar_width,
                    alpha=opacity, color='b', label='Predict')
        ax[1].bar([i+bar_width for i in index], true[pointer,packet_num,:], bar_width,
                    alpha=opacity, color='r', label='True')
        ax[1].set_xlabel('Dimension')
        ax[1].set_ylabel('Predict/True output')
        ax[1].set_title('Predict/True + SE score graph for each dimension')
        ax[1].set_xticks([i+(bar_width/2) for i in index])
        ax[1].set_xticklabels(dim_names, rotation='vertical', fontsize=6)
        ax[1].legend()

        color = '#000000'
        ax2.plot(index, pkwise_sqerr[pointer][packet_num], color=color, linewidth=0.7)
        ax2.set_ylabel('Squared error', color=color)

    def next(event):
        nonlocal pointer
        pointer = (pointer+1)%len(pktwise_acc)
        ax[0].clear()
        plot_graph()

    def prev(event):
        nonlocal pointer
        pointer = (pointer-1)%len(pktwise_acc)
        ax[0].clear()
        plot_graph()

    axprev = plt.axes([0.69, 0.90, 0.1, 0.04])
    axnext = plt.axes([0.80, 0.90, 0.1, 0.04])
    bnext = Button(axnext, 'Next')
    bnext.on_clicked(next)
    bprev = Button(axprev, 'Previous')
    bprev.on_clicked(prev)
    fig.canvas.mpl_connect('pick_event', on_pick)
    plt.show()


#########   Training   ##########

def plot_accuracy_and_distribution(mean_acc_train, median_acc_train, mean_acc_test, median_acc_test, final_acc_train, final_acc_test, 
                                    first, save_every_epoch, save_dir, show=False):
    """
    Plots train and test cosine similarity (mean/median) over training epochs 
    AND distribution of mean cosine similarity for train and test dataset.

    Parameters
    mean_acc_train:     list of mean cosine similarity on train dataset for each epoch
    median_acc_train:   list of median cosine similarity on train dataset for each epoch
    mean_acc_test:      list of mean cosine similarity on test dataset for each epoch
    median_acc_test:    list of median cosine similarity on test dataset for each epoch
    final_acc_train:    list of mean cosine similarity for each traffic in train dataset after last epoch
    final_acc_test:     list of mean cosine similarity for each traffic in test dataset after last epoch
    
    first:              integer to indicate first ___ packets to apply cosine similarity over 1 traffic
    save_every_epoch:   integer to indicate the number of epochs for each save
    save_dir:           string to indicate the directory to save the plots
    show:               boolean to show the plots or not

    """
    plt.subplots_adjust(hspace=0.7)

    plt.subplot(311)
    epochs = len(mean_acc_train)
    # epochs = len(predict_train)
    # for epoch in range(0, epochs):
    #     manual_update(epoch)
    #     plt.savefig(os.path.join(traffic_len, 'traffic_len_epoch{}'.format((epoch*save_every_epoch)+5)))
    x_values = [(epoch*save_every_epoch)+save_every_epoch for epoch in range(0, epochs)]
    plt.plot(x_values, mean_acc_train, alpha=0.7)
    plt.plot(x_values, median_acc_train, alpha=0.7)
    plt.plot(x_values, mean_acc_test, alpha=0.7)
    plt.plot(x_values, median_acc_test, alpha=0.7)
    plt.title('Model cosine similarity for first {} pkts'.format(first))
    plt.ylabel('Cosine Similarity')
    plt.xlabel('Epoch')
    plt.legend(['Train(mean)', 'Train(median)' , 'Val(mean)', 'Val(median)'], loc='upper left')

    plt.subplot(312)
    plt.plot(final_acc_train,'|')
    plt.title('Dist of mean cosine similarity for first {} pkts (train)'.format(first))
    plt.ylabel('Mean Cosine Similarity')
    plt.xlabel('Traffic #')

    plt.subplot(313)
    plt.plot(final_acc_test,'|')
    plt.title('Dist of mean cosine similarity for first {} pkts (validation)'.format(first))
    plt.ylabel('Mean Cosine Similarity')
    plt.xlabel('Traffic #')

    acc_dist = os.path.join(save_dir, 'acc_dist')
    if not os.path.exists(acc_dist):
        os.mkdir(acc_dist)
    plt.savefig(os.path.join(acc_dist,'acc_dist_{}pkts').format(first))
    if show:
        plt.show()
    plt.clf()

def plot_prediction_on_pktlen(predict_train, true_train, predict_test, true_test, 
                                save_every_epoch, save_dir, show=False):
    """
    Given an array, visualize the traffic over time in a given dimension. This helps us to understand
    whether the model is learning anything at all. We can callback this method at every epoch to observe 
    the changes in predicted traffic
    """
    count = 5
    def choose_random(min, max, count):
        return random.sample(range(min, max), count)

    fig, ax = plt.subplots(nrows=2, ncols=count)
    plt.subplots_adjust(left=0.15, bottom=0.25, wspace=0.4, hspace=0.4)
    fig.set_size_inches(10, 8)
    train_random = choose_random(0, predict_train[0].shape[0], count)
    test_random = choose_random(0, predict_test[0].shape[0], count)
    for i, index in enumerate(zip(train_random,test_random)):
        ax[0,i].set_ylim([0,1])
        ax[1,i].set_ylim([0,1])
        predict = ax[0,i].plot(predict_train[0,index[0],:,0],)
        true = ax[0,i].plot(true_train[0,index[0],:,0], alpha=0.8)
        ax[0,i].set_title('Train #{}'.format(index[0]))
        ax[1,i].plot(predict_test[0,index[1],:,0])
        ax[1,i].plot(true_train[0,index[1],:,0], alpha=0.8)
        ax[1,i].set_title('Test #{}'.format(index[1]))
    fig.legend((predict[0], true[0]),('Predict','True'),loc='center left')
    
    axcolor = 'lightgoldenrodyellow'
    axslider = plt.axes([0.15, 0.1, 0.75, 0.03], facecolor=axcolor)
    s = Slider(axslider, 'Epoch', valmin=1, valmax=len(predict_train), valinit=1, valstep=1)

    def update(val):
        epoch = int(s.val)
        for i, index in enumerate(zip(train_random,test_random)):
            ax[0,i].clear()
            ax[1,i].clear()
            ax[0,i].set_ylim([0,1])
            ax[1,i].set_ylim([0,1])
            ax[0,i].plot(predict_train[epoch-1,index[0],:,0])
            ax[0,i].plot(true_train[0,index[0],:,0], alpha=0.8)
            ax[0,i].set_title('Train #{}'.format(index[0]))
            ax[1,i].plot(predict_test[epoch-1,index[1],:,0])
            ax[1,i].plot(true_train[0,index[1],:,0], alpha=0.8)
            ax[1,i].set_title('Test #{}'.format(index[1]))
        fig.canvas.draw_idle()

    def manual_update(epoch):
        for i, index in enumerate(zip(train_random,test_random)):
            ax[0,i].clear()
            ax[1,i].clear()
            ax[0,i].set_ylim([0,1])
            ax[1,i].set_ylim([0,1])
            ax[0,i].plot(predict_train[epoch-1,index[0],:,0])
            ax[0,i].plot(true_train[0,index[0],:,0], alpha=0.8)
            ax[0,i].set_title('Train #{}'.format(index[0]))
            ax[1,i].plot(predict_test[epoch-1,index[1],:,0])
            ax[1,i].plot(true_train[0,index[1],:,0], alpha=0.8)
            ax[1,i].set_title('Test #{}'.format(index[1]))
        fig.canvas.draw_idle()
    
    s.on_changed(update)

    traffic_len = os.path.join(save_dir, 'traffic_len')
    if not os.path.exists(traffic_len):
        os.mkdir(traffic_len)
    epochs = len(predict_train)
    for epoch in range(0, epochs):
        manual_update(epoch)
        plt.savefig(os.path.join(traffic_len, 'traffic_len_epoch{}'.format((epoch*save_every_epoch)+save_every_epoch)))
    if show:
        plt.show()
    plt.clf()

if __name__=='__main__':
    name = ['hello','world']
    acc = [0.1,0.1]
    example = [[1,2,3],[6,5,6]]
    plot_interactive_summary_for_sampled_traffic(name, acc, example, None, None,
                                                    None, None,
                                                    None, None)