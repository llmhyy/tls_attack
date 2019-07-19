import numpy as np
import utils_plot as utilsPlot
import utils_datagen as utilsDatagen
import utils_metric as utilsMetric

import tracemalloc

# def compute_metrics(model, data_generator, return_output=False):
#     # Generate predictions and perform computation of metrics
#     acc_for_all_traffic = []
#     mean_acc_for_all_traffic = []
#     squared_error_for_all_traffic = []
#     mean_squared_error_for_all_traffic = []
#     idx_for_all_traffic = [] # idx_for_all_traffic is a list of the original index of the traffic in the feature file and the pcapname file. this is the ground truth
#     true_for_all_traffic = []
#     predict_for_all_traffic = []
#
#     # Data collection about traffic while iterating through traffic
#     for (batch_inputs, batch_true, batch_info) in data_generator:
#         batch_seq_len = batch_info['seq_len']
#         batch_idx = batch_info['batch_idx']
#         batch_predict = model.predict_on_batch(batch_inputs)
#         idx_for_all_traffic.extend(batch_idx.tolist())
#
#         padded_batch_acc = utilsMetric.calculate_acc_of_traffic(batch_predict, batch_true)
#         batch_acc = [padded_batch_acc[i,0:seq_len] for i,seq_len in enumerate(batch_seq_len)]
#         batch_mean_acc = [np.mean(acc) for acc in batch_acc]
#         acc_for_all_traffic.extend(batch_acc)
#         mean_acc_for_all_traffic.extend(batch_mean_acc)
#
#         padded_batch_squared_error = utilsMetric.calculate_squared_error_of_traffic(batch_predict, batch_true)
#         batch_squared_error = [padded_batch_squared_error[i,0:seq_len,:] for i,seq_len in enumerate(batch_seq_len)]
#         batch_mean_squared_error = [np.sum(sqerr, axis=0)/sqerr.shape[0] for i,sqerr in enumerate(batch_squared_error)]
#         squared_error_for_all_traffic.extend(batch_squared_error)
#         mean_squared_error_for_all_traffic.extend(batch_mean_squared_error)
#
#         if return_output:
#             batch_true_list = [i_true for i_true in batch_true]
#             batch_predict_list = [i_predict for i_predict in batch_predict]
#             true_for_all_traffic.extend(batch_true_list)
#             predict_for_all_traffic.extend(batch_predict_list)
#
#     # return acc_for_all_traffic, mean_acc_for_all_traffic, squared_error_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic
#     metrics = {'acc':acc_for_all_traffic, 'mean_acc':mean_acc_for_all_traffic,
#                 'squared_error':squared_error_for_all_traffic, 'mean_squared_error':mean_squared_error_for_all_traffic,
#                 'true':true_for_all_traffic, 'predict':predict_for_all_traffic,
#                 'idx':idx_for_all_traffic}
#     return metrics

def compute_metrics_on_the_fly(model, data_generator, metric=None):
    output = []
    for (batch_inputs, batch_true, batch_info) in data_generator:
        batch_seq_len = batch_info['seq_len']
        batch_predict = model.predict_on_batch(batch_inputs)
        if metric == 'acc' or metric == 'mean_acc':
            padded_batch_acc = utilsMetric.calculate_acc_of_traffic(batch_predict, batch_true)
            batch_acc = [padded_batch_acc[i,0:seq_len] for i,seq_len in enumerate(batch_seq_len)]
            if metric == 'acc':
                output.extend(batch_acc)
            elif metric == 'mean_acc':
                batch_mean_acc = [np.mean(acc) for acc in batch_acc]
                output.extend(batch_mean_acc)
        elif metric == 'squared_error' or metric == 'mean_squared_error':
            padded_batch_squared_error = utilsMetric.calculate_squared_error_of_traffic(batch_predict, batch_true)
            batch_squared_error = [padded_batch_squared_error[i,0:seq_len,:] for i,seq_len in enumerate(batch_seq_len)]
            if metric == 'squared_error':
                output.extend(batch_squared_error)
            elif metric == 'mean_squared_error':
                batch_mean_squared_error = [np.sum(sqerr, axis=0)/sqerr.shape[0] for i,sqerr in enumerate(batch_squared_error)]
                output.extend(batch_mean_squared_error)
        elif metric == 'idx':
            batch_idx = batch_info['batch_idx']
            output.extend(batch_idx.tolist())
    return output

def compute_metrics_generator(model, data_generator, metrics=None):
    output = {}
    for (batch_inputs, batch_true, batch_info) in data_generator:
        batch_seq_len = batch_info['seq_len']
        batch_predict = model.predict_on_batch(batch_inputs)

        for metric in metrics:
            if metric == 'acc' or metric == 'mean_acc':
                padded_batch_acc = utilsMetric.calculate_acc_of_traffic(batch_predict, batch_true)
                masked_batch_acc = np.ma.array(padded_batch_acc)
                # Mask based on true seq len for every row
                for i in range(len(batch_seq_len)):
                    masked_batch_acc[i,batch_seq_len[i]:] = np.ma.masked
                if metric == 'acc':
                    output[metric] = masked_batch_acc
                elif metric == 'mean_acc':
                    batch_mean_acc = np.mean(masked_batch_acc, axis=-1)
                    output[metric] = batch_mean_acc

            elif metric == 'squared_error' or metric == 'mean_squared_error':
                padded_batch_squared_error = utilsMetric.calculate_squared_error_of_traffic(batch_predict, batch_true)
                masked_batch_squared_error = np.ma.array(padded_batch_squared_error)
                # Mask based on true seq len for every row
                for i in range(len(batch_seq_len)):
                    masked_batch_squared_error[i,batch_seq_len[i]:,:] = np.ma.masked
                if metric == 'squared_error':
                    output[metric] = masked_batch_squared_error
                elif metric == 'mean_squared_error':
                    batch_mean_squared_error = np.mean(masked_batch_squared_error, axis=1)
                    output[metric] = batch_mean_squared_error

            elif metric == 'idx':
                batch_idx = batch_info['batch_idx']
                output[metric] = batch_idx

            elif metric == 'seq_len':
                output[metric] = batch_seq_len

            elif type(metric) == int:  # dim number
                output[metric] = (batch_true[:,:,metric:metric+1], batch_predict[:,:,metric:metric+1])

            elif metric == 'true_predict':
                output[metric] = (batch_true, batch_predict)

        yield output

def test_accuracy_of_traffic(mean_acc_for_all_traffic, logfile, save_dir):
    overall_mean_acc = np.mean(mean_acc_for_all_traffic)
    utilsPlot.plot_distribution(mean_acc_for_all_traffic, overall_mean_acc, save_dir)

    logfile.write("#####  TEST 1: OVERALL MEAN COSINE SIMILARITY  #####\n")
    logfile.write('Overall Mean Accuracy{:60}{:>10.6f}\n'.format(':', overall_mean_acc))

def test_mse_dim_of_traffic(squared_error_for_all_traffic, dim_names, logfile, save_dir):
    n = sum([sqerr.shape[0] for sqerr in squared_error_for_all_traffic])
    mean_squared_error_for_features = np.sum([np.sum(sqerr,axis=0) for sqerr in squared_error_for_all_traffic], axis=0)/n
    utilsPlot.plot_mse_for_dim(mean_squared_error_for_features, dim_names, save_dir)

    logfile.write("\n#####  TEST 2: MEAN SQUARED ERROR FOR EACH DIMENSION  #####\n")
    sorted_mse_idx = sorted(range(len(mean_squared_error_for_features)), key=lambda k:mean_squared_error_for_features[k])
    for i in sorted_mse_idx:
        line = 'Mean Squared Error for {:60}{:>10.6f}\n'.format(dim_names[i]+':', mean_squared_error_for_features[i])
        logfile.write(line)

def find_outlier(outlier_count, mean_acc_for_all_traffic):
    sorted_acc_idx = sorted(range(len(mean_acc_for_all_traffic)), key=lambda k:mean_acc_for_all_traffic[k])
    bottom_idx = sorted_acc_idx[:outlier_count]
    top_idx = sorted_acc_idx[-outlier_count:]
    return bottom_idx, top_idx

def test_mse_dim_of_outlier(bottom_idx, top_idx, mean_acc_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic, pcap_filename, logfile, save_dir):

    def gen_plot(selected_idx, outliertype):
        selected_pcap_filename = [pcap_filename[idx_for_all_traffic[i]] for i in selected_idx]
        selected_mean_acc = [mean_acc_for_all_traffic[i] for i in selected_idx]
        selected_mse_dim = [mean_squared_error_for_all_traffic[i] for i in selected_idx]
        utilsPlot.plot_mse_for_dim_for_outliers(pcap_filename=selected_pcap_filename,
                                                mean_acc=selected_mean_acc,
                                                mse_dim=selected_mse_dim,
                                                typename=outliertype,
                                                save_dir=save_dir)
        if outliertype == 'bottom':
            logfile.write('Bottom {} Performing Traffic\n'.format(len(selected_idx)))
        elif outliertype == 'top':
            logfile.write('Top {} Performing Traffic\n'.format(len(selected_idx)))
        for i in range(len(selected_pcap_filename)):
            line = 'Mean Accuracy for {:60}{:>10.6f}\n'.format(selected_pcap_filename[i]+':', selected_mean_acc[i])
            logfile.write(line)

    logfile.write("\n#####  TEST 3: OUTLIER TRAFFIC IN MEAN COSINE SIMILARITY  #####\n")
    gen_plot(bottom_idx, 'bottom')
    gen_plot(top_idx, 'top')

def get_metrics_from_idx(sampled_idx, mean_acc_for_all_traffic, acc_for_all_traffic,
                squared_error_for_all_traffic, mean_squared_error_for_all_traffic,
                idx_for_all_traffic, pcap_filename,
                mmap_data, byte_offset, sequence_len, norm_fn, model):
    sampled_pcap_filename = [pcap_filename[idx_for_all_traffic[i]] for i in sampled_idx]
    sampled_acc = [acc_for_all_traffic[i] for i in sampled_idx]
    sampled_mean_acc = [mean_acc_for_all_traffic[i] for i in sampled_idx]
    # sampled_mse_dim = [mean_squared_error_for_all_traffic[i] for i in sampled_idx]
    sampled_sqerr = [squared_error_for_all_traffic[i] for i in sampled_idx]
    sampled_mean_sqerr = [mean_squared_error_for_all_traffic[i] for i in sampled_idx]
    sampled_input, sampled_true, sampled_seq_len = utilsDatagen.get_feature_vector([idx_for_all_traffic[i] for i in sampled_idx], mmap_data, byte_offset, sequence_len, norm_fn)
    sampled_predict = model.predict_on_batch(sampled_input)
    metrics = {'acc':sampled_acc, 'mean_acc':sampled_mean_acc,
                'squared_error':sampled_sqerr, 'mean_squared_error':sampled_mean_sqerr,
                'true':sampled_true, 'predict':sampled_predict,
                'pcap_filename':sampled_pcap_filename, 'seq_len':sampled_seq_len}
    return metrics

def summary_for_sampled_traffic(sampled_metrics, dim_names, save_dir):
    sampled_pcap_filename = sampled_metrics['pcap_filename']
    sampled_acc = sampled_metrics['acc']
    sampled_mean_acc = sampled_metrics['mean_acc']
    sampled_mean_sqerr = sampled_metrics['mean_squared_error']
    sampled_true = sampled_metrics['true']
    sampled_predict = sampled_metrics['predict']
    sampled_seq_len = sampled_metrics['seq_len']
    for i in range(len(sampled_pcap_filename)):
        top5dim = sorted(range(len(sampled_mean_sqerr[i])), key=lambda k:sampled_mean_sqerr[i][k])[:5]
        bottom5dim = sorted(range(len(sampled_mean_sqerr[i])), key=lambda k:sampled_mean_sqerr[i][k])[-5:]
        utilsPlot.plot_summary_for_sampled_traffic(sampled_pcap_filename[i], sampled_mean_sqerr[i], dim_names, sampled_mean_acc[i], sampled_acc[i],
                                            sampled_predict[:,:,top5dim][i,:sampled_seq_len[i]], sampled_true[:,:,top5dim][i,:sampled_seq_len[i]], top5dim,
                                            sampled_predict[:,:,bottom5dim][i,:sampled_seq_len[i]], sampled_true[:,:,bottom5dim][i,:sampled_seq_len[i]], bottom5dim,
                                            save_dir, trough_marker=True)

if __name__ == '__main__':
    pass