import os
import fnmatch
import random
import argparse
import numpy as np
from keras.models import load_model

import utils_plot as utilsPlot
import utils_metric as utilsMetric
import utils_datagen as utilsDatagen
import utils_predict as utilsPredict

'''
PREDICT RNN

Note: PREDICT RNN is a script for standard evaluation of the model. It should be a one-off execution of the script and not executed repeatedly

This script is used to evaluate the performance of the model. A series of tests will be conducted to gain insights into the model

TEST 1 (acc-traffic)
• Calculate the mean cosine similarity over each traffic (true packets) and plot its distribution. 
• Calculate the overall mean cosine similarity across all traffic

TEST 2 (mse-dim)
• Calculate the mean squared error for each dimension over all traffic and rank it in descending order
• Plot the mean squared error for each dimension

TEST 3 (outlier)
• Sample the top 10 performing and bottom 10 performing traffic. 
• Record the pcap filename, the cosine similarity and the mean squared error of its dimensions

'''

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--model', help='Input directory path of existing model to be used for prediction', required=True)
parser.add_argument('-r', '--rootdir', help='Input the root directory path containing the feature csv file and other supporting files')
parser.add_argument('-s', '--savedir', help='Input the directory path to save the prediction results', required=True)  # e.g foo/bar/trained-rnn/normal/expt_2019-03-15_21-52-20/predict_results/predict_on_normal/
args = parser.parse_args()

# Obtain relevant filenames using string matches
FEATURE_FILENAME = 'features_tls_*.csv'
FEATUREINFO_FILENAME = 'feature_info_*.csv'
PCAPNAME_FILENAME = 'pcapname_*.csv'
rootdir_filenames = os.listdir(args.rootdir)
feature_dir = os.path.join(args.rootdir, fnmatch.filter(rootdir_filenames, FEATURE_FILENAME)[0])
featureinfo_dir = os.path.join(args.rootdir, fnmatch.filter(rootdir_filenames, FEATUREINFO_FILENAME)[0])
pcapname_dir = os.path.join(args.rootdir, fnmatch.filter(rootdir_filenames, PCAPNAME_FILENAME)[0])

BATCH_SIZE = 64
SEQUENCE_LEN = 100
SPLIT_RATIO = 0.05
SEED = 2019

# Load the trained model
print('Loading trained model...')
model = load_model(args.model)
model.summary()

# Load the mmap data and the byte offsets from the feature file
print('\nLoading features into memory...')
mmap_data, byte_offset = utilsDatagen.get_mmapdata_and_byteoffset(feature_dir)
# Get min and max for each feature
min_max_feature = utilsDatagen.get_min_max(mmap_data, byte_offset)
# Split the dataset into train and test and return train/test indexes to the byte offset
train_idx,test_idx = utilsDatagen.split_train_test(byte_offset, SPLIT_RATIO, SEED)
# Initialize the normalization function
norm_fn = utilsDatagen.normalize(2, min_max_feature)
# Initialize the batch generator
train_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, train_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, 
                                                return_seq_len=True, return_batch_idx=True)
test_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, test_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, 
                                                return_seq_len=True, return_batch_idx=True)


def evaluate_sampled_traffic_on_generator(model, data_generator, featureinfo_dir, pcapname_dir, save_dir):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    # Compute metrics used for conducting tests
    # acc_for_all_traffic, mean_acc_for_all_traffic, squared_error_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic = utilsPredict.compute_metrics(model, data_generator)
    metrics = utilsPredict.compute_metrics(model, data_generator)
    acc_for_all_traffic = metrics['acc']
    mean_acc_for_all_traffic = metrics['mean_acc']
    squared_error_for_all_traffic = metrics['squared_error']
    mean_squared_error_for_all_traffic = metrics['mean_squared_error']
    idx_for_all_traffic = metrics['idx_for_all_traffic']
    
    # Extract dim names for identifying dim
    dim_names = []
    with open(featureinfo_dir, 'r') as f:
        features_info = f.readlines()[1:] # Ignore header
        for row in features_info:
            split_row = row.split(',')
            network_layer, tls_protocol, dim_name, feature_type, feature_enum_value = split_row[0].strip(), split_row[1].strip(), split_row[2].strip(), split_row[3].strip(), split_row[4].strip()
            if 'Enum' in feature_type:
                dim_name = dim_name+'-'+feature_enum_value
            if 'TLS' in network_layer:
                dim_name = '('+tls_protocol+')'+dim_name
            dim_names.append(dim_name)
    # Extract the pcap filename for traffic identification
    with open(pcapname_dir) as f:
        pcap_filename = [row.strip() for row in f.readlines()]
    # Log file for logging in each tests
    logfile = open(os.path.join(save_dir, 'predict_log.txt'),'w')

    save_sampled_dir = os.path.join(save_dir, 'sampledtraffic_seed{}'.format(SEED))
    if not os.path.exists(save_sampled_dir):
        os.makedirs(save_sampled_dir)
    lower_limit_acc, upper_limit_acc = 0.79, 0.81
    bounded_acc_idx = [(i,mean_acc) for i,mean_acc in enumerate(mean_acc_for_all_traffic) if mean_acc >= lower_limit_acc and mean_acc <= upper_limit_acc]
    if len(bounded_acc_idx)>0:
        try: 
            random.seed(SEED)
            sampled_acc_idx = random.sample(bounded_acc_idx, 10)
        except ValueError:
            sampled_acc_idx = bounded_acc_idx

        sampled_idx, _ = [list(t) for t in zip(*sampled_acc_idx)]
        sampled_pcap_filename = [pcap_filename[idx_for_all_traffic[i]] for i in sampled_idx]
        sampled_acc = [acc_for_all_traffic[i] for i in sampled_idx]
        sampled_mean_acc = [mean_acc_for_all_traffic[i] for i in sampled_idx]
        sampled_sqerr = [squared_error_for_all_traffic[i] for i in sampled_idx]
        sampled_mean_sqerr = [mean_squared_error_for_all_traffic[i] for i in sampled_idx]
        sampled_input, sampled_true, sampled_seq_len = utilsDatagen.get_feature_vector([idx_for_all_traffic[i] for i in sampled_idx], mmap_data, byte_offset, SEQUENCE_LEN, norm_fn)
        sampled_predict = model.predict_on_batch(sampled_input)


        utilsPlot.plot_interactive_summary_for_sampled_traffic(sampled_pcap_filename, sampled_mean_acc, sampled_acc, sampled_sqerr, dim_names,
                                                                    sampled_predict, sampled_true,
                                                                    save_sampled_dir, show=True)

        # utilsPredict.summary_for_sampled_traffic(sampled_idx, mean_acc_for_all_traffic, acc_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic, pcap_filename, dim_names,
        #                                             mmap_data, byte_offset, SEQUENCE_LEN, norm_fn, model, save_sampled_dir)
    else:
        print("No traffic found within bound of {}-{}".format(lower_limit_acc, upper_limit_acc))

    logfile.close()

print('Computing metrics for train traffic...')
evaluate_sampled_traffic_on_generator(model, train_generator, featureinfo_dir, pcapname_dir, os.path.join(args.savedir, 'train'))
print('Computing metrics for val traffic...')
evaluate_sampled_traffic_on_generator(model, test_generator, featureinfo_dir, pcapname_dir, os.path.join(args.savedir, 'val'))