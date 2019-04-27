import os
import json
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
MINMAX_FILENAME = 'minmax_features.csv'
minmax_dir = os.path.join(args.rootdir, MINMAX_FILENAME)
try:
    with open(minmax_dir, 'r') as f:
        min_max_feature_list = json.load(f)
    min_max_feature = (np.array(min_max_feature_list[0]), np.array(min_max_feature_list[1]))
except FileNotFoundError:
    print('Min-max feature file does not exist')
    min_max_feature = utilsDatagen.get_min_max(mmap_data, byte_offset)
    min_max_feature_list = (min_max_feature[0].tolist(), min_max_feature[1].tolist())
    with open(minmax_dir, 'w') as f:
        json.dump(min_max_feature_list, f)

# Split the dataset into train and test and return train/test indexes to the byte offset
train_idx,test_idx = utilsDatagen.split_train_test(byte_offset, SPLIT_RATIO, SEED)
# Initialize the normalization function
norm_fn = utilsDatagen.normalize(2, min_max_feature)
# Initialize the batch generator
train_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, train_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, 
                                                return_seq_len=True, return_batch_idx=True)
test_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, test_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, 
                                                return_seq_len=True, return_batch_idx=True)


def test_model_on_generator(model, data_generator, featureinfo_dir, pcapname_dir, save_dir):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    # Compute metrics used for conducting tests
    # acc_for_all_traffic, mean_acc_for_all_traffic, squared_error_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic = utilsPredict.compute_metrics(model, data_generator)
    metrics = utilsPredict.compute_metrics(model, data_generator, return_output=True)
    acc_for_all_traffic = metrics['acc']
    mean_acc_for_all_traffic = metrics['mean_acc']
    squared_error_for_all_traffic = metrics['squared_error']
    mean_squared_error_for_all_traffic = metrics['mean_squared_error']
    idx_for_all_traffic = metrics['idx']

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
    # Create a log file for logging in each tests
    logfile = open(os.path.join(save_dir, 'predict_log.txt'),'w')

    # Save all results into python serialization format
    # print('Dumping results into json file...')
    # for k,v in metrics.items():
    #     if type(v[0]) is np.ndarray:
    #         metrics[k] = [nparray.tolist() for nparray in v] # due to unequal number in the traffic length dim
    # metrics['dim_names'] = dim_names
    # metrics['pcap_filenames'] = [pcap_filename[idx] for idx in idx_for_all_traffic]
    # with open(os.path.join(save_dir,'data.json'), 'w') as f:
    #     json.dump(metrics, f)
    # print('Dumped!')

    ####  TEST 1 ####
    utilsPredict.test_accuracy_of_traffic(mean_acc_for_all_traffic, logfile, save_dir)

    ####  TEST 2 ####
    utilsPredict.test_mse_dim_of_traffi(squared_error_for_all_traffic, dim_names, logfile, save_dir)

    ####  TEST 3 ####
    outlier_count = 10
    bottom_idx, top_idx = utilsPredict.find_outlier(outlier_count, mean_acc_for_all_traffic)
    utilsPredict.test_mse_dim_of_outlier(bottom_idx, top_idx, mean_acc_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic, pcap_filename, logfile, save_dir)

    ####  TEST 4 ####
    save_bottom10_dir = os.path.join(save_dir, 'bottom10traffic')
    if not os.path.exists(save_bottom10_dir):
        os.makedirs(save_bottom10_dir)
    utilsPredict.summary_for_sampled_traffic(bottom_idx, mean_acc_for_all_traffic, acc_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic, pcap_filename, dim_names,
                                                mmap_data, byte_offset, SEQUENCE_LEN, norm_fn, model, save_bottom10_dir)

    save_top10_dir = os.path.join(save_dir, 'top10traffic')
    if not os.path.exists(save_top10_dir):
        os.makedirs(save_top10_dir)
    utilsPredict.summary_for_sampled_traffic(top_idx, mean_acc_for_all_traffic, acc_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic, pcap_filename, dim_names,
                                                mmap_data, byte_offset, SEQUENCE_LEN, norm_fn, model, save_top10_dir)

    # ####  TEST 5 ####
    # save_sampled_dir = os.path.join(save_dir, 'sampledtraffic')
    # if not os.path.exists(save_sampled_dir):
    #     os.makedirs(save_sampled_dir)
    # lower_limit_acc, upper_limit_acc = 0.79, 0.81
    # bounded_acc_idx = [(i,mean_acc) for i,mean_acc in enumerate(mean_acc_for_all_traffic) if mean_acc >= lower_limit_acc and mean_acc <= upper_limit_acc]
    # if len(bounded_acc_idx)>0:
    #     try: 
    #         random.seed(2018)
    #         sampled_acc_idx = random.sample(bounded_acc_idx, 10)
    #     except ValueError:
    #         sampled_acc_idx = bounded_acc_idx

    #     sampled_idx, sampled_mean_acc = [list(t) for t in zip(*sampled_acc_idx)]
    #     utilsPredict.summary_for_sampled_traffic(sampled_idx, mean_acc_for_all_traffic, acc_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic, pcap_filename, dim_names,
    #                                                 mmap_data, byte_offset, SEQUENCE_LEN, norm_fn, model, save_sampled_dir)
    # else:
    #     print("No traffic found within bound of {}-{}".format(lower_limit_acc, upper_limit_acc))


    logfile.close()

print('Computing metrics for train traffic...')
test_model_on_generator(model, train_generator, featureinfo_dir, pcapname_dir, os.path.join(args.savedir, 'train'))
print('Computing metrics for val traffic...')
test_model_on_generator(model, test_generator, featureinfo_dir, pcapname_dir, os.path.join(args.savedir, 'val'))
