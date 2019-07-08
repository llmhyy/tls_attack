import os
import json
import shutil
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

This script is used to evaluate the performance of the model. A series of tests will be conducted to evaulate the performance of the model

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

def restricted_float(x):
    x = float(x)
    if x < 0.0 or x > 1.0:
        raise argparse.ArgumentTypeError('{} not in range [0.0, 1.0]'.format(x))
    return x

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--model', help='Input directory path of existing model to be used for prediction', required=True)
parser.add_argument('-r', '--rootdir', help='Input the directory path of the folder containing the feature file and other supporting files')
parser.add_argument('-s', '--savedir', help='Input the directory path to save the prediction results', required=True)  # e.g foo/bar/trained-rnn/normal/expt_2019-03-15_21-52-20/predict_results/predict_on_normal/
parser.add_argument('-o', '--mode', help='Input the combination of test for evaluation of the model', default=0, type=int, choices=[0,1,2])
parser.add_argument('-l', '--lower', help='Input the lower bound for sampling traffic', default=0, type=restricted_float)
parser.add_argument('-u', '--upper', help='Input upper bound for sampling traffic', default=1, type=restricted_float)
args = parser.parse_args()

# Switches to run the test
if args.mode == 0:
    BASIC_TEST_SWITCH = True
    SAMPLE_TRAFFIC_SWITCH = False
elif args.mode == 1:
    BASIC_TEST_SWITCH = False
    SAMPLE_TRAFFIC_SWITCH = True
elif args.mode == 2:
    BASIC_TEST_SWITCH = True
    SAMPLE_TRAFFIC_SWITCH = True

# Define filenames from args.rootdir
FEATURE_FILENAME = 'features_tls_*.csv'
FEATUREINFO_FILENAME = 'features_info_*.csv'
PCAPNAME_FILENAME = 'pcapname_*.csv'
MINMAX_FILENAME = 'features_minmax_ref.csv'
rootdir_filenames = os.listdir(args.rootdir)
feature_dir = os.path.join(args.rootdir, fnmatch.filter(rootdir_filenames, FEATURE_FILENAME)[0])
featureinfo_dir = os.path.join(args.rootdir, fnmatch.filter(rootdir_filenames, FEATUREINFO_FILENAME)[0])
pcapname_dir = os.path.join(args.rootdir, fnmatch.filter(rootdir_filenames, PCAPNAME_FILENAME)[0])
minmax_dir = os.path.join(args.rootdir, '..', '..', MINMAX_FILENAME)

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
try:
    with open(minmax_dir, 'r') as f:
        min_max_feature_list = json.load(f)
    min_max_feature = (np.array(min_max_feature_list[0]), np.array(min_max_feature_list[1]))
except FileNotFoundError:
    print('Error: Min-max feature file does not exist in args.rootdir')
    exit()

# Split the dataset into train and test and return train/test indexes to the byte offset
train_idx,test_idx = utilsDatagen.split_train_test(byte_offset, SPLIT_RATIO, SEED)
# Initialize the normalization function
norm_fn = utilsDatagen.normalize(2, min_max_feature)
# Initialize the batch generator
train_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, train_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, 
                                                return_seq_len=True, return_batch_idx=True)
test_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, test_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, 
                                                return_seq_len=True, return_batch_idx=True)


def evaluate_model_on_generator(model, data_generator, featureinfo_dir, pcapname_dir, save_dir):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    # Compute metrics used for conducting tests
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

    if BASIC_TEST_SWITCH:

        # Create a log file for logging in each tests
        logfile = open(os.path.join(save_dir, 'predict_log.txt'),'w')

        ####  TEST 1 ####
        utilsPredict.test_accuracy_of_traffic(mean_acc_for_all_traffic, logfile, save_dir)

        ####  TEST 2 ####
        utilsPredict.test_mse_dim_of_traffic(squared_error_for_all_traffic, dim_names, logfile, save_dir)

        if len(idx_for_all_traffic) > 100: # find outliers only for sufficiently large datasets
            # Get outliers from traffic based on mean acc
            outlier_count = 10
            bottom_idx, top_idx = utilsPredict.find_outlier(outlier_count, mean_acc_for_all_traffic)

            ####  TEST 3a ####
            utilsPredict.test_mse_dim_of_outlier(bottom_idx, top_idx, mean_acc_for_all_traffic, mean_squared_error_for_all_traffic, idx_for_all_traffic, pcap_filename, logfile, save_dir)

            ####  TEST 3b ####
            outlier_traffic_types = ['bottom10traffic', 'top10traffic']
            outlier_traffic_idx = [bottom_idx, top_idx]
            for i in range(len(outlier_traffic_types)):
                save_traffic_dir = os.path.join(save_dir,  outlier_traffic_types[i])
                if os.path.exists(save_traffic_dir):
                    shutil.rmtree(save_traffic_dir)
                os.makedirs(save_traffic_dir)
                sampled_metrics = utilsPredict.get_metrics_from_idx(outlier_traffic_idx[i], mean_acc_for_all_traffic, acc_for_all_traffic, 
                                                                    squared_error_for_all_traffic, mean_squared_error_for_all_traffic,
                                                                    idx_for_all_traffic, pcap_filename,
                                                                    mmap_data, byte_offset, SEQUENCE_LEN, norm_fn, model)
                utilsPredict.summary_for_sampled_traffic(sampled_metrics, dim_names, save_traffic_dir)

        logfile.close()

    if SAMPLE_TRAFFIC_SWITCH:
        ####  TEST 4 ####
        save_sampled_dir = os.path.join(save_dir, 'sampledtraffic_L{}_U{}'.format(args.lower, args.upper))
        if os.path.exists(save_sampled_dir):
            shutil.rmtree(save_sampled_dir)
        os.makedirs(save_sampled_dir)
        bounded_acc_idx = [(i,mean_acc) for i,mean_acc in enumerate(mean_acc_for_all_traffic) if mean_acc >= args.lower and mean_acc <= args.upper]
        if len(bounded_acc_idx)>0:
            print("{} traffic found within bound of {}-{}".format(len(bounded_acc_idx), args.lower, args.upper))
            
            try: 
                random.seed(2018)
                sampled_acc_idx = random.sample(bounded_acc_idx, 10)
            except ValueError:
                sampled_acc_idx = bounded_acc_idx

            print("Sampling {} traffic".format(len(sampled_acc_idx)))
            sampled_idx,_ = [list(t) for t in zip(*sampled_acc_idx)]
            sampled_metrics = utilsPredict.get_metrics_from_idx(sampled_idx, mean_acc_for_all_traffic, acc_for_all_traffic, 
                                                        squared_error_for_all_traffic, mean_squared_error_for_all_traffic, 
                                                        idx_for_all_traffic, pcap_filename,
                                                        mmap_data, byte_offset, SEQUENCE_LEN, norm_fn, model)

            # General summary of sampled traffic
            utilsPredict.summary_for_sampled_traffic(sampled_metrics, dim_names, save_sampled_dir)

            # Interactive plot for sampled traffic
            utilsPlot.plot_interactive_summary_for_sampled_traffic(sampled_metrics, dim_names, save_sampled_dir, show=True)

        else:
            print("No traffic found within bound of {}-{}".format(args.lower, args.upper))

    # Record the prediction accuracy into file
    RESULTS_FILENAME = 'results.csv'
    zipped = zip(idx_for_all_traffic, mean_acc_for_all_traffic)
    sorted_acc = [x for _, x in sorted(zipped)]
    with open(os.path.join(save_dir, RESULTS_FILENAME), 'w') as f:
        for x in sorted_acc:
            f.write(str(x)+'\n')

dataset_name = ['train', 'val']
dataset_generator = [train_generator, test_generator]
for i in range(len(dataset_name)):
    print('Computing metrics for {} traffic...'.format(dataset_name[i]))
    evaluate_model_on_generator(model, dataset_generator[i], featureinfo_dir, pcapname_dir, os.path.join(args.savedir, dataset_name[i]))
