import os
import json
import fnmatch
import argparse
import numpy as np

from datetime import datetime
import matplotlib.pyplot as plt

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress Tensorflow debugging information for INFO level
import tensorflow as tf
from tensorflow.keras.backend import set_session

import utils_many2one
import config

parser = argparse.ArgumentParser()
parser.add_argument('-nr', '--normal_dir', help='Input the directory path of the folder containing normal feature file', required=True)
parser.add_argument('-bd', '--breach_dir', help='Input the directory path of the folder containing breach feature file', default=None)
parser.add_argument('-pd', '--poodle_dir', help='Input the directory path of the folder containing poodle feature file', default=None)
parser.add_argument('-rr', '--rc4_dir', help='Input the directory path of the folder containing rc4 feature file', default=None)
parser.add_argument('-dr', '--dos_dir', help='Input the directory path of the folder containing dos feature file', default=None)
parser.add_argument('-s', '--savedir', help='Input the directory path to save the rnn model and its training results', required=True)  # e.g foo/bar/trained-rnn/normal/

parser.add_argument('-m', '--model', help='Input directory for existing model to be trained')
parser.add_argument('-o', '--show', help='Flag for displaying plots', action='store_true', default=False)
parser.add_argument('-g', '--gpu', help='Flag for using GPU in model training', action='store_true')
args = parser.parse_args()

#####################################################
# PRE-CONFIGURATION
#####################################################

# Setting of CPU/GPU configuration for TF
if args.gpu:
    config = tf.ConfigProto()
    config.gpu_options.allow_growth = True  # dynamically grow the memory used on the GPU
    config.log_device_placement = False  # to log device placement (on which device the operation ran)
                                        # (nothing gets printed in Jupyter, only if you run it standalone)
else:
    config = tf.ConfigProto(
        device_count={'GPU': 0}
    )
sess = tf.Session(config=config)
set_session(sess)  # set this TensorFlow session as the default session for Keras

# Define directory path to key files
def get_feature_filepath(rootdir):
    return os.path.join(rootdir, fnmatch.filter(os.listdir(rootdir), feature_filename_template)[0])

minmax_filepath = os.path.join(args.normal_dir, '..', '..', 'features_minmax_ref.csv')

dim_filename_template = 'features_info_*.csv'
try:
    dim_filepath = os.path.join(args.normal_dir, fnmatch.filter(os.listdir(args.normal_dir), dim_filename_template)[0])
except IndexError as e:
    print(e)
    print('\nERROR: Dimension file is missing in directory.')

try:
    feature_filename_template = 'features_tls_*.csv'
    feature_filepaths = {'normal':get_feature_filepath(args.normal_dir)}
    if args.breach_dir:
        feature_filepaths['breach'] = get_feature_filepath(args.breach_dir)
    if args.poodle_dir:
        feature_filepaths['poodle'] = get_feature_filepath(args.poodle_dir)
    if args.rc4_dir:
        feature_filepaths['rc4'] = get_feature_filepath(args.rc4_dir)
    if args.dos_dir:
        feature_filepaths['dos'] = get_feature_filepath(args.dos_dir)
except IndexError as e:
    print(e)
    print('\nERROR: Feature file is missing in directory.\nHint: Did you remember to join the feature files together?')
    exit()

#####################################################
# DATA LOADING AND PREPROCESSING
#####################################################

# Load the mmap data and byte offset for each dataset
feature_mmap_byteoffsets = {}
for label, filepath in feature_filepaths.items():
    print('Loading {} features into memory...'.format(label))
    feature_mmap_byteoffsets[label] = utils_many2one.get_mmapdata_and_byteoffset(filepath)

# Load min-max features from file
if not os.path.exists(minmax_filepath):
    print('Error: Min-max feature file does not exist')
    exit()
with open(minmax_filepath) as f:
    min_max_feature_list = json.load(f)
    min_max_feature = (np.array(min_max_feature_list[0]),np.array(min_max_feature_list[1]))

# Load the dimension from file
with open(dim_filepath) as f:
    dim_len = len(f.readlines()) - 1  # Do not count header

# Split dataset into train and test
feature_train_idxs = {}
feature_test_idxs = {}
for label, mmap_byteoffset in feature_mmap_byteoffsets.items():
    feature_train_idx, feature_test_idx = utils_many2one.gen_train_test_idx(len(mmap_byteoffset[1]))
    feature_train_idxs[label] = feature_train_idx
    feature_test_idxs[label] = feature_test_idx

# Initialize the normalization function
norm_fn = utils_many2one.normalize(2, min_max_feature)

# Initialize the train and test generators for model training


#####################################################
# MODEL TRAINING
#####################################################

# TODO

#####################################################
# MODEL EVALUATION
#####################################################

print('\nModel Training Completed!')