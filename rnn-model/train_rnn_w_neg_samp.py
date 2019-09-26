import os
import json
import time
import math
import random
import fnmatch
import argparse
import tracemalloc
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppress Tensorflow debugging information for INFO level
import tensorflow as tf
from tensorflow.keras.layers import Activation, LSTM, CuDNNLSTM, Input
from tensorflow.keras.models import Sequential, Model, load_model, clone_model
from tensorflow.keras.backend import set_session
from tensorflow.keras import backend as K

import utils_datagen as utilsDatagen
import utils_plot as utilsPlot

parser = argparse.ArgumentParser()
parser.add_argument('-nr', '--normal_dir', help='Input the directory path of the folder containing normal feature file', required=True)
parser.add_argument('-bd', '--breach_dir', help='Input the directory path of the folder containing breach feature file', default=None)
parser.add_argument('-pd', '--poodle_dir', help='Input the directory path of the folder containing poodle feature file', default=None)
parser.add_argument('-rr', '--rc4_dir', help='Input the directory path of the folder containing rc4 feature file', default=None)
parser.add_argument('-dr', '--dos_dir', help='Input the directory path of the folder containing dos feature file', default=None)
parser.add_argument('-s', '--savedir', help='Input the directory path to save the rnn model and its training results', required=True)  # e.g foo/bar/trained-rnn/normal/

parser.add_argument('-pos', '--poslabel', help='Input name of dataset to be used for training', required=True)
parser.add_argument('-e', '--epoch', help='Input epoch for training', default=100, type=int)
parser.add_argument('-q', '--tstep', help='Input the number of time steps for RNN model training', default=1000, type=int)
parser.add_argument('-b', '--bsize', help='Input the batch size used for RNN model training', default=64, type=int)
parser.add_argument('-p', '--split', help='Input the split ratio for the validation set as a percentage of the dataset', default=0.2, type=float)
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
    import traceback
    traceback.print_exc()
    print('\nERROR: Feature file is missing in directory.\nHint: Did you remember to join the feature files together?')
    exit()

# Take ref from any of the feature_filepaths to get the minmax and dim filepath
a_dataset_filepath = os.path.dirname(feature_filepaths[list(feature_filepaths.keys())[0]])
minmax_filepath = os.path.join(os.path.join(a_dataset_filepath, '..', '..'), 'features_minmax_ref.csv')  # TODO: CHANGE THIS
if not os.path.exists(minmax_filepath):
    print('ERROR: Min-max feature file is missing in root directory of feature extraction module')
    exit()

dim_filename_template = 'features_info_*.csv'
try:
    dim_filepath = os.path.join(a_dataset_filepath, fnmatch.filter(os.listdir(a_dataset_filepath), dim_filename_template)[0])
except IndexError as e:
    print(e)
    print('ERROR: Dimension file is missing in directory {}'.format(a_dataset_filepath))
    exit()

# Configuration for model training
DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
BATCH_SIZE = args.bsize
SEQUENCE_LEN = args.tstep
EPOCH = args.epoch
SAVE_EVERY_EPOCH = 5
SPLIT_RATIO = args.split
SEED = 2019

# TODO: Should put this in a config file since it is shared
POS_LABEL = args.poslabel
label2id = {'normal':0, 'breach':1, 'poodle':2, 'rc4':3, 'dos':4}

# Start diagnostic analysis for memory usage
tracemalloc.start()

#####################################################
# DATA LOADING AND PREPROCESSING
#####################################################

# Load the mmap data and byte offset for each dataset
start_time = time.time()
feature_mmap_byteoffsets = {}
for label, filepath in feature_filepaths.items():
    print('Loading {} features into memory...'.format(label))
    feature_mmap_byteoffsets[label] = utilsDatagen.get_mmapdata_and_byteoffset(filepath)
print('Time taken to load all datasets: {:.5f}'.format(time.time()-start_time))

# Load min-max features from file
with open(minmax_filepath, 'r') as f:
    min_max_feature_list = json.load(f)
min_max_feature = (np.array(min_max_feature_list[0]), np.array(min_max_feature_list[1]))

# Load the dimension from file
with open(dim_filepath) as f:
    dim_len = len(f.readlines()) - 1  # Do not count header

# Split dataset into train and test
feature_train_idxs = {}
feature_test_idxs = {}
for label, mmap_byteoffset in feature_mmap_byteoffsets.items():
    feature_train_idx, feature_test_idx = utilsDatagen.split_train_test(len(mmap_byteoffset[1]), SPLIT_RATIO, SEED)
    feature_train_idxs[label] = feature_train_idx
    feature_test_idxs[label] = feature_test_idx

# Initialize the normalization function
norm_fn = utilsDatagen.normalize(3)

# Initialize the train and test generators for model training
train_generator = utilsDatagen.SpecialBatchGenerator(feature_mmap_byteoffsets, feature_train_idxs, norm_fn,label2id[POS_LABEL])
test_generator = utilsDatagen.SpecialBatchGenerator(feature_mmap_byteoffsets, feature_test_idxs, norm_fn, label2id[POS_LABEL])

# Define variables that are related to the positive label
pos_mmap, pos_byteoffsets = feature_mmap_byteoffsets[POS_LABEL]
pos_train_idx = feature_train_idxs[POS_LABEL]
pos_test_idx = feature_test_idxs[POS_LABEL]

#####################################################
# MODEL TRAINING
#####################################################

def dual_mse_loss_fn(y_true, y_pred):
    y_true_sliced = y_true[:,1:,:]
    label = y_true[:, 0, 0]
    label = K.expand_dims(label,axis=-1)
    label = K.repeat_elements(label, SEQUENCE_LEN, axis=-1)
    mask = label * 2 - 1  # Convert 0 into -1
    dual_mse_loss = K.mean(K.square(y_pred - y_true_sliced), axis=-1) * mask
    dual_mse_loss = K.print_tensor(dual_mse_loss, message='dual_mse_loss')
    clipped_dual_mse_loss = K.clip(dual_mse_loss, min_value=-0.01, max_value=1000)  # Max value is an arbitrary large value
    # clipped_dual_mse_loss = K.print_tensor(clipped_dual_mse_loss, message='clipped_dual_mse_loss')
    return clipped_dual_mse_loss

# Build RNN model or load existing RNN model
if args.model:
    model = load_model(args.model)
else:
    model = Sequential()
    if args.gpu:
        model.add(CuDNNLSTM(dim_len, input_shape=(SEQUENCE_LEN, dim_len), return_sequences=True))
    else:
        model.add(LSTM(dim_len, input_shape=(SEQUENCE_LEN, dim_len), return_sequences=True))
    model.add(Activation('relu'))
    model.compile(loss=dual_mse_loss_fn,
                    optimizer='rmsprop')

model.summary()

class TrainHistory(tf.keras.callbacks.Callback):
    def __init__(self, idx, mmap_data, byte_offset):
        super().__init__()
        self.idx = idx
        self.mmap_data = mmap_data
        self.byte_offset = byte_offset

    def on_train_begin(self, logs={}):
        self.list_of_metrics_generator = []

    def on_epoch_end(self, epoch, logs={}):
        if epoch%SAVE_EVERY_EPOCH==(SAVE_EVERY_EPOCH-1):
            data_generator = utilsDatagen.BatchGenerator(self.mmap_data, self.byte_offset, self.idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, return_batch_info=True)
            model_copy = clone_model(model)
            model_copy.set_weights(model.get_weights())
            metrics_generator = utilsDatagen.compute_metrics_generator(model_copy, data_generator, metrics=['acc', 7, 'idx'])
            self.list_of_metrics_generator.append(metrics_generator)

# Initialize NEW train and test generators for model prediction
trainHistory_on_traindata = TrainHistory(feature_train_idxs[POS_LABEL], pos_mmap, pos_byteoffsets)
trainHistory_on_testdata = TrainHistory(feature_test_idxs[POS_LABEL], pos_mmap, pos_byteoffsets)

# Training the RNN model
history = model.fit_generator(train_generator, epochs=EPOCH, callbacks=[trainHistory_on_traindata, trainHistory_on_testdata],
                              validation_data=test_generator,workers=1,use_multiprocessing=False)

#####################################################
# MODEL EVALUATION
#####################################################

# Directory for saving training results
results_dir = os.path.join(args.savedir, 'expt_{}'.format(DATETIME_NOW),'train_results')
os.makedirs(results_dir)

plt.rcParams['figure.figsize'] = (10,7)
plt.rcParams['legend.fontsize'] = 8

# Generating the metrics from the generators
assert len(trainHistory_on_traindata.list_of_metrics_generator) == len(trainHistory_on_testdata.list_of_metrics_generator)
num_trainhistory = len(trainHistory_on_traindata.list_of_metrics_generator)

# Initializing variables for storing metrics
list_of_overall_mean_acc_train = []
list_of_overall_median_acc_train = []
list_of_overall_mean_acc_test = []
list_of_overall_median_acc_test = []
list_of_pkt_len_predict_train = []
list_of_pkt_len_predict_test = []
pkt_len_true_train = None
pkt_len_true_test = None

# Sampling traffic for model prediction on packet length on epochs
sample_count = 5
sample_train_idx = random.sample(pos_train_idx.tolist(), sample_count)
sample_test_idx = random.sample(pos_test_idx.tolist(), sample_count)

# TODO: Change the name of this function. It is too complex and ambiguous
def get_and_process_metrics_from_trainhistory_generator(met_gen, sample_idx):
    trf_mean_acc = np.array([])
    trf_median_acc = np.array([])
    pkt_len_predict = []
    pkt_len_true = []

    # Extract and process batch of metrics on the fly to reduce memory allocation
    for batch_metrics in met_gen:
        # Compute metrics for accuracy
        batch_pkt_acc = batch_metrics['acc']
        batch_trf_mean_acc = np.mean(batch_pkt_acc, axis=1)
        batch_trf_median_acc = np.median(batch_pkt_acc, axis=1)
        trf_mean_acc = np.hstack([trf_mean_acc, batch_trf_mean_acc])
        trf_median_acc = np.hstack([trf_median_acc, batch_trf_median_acc])

        # Compute metrics for packet length
        batch_pkt_len_true_predict = batch_metrics[7]
        batch_idx = batch_metrics['idx']
        batch_pkt_len_true, batch_pkt_len_predict = batch_pkt_len_true_predict
        is_inside_sampled_idx = np.in1d(batch_idx, sample_idx)
        filtered_batch_pkt_len_predict = batch_pkt_len_predict[is_inside_sampled_idx]  # Applying masking
        pkt_len_predict.append(filtered_batch_pkt_len_predict)
        filtered_batch_pkt_len_true = batch_pkt_len_true[is_inside_sampled_idx]
        pkt_len_true.append(filtered_batch_pkt_len_true)

    overall_mean_acc = np.mean(trf_mean_acc)
    overall_median_acc = np.mean(trf_median_acc)

    pkt_len_predict = np.concatenate(pkt_len_predict, axis=0)
    pkt_len_true = np.concatenate(pkt_len_true, axis=0)

    return (trf_mean_acc, overall_mean_acc, overall_median_acc, pkt_len_predict, pkt_len_true)

for i in range(num_trainhistory):
    print('Computing metrics for epoch {}'.format((i+1)*SAVE_EVERY_EPOCH))
    # Computing metrics for train dataset
    trf_mean_acc_train, overall_mean_acc_train,overall_median_acc_train,pkt_len_predict_train,pkt_len_true_train = get_and_process_metrics_from_trainhistory_generator(trainHistory_on_traindata.list_of_metrics_generator[i],sample_train_idx)
    list_of_overall_mean_acc_train.append(overall_mean_acc_train)
    list_of_overall_median_acc_train.append(overall_median_acc_train)
    list_of_pkt_len_predict_train.append(pkt_len_predict_train)

    # Computing metrics for test dataset
    trf_mean_acc_test, overall_mean_acc_test, overall_median_acc_test, pkt_len_predict_test,pkt_len_true_test = get_and_process_metrics_from_trainhistory_generator(trainHistory_on_testdata.list_of_metrics_generator[i],sample_test_idx)
    list_of_overall_mean_acc_test.append(overall_mean_acc_test)
    list_of_overall_median_acc_test.append(overall_median_acc_test)
    list_of_pkt_len_predict_test.append(pkt_len_predict_test)

# Generate plots for model accuracy
utilsPlot.plot_accuracy_and_distribution(list_of_overall_mean_acc_train,
                                    list_of_overall_median_acc_train,
                                    list_of_overall_mean_acc_test,
                                    list_of_overall_median_acc_test,
                                    trf_mean_acc_train,
                                    trf_mean_acc_test,
                                    save_every_epoch=SAVE_EVERY_EPOCH, save_dir=results_dir, show=args.show)

# Generate plots for the model prediction on packet length over epochs
utilsPlot.plot_prediction_on_pktlen(list_of_pkt_len_predict_train,
                                    pkt_len_true_train,
                                    list_of_pkt_len_predict_test,
                                    pkt_len_true_test,
                                    save_every_epoch=SAVE_EVERY_EPOCH, save_dir=results_dir, show=args.show)

# Generate plots for training & validation loss
plt.plot(history.history['loss'])
plt.plot(history.history['val_loss'])
plt.title('Model loss')
plt.ylabel('Loss')
plt.xlabel('Epoch')
plt.legend(['Train', 'Val'], loc='upper left')
plt.savefig(os.path.join(results_dir,'loss'))
if args.show:
    plt.show()
plt.clf()

# File for storing model configuration and training results in numerical form
with open(os.path.join(results_dir, 'train_log.txt'),'w') as logfile:
    logfile.write('####################################\n')
    logfile.write('Training Start Date: {}\n'.format(DATETIME_NOW.split('_')[0]))
    logfile.write('Training Start Time: {}\n'.format(DATETIME_NOW.split('_')[1]))
    logfile.write('Batch Size: {}\n'.format(BATCH_SIZE))
    logfile.write('Epoch: {}\n'.format(EPOCH))
    logfile.write('Feature files used: {}\n'.format(','.join([os.path.basename(feature_filepath) for feature_filepath in feature_filepaths])))
    logfile.write("Existing model used: {}\n".format(args.model))
    logfile.write("Split Ratio: {}\n".format(SPLIT_RATIO))
    logfile.write("Seed: {}\n".format(SEED))
    logfile.write('####################################\n\n')
    model.summary(print_fn=lambda x:logfile.write(x + '\n\n'))

    logfile.write("#####  TRAIN/VAL LOSS  #####\n")
    for i, (loss, val_loss) in enumerate(zip(history.history['loss'], history.history['val_loss'])):
        logfile.write('Epoch  #{}\tTrain Loss: {:.6f}\tVal Loss: {:.6f}\n'.format(i+1, loss, val_loss))
    logfile.write("\n#####  TRAIN/VAL MEAN ACCURACY  #####\n")
    for i, (train_mean, test_mean) in enumerate(zip(list_of_overall_mean_acc_train, list_of_overall_mean_acc_test)):
        logfile.write('Epoch  #{}\tTrain Mean Accuracy: {:.6f}\tVal Mean Accuracy: {:.6f}\n'.format((i*SAVE_EVERY_EPOCH)+SAVE_EVERY_EPOCH, train_mean, test_mean))
    logfile.write("\n#####  TRAIN/VAL MEDIAN ACCURACY  #####\n")
    for i, (train_median, test_median) in enumerate(zip(list_of_overall_median_acc_train, list_of_overall_median_acc_test)):
        logfile.write('Epoch  #{}\tTrain Median Accuracy: {:.6f}\tVal Median Accuracy: {:.6f}\n'.format((i*SAVE_EVERY_EPOCH)+SAVE_EVERY_EPOCH, train_median, test_median))

# Save the model
model.save(os.path.join(args.savedir, 'expt_{}'.format(DATETIME_NOW),'rnnmodel_{}.h5'.format(DATETIME_NOW)))

#####################################################
# DIAGNOSTIC TESTS
#####################################################

print('\n##################################################')
print('RUNNING DIAGNOSTIC TESTS...')
print('##################################################\n')

snapshot = tracemalloc.take_snapshot()
# utilsDiagnostic.display_top(snapshot)
# Pick the top 5 biggest memory blocks
top_stats = snapshot.statistics('traceback')
for i in range(0,5):
    stat = top_stats[i]
    print("%s memory blocks: %.1f KiB" % (stat.count, stat.size / 1024))
    for line in stat.traceback.format():
        print(line)
print('##################################################')

print('\nModel Training Completed!')
