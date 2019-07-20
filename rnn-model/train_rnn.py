import os
import json
import math
import fnmatch
import argparse
import tracemalloc
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt

import utils_datagen as utilsDatagen
import utils_plot as utilsPlot

parser = argparse.ArgumentParser()
parser.add_argument('-e', '--epoch', help='Input epoch for training', default=100, type=int)
parser.add_argument('-q', '--tstep', help='Input the number of time steps for RNN model training', default=1000, type=int)
parser.add_argument('-p', '--split', help='Input the split ratio for the validation set as a percentage of the dataset', default=0.05, type=float)
parser.add_argument('-r', '--rootdir', help='Input the directory path of the folder containing the feature file and other supporting files', required=True)
parser.add_argument('-s', '--savedir', help='Input the directory path to save the rnn model and its training results', required=True)  # e.g foo/bar/trained-rnn/normal/
parser.add_argument('-m', '--model', help='Input directory for existing model to be trained')
parser.add_argument('-o', '--show', help='Flag for displaying plots', action='store_true', default=False)
parser.add_argument('-g', '--gpu', help='Flag for using GPU in model training', action='store_true')
args = parser.parse_args()

# Force use of CPU before importing keras
if not args.gpu:
    os.environ['CUDA_VISIBLE_DEVICES'] = '-1'
import keras
from keras.layers import Activation
from keras.layers import LSTM, CuDNNLSTM
from keras.models import Sequential
from keras.models import load_model
from keras.models import clone_model

# Define filenames from args.rootdir
FEATURE_FILENAME = 'features_tls_*.csv'
MINMAX_FILENAME = 'features_minmax_ref.csv'
rootdir_filenames = os.listdir(args.rootdir)
try:
    feature_dir = os.path.join(args.rootdir, fnmatch.filter(rootdir_filenames, FEATURE_FILENAME)[0])
except IndexError:
    print('\nERROR: Feature file is missing in directory.\nHint: Did you remember to join the feature files together?')
    exit()
minmax_dir = os.path.join(args.rootdir, '..', '..', MINMAX_FILENAME)

# Config info
DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
BATCH_SIZE = 64
SEQUENCE_LEN = args.tstep
EPOCH = args.epoch
SAVE_EVERY_EPOCH = 5
SPLIT_RATIO = args.split
SEED = 2019

# Start diagnostic analysis
tracemalloc.start()

#####################################################
# DATA LOADING AND PREPROCESSING
#####################################################

# Load the mmap data and the byte offsets from the feature file
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
train_idx, test_idx = utilsDatagen.split_train_test(dataset_size=len(byte_offset), split_ratio=SPLIT_RATIO, seed=SEED)

# Intializing constants for building RNN model
TRAIN_SIZE = len(train_idx)
TEST_SIZE = len(test_idx)
sample_traffic = json.loads('['+mmap_data[byte_offset[0][0]:byte_offset[0][1]+1].decode('ascii').strip().rstrip(',')+']')
INPUT_DIM = len(sample_traffic[0])

# Initialize the normalization function
norm_fn = utilsDatagen.normalize(2, min_max_feature)

# Initialize the train and test generators for model training
train_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, train_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn)
test_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, test_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn)

#####################################################
# MODEL TRAINING
#####################################################

if args.gpu:
    import tensorflow as tf
    from keras.backend.tensorflow_backend import set_session

    config = tf.ConfigProto()
    config.gpu_options.allow_growth = True  # dynamically grow the memory used on the GPU
    config.log_device_placement = True  # to log device placement (on which device the operation ran)
                                        # (nothing gets printed in Jupyter, only if you run it standalone)
    sess = tf.Session(config=config)
    set_session(sess)  # set this TensorFlow session as the default session for Keras

# Build RNN model or load existing RNN model
if args.model:
    model = load_model(args.model)
else:
    model = Sequential()
    if args.gpu:
        model.add(CuDNNLSTM(INPUT_DIM, input_shape=(SEQUENCE_LEN, INPUT_DIM), return_sequences=True))
    else:
        model.add(LSTM(INPUT_DIM, input_shape=(SEQUENCE_LEN, INPUT_DIM), return_sequences=True))
    model.add(Activation('relu'))
    model.compile(loss='mean_squared_error',
                    optimizer='rmsprop')
model.summary()

class TrainHistory(keras.callbacks.Callback):
    def __init__(self, idx):
        super().__init__()
        self.idx = idx

    def on_train_begin(self, logs={}):
        self.list_of_metrics_generator = []

    def on_epoch_end(self, epoch, logs={}):
        if epoch%SAVE_EVERY_EPOCH==(SAVE_EVERY_EPOCH-1):
            data_generator = utilsDatagen.BatchGenerator(mmap_data, byte_offset, self.idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, return_batch_info=True)
            model_copy = clone_model(model)
            model_copy.set_weights(model.get_weights())
            metrics_generator = utilsDatagen.compute_metrics_generator(model_copy, data_generator, metrics=['acc', 7])
            self.list_of_metrics_generator.append(metrics_generator)

# Initialize NEW train and test generators for model prediction
trainHistory_on_traindata = TrainHistory(train_idx)
trainHistory_on_testdata = TrainHistory(test_idx)

# Training the RNN model
history = model.fit_generator(train_generator, steps_per_epoch=math.ceil(TRAIN_SIZE/BATCH_SIZE), 
                                                epochs=EPOCH, 
                                                callbacks=[trainHistory_on_traindata, trainHistory_on_testdata], 
                                                validation_data=test_generator, 
                                                validation_steps=math.ceil(TEST_SIZE/BATCH_SIZE), 
                                                workers=1,
                                                use_multiprocessing=False)

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

for i in range(num_trainhistory):
    print('Computing metrics for epoch {}'.format((i+1)*SAVE_EVERY_EPOCH))
    # Computing metrics for train dataset
    metrics_generator_train_for_i_epoch = trainHistory_on_traindata.list_of_metrics_generator[i]
    epoch_train_metrics = [batch_metrics for batch_metrics in metrics_generator_train_for_i_epoch]

    pkt_acc_train = [batch_metrics['acc'] for batch_metrics in epoch_train_metrics]
    pkt_acc_train = np.concatenate(pkt_acc_train, axis=0)  # Join up the batches
    trf_mean_acc_train = np.mean(pkt_acc_train, axis=1)
    trf_median_acc_train = np.median(pkt_acc_train, axis=1)
    overall_mean_acc_train = np.mean(trf_mean_acc_train)
    overall_median_acc_train = np.median(trf_median_acc_train)
    list_of_overall_mean_acc_train.append(overall_mean_acc_train)
    list_of_overall_median_acc_train.append(overall_median_acc_train)

    pkt_len_true_predict_train = [metrics[7] for metrics in epoch_train_metrics]
    zipped_pkt_len_true_predict_train = list(zip(*pkt_len_true_predict_train))
    if pkt_len_true_train is None:  # Join up batches for true value of pkt len once
        pkt_len_true_train = np.concatenate(zipped_pkt_len_true_predict_train[0], axis=0)  # Join up the batches
    pkt_len_predict_train = np.concatenate(zipped_pkt_len_true_predict_train[1], axis=0)  # Join up the batches
    list_of_pkt_len_predict_train.append(pkt_len_predict_train)

    # Computing metrics for test dataset
    metrics_generator_test_for_i_epoch = trainHistory_on_testdata.list_of_metrics_generator[i]
    epoch_test_metrics = [metrics for metrics in metrics_generator_test_for_i_epoch]

    pkt_acc_test = [metrics['acc'] for metrics in epoch_test_metrics]
    pkt_acc_test = np.concatenate(pkt_acc_test, axis=0)  # Join up the batches
    trf_mean_acc_test = np.mean(pkt_acc_test,axis=1)
    trf_median_acc_test = np.median(pkt_acc_test, axis=1)
    overall_mean_acc_test = np.mean(trf_mean_acc_test)
    overall_median_acc_test = np.median(trf_median_acc_test)
    list_of_overall_mean_acc_test.append(overall_mean_acc_test)
    list_of_overall_median_acc_test.append(overall_median_acc_test)

    pkt_len_true_predict_test = [metrics[7] for metrics in epoch_test_metrics]
    zipped_pkt_len_true_predict_test = list(zip(*pkt_len_true_predict_test))
    if pkt_len_true_test is None:  # Join up batches for true value of pkt len once
        pkt_len_true_test = np.concatenate(zipped_pkt_len_true_predict_test[0], axis=0)  # Join up the batches
    pkt_len_predict_test = np.concatenate(zipped_pkt_len_true_predict_test[1], axis=0)  # Join up the batches
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
    logfile.write('Feature file used: {}\n'.format(os.path.basename(feature_dir)))
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
