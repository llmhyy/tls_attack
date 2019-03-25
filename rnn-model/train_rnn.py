import os
import sys
import json
import math
import mmap
import argparse
import tracemalloc
import numpy as np
from sys import getsizeof
from datetime import datetime
from random import shuffle
import keras
from keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential
from keras.models import load_model
from keras.layers import Dense, Dropout, Activation
from keras.layers import LSTM
import keras.backend as K
from keras.utils import Sequence
from sklearn.model_selection import train_test_split
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize
import matplotlib.pyplot as plt

import utils_datagen as utilsDatagen
import utils_plot as utilsPlot
import utils_diagnostic as utilsDiagnostic
import utils_metric as utilsMetric


parser = argparse.ArgumentParser()
parser.add_argument('-e', '--epoch', help='Input epoch for training', default=100, type=int)
parser.add_argument('-f', '--featuredir', help='Input the directory path of feature file to be used', required=True)
parser.add_argument('-s', '--savedir', help='Input the directory path to save the rnn model and its training results', required=True)  # e.g foo/bar/trained-rnn/normal/
parser.add_argument('-o', '--show', help='Flag for displaying plots', action='store_true', default=False)
parser.add_argument('-m', '--model', help='Input directory for existing model to be trained')
args = parser.parse_args()

# Config info
DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
BATCH_SIZE = 64
SEQUENCE_LEN = 100
EPOCH = args.epoch
SAVE_EVERY_EPOCH = 1
SPLIT_RATIO = 0.05
SEED = 2019

# Start diagnostic analysis
tracemalloc.start()

#####################################################
# DATA LOADING AND PREPROCESSING
#####################################################

# Load the mmap data and the byte offsets from the feature file
mmap_data, byte_offset = utilsDatagen.get_mmapdata_and_byteoffset(args.featuredir)

# Get min and max for each feature
min_max_feature = utilsDatagen.get_min_max(mmap_data, byte_offset)

# Split the dataset into train and test and return train/test indexes to the byte offset
train_idx, test_idx = utilsDatagen.split_train_test(byte_offset, SPLIT_RATIO, SEED)

# Intializing constants for data
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
# MODEL BUILDING
#####################################################

# Build RNN model or load existing RNN model
if args.model:
    model = load_model(args.model)
else:
    model = Sequential()
    model.add(LSTM(INPUT_DIM, input_shape=(SEQUENCE_LEN,INPUT_DIM), return_sequences=True))
    model.add(Activation('relu'))
    model.compile(loss='mean_squared_error',
                    optimizer='rmsprop')
model.summary()

class TrainHistory(keras.callbacks.Callback):
    def __init__(self, generator):
        self.generator = generator

    def on_train_begin(self, logs={}):
        self.mean_acc = {}
        self.median_acc = {}
        self.final_mean_acc = {}
        self.predict_on_len = np.array([])
        self.true_on_len = np.array([])

    def on_epoch_end(self, epoch, logs={}):
        # At the end of every epoch, we make a prediction and evaluate its accuracy, instead of savings the prediction...too much MEM!
        if epoch%SAVE_EVERY_EPOCH==(SAVE_EVERY_EPOCH-1): # save after every 5,10,15,... epoch
            temp_mean_acc = {}
            temp_median_acc = {}
            temp_predict_on_len = np.array([])
            temp_true_on_len = np.array([])

            for (batch_inputs, batch_true, batch_info) in self.generator:
                batch_seq_len = batch_info['seq_len']
                batch_predict = self.model.predict_on_batch(batch_inputs)
                batch_acc = utilsMetric.calculate_acc_of_traffic(batch_predict, batch_true)

                # Calculate cosine similarity for true packets
                if 'true' not in temp_mean_acc:
                    temp_mean_acc['true'] = np.array([])
                if 'true' not in temp_median_acc:
                    temp_median_acc['true'] = np.array([])
                for i,seq_len in enumerate(batch_seq_len):
                    acc_spliced = batch_acc[i:i+1,0:seq_len] # slicing to retain the dimensionality
                    mean_acc_of_true_traffic = utilsMetric.calculate_mean_over_traffic(acc_spliced)
                    median_acc_of_true_traffic = utilsMetric.calculate_median_over_traffic(acc_spliced)
                    temp_mean_acc['true'] = np.concatenate((temp_mean_acc['true'], mean_acc_of_true_traffic))
                    temp_median_acc['true'] = np.concatenate((temp_median_acc['true'], median_acc_of_true_traffic))

                # Calculate cosine similarity for packet length ranging from 10 to 100
                for seq_len in range(10,101,10):
                    if seq_len not in temp_mean_acc:
                        temp_mean_acc[seq_len] = np.array([])
                    if seq_len not in temp_median_acc:
                        temp_median_acc[seq_len] = np.array([])
                    batch_acc_spliced = batch_acc[:,0:seq_len]
                    mean_batch_acc_of_traffic = utilsMetric.calculate_mean_over_traffic(batch_acc_spliced)
                    median_batch_acc_of_traffic = utilsMetric.calculate_median_over_traffic(batch_acc_spliced)
                    temp_mean_acc[seq_len] = np.concatenate((temp_mean_acc[seq_len], mean_batch_acc_of_traffic))
                    temp_median_acc[seq_len] = np.concatenate((temp_median_acc[seq_len], median_batch_acc_of_traffic))

                # Save prediction on packet length
                batch_predict_len = batch_predict[:,:,7:8]
                batch_true_len = batch_true[:,:,7:8]
                if temp_predict_on_len.size==0:
                    temp_predict_on_len = temp_predict_on_len.reshape(0,batch_predict_len.shape[1], batch_predict_len.shape[2])
                if temp_true_on_len.size==0:
                    temp_true_on_len = temp_true_on_len.reshape(0,batch_true_len.shape[1], batch_true_len.shape[2])
                temp_predict_on_len = np.concatenate((temp_predict_on_len, batch_predict_len), axis=0)
                temp_true_on_len = np.concatenate((temp_true_on_len, batch_true_len), axis=0)

            # Calculate mean across all traffic for 1 epoch 
            for k,v in temp_mean_acc.items():
                if k not in self.mean_acc:
                    self.mean_acc[k] = np.array([])
                self.mean_acc[k] = np.concatenate((self.mean_acc[k], np.mean(v, keepdims=True)))
                self.final_mean_acc[k] = v

            # Calculate median across all traffic for 1 epoch
            for k,v in temp_median_acc.items():
                if k not in self.median_acc:
                    self.median_acc[k] = np.array([])
                self.median_acc[k] = np.concatenate((self.median_acc[k], np.median(v, keepdims=True)))

            # Saving the prediction and actual for 1 epoch
            if self.predict_on_len.size==0:
                self.predict_on_len = self.predict_on_len.reshape(0,*temp_predict_on_len.shape)
            if self.true_on_len.size==0:
                self.true_on_len = self.true_on_len.reshape(0,*temp_true_on_len.shape)
            self.predict_on_len = np.concatenate((self.predict_on_len, temp_predict_on_len.reshape(1, *temp_predict_on_len.shape))) 
            self.true_on_len = np.concatenate((self.true_on_len, temp_predict_on_len.reshape(1, *temp_true_on_len.shape)))

# Initialize NEW train and test generators for model prediction
train_generator_prediction = utilsDatagen.BatchGenerator(mmap_data, byte_offset, train_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, return_seq_len=True)
test_generator_prediction = utilsDatagen.BatchGenerator(mmap_data, byte_offset, test_idx, BATCH_SIZE, SEQUENCE_LEN, norm_fn, return_seq_len=True)
trainHistory_on_traindata = TrainHistory(train_generator_prediction)
trainHistory_on_testdata = TrainHistory(test_generator_prediction)

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

# Generate plots for the model prediction on packet length over epochs
utilsPlot.plot_prediction_on_pktlen(trainHistory_on_traindata.predict_on_len, 
                                    trainHistory_on_traindata.true_on_len, 
                                    trainHistory_on_testdata.predict_on_len, 
                                    trainHistory_on_testdata.true_on_len, 
                                    save_every_epoch=SAVE_EVERY_EPOCH, save_dir=results_dir, show=args.show)

# Generate plots for model accuracy on different sequence length
seq_len_keys = ['true'] + list(range(10,101,10))
for key in seq_len_keys:
    acc_pkt_mean_train = trainHistory_on_traindata.mean_acc[key]
    acc_pkt_median_train = trainHistory_on_traindata.median_acc[key]
    acc_pkt_mean_test = trainHistory_on_testdata.mean_acc[key]
    acc_pkt_median_test = trainHistory_on_testdata.median_acc[key]
    final_acc_pkt_mean_train = trainHistory_on_traindata.final_mean_acc[key]
    final_acc_pkt_mean_test = trainHistory_on_testdata.final_mean_acc[key]
    print('Final mean cosine similarity for first {} pkts on train data'.format(key))
    print(acc_pkt_mean_train[-1])
    print('Final mean cosine similarity for first {} pkts on test data'.format(key))
    print(acc_pkt_mean_test[-1])
    utilsPlot.plot_accuracy_and_distribution(acc_pkt_mean_train, 
                                    acc_pkt_median_train, 
                                    acc_pkt_mean_test, 
                                    acc_pkt_median_test, 
                                    final_acc_pkt_mean_train, 
                                    final_acc_pkt_mean_test, 
                                    first=key, save_every_epoch=SAVE_EVERY_EPOCH, save_dir=results_dir, show=args.show)

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
    logfile.write('Feature file used: {}\n'.format(os.path.basename(args.featuredir)))
    logfile.write("Existing model used: {}\n".format(args.model))
    logfile.write("Split Ratio: {}\n".format(SPLIT_RATIO))
    logfile.write("Seed: {}\n".format(SEED))
    logfile.write('####################################\n\n')
    model.summary(print_fn=lambda x:logfile.write(x + '\n\n'))

    logfile.write("#####  TRAIN/VAL LOSS  #####\n")
    for i, (loss, val_loss) in enumerate(zip(history.history['loss'], history.history['val_loss'])):
        logfile.write('Epoch  #{}\tTrain Loss: {:.6f}\tVal Loss: {:.6f}\n'.format(i+1, loss, val_loss))
    logfile.write("\n#####  TRAIN/VAL MEAN ACCURACY  #####\n")
    for i, (train_mean, test_mean) in enumerate(zip(trainHistory_on_traindata.mean_acc['true'], trainHistory_on_testdata.mean_acc['true'])):
        logfile.write('Epoch  #{}\tTrain Mean Accuracy: {:.6f}\tVal Mean Accuracy: {:.6f}\n'.format((i*SAVE_EVERY_EPOCH)+SAVE_EVERY_EPOCH, train_mean, test_mean))
    logfile.write("\n#####  TRAIN/VAL MEDIAN ACCURACY  #####\n")
    for i, (train_median, test_median) in enumerate(zip(trainHistory_on_traindata.median_acc['true'], trainHistory_on_testdata.median_acc['true'])):
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
