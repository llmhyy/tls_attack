import json
import math
import mmap
import argparse
import numpy as np
from random import shuffle
from functools import partial
from tensorflow.keras.utils import Sequence
from tensorflow.keras.preprocessing.sequence import pad_sequences

import utils_metric as utilsMetric

def find_lines(data):
    for i, char in enumerate(data):
        if char == b'\n':
            yield i

def get_mmapdata_and_byteoffset(feature_file):
    ########################################################################
    # Biggest saviour: shuffling a large file w/o loading in memory
    # >>> https://stackoverflow.com/questions/24492331/shuffle-a-large-list-of-items-without-loading-in-memory
    ########################################################################

    # Creating a list of byte offset for each line
    with open(feature_file, 'r') as f:
        mmap_data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        start = 0
        byte_offset = []
        for end in find_lines(mmap_data):
            byte_offset.append((start, end))
            start = end + 1
    return mmap_data, byte_offset

def get_min_max(mmap_data, byte_offset):
    min_feature = None
    max_feature = None
    for start,end in byte_offset:
        dataline = mmap_data[start:end+1].decode('ascii').strip().rstrip(',')
        dataline = np.array(json.loads('['+dataline+']'))
        if min_feature is not None:
            dataline = np.vstack((min_feature, dataline))
        if max_feature is not None:
            dataline = np.vstack((max_feature, dataline))
        min_feature = np.min(dataline, axis=0)
        max_feature = np.max(dataline, axis=0)

    return (min_feature, max_feature)

def split_train_test(dataset_size, split_ratio, seed):
    # Shuffling the indices to give a random train test split
    indices = np.random.RandomState(seed=seed).permutation(dataset_size)
    split_idx = math.ceil((1-split_ratio)*dataset_size)
    train_idx, test_idx = indices[:split_idx], indices[split_idx:]
    # Avoid an empty list in test set
    if len(test_idx) == 0:
        test_idx = train_idx[-1:]
        train_idx = train_idx[:-1]
    return train_idx, test_idx

def normalize(option, min_max_feature=None):
    def l2_norm(batch_data):
        l2_norm = np.linalg.norm(batch_data, axis=2, keepdims=True)
        batch_data = np.divide(batch_data, l2_norm, out=np.zeros_like(batch_data), where=l2_norm!=0.0)
        return batch_data
    def min_max_norm(batch_data, min_max_feature):
        min_feature, max_feature = min_max_feature
        # Dimension 20~62 of ciphersuite are frequency values and should not be normalized like other features
        min_feature[20:63] = 0
        max_feature[20:63] = 1
        num = batch_data-min_feature
        den = max_feature-min_feature
        batch_data = np.divide(num, den, out=np.zeros_like(num), where=den!=0.0)
        batch_data[batch_data<0] = 0  # if < min, set to 0
        batch_data[batch_data>1] = 1  # if > max, set to 1
        assert (batch_data <= 1).all() and (batch_data >= 0).all()
        return batch_data
    if option == 1:
        return l2_norm
    elif option == 2:
        if min_max_feature is not None:
            return partial(min_max_norm, min_max_feature=min_max_feature)
        else:
            print("Error: min-max range for feature is not provided")
            return

def denormalize(min_max_feature):
    # TODO: Denormalize the data based on a user-specified option in future
    def min_max_denorm(batch_norm_data):
        min_feature, max_feature = min_max_feature
        batch_data = (batch_norm_data * (max_feature - min_feature)) + min_feature
        return batch_data
    return min_max_denorm

def get_feature_vector(selected_idx, mmap_data, byte_offset, sequence_len, norm_fn):
    selected_byte_offset = [byte_offset[i] for i in selected_idx]
    selected_data = []
    for start,end in selected_byte_offset:
        dataline = mmap_data[start:end+1].decode('ascii').strip().rstrip(',')
        selected_data.append(json.loads('['+dataline+']'))
    selected_seq_len = [len(data) for data in selected_data]
    selected_inputs,selected_targets = preprocess_data(selected_data, pad_len=sequence_len, norm_fn=norm_fn)
    return (selected_inputs, selected_targets, selected_seq_len)

def preprocess_data(batch_data, pad_len, norm_fn):
    # Step 1: Pad sequences
    batch_data = pad_sequences(batch_data, maxlen=pad_len, dtype='float32', padding='post', truncating='post', value=0.0)
    # Step 2: Scale features with a normalization function
    batch_data = norm_fn(batch_data)
    # Step 3: Append zero to start of the sequence
    packet_zero = np.zeros((batch_data.shape[0], 1, batch_data.shape[2]))
    batch_data = np.concatenate((packet_zero, batch_data), axis=1)
    # Step 4: Split the data into inputs and targets
    batch_inputs = batch_data[:,:-1,:]
    batch_targets = batch_data[:,1:,:]

    return batch_inputs, batch_targets

class BatchGenerator(Sequence):
    def __init__(self, mmap_data, byte_offset, selected_idx, batch_size, sequence_len, norm_fn, return_batch_info=False):
        self.mmap_data = mmap_data
        self.byte_offset = byte_offset
        self.selected_idx = selected_idx
        self.batch_size = batch_size
        self.sequence_len = sequence_len
        self.norm_fn = norm_fn
        self.return_batch_info = return_batch_info

    def __len__(self):
        return int(np.ceil(len(self.selected_idx)/float(self.batch_size)))

    def __getitem__(self, idx):
        batch_idx = self.selected_idx[idx*self.batch_size:(idx+1)*self.batch_size]
        batch_byte_offset = [self.byte_offset[i] for i in batch_idx]

        batch_data = []
        for start,end in batch_byte_offset:
            dataline = self.mmap_data[start:end+1].decode('ascii').strip().rstrip(',')
            batch_data.append(json.loads('['+dataline+']'))
        batch_inputs, batch_targets = preprocess_data(batch_data, pad_len=self.sequence_len, norm_fn=self.norm_fn)

        if not self.return_batch_info:
            return (batch_inputs, batch_targets)

        batch_info = {}
        batch_seq_len = [len(data) for data in batch_data]
        batch_info['seq_len'] = np.array(batch_seq_len)  # Standardize output into numpy array
        batch_info['batch_idx'] = batch_idx  # batch_idx is already a numpy array

        return (batch_inputs, batch_targets, batch_info)

    def on_epoch_end(self):
        shuffle(self.selected_idx)

def compute_metrics_for_batch(model, batch_data, metrics, denorm_fn):
    # Metric supported: 'seq_len', 'idx', 'acc', 'mean_acc'
    #                   'squared_error', 'mean_squared_error', 'true', 'predict', <an int value for the dim number>

    PKT_LEN_THRESHOLD = 100 # <<< CHANGE THIS VALUE
                            # for computation of mean over big packets. If -1, computation over all packets

    batch_inputs, batch_true, batch_info = batch_data
    output = {}
    for metric in metrics:
        batch_seq_len = batch_info['seq_len']
        if metric == 'idx':
            batch_idx = batch_info['batch_idx']
            output[metric] = batch_idx

        elif metric == 'seq_len':
            output[metric] = batch_seq_len

        else:
            batch_predict = model.predict_on_batch(batch_inputs)
            if metric == 'acc' or metric == 'mean_acc':
                padded_batch_acc = utilsMetric.calculate_acc_of_traffic(batch_predict, batch_true)
                masked_batch_acc = np.ma.array(padded_batch_acc)
                # Mask based on true seq len for every row
                for i in range(len(batch_seq_len)):
                    masked_batch_acc[i, batch_seq_len[i]:] = np.ma.masked
                if metric == 'acc':
                    output[metric] = masked_batch_acc
                elif metric == 'mean_acc':
                    if PKT_LEN_THRESHOLD > 0 and denorm_fn:
                        denorm_batch_true = denorm_fn(batch_true)
                        batch_pktlen = denorm_batch_true[:,:,7]
                        mask = batch_pktlen <= PKT_LEN_THRESHOLD
                        masked2_batch_acc = np.ma.array(masked_batch_acc)
                        masked2_batch_acc.mask = mask
                        batch_mean_acc_over_big_pkts = np.mean(masked2_batch_acc, axis=-1)
                        output[metric] = batch_mean_acc_over_big_pkts
                    elif PKT_LEN_THRESHOLD == -1:
                        batch_mean_acc = np.mean(masked_batch_acc, axis=-1)
                        output[metric] = batch_mean_acc

            elif metric == 'squared_error' or metric == 'mean_squared_error':
                padded_batch_squared_error = utilsMetric.calculate_squared_error_of_traffic(batch_predict, batch_true)
                masked_batch_squared_error = np.ma.array(padded_batch_squared_error)
                # Mask based on true seq len for every row
                for i in range(len(batch_seq_len)):
                    masked_batch_squared_error[i, batch_seq_len[i]:, :] = np.ma.masked
                if metric == 'squared_error':
                    output[metric] = masked_batch_squared_error
                elif metric == 'mean_squared_error':
                    batch_mean_squared_error = np.mean(masked_batch_squared_error, axis=1)
                    output[metric] = batch_mean_squared_error

            elif type(metric) == int:  # dim number
                output[metric] = (batch_true[:, :, metric:metric + 1], batch_predict[:, :, metric:metric + 1])

            elif metric == 'true':
                output[metric] = batch_true

            elif metric == 'predict':
                output[metric] = batch_predict
    return output

def compute_metrics_generator(model, data_generator, metrics, denorm_fn=None):
    for batch_data in data_generator:
        output = compute_metrics_for_batch(model, batch_data, metrics, denorm_fn)
        yield output

# For defining float values between 0 and 1 for argparse
def restricted_float(x):
    x = float(x)
    if x < 0.0 or x > 1.0:
        raise argparse.ArgumentTypeError('{} not in range [0.0, 1.0]'.format(x))
    return x

