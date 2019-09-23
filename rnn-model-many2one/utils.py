import json
import math
import mmap
import numpy as np
from random import shuffle
from functools import partial
from tensorflow.keras.utils import Sequence
from tensorflow.keras.preprocessing.sequence import pad_sequences

import config

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

def gen_train_test_idx(dataset_size):
    # Shuffling the indices to give a random train test split
    indices = np.random.RandomState(seed=config.SEED).permutation(dataset_size)
    split_idx = math.ceil((1-config.SPLIT_RATIO)*dataset_size)
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

class BatchGenerator(Sequence):
    def __init__(self, feature_mmap_byteoffsets, feature_idxs, norm_fn, return_batch_info=False):
        self.feature_mmap_byteoffsets = feature_mmap_byteoffsets
        self.norm_fn = norm_fn
        self.return_batch_info = return_batch_info

        # Aggregate the data
        self.aggregated_idx = []
        self.label2id = {'normal':0, 'breach':1, 'poodle':2, 'rc4':3, 'dos':4}  # TODO: should put this in config since will be used in model predicgtion as well
        self.id2label = {v:k for k,v in self.label2id.items()}
        for label, feature_idx in feature_idxs.items():
            label_id = self.label2id[label]
            labelled_feature_idx = [(label_id, i) for i in feature_idx]
            self.aggregated_idx.extend(labelled_feature_idx)
        shuffle(self.aggregated_idx)  # Shuffle once first

    def __len__(self):
        return int(np.ceil(len(self.aggregated_idx)/float(config.BATCH_SIZE)))

    def __getitem__(self, idx):
        batch_idx = self.aggregated_idx[idx*config.BATCH_SIZE:(idx+1)*config.BATCH_SIZE]
        batch_data, batch_labels = [],[]
        for label_id, i in batch_idx:
            label = self.id2label[label_id]
            mmap,byteoffset = self.feature_mmap_byteoffsets[label]
            start,end = byteoffset[i]
            dataline = mmap[start:end+1].decode('ascii').strip().rstrip(',')
            batch_data.append(json.loads('['+dataline+']'))
            batch_labels.append(label_id)

        # Zero-padding and normalize
        batch_input = pad_sequences(batch_data, maxlen=config.SEQUENCE_LEN,dtype='float32',padding='post',truncating='post',value=0.0)
        batch_input = self.norm_fn(batch_input)

        # One-hot encoding
        num_dim = len(self.label2id)
        batch_labels = np.array(batch_labels)
        batch_targets = np.zeros((batch_labels.size, num_dim))
        batch_targets[np.arange(batch_labels.size),batch_labels] = 1

        if not self.return_batch_info:
            return (batch_input, batch_targets)

        # Extract secondary info about batch
        batch_info = {}
        batch_seq_len = [len(data) for data in batch_data]
        batch_info['seq_len'] = np.array(batch_seq_len)

        return (batch_input, batch_targets,batch_info)
