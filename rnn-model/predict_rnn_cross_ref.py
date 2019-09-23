import os
import json
import fnmatch
import argparse
import numpy as np
import config_cross_ref1 as config_cross_ref
import utils_datagen as utilsDatagen

# Fking hack to use the BatchGenerator from rnn-model-many2one
# TODO: Combine rnn-model and rnn-model-many2one module since they share alot of functions
import sys
sys.path.append(os.path.join('..','rnn-model-many2one'))
import utils as utilsMany2one

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '0'  # Suppress Tensorflow debugging information for INFO level
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.backend import set_session

parser = argparse.ArgumentParser()
# parser.add_argument('-s', '--savedir', help='Input the directory path to save the prediction results', required=True)
parser.add_argument('-g', '--gpu', help='Flag for using GPU in model training', action='store_true')
args = parser.parse_args()

#####################################################
# PRE-CONFIGURATION
#####################################################

# Setting of CPU/GPU configuration for TF
if args.gpu:
    tf_config = tf.ConfigProto()
    tf_config.gpu_options.allow_growth = True  # dynamically grow the memory used on the GPU
    tf_config.log_device_placement = False
sess = tf.Session(config=tf_config)
set_session(sess)  # set this TensorFlow session as the default session for Keras

# Load model
models = {}
if config_cross_ref.normal_modeldir and os.path.exists(config_cross_ref.normal_modeldir):
    print('Loading normal model...')
    models['normal'] = load_model(config_cross_ref.normal_modeldir)
if config_cross_ref.breach_modeldir and os.path.exists(config_cross_ref.breach_modeldir):
    print('Loading breach model...')
    models['breach'] = load_model(config_cross_ref.breach_modeldir)
if config_cross_ref.poodle_modeldir and os.path.exists(config_cross_ref.poodle_modeldir):
    print('Loading poodle model...')
    models['poodle'] = load_model(config_cross_ref.poodle_modeldir)
if config_cross_ref.rc4_modeldir and os.path.exists(config_cross_ref.rc4_modeldir):
    print('Loading rc4 model...')
    models['rc4'] = load_model(config_cross_ref.rc4_modeldir)
if config_cross_ref.dos_modeldir and os.path.exists(config_cross_ref.dos_modeldir):
    print('Loading dos model...')
    models['dos'] = load_model(config_cross_ref.dos_modeldir)

# Define directory paths to feature files
def get_feature_filepath(rootdir):
    return os.path.join(rootdir, fnmatch.filter(os.listdir(rootdir), feature_filename_template)[0])
feature_filename_template = 'features_tls_*.csv'
feature_filepaths = {}
try:
    if config_cross_ref.normal_featuredir and os.path.exists(config_cross_ref.normal_featuredir):
        feature_filepaths['normal'] = get_feature_filepath(config_cross_ref.normal_featuredir)
    if config_cross_ref.breach_featuredir and os.path.exists(config_cross_ref.breach_featuredir):
        feature_filepaths['breach'] = get_feature_filepath(config_cross_ref.breach_featuredir)
    if config_cross_ref.poodle_featuredir and os.path.exists(config_cross_ref.poodle_featuredir):
        feature_filepaths['poodle'] = get_feature_filepath(config_cross_ref.poodle_featuredir)
    if config_cross_ref.rc4_featuredir and os.path.exists(config_cross_ref.rc4_featuredir):
        feature_filepaths['rc4'] = get_feature_filepath(config_cross_ref.rc4_featuredir)
    if config_cross_ref.dos_featuredir and os.path.exists(config_cross_ref.dos_featuredir):
        feature_filepaths['dos'] = get_feature_filepath(config_cross_ref.dos_featuredir)
except IndexError as e:
    import traceback
    traceback.print_exc()
    print('\nERROR: Feature file is missing in directory.\nHint: Did you remember to join the feature files together?')
    exit()

#####################################################
# DATA LOADING AND PREPROCESSING
#####################################################

# Load the mmap data and byte offset for each dataset
feature_mmap_byteoffsets = {}
for label, filepath in feature_filepaths.items():
    print('Loading {} features into memory..'.format(label))
    feature_mmap_byteoffsets[label] = utilsDatagen.get_mmapdata_and_byteoffset(filepath)

# Load min-max features from file
if not os.path.exists(config_cross_ref.minmax_dir):
    print('Error: Min-max feature file does not exist')
    exit()
with open(config_cross_ref.minmax_dir) as f:
    min_max_feature_list = json.load(f)
    min_max_feature = (np.array(min_max_feature_list[0]),np.array(min_max_feature_list[1]))

# Initialize the normalization function
norm_fn = utilsDatagen.normalize(2, min_max_feature)
denorm_fn = utilsDatagen.denormalize(min_max_feature)

# Initialize data generator for prediction
data_generators = {}
for label, feature_mmap_byteoffset in feature_mmap_byteoffsets.items():
    mmap,byteoffset = feature_mmap_byteoffset
    data_generators[label] = utilsDatagen.BatchGenerator(mmap, byteoffset, list(range(len(byteoffset))),
                                                         config_cross_ref.BATCH_SIZE,config_cross_ref.SEQUENCE_LEN,
                                                         norm_fn,return_batch_info=True)

#####################################################
# CROSS REFERENCE MODEL EVALUATION
#####################################################

metrics = ['mean_acc']
for feature_label, data_generator in data_generators.items():
    print('#####################################################')
    print('Predicting on {} dataset...'.format(feature_label))
    model_mean_acc_dict = {model_label:[] for model_label in models.keys()}
    for batch_data in data_generator:
        for model_label, model in models.items():
            output = utilsDatagen.compute_metrics_for_batch(model, batch_data, metrics, denorm_fn)
            model_mean_acc_dict[model_label].extend(output['mean_acc'].tolist())
    # model_mean_acc = {np.concatenate(list_of_mean_acc, axis=0) for model_label, list_of_mean_acc in model_mean_acc.items()}
    # model_overall_mean_acc = {np.mean(np.concatenate(list_of_mean_acc, axis=0))
    #                           for model_label, list_of_mean_acc in model_mean_acc.items()}
    # model_mean_acc = np.array([list_of_mean_acc for model_label, list_of_mean_acc in model_mean_acc_dict.items()]) # NO ORDER
    model_mean_acc = np.array([model_mean_acc_dict[config_cross_ref.id2label[i]] for i in range(len(config_cross_ref.id2label))])
    model_mean_acc_cleaned = model_mean_acc[:,~np.any(model_mean_acc==None,axis=0)]  # Remove None values due to prediction on small 1-packet traffic
    predict = np.argmax(model_mean_acc_cleaned, axis=0)
    true = config_cross_ref.label2id[feature_label]
    total = predict.size
    correct = np.sum(predict==true)
    print('{0:30s} {1:d}'.format('# TOTAL:',total))
    print('{0:30s} {1:d}'.format('# CORRECT:', correct))
    for label,id in config_cross_ref.label2id.items():
        if id!=true:
            print('{0:30s} {1:d}'.format('# INCORRECT ({} MODEL):'.format(label.upper()),np.sum(predict==id)))
    print('{0:30s} {1:.5f}%'.format('ACCURACY:', correct/total*100))

