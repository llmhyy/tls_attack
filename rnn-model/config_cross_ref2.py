import os
from datetime import datetime

normal_featuredir = None
breach_featuredir = None
poodle_featuredir = None
rc4_featuredir = None
dos_featuredir = None

# Write your directory path to the feature files here
root_featuredir = os.path.join('..','feature-extraction','extracted-features')
normal_featuredir = os.path.join(root_featuredir, 'normal-36k')
breach_featuredir = os.path.join(root_featuredir, 'breach-10k')
poodle_featuredir = os.path.join(root_featuredir, 'poodle-10k')
rc4_featuredir = os.path.join(root_featuredir, 'rc4-10k')
dos_featuredir = os.path.join(root_featuredir, 'thc-tls-dos-10k')

minmax_dir = os.path.join('..', 'feature-extraction', 'features_minmax_ref.csv')

# Write your directory path to the models here
root_modeldir = 'trained-rnn'
normal_modeldir = os.path.join(root_modeldir, 'normal-36k-gpu','expt_2019-09-16_15-56-03','rnnmodel_2019-09-16_15-56-03.h5')
breach_modeldir = os.path.join(root_modeldir, 'breach-10k-gpu','expt_2019-09-16_15-56-32','rnnmodel_2019-09-16_15-56-32.h5')
poodle_modeldir = os.path.join(root_modeldir, 'poodle-10k-gpu','expt_2019-09-17_13-11-15','rnnmodel_2019-09-17_13-11-15.h5')
rc4_modeldir = os.path.join(root_modeldir, 'rc4-10k-gpu','expt_2019-09-17_13-59-18','rnnmodel_2019-09-17_13-59-18.h5')
dos_modeldir = os.path.join(root_modeldir, 'thc-tls-dos-10k-gpu','expt_2019-09-16_15-56-56','rnnmodel_2019-09-16_15-56-56.h5')

# Write your model configuration here
DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
SEQUENCE_LEN = 1000
SPLIT_RATIO = 0.05  # Validation dataset as a %
BATCH_SIZE = 4
SEED = 2019

# ID for traffic labels
label2id = {'normal':0, 'breach':1, 'poodle':2, 'rc4':3, 'dos':4}
id2label = {v:k for k,v in label2id.items()}