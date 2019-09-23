import os
from datetime import datetime

normal_featuredir = None
breach_featuredir = None
poodle_featuredir = None
rc4_featuredir = None
dos_featuredir = None

# Write your directory path to the feature files here
root_featuredir = os.path.join('..','feature-extraction','extracted-features')
normal_featuredir = os.path.join(root_featuredir, 'normal-6k')
breach_featuredir = os.path.join(root_featuredir, 'breach')
poodle_featuredir = os.path.join(root_featuredir, 'poodle')
rc4_featuredir = os.path.join(root_featuredir, 'rc4')
dos_featuredir = os.path.join(root_featuredir, 'thc-tls-dos')

minmax_dir = os.path.join('..', 'feature-extraction', 'features_minmax_ref_deprecated.csv')

# Write your directory path to the models here
root_modeldir = 'trained-rnn'
normal_modeldir = os.path.join(root_modeldir, 'normal-6k-gpu','expt_2019-09-04_11-43-05','rnnmodel_2019-09-04_11-43-05.h5')
breach_modeldir = os.path.join(root_modeldir, 'breach-gpu','expt_2019-08-28_11-18-06','rnnmodel_2019-08-28_11-18-06.h5')
poodle_modeldir = os.path.join(root_modeldir, 'poodle-gpu','expt_2019-08-10_16-32-28','rnnmodel_2019-08-10_16-32-28.h5')
rc4_modeldir = os.path.join(root_modeldir, 'rc4-gpu','expt_2019-09-04_15-03-32','rnnmodel_2019-09-04_15-03-32.h5')
dos_modeldir = os.path.join(root_modeldir, 'thc-tls-dos-gpu','expt_2019-08-10_16-32-29','rnnmodel_2019-08-10_16-32-29.h5')

# Write your model configuration here
DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
SEQUENCE_LEN = 1000
SPLIT_RATIO = 0.05  # Validation dataset as a %
BATCH_SIZE = 4
SEED = 2019

# ID for traffic labels
label2id = {'normal':0, 'breach':1, 'poodle':2, 'rc4':3, 'dos':4}
id2label = {v:k for k,v in label2id.items()}