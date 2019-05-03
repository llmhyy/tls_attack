# directory path to model/features

# given path: rnn-model/trained-rnn/ 
model = {
    'normal':'normal/expt_2019-04-28_19-18-34/rnnmodel_2019-04-28_19-18-34.h5',
    'thc-tls-dos':'thc-tls-dos/expt_2019-04-30_07-31-14/rnnmodel_2019-04-30_07-31-14.h5',
    # 'sample':'sample/expt_2019-03-17_12-20-30/rnnmodel_2019-03-17_12-20-30.h5'
}

# given path: feature_extraction/extracted-features/
features = {
    'normal':'normal/',
    'thc-tls-dos':'thc-tls-dos/',
    # 'sample':'sample/'
}

# given path: path/to/root/dir/where/pcap/files/are/stored/
pcapfiles = {
    'normal':'normal/',
    'thc-tls-dos':'thc-tls-dos/',
    # 'sample':'sample/'
}
# note: the directory paths must be exact. For instance, the directory to pcap files for normal/ and thc-tls-dos/ must be found in the same parent directory

# model -> dataset -> split
results = {
    'normal':{
        'normal':{
            'train':'normal/expt_2019-04-28_19-18-34/predict_results/predict_on_normal/train/results.csv',
            'val':'normal/expt_2019-04-28_19-18-34/predict_results/predict_on_normal/val/results.csv'
        },
        'thc-tls-dos':{
            'train':'normal/expt_2019-04-28_19-18-34/predict_results/predict_on_thc-tls-dos/train/results.csv',
            'val':'normal/expt_2019-04-28_19-18-34/predict_results/predict_on_thc-tls-dos/val/results.csv'
        }
    },
    'thc-tls-dos':{
        'normal':{
            'train':'thc-tls-dos/expt_2019-04-30_07-31-14/predict_results/predict_on_normal/train/results.csv',
            'val':'thc-tls-dos/expt_2019-04-30_07-31-14/predict_results/predict_on_normal/val/results.csv',
        },
        'thc-tls-dos':{
            'train':'thc-tls-dos/expt_2019-04-30_07-31-14/predict_results/predict_on_thc-tls-dos/train/results.csv',
            'val':'thc-tls-dos/expt_2019-04-30_07-31-14/predict_results/predict_on_thc-tls-dos/val/results.csv'
        }
    },
    # 'sample':{
    #     'sample':{
    #         'train':'sample/expt_2019-03-17_12-20-30/predict_results/predict_on_sample/train/results.csv',
    #         'val':'sample/expt_2019-03-17_12-20-30/predict_results/predict_on_sample/val/results.csv'
    #     }
    # }
}

criteria = {
    'none':None,
    'low':0.5,
    'high':0.8
}