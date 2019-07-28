import os

normal_model_dirname = 'normal-gpu/expt_2019-07-24_16-35-13/'
thc_tls_dos_model_dirname = 'thc-tls-dos-gpu/expt_2019-07-22_15-23-12/'
poodle_model_dirname = 'poodle-gpu/expt_2019-07-22_15-23-10/'

# given path: rnn-model/trained-rnn/ 
model = {
    'normal': os.path.join(normal_model_dirname, 'rnnmodel_2019-07-24_16-35-13.h5'),
    'thc-tls-dos': os.path.join(thc_tls_dos_model_dirname, 'rnnmodel_2019-07-22_15-23-12.h5'),
    'poodle': os.path.join(poodle_model_dirname, 'rnnmodel_2019-07-22_15-23-10.h5'),
}

# given path: feature_extraction/extracted-features/
features = {
    'normal':'normal/',
    'thc-tls-dos':'thc-tls-dos/',
    'malware':'malware/',
    'poodle':'poodle/',
}

# given path: path/to/root/dir/where/pcap/files/are/stored/
pcapfiles = {
    'normal':'normal/',
    'thc-tls-dos':'thc-tls-dos/',
    'malware':'malware/',
    'poodle':'poodle/',
}
# note: the directory paths must be exact. For instance, the directory to pcap files for normal/ and thc-tls-dos/ must be found in the same parent directory

# model -> dataset -> split

results = {
    'normal':{
        'normal':{
            'train': os.path.join(normal_model_dirname, 'predict_results/predict_on_normal/train/results.csv'),
            'val': os.path.join(normal_model_dirname, 'predict_results/predict_on_normal/val/results.csv')
        },
        'thc-tls-dos':{
            'train': os.path.join(normal_model_dirname, 'predict_results/predict_on_thc-tls-dos/train/results.csv'),
            'val': os.path.join(normal_model_dirname, 'predict_results/predict_on_thc-tls-dos/val/results.csv')
        },
        'malware':{
            'train': os.path.join(normal_model_dirname, 'predict_results/predict_on_malware/train/results.csv'),
            'val': os.path.join(normal_model_dirname, 'predict_results/predict_on_malware/val/results.csv')
        },
        'poodle':{
            'train':os.path.join(normal_model_dirname, 'predict_results/predict_on_poodle/train/results.csv'),
            'val':os.path.join(normal_model_dirname,'predict_results/predict_on_poodle/val/results.csv')
        },
    },
    'thc-tls-dos':{
        'normal':{
            'train':os.path.join(thc_tls_dos_model_dirname, 'predict_results/predict_on_normal/train/results.csv'),
            'val':os.path.join(thc_tls_dos_model_dirname,'predict_results/predict_on_normal/val/results.csv')
        },
        'thc-tls-dos':{
            'train':os.path.join(thc_tls_dos_model_dirname,'predict_results/predict_on_thc-tls-dos/train/results.csv'),
            'val':os.path.join(thc_tls_dos_model_dirname,'predict_results/predict_on_thc-tls-dos/val/results.csv')
        },
        'malware':{
            'train':os.path.join(thc_tls_dos_model_dirname,'predict_results/predict_on_malware/train/results.csv'),
            'val':os.path.join(thc_tls_dos_model_dirname,'predict_results/predict_on_malware/val/results.csv')
        },
        'poodle':{
            'train':os.path.join(thc_tls_dos_model_dirname,'predict_results/predict_on_poodle/train/results.csv'),
            'val':os.path.join(thc_tls_dos_model_dirname,'predict_results/predict_on_poodle/val/results.csv')
        },
    },
    'poodle':{
        'normal':{
            'train':os.path.join(poodle_model_dirname, 'predict_results/predict_on_normal/train/results.csv'),
            'val':os.path.join(poodle_model_dirname, 'predict_results/predict_on_normal/val/results.csv'),
        },
        'thc-tls-dos':{
            'train':os.path.join(poodle_model_dirname, 'predict_results/predict_on_thc-tls-dos/train/results.csv'),
            'val':os.path.join(poodle_model_dirname, 'predict_results/predict_on_thc-tls-dos/val/results.csv')
        },
        'malware':{
            'train':os.path.join(poodle_model_dirname, 'predict_results/predict_on_malware/train/results.csv'),
            'val':os.path.join(poodle_model_dirname, 'predict_results/predict_on_malware/val/results.csv')
        },
        'poodle':{
            'train':os.path.join(poodle_model_dirname, 'predict_results/predict_on_poodle/train/results.csv'),
            'val':os.path.join(poodle_model_dirname, 'predict_results/predict_on_poodle/val/results.csv')
        },
    },
}