import os

normal_model_dirname = os.path.join('normal-gpu', 'expt_2019-08-10_16-32-26')
thc_tls_dos_model_dirname = os.path.join('thc-tls-dos-gpu','expt_2019-08-10_16-32-29')
poodle_model_dirname = os.path.join('poodle-gpu', 'expt_2019-08-10_16-32-28')
breach_model_dirname = os.path.join('breach-gpu', 'expt_2019-08-28_11-18-06')
normal_6k_model_dirname = os.path.join('normal-6k-gpu', 'expt_2019-09-01_11-36-23')
normal_streaming_dirname = os.path.join('normal-streaming-gpu', 'expt_2019-09-01_11-36-01')

# given path: rnn-model/trained-rnn/ 
model = {
    'normal': os.path.join(normal_model_dirname, 'rnnmodel_2019-08-10_16-32-26.h5'),
    'thc-tls-dos': os.path.join(thc_tls_dos_model_dirname, 'rnnmodel_2019-08-10_16-32-29.h5'),
    'poodle': os.path.join(poodle_model_dirname, 'rnnmodel_2019-08-10_16-32-28.h5'),
    'breach': os.path.join(breach_model_dirname, 'rnnmodel_2019-08-28_11-18-06.h5'),
    'normal_6k':os.path.join(normal_6k_model_dirname, 'rnnmodel_2019-09-01_11-36-23.h5'),
    'normal_streaming':os.path.join(normal_streaming_dirname, 'rnnmodel_2019-09-01_11-36-01.h5'),
}

# given path: feature_extraction/extracted-features/
features = {
    'normal':'normal/',
    'thc-tls-dos':'thc-tls-dos/',
    'malware':'malware/',
    'poodle':'poodle/',
    'breach':'breach/',
    'normal-6k':'normal-6k/',
    'normal-streaming':'normal-streaming/'
}

# given path: path/to/root/dir/where/pcap/files/are/stored/
pcapfiles = {
    'normal':'normal/',
    'thc-tls-dos':'thc-tls-dos/',
    'malware':'malware/',
    'poodle':'poodle/',
    'breach':'breach/',
    'normal-6k':'normal-6k/',
    'normal-streaming':'normal-streaming/'
}
# note: the directory paths must be exact. For instance, the directory to pcap files for normal/ and thc-tls-dos/ must be found in the same parent directory
