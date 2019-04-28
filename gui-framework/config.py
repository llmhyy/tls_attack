# directory path to model/features

# given path: rnn-model/trained-rnn/ 
model = {
	'normal':'normal/expt_2019-03-18_00-01-42/rnnmodel_2019-03-18_00-01-42.h5',
	'thc-tls-dos':'thc-tls-dos/expt_2019-03-18_10-47-33/rnnmodel_2019-03-18_10-47-33.h5',
	'sample':'sample/expt_2019-03-17_12-20-30/rnnmodel_2019-03-17_12-20-30.h5'
}

# given path: feature_extraction/extracted-features/
features = {
	'normal':'normal/',
	'thc-tls-dos':'thc-tls-dos/',
	'sample':'sample/'
}

# given path: path/to/root/dir/where/pcap/files/are/stored/
pcapfiles = {
	'normal':'normal/',
	'thc-tls-dos':'thc-tls-dos/',
	'sample':'sample/'
}
# note: the directory paths must be exact. For instance, the directory to pcap files for normal/ and thc-tls-dos/ must be found in the same parent directory