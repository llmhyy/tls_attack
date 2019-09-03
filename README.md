# Encrypted Traffic Detection

__Major update to Pyshark 0.4.2.9__ - This package no longer depends on Pyshark 0.3.7.11, which has dependencies for the deprecated Trollius library. The newer version of Pyshark is more stable and has been tested on Linux/Windows platform. Upgrade is __highly recommended__. You can upgrade with a `pip install pyshark==0.4.2.9`

## Getting Started
* Linux/MacOS (for Windows, the commands need to be slightly modified)
* Python 3 (preferrably 3.6.5 and on a virtual environment)

Install virtualenv using pip and create a new virtual environment in your preferred directory

```
pip install virutalenv
virtualenv *name of your virtual env*
```

Install the dependencies from either `requirements.txt` or `requirements-gpu.txt`
```
pip install -r requirements.txt  #  for non gpu-supported machine
# OR 
pip install -r requirements-gpu.txt  # for gpu-supported machine
```

# 1. Feature Extraction

The module extracts TCP and TLS/SSL features from network traffic in PCAP files and stores them in a file.

To begin, change directory to feature-extraction from the root directory
```
cd feature-extraction/
```

Note:
* `feature_extraction.docx` is a document containing the proposed list of features to be extracted. Note that the sequential order of dimension of the vector does NOT follow the order in this document. For that, refer to the `feature_info_{date}_{time}.csv` that will be generated once feature extraction is complete
* `feature_info.csv` is the base file for identifying the feature name in each dimension of the vector. However, this file does NOT contain the feature name for dimensions with type _enum_, because this varies depending on the dataset and will be generated dynamically during the feature extraction process. A complete `feature_info_{date}_{time}.csv` will be generated once feature extraction is done.
* Log during script execution can be found in `output.log`

## Usage

Usage : main.py [-h] -p PCAPDIR -s SAVEDIR [-r REFENUM]

Options:
* __-p/--pcapdir__:     Input the directory path containing the pcap files for extraction. Example: '../foo/bar/dataset/'
* __-s/--savedir__:     Input the directory path to save the extracted feature files. Example: 'extracted-features/normal/'
* __-r/--refenum__:     (optional) Input the file path to the yaml file for enum reference. This is to ensure consistent use of enums across different pcap datasets. Example: 'enums_ref.yml'
* __-m/--minmax__: 		Flag to generate file containing min-max values during feature generation. Typically turned on during feature extraction of normal traffic. Default false

Example:
```
python main.py -p {directory path containing pcap files} -s {directory path to save extracted feature files} -r {directory path to enum yaml file} -m {flag to generate min-max file}
```

Output:
* `features_tls_{date}_{time}.csv`:   file containing the extracted features
* `features_info_{date}_{time}.csv`:  file containing detailed information about feature in sequential order of dimension of the vector (e.g. dim 0 of a vector in features_tls_{date}_{time}.csv corresponds to Come/Leave feature as stated in this file)
* `enums_{date}_{time}.yml`:          file containing the list of dynamic enums that are used
* `pcapname_{date}_{time}.csv`:       file containing the list of pcap filenames that are extracted from in sequential order of traffic collected (e.g. the first traffic collected in features_tls_{date}_{time}.csv corresponds to the first pcap filename in this file)
* `features_minmax_{date}_{time}.csv`:file containing the min and max values for each dimension of the extracted features
* `output.log`:                       file containing logging output

## Uploading into GitHub

Because Github has a filesize limit of 100MB, the feature file, which can be  quite large, has be to be split into smaller files.

Usage: file_splitter.py -i INPUT

Options:
* __-i/--input__: Input feature file to be split

Example:
```
python file_splitter.py -i {feature file to be split}
```

Output:
* `features_tls_{date}_{time}`: folder containing all the feature files smaller than 100MB which are indexed accordingly.

## Bugs
__RuntimeError: dictionary changed size during iteration__

During feature extraction, this error happens due to modification of the dictionary during runtime iteration. To resolve it, find pyshark's `layer.py` module in your Python site-packages (typically, if you are using a virtual env, `venv/lib/python3.6/site-packages/pyshark/packet/layer.py`) and make the following modification:

From:
```
for field_name in self._all_fields:
```
To:
```
for field_name in list(self._all_fields):
```

# 2. Model Training

The module trains RNN model with the features extracted from the network traffic. Model training can be done with/without GPU

To begin, change directory to rnn-model from the root directory
```
cd rnn-model/
```

## Merging the feature files

Remember that you split the feature files when uploading to GitHub? Now you have to merged them after pulling from GitHub.

Usage: file_joiner.py -i INPUT

Options:
* __-i/--input__: Input the folder containing the split feature files to be joined

Example:
```
python file_joiner.py -i {folder containing split feature files}
```

Output:
* `features_tls_{date}_{time}.csv`: merged feature file

## Usage

Usage: train_rnn.py [-e EPOCH] [-q TSTEP] [-p SPLIT] -r ROOTDIR -s SAVEDIR [-m MODEL] [-o] [-g]

Options: 
* __-e/--epoch__: 	Input the num of epoch for RNN model training. Default 100
* __-q/--tstep__:	Input the number of time steps for RNN model training. Default 1000
* __-p/--split__:	Input the split ratio for the validation set as a percentage of the dataset. Default 0.05
* __-r/--rootdir__: Input the directory path of the folder containing the feature file and other supporting files. Example: ../feature-extraction/extracted-features/normal/
* __-s/--savedir__:	Input the directory path to save the rnn model and its training results. Example: trained-rnn/normal-gpu/
* __-m/--model__:	Input directory for existing model to be trained. Example: trained-rnn/normal-gpu/expt_2019-07-24_16-35-13/rnnmodel_2019-07-24_16-35-13.h5
* __-o/--show__:	Flag for displaying plots. Default False
* __-g/--gpu__:		Flag for using GPU in model training. Default False

Example:
```
python train_rnn.py -r {directory path to folder containing feature files} -s {directory path to save trained model and training results} -g
```

Output:
* ```train_results/```:				Folder containing training results
* ```rnnmodel_{date}_{time}.h5```: 	Trained rnn model


For more details about the model implementation and usage of data loader, click [here](https://github.com/llmhyy/tls_attack/tree/master/rnn-model)

# 3. Model Evaluation

The module evaluates trained models by calculating metrics score between the predicted value of the model and the true value in order to determine model performance. The module can also be used to sample traffic which falls between a lower and upper bound. This is useful especially for finding false positives and false negatives so as to understand the limitations of the model as well as come up with new ways to improve the model.

To begin, change directory to rnn-model from the root directory
```
cd rnn-model/
```

## Usage

Usage: predict_rnn.py -m MODEL -r ROOTDIR [-q TSTEP] [-o {0,1,2}] [-l LOWER] [-u UPPER] [-g]

Options: 
* __-m/--model__: 		Input directory path of existing model to be used for prediction. Example: trained-rnn/normal-gpu/expt_2019-07-24_16-35-13/rnnmodel_2019-07-24_16-35-13.h5
* __-r/--rootdir__: 	Input the directory path of the folder containing the feature file and other supporting files. Example: ../feature-extraction/extracted-features/normal/
* __-q/--tstep__:		Input the number of time steps used in this model. Default 100
* __-o/--mode__:		Input the combination of test for evaluation of the model (Choices: {0,1,2}) Default 0
* __-l/--lower__:		Input the lower bound for sampling traffic. Default 0.0
* __-u/--upper__:		Input upper bound for sampling traffic. Default 1.0
* __-g/--gpu__:			Flag for using GPU in model training. Default False

Example:

General evaluation of model (mode = 0)
```
python predict_rnn.py -m {directory path of the model to be evaluated} -r {directory path of the folder containing the feature files to be evaluated against} -g
```

Sampling outliers between a lower and upper bound (mode = 1)
```
python predict_rnn.py -m {directory path of the model to be evaluated} -r {directory path of the folder containing the feature files to be evaluated against} -o 1 -l {lower bound} -u {upper bound} -g
```

_Note: mode = 2 executes both tasks abovementioned_

Output:
* ```predict_results/predict_on_{selected dataset/train```:	Folder containing evaluation results for train dataset 
* ```predict_results/predict_on_{selected dataset/val```:	Folder containing evaluation results for validation dataset

# TODO: 4. Debugging with GUI