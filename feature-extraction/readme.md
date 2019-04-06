# Extraction of TCP/TLS features

The module extracts both TCP and TLS/SSL features from network traffic in PCAP files and stores them in a file.

* No. of features extracted:   28
* No. of  dimension:            146

Note:
* `feature_extraction.docx` is a list of features to be extracted based on initial discussion. Note that the sequential order of dimension of the vector does NOT follow the order in this document. For that, refer to the `feature_info_{date}_{time}.csv` that will be generated once feature extraction is complete
* `feature_info.csv` is the base file for identifying the feature name in each dimension of the vector. However, this file does NOT contain information about features with type _enum_, because this varies depending on the dataset and will be generated dynamically during the feature extraction process. A separate `feature_info_{date}_{time}.csv` will be generated once feature extraction is complete
* Log during script execution can be found in `output.log`

## Getting Started

With a Python 3 environment, install the dependencies from `requirements.txt`

```
pip install -r requirements.txt
```

Usage : main.py [-h] -p PCAPDIR -s SAVEDIR [-r REFENUM]

Options:
* -p/--pcapdir:     Input the directory path containing the pcap files for extraction
* -s/--savedir:     Input the directory path to save the extracted feature files
* -r/--refenum:     (optional) Input the file path to the yaml file for enum reference. To ensure consistent use of enums across different pcap datasets

Example:

```
python main.py -p {directory containing pcap files} -s {directory to save extracted feature files}
```

Output:
* `features_tls_{date}_{time}.csv`:   file containing the extracted features
* `feature_info_{date}_{time}.csv`:   file containing detailed information about feature in sequential order of dimension of the vector (e.g. dim 0 of a vector in features_tls_{date}_{time}.csv corresponds to Come/Leave feature as stated in this file)
* `enums_{date}_{time}.yml`:          file containing the list of dynamic enums that are used
* `pcapname_{date}_{time}.csv`:       file containing the list of pcap filenames that are extracted from in sequential order of traffic collected (e.g. the first traffic collected in features_tls_{date}_{time}.csv corresponds to the first pcap filename in this file)
* `output.log`:                       file containing logging output
