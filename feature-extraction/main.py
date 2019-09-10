import os
import sys
import json
import logging
import argparse
import numpy as np
from datetime import datetime
from ruamel.yaml import YAML
import utils
sys.path.append(os.path.join('..', 'rnn-model'))
import utils_datagen as utilsDatagen

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--pcapdir', help='Input the directory path containing the pcap files for extraction', required=True)
parser.add_argument('-s', '--savedir', help='Input the directory path to save the extracted feature files', required=True)  # e.g foo/bar/extracted-features/normal/
parser.add_argument('-r', '--refenum', help='Input the file path to the yaml file for enum reference', default=None)
parser.add_argument('-m', '--minmax', help='Turn on switch to generate file containing min-max values during feature generation', action='store_true')
args = parser.parse_args()
if not os.path.exists(args.savedir):
    os.mkdir(args.savedir) 

# Initialize a yaml object for reading and writing yaml files
yaml = YAML(typ='rt') # Round trip loading and dumping
yaml.preserve_quotes = True
yaml.indent(mapping=4, sequence=4)

# Initialize current datetime into a variable
datetime_now = datetime.now()
# Configure logging
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(filename=os.path.join(args.savedir,'output.log'), level=logging.INFO,format='%(asctime)s-%(levelname)s-%(message)s')

def search_and_extract(pcap_dir, features_dir, pcapname_dir, enums):
    success = 0
    failed = 0
    traffic_limit = 1000
    with open(features_dir, 'w') as features_file, open(pcapname_dir, 'w') as pcapname_file:
        for root, dirs, files in os.walk(pcap_dir):
            for f in files:
                if f.endswith(".pcap"):
                    try:
                        logging.info("Extracting features from {}".format(f))
                        # Generate TCP features
                        tcp_features = utils.extract_tcp_features(os.path.join(root, f), limit=traffic_limit)
                        # Generate TLS/SSL features
                        tls_features = utils.extract_tslssl_features(os.path.join(root, f), enums, limit=traffic_limit)
                        # Combine TCP and TLS/SSL features and each packet in traffic features is a vector of 146 dimension
                        traffic_features = (np.concatenate((np.array(tcp_features), np.array(tls_features)), axis=1)).tolist()

                        # Write into csv file
                        for traffic_feature in traffic_features:
                            features_file.write(str(traffic_feature)+', ')
                        features_file.write('\n')

                        # Write the filename of the pcap file into a file for reference
                        pcapname_file.write(str(os.path.join(root,f)).replace(pcap_dir,"")+'\n')

                        success+=1
                        if success%1000==0:
                            print('{} pcap files has been parsed...'.format(success))

                    # Skip this pcap file 
                    except (KeyError, AttributeError, TypeError, utils.ZeroPacketError):
                        logging.exception('Known error in file {}. Traffic is skipped'.format(f))
                        failed+=1
                        continue
                    except Exception:
                        logging.exception('Unknown error in file {}. Traffic is skipped')
                        failed += 1
                        continue

    print("Extracted features from pcap files: {} success, {} failure".format(success, failed))

if args.refenum:
    with open(args.refenum, 'r') as f:
        enums = yaml.load(f)
else:
    print('Iterating through PCAP files and processing enums...')
    enums = {}
    # Iterate through sub-directories inside the root directory for alternate traffic. Dont over commit to 1 sub-directory
    pcapdirs = [os.path.join(args.pcapdir, o) for o in os.listdir(args.pcapdir) if os.path.isdir(os.path.join(args.pcapdir, o))]
    pcapdirs.append(args.pcapdir)
    for dirname in pcapdirs:
        enums_in_a_file = utils.searchEnums(dirname, limit=5200)  # 5000 + 200 (in case of failed pcap files)
        for k,v in enums_in_a_file.items():
            if k not in enums:
                enums[k] = []
            enums[k] = list(set(enums[k] + v))

    # File for storing enums used in this feature extraction
    enums_filename = os.path.join(args.savedir,'enums_{}.yml'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
    with open(enums_filename, 'w') as f:
        yaml.dump(enums, f)

# File for updating information on feature extracted in this feature extraction
features_info_filename = 'features_info.csv'
new_features_info_filename = os.path.join(args.savedir, 'features_info_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
with open(features_info_filename,'r') as in_file, open(new_features_info_filename,'w') as out_file:
    for line in in_file:
        enum_list = None
        split_line = line.split(',')
        if 'ClientHello' == split_line[1]:
            if 'Compression method' == split_line[2]:
                enum_list = enums['compressionmethods']
            elif 'Supported groups' == split_line[2]:
                enum_list = enums['supportedgroups']
            elif 'Signature hash algorithm' == split_line[2]:
                enum_list = enums['sighashalgorithms_client']
        elif 'Certificate' == split_line[1] and 'Signature algorithm' == split_line[2]:
            enum_list = enums['sighashalgorithms_cert']

        if enum_list:
            enum_list = enum_list + [0]
            for each_enum in enum_list:
                split_line[4] = str(each_enum)
                out_file.write(','.join(split_line)+'\n')
        else:
            out_file.write(line)

# Generate file for storing extracted features
print('Iterating through PCAP files and extracting features...')
features_dir = os.path.join(args.savedir, 'features_tls_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
pcapname_dir = os.path.join(args.savedir, 'pcapname_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
search_and_extract(args.pcapdir, features_dir, pcapname_dir, enums)

# Generate file for storing min-max of extracted features file
if args.minmax:
    print('Determining min-max for each dimension from extracted features...')
    minmax_dir = os.path.join(args.savedir, 'features_minmax_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
    mmap_data, byte_offset = utilsDatagen.get_mmapdata_and_byteoffset(features_dir)
    min_max_feature = utilsDatagen.get_min_max(mmap_data, byte_offset)
    min_max_feature_list = (min_max_feature[0].tolist(), min_max_feature[1].tolist())
    with open(minmax_dir, 'w') as f:
        json.dump(min_max_feature_list, f)
