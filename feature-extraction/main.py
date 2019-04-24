import os
import logging
import argparse
import numpy as np
from datetime import datetime
from ruamel.yaml import YAML

import utils 

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--pcapdir', help='Input the directory path containing the pcap files for extraction', required=True)
parser.add_argument('-s', '--savedir', help='Input the directory path to save the extracted feature files', required=True)  # e.g foo/bar/extracted-features/normal/
parser.add_argument('-r', '--refenum', help='Input the file path to the yaml file for enum reference', default=None)
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
logging.basicConfig(filename=os.path.join(args.savedir,'output.log'), level=logging.INFO,format='%(asctime)s-%(levelname)s-%(message)s')

def search_and_extract(pcap_dir, features_dir, pcapname_dir, enums):
    success = 0
    failed = 0
    traffic_limit = 200
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
                        # print(str(os.path.join(root,f)).replace(pcap_dir,""))
                        pcapname_file.write(str(os.path.join(root,f)).replace(pcap_dir,"")+'\n')

                        success+=1
                        if success%1000==0:
                            print('{} pcap files has been parsed...'.format(success))

                    # Skip this pcap file 
                    except (KeyError, AttributeError, TypeError):
                        logging.exception('Serious error in file {}. Traffic is skipped'.format(f))
                        failed+=1
                        continue

    # print("{} pcap files have been successfully parsed from {} with features generated. {} pcap files have failed".format(success, pcap_dir, failed))
    print("Extracted features from pcap files: {} success, {} failure".format(success, failed))

if args.refenum:
    with open(args.refenum, 'r') as f:
        enums = yaml.load(f)
else:
    enums = {}
    # Iterate through sub-directories inside the root directory for alternate traffic
    for dirname in os.listdir(args.pcapdir):
        enums_in_a_file = utils.searchEnums(os.path.join(args.pcapdir, dirname), limit=1000)
        for k,v in enums_in_a_file.items():
            if k not in enums:
                enums[k] = []
            enums[k] = list(set(enums[k] + v))

    # File for storing enums used in this feature extraction
    enums_filename = os.path.join(args.savedir,'enums_{}.yml'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
    with open(enums_filename, 'w') as f:
        yaml.dump(enums, f)

# File for updating information on feature extracted in this feature extraction
feature_info_filename = 'feature_info.csv'
new_feature_info_filename = os.path.join(args.savedir, 'feature_info_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
with open(feature_info_filename,'r') as in_file, open(new_feature_info_filename,'w') as out_file:
    for line in in_file:
        enum_list = None
        split_line = line.split(',')
        if 'ClientHello' == split_line[1]:
            if 'Cipher suites' == split_line[2]:
                enum_list = enums['ciphersuites']
            elif 'Compression method' == split_line[2]:
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

# File for storing extracted features
features_dir = os.path.join(args.savedir, 'features_tls_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
pcapname_dir = os.path.join(args.savedir, 'pcapname_{}.csv'.format(datetime_now.strftime('%Y-%m-%d_%H-%M-%S')))
search_and_extract(args.pcapdir, features_dir, pcapname_dir, enums)

