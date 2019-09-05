# -*- coding: utf-8 -*-
"""
Created on Tue Aug 20 13:45:54 2019

@author: yinger
"""

import subprocess
import os
import shlex
import sys
import numpy as np
import json
current_dir=os.path.dirname(__file__)
sys.path.append(os.path.join('current_dir','..','rnn-model'))
import utils_datagen as utilsDatagen

def packet(pac_dir,save_dir):
    '''
    extract features from packect
    save the result in save_dir
    '''
    pac_dir=os.path.join(current_dir,pac_dir)
    pac_dir=pac_dir.replace('\\','/')  # os.path.join in windows system will be splited by \,which will be ignored by shlex.split.  
    save_dir=os.path.join(current_dir,save_dir)  # so we have to replace it  
    save_dir=save_dir.replace('\\','/')
    cmd1='python main.py -p '+pac_dir+' -s '+save_dir+' -r enums_ref.yml'  
    cmd=shlex.split(cmd1)
    cwdname=os.path.join(current_dir,'..','feature-extraction')
    try:
        p1=subprocess.check_output(cmd,cwd=cwdname,stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))



    
# In[3]
    
def extract_x(save_dir): 
    '''
    read the x input from csv file, which generated from function 'packect' 
    '''
    
    import os
    import fnmatch
    FEATURE_FILENAME = 'features_tls_*.csv'
    rootdir=os.path.join(current_dir,save_dir)
    rootdir_filenames = os.listdir(rootdir)
    try:
        feature_dir = os.path.join(rootdir, fnmatch.filter(rootdir_filenames, FEATURE_FILENAME)[0])  #locate the csv file ,because we don't
    except IndexError:                                                                              # know the exact name
        print('\nERROR: Feature file is missing in directory.\nHint: Did you remember to join the feature files together?')
        exit()
    with open(feature_dir,'r') as csvfile:  # actually,the file is not a csv file,so we cannot use csv.reader
        line=next(csvfile)
        lines=line.strip().rstrip(',')   # delete the last comma
    traffic=np.array(json.loads('['+lines+']'))  # add[] to form a list,then transform to np.array
    valid_len=traffic.shape[0]   # valid sequence length
    traffic_reshape=np.reshape(traffic,(1,traffic.shape[0],traffic.shape[1]))
    
    return traffic_reshape,valid_len



def extract_minmax(minmax_dir):
    '''
    acquire minmax value and return normalize function
    '''
    MINMAX_FILENAME = 'features_minmax_ref.csv' 
    minmax_dir = os.path.join(minmax_dir,MINMAX_FILENAME)
    try:
        with open(minmax_dir, 'r') as f:
            min_max_feature_list = json.load(f)
        min_max_feature = (np.array(min_max_feature_list[0]), np.array(min_max_feature_list[1]))
    except FileNotFoundError:
        print('Error: Min-max feature file does not exist in args.rootdir')
        exit()
    norm_fn = utilsDatagen.normalize(2, min_max_feature)
    
    return norm_fn

    
    

     


    
    
    
    


    
        

