# -*- coding: utf-8 -*-
"""
Created on Fri Aug 16 17:31:53 2019

@author: yinger
"""
    
import numpy as np
import geatpy as ea
import pandas as pd
import tensorflow as tf
import sys
import os
from keras.models import load_model
from keras.backend.tensorflow_backend import set_session
import preprocess
import shutil
# locate the related directory to import some useful file
current_dir=os.path.dirname(__file__)
sys.path.append(os.path.join(current_dir,'..','rnn-model'))
sys.path.append(os.path.join(current_dir,'..','TlsAttack_batch'))
import TlsAttack_batch.getPcap as gP
import utils_metric as utilsMetric
import utils_datagen as utilsDatagen

def load():   
# =============================================================================
#     GPU
#     config = tf.ConfigProto()
#     config.gpu_options.allow_growth = True  # dynamically grow the memory used on the GPU
#     config.log_device_placement = True  # to log device placement (on which device the operation ran)                                    # (nothing gets printed in Jupyter, only if you run it standalone)
#     sess = tf.Session(config=config)
#     set_session(sess)  # set this TensorFlow session as the default session for Keras
# =============================================================================
    model = load_model(os.path.join(current_dir,'..','rnn-model','trained-rnn','poodle','expt_2019-07-17_16-24-33','rnnmodel_2019-07-17_16-24-33.h5'))
    
    return model


def accarcy_mean(batch_predict,batch_true,batch_len,metric):
    """
    accuracy function
    """
    padded_batch_acc = utilsMetric.calculate_acc_of_traffic(batch_predict, batch_true)
    masked_batch_acc = np.ma.array(padded_batch_acc) # Mask based on true seq len for every row                                   
    for i in range(len(batch_len)):    
        masked_batch_acc[i,batch_len[i]:] = np.ma.masked        
    if metric == 'acc_vector':
        return masked_batch_acc
    elif metric == 'mean_acc':        
        batch_mean_acc = np.mean(masked_batch_acc, axis=-1)
        return batch_mean_acc 
    


class myproblem(ea.Problem):
    def __init__(self):
        self.model=load()
        name='traffic'
        M=1 # The dimension of target, that is, how many optimization goals
        maxormins = [1] # 1: minimize the target; -1: maximize the target
        self.Dim = 22 # Variable dimension
        varTypes = [1]*self.Dim # The type of the variable, 0 :continuous; 1 :discrete)
        lb=[65536,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8] # lower bound of variable 
        ub=[8388608,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,2000,8192] # upper bound of variable
        lbin = [1] * self.Dim # Can the lower boundary of the variable be taken? 1: yes 
        ubin = [1] * self.Dim # Can the upper boundary of the variable be taken
        ea.Problem.__init__(self, name, M, maxormins, self.Dim, varTypes, lb, ub, lbin, ubin) # Call the parent class constructor to complete the instantiation
        
        
            
    def aimFunc(self, pop): #Objective function 
        temp_dir=os.path.join(current_dir,'GA_temp') # dir to save feature csv file temporarily
        minmax_dir=os.path.join(current_dir,'..','feature-extraction')  # dir of minmax file
        Vars = pop.Phen # matrix of variables
        size=Vars.shape[0]  # record population size,sinceThe population capacity is different between 
                      # the first generation and subsequent generations. 
        x_variable=[]
        for i in range(self.Dim): # acquire the variable and record it in x, then generate new attack
            x_variable.append(Vars[:, [i]])
        
        norm_fn=preprocess.extract_minmax(minmax_dir)  #one time
        pad_len=1000
        acc_array=[]
        
        for j in range(size):
            v=[]
            for i in range(self.Dim):
                v.append(int((x_variable[i])[j][0]))
            
            '''
            v1=int(x1[j][0])
            v2=int(x2[i][0])
            v3=int(x3[i][0])
            '''
            # write the changed variable in txt file
            with open(os.path.join(current_dir,'..','TlsAttack_batch','parameter.txt'),'w') as f: 
                f.write(str(v[0])+'\n')
                f.write(str(v[1:21])+'\n')
                f.write(str(v[21])+'\n')
            pcapPath = gP.getPcap() # start a new attack and capture the corresponding packect   !!!!remenmber to revise         
            preprocess.packet(pcapPath,temp_dir) # extract features from pcap
            x_origin,valid_len=preprocess.extract_x(temp_dir) # extract x            
            x,y_t=utilsDatagen.preprocess_data(x_origin,pad_len,norm_fn) # process x and y before being feede into the model
            y_p=self.model.predict(x)
            acc_value=accarcy_mean(y_p, y_t,[valid_len],'mean_acc')
            print('value',acc_value)
            acc_array.append(acc_value)
            if (acc_value<0.75):  #record pacp for good result
                file=str(acc_value)+'.pcap'
                shutil.copy(os.path.join(pcapPath,'result.pcap'),os.path.join(current_dir,'select_packect',file)) # save the eligible package
            shutil.rmtree(temp_dir) #delete csv file in this 
        
        acc_array=np.array(acc_array)
        acc_array=np.reshape(acc_array,(size,1))

        
        
         # transform tothe format of np.array 
        pop.ObjV = acc_array  # Assign the pop population object to ObjV attribute
        
    
    
        
    
        
        
        
    
                    
        
    
        
        
        
    
                