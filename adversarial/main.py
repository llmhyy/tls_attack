import os
import sys
current_dir=os.path.dirname(__file__)
print(current_dir)
sys.path.append(os.path.join(current_dir,'..','GA'))  # locate to process.property
sys.path.append(os.path.join(current_dir,'..','rnn-model'))
import preprocess
import utils_metric as utilsMetric
import utils_datagen as utilsDatagen

### accuracy function ###
def accarcy_mean(batch_predict,batch_true,batch_len,metric):
    padded_batch_acc = utilsMetric.calculate_acc_of_traffic(batch_predict, batch_true)
    masked_batch_acc = np.ma.array(padded_batch_acc)
                    # Mask based on true seq len for every row               
    for i in range(len(batch_len)):    
        masked_batch_acc[i,batch_len[i]:] = np.ma.masked
        
    if metric == 'acc_vector':
        return masked_batch_acc
    elif metric == 'mean_acc':
        
        batch_mean_acc = np.mean(masked_batch_acc, axis=-1)
        return batch_mean_acc    


### function to denormalize ###
import json
def de_norm(x_norm,minmax_dir):
    MINMAX_FILENAME = 'features_minmax_ref.csv'
    minmax_dir = os.path.join(minmax_dir,MINMAX_FILENAME)
    try:
        with open(minmax_dir, 'r') as f:
            min_max_feature_list = json.load(f)
        min_max_feature = (np.array(min_max_feature_list[0]), np.array(min_max_feature_list[1]))
    except FileNotFoundError:
        print('Error: Min-max feature file does not exist in args.rootdir')
        exit()
    min_feature, max_feature = min_max_feature[0], min_max_feature[1]
    den = max_feature-min_feature
    x_denorm=x_norm*den+min_feature

    return x_denorm


### prepare data ###
pad_len=1000
minmax_dir=os.path.join(current_dir,'..','feature-extraction') 
norm_fn=preprocess.extract_minmax(minmax_dir)  
acc_list=[]
packet_num=10
method=1
import tensorflow as tf
import keras
from keras.models import load_model
import pandas as pd
import copy
import keras.backend as K 
import numpy as np
import ad_method2
import ad_method3
model = load_model(os.path.join(current_dir,'..','rnn-model','trained-rnn','poodle','expt_2019-07-17_16-24-33','rnnmodel_2019-07-17_16-24-33.h5'))
model.summary()


for num in range(packet_num): 
    #pcapPath='C:/Users/yinger/intern_summer/217.64.228.121/'+str(num+1) ## can be changed
    pcapPath=os.path.join('sample_packet',str(num+1))
    #save_dir='C:/Users/yinger/intern_summer/tls_attack/feature-extraction/extracted-features/test/'+str(num+1)  # can be changed    
    save_dir=os.path.join('temp',str(num+1))
    preprocess.packet(pcapPath,save_dir)
    x_origin,valid_len=preprocess.extract_x(save_dir)  #save in dir test,but have to copy it to another place
    x,y_t=utilsDatagen.preprocess_data(x_origin,pad_len,norm_fn)    
    #model = load_model(os.path.join(current_dir,'..','rnn-model','trained-rnn','poodle','expt_2019-08-24_15-58-01','rnnmodel_2019-08-24_15-58-01.h5'))
   
    seq_len=1000
    feature_num=109
    x=np.reshape(x,(1,seq_len,feature_num))
    y_t=np.reshape(y_t,(1,seq_len,feature_num))
    x_origin=copy.deepcopy(x)
    y_origin=copy.deepcopy(y_t)
    
        
# =============================================================================
#   fn_grad is to calculate the gradient of the loss 
# =============================================================================
    target = K.variable(tf.zeros((1,seq_len,feature_num)))
    loss=keras.losses.mean_squared_error(target,model.output)
    loss_for_all=tf.reduce_mean(loss, axis=1)  
    grad=K.gradients(loss_for_all,model.input)[0]
    fn_grad=K.function([model.input,target],[grad,loss_for_all])
    
    
    
# =============================================================================
#   step1:judge the type for every time step and record it in type_list
# =============================================================================
    import judge
    import constrains
    type_list=[]
    for step in range(valid_len): #只需要判断有效的即可,若有多个sample，只要加循环改变[]里面即可
        vector=x_origin[0][step]
        vector_type=judge.judge_type(vector)
        type_list.append(vector_type)
    
    
# =============================================================================
#    step2: increase loss via gradient 
# =============================================================================
    iterations=2000
    alpha=10000.0  #changable parameters
    grad_o,losses_o=fn_grad([x_origin,y_origin])
    y_p=model.predict(x_origin)
    acc_value_origin=accarcy_mean(y_p, y_origin,[valid_len],'mean_acc')
    acc_list.append(acc_value_origin)
    print('acc_origin',acc_value_origin)
    
    for it in range(iterations):        
        grads,losses=fn_grad([x,y_t]) 
        if (method==2):
            grads=ad_method2.grad_rotation(grads,valid_len)
        if (method==3):
            grads=ad_method3.generate_grad(grads,x_origin,type_list,valid_len)
        x += alpha*grads
        
# =============================================================================
#    step3:do some constrains after change
# =============================================================================
        for step in range(valid_len):           
            vector=x[0][step] # take the vector of the step      
            vector_type=type_list[step]
            #constrain on tcp header
            vector[0]=x_origin[0][step][0] #[0] should be kept as before       
            vector=constrains.tcp_head(vector)         
            for i in range(0,8,1):
                t_n=vector_type[i]
                condition=(i,t_n)
                dict_kind={(0,1):constrains.nonzero_ch,
                       (0,0):constrains.zero_ch,
                       (1,1):constrains.nonzero_sh,
                       (1,0):constrains.zero_sh,
                       (2,1):constrains.nonzero_cert,
                       (2,0):constrains.zero_cert,
                       (3,1):constrains.nonzero_shd,
                       (3,0):constrains.zero_shd,
                       (4,1):constrains.nonzero_cke,
                       (4,0):constrains.zero_cke,
                       (5,1):constrains.nonzero_ehm,
                       (5,0):constrains.zero_ehm,
                       (6,1):constrains.nonzero_ccs,
                       (6,0):constrains.zero_ccs,
                       (7,1):constrains.nonzero_app,
                       (7,0):constrains.zero_app
                       }            
                fun_name=dict_kind[condition] #会自动调用函数，并且vector会发生变化
                vector=fun_name(vector)
            x[0][step]=vector 
    # x belongs to [0,1]
        x[x<0]=0
        x[x>1]=1
    
    
# =============================================================================
#    step4:accuracy  
# =============================================================================
        x[0][valid_len:][:]=0 #set those unvalid demension to 0
        y_p=model.predict(x)
        y_t[:,:-1,:]=x[:,1:,:]  #构造新的y_t
        acc_value=accarcy_mean(y_p, y_t,[valid_len-1],'mean_acc') #因为缺失最后一个新信息，因此不计入accuracy    
        if (it % 1==0):                
            print('acc',acc_value)        
        if (acc_value<0.6):
            x_modify=x
            break
        
    
# =============================================================================
#    save the file_norm 
# =============================================================================
    from datetime import datetime
    DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    #savedir='C:\\Users\\yinger\\intern_summer\\217.64.228.121\\norm'
    savedir=os.path.join(current_dir,'..','GA','sample_packet','norm')
    x_write=np.reshape(x_modify,(seq_len,feature_num))
    df=pd.DataFrame(data=x_write)
    if (method==2):
        filename='norm_{}'.format(num+1)+'_method_2'+'.csv'
    if (method==3):
        filename='norm_{}'.format(num+1)+'_method_3'+'.csv'
    else:    
        filename='norm_{}'.format(num+1)+'_method_1'+'.csv'
    df.to_csv(os.path.join(savedir,filename),header=None,index=None)




# =============================================================================
#   save to file denorm 
# =============================================================================
    minmax_dir=os.path.join(current_dir,'..','feature-extraction')  
    x_denorm=de_norm(x_write,minmax_dir)
    df=pd.DataFrame(data=x_denorm)
    savedir=os.path.join(current_dir,'..','GA','sample_packet','denorm')
    if (method==2):
        filename='denorm_{}'.format(num+1)+'_method_2.csv'
    if (method==3):
        filename='denorm_{}'.format(num+1)+'_method_3.csv'
    else:    
        filename='denorm_{}'.format(num+1)+'_method_1.csv'
    df.to_csv(os.path.join(savedir,filename),header=None,index=None)


# =============================================================================
# save origin accuracy 
# =============================================================================
print(acc_list)
if (method==2):
    filename_acc=os.path.join(current_dir,'..','GA','sample_packet','acc_2.txt')
if (method==3):
    filename_acc=os.path.join(current_dir,'..','GA','sample_packet','acc_3.txt')
else:
    filename_acc=os.path.join(current_dir,'..','GA','sample_packet','acc_1.txt')
f=open(filename_acc,'w')   
for i in range(len(acc_list)):
    f.writelines([str(i)+'   ',str(acc_list[i]),'\n'])   
f.close() 
