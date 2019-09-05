# -*- coding: utf-8 -*-
"""
Created on Thu Jul 18 10:11:01 2019

@author: Dell
"""
import numpy as np
import copy 
#全局变量
tcp_end=18 #0~18
tls_begin=19 #19~145
tls_end=108
ch_begin=19 #client hello
ch_end=89
sh_begin=90 #server_hello
sh_end=91
cert_begin=92#certificate
cert_end=102
shd=103 #server_hello_done
cke_begin=104 #client_key_exchange
cke_end=105
ehm=106 #encrypted_handshake_message
ccs=107 #change_cipher_spec
app=108 #

SCS_begin=90
SCS_end=103
APP_num=108
sequence_length=109
#判断形式为(109,)的vector
#对tcp公共头部进行约束
        
def tcp_head(vector):
    #0由外部直接约束，不得更改
    #9~17
    for i in range(9,18,1):
        vector[i]=type_constrain(vector[i])
    #1~6中仅一个1
    #与其他不同，直接比大小，不需要先约束到(0,1)
    vector_1_6=vector[1:7]
    maxmax=np.argmax(vector_1_6)
    vector_1_6=np.zeros(6)
    vector_1_6[maxmax]=1 #将最大的置1
    vector[1:7]=vector_1_6
    
    return vector

#
#hello_client类    
def nonzero_ch(vector):   
    # 19~89 
    vector_copy=copy.copy(vector)
    for i in range(ch_begin,ch_end+1,1):
        vector[i]=type_constrain(vector[i])
    for j in range(ch_begin,64,1):
        vector[j]=vector_copy[j]
    vector[66]=vector_copy[66]
    vector[72]=vector_copy[72]
    vector[73]=vector_copy[73]
    #ssl protocol : Signature hash algorithm (74~89):0 
    vector[74:90]=0.0
    #sum of each component equals 1
    #KEA:20~ 29
    sum_KEA=np.sum(vector[20:30])
    vector[20:30]=vector[20:30]/sum_KEA
    #AUTH:30~37
    sum_AUTH=np.sum(vector[30:38])
    vector[30:38]=vector[30:38]/sum_AUTH
    #ENC:38~52
    sum_ENC=np.sum(vector[38:53])
    vector[38:53]=vector[38:53]/sum_ENC
    #MODE:53~57
    sum_MODE=np.sum(vector[53:58])
    vector[53:58]=vector[53:58]/sum_MODE
    #HASH:58~62
    sum_HASH=np.sum(vector[58:63])
    vector[58:63]=vector[58:63]/sum_HASH
    return vector

def zero_ch(vector):
    #print('vector in fun befor',vector[92])
    for i in range(ch_begin,ch_end+1,1):
        vector[i]=0
    #print('vector in fun after',vector[92])
    return vector
   

        
#server_hello: 90,91
def nonzero_sh(vector):
    return vector
    

def zero_sh(vector):
    for i in range(sh_begin,sh_end+1,1):
        vector[i]=0
    return vector

#certificate
# 92~102
def nonzero_cert(vector):
    #92~95不变    
    for i in range(96,103,1):
        vector[i]=type_constrain(vector[i])
    return vector

def zero_cert(vector):
    for i in range(cert_begin,cert_end+1,1):
        vector[i]=0
    return vector

#server_hello_done
def nonzero_shd(vector):
    #Sever Hello Done length （103） always= 0
    vector[shd]=0
    return vector
def zero_shd(vector):
    vector[shd]=0
    return vector

#client_key_exchange  !!!!! 105是一个随机生成的东西
def nonzero_cke(vector):
    return vector

def zero_cke(vector):
    for i in range(cke_begin,cke_end+1,1):
        vector[i]=0
    return vector
#Encrypted Handshake Message
def nonzero_ehm(vector):
    return vector
def zero_ehm(vector):
    vector[ehm]=0
    return vector  

#Change Cipher Spec
def nonzero_ccs(vector):
    #Change Cipher Spec length（107）always = 1
    vector[ccs]=1
    return vector
def zero_ccs(vector):
    vector[ccs]=0
    return  vector

#Application Data Protocol
def nonzero_app(vector):
    return vector
def zero_app(vector):
    vector[app]=0
    return  vector

     
#将一个数约束成0/1
def type_constrain(value):
    if (value>0.5):
        value=1
    else:
        value=0
    return value
        