# -*- coding: utf-8 -*-
"""
Created on Thu Jul 18 16:57:55 2019

@author: Dell
"""
#judge the type of packet
#input:(109,)
#output:  8个 
#0:client_hello, 
#1:server_hello,  
#2:certificate,  
#3:server_hello done,  
#4:client_key_exchange,  
#5:encrypted_h_m,  
#6:change_c_s, 
#7:app
tls_flag_list=[19,90,92,103,104,106,107,108]
def judge_type(vector):
  # step1: tls or tcp
    type_list=[0,0,0,0,0,0,0,0]          
    tls_flag=0
    type_order_list=[]
    num=0
    for i in tls_flag_list:
        if(vector[i]!=0):
            tls_flag=1 # tls type 
            type_order_list.append(num)
        num=num+1
  # step2:tls分类
     
    if (tls_flag==1):
        for j in type_order_list:
            type_list[j]=1
            
    

    return type_list
        
                
            
        
    
