# -*- coding: utf-8 -*-
"""
Created on Mon Sep  2 21:21:08 2019

@author: yinger
"""

#judge the type of packet for longest common subsequence
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
#8:RST
#9:SYN
#10:FIN

flag_list=[19,90,92,103,104,106,107,108,15,16,17]
def judge_type(vector):
  # step1: tls or tcp
    type_list=[0,0,0,0,0,0,0,0,0,0,0]          
    flag=0
    type_order_list=[]
    num=0
    for i in flag_list:
        if(vector[i]!=0):
            flag=1  
            type_order_list.append(num)
        num=num+1
  # step2:tls分类
     
    if (flag==1):
        for j in type_order_list:
            type_list[j]=1
            
    

    return type_list