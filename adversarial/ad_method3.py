# -*- coding: utf-8 -*-
"""
Created on Sat Jul 27 15:33:58 2019

@author: yinger
"""
import numpy as np
import random
from scipy.spatial.distance import pdist
import copy
def generate_grad(stand,x_origin,type_list,seq_len_valid):  #(1,1000,109)  (x_origin)
    
    for i in range(seq_len_valid):
        print('it',i)
        x=x_origin[0][i]  #判断哪些维度非零
        vec=stand[0][i]  #作为原始记录不变
        kind=type_list[i] #类型记录
        #print('kind',kind)
        vec_copy=copy.copy(vec) #改变vec_copy
        
            
        #step1:先将 非零的变玩   
        vec_list=(np.nonzero(x))[0] #获取非零信息
        #print(vec_list)
        vec_list_len=len(vec_list)   #x非零的数量 
        print('len',vec_list_len)
        #print('vec-len',vec_list_len)
        
        g=np.random.rand(vec_list_len)-0.5
        g=(np.linalg.norm(vec)/np.linalg.norm(g))*g  #将norm变换到相同数量级
        #g=vec
        vec_copy[vec_list]=g
         #step2       
        if (vec_list_len<=20):
            left_num=20-vec_list_len  #剩余再做些变化
            #print(vec_list)
            if(kind[0]==1): #如果是client hello类型
                #print('client_hello')
                client_list=random.sample(list(range(19,90,1)),left_num)#随机选几位
                g=np.random.rand(left_num)-0.5
                g=((np.linalg.norm(vec)/np.linalg.norm(g)))*(left_num/vec_list_len)*g  #将norm变换到相同数量级
                vec_copy[client_list]=g
            if(kind[2]==1): #certificate
                #print('certificate')
                certificate_list=random.sample(list(range(92,109,1)),left_num)#随机选几位
                g=np.random.rand(left_num)-0.5
                g=(np.linalg.norm(vec)/np.linalg.norm(g))*(left_num/vec_list_len)*g  #将norm变换到相同数量级
                vec_copy[certificate_list]=g
        #step3:将tcp头部
            else:
                g=np.random.rand(10)-0.5
                
                if(vec_list_len==0):
                    g=(np.linalg.norm(vec)/np.linalg.norm(g))*g  #将norm变换到相同数量级
                else:
                    g=(np.linalg.norm(vec)/np.linalg.norm(g))*(10/vec_list_len)*g  #将norm变换到相同数量级
                
                vec_copy[9:19]=g
        
                                                            
        X=np.vstack([vec,vec_copy])
        d=1-pdist(X,'cosine')   
        #print('d',d)
        num=1
        #while d<((math.sqrt(2))/2.0):
        while (d<0.5):
            #print('d in while',d)
            vec_copy=copy.copy(vec)
            num=num+1
            
            g=np.random.rand(vec_list_len)-0.5
            g=(np.linalg.norm(vec)/np.linalg.norm(g))*g  #将norm变换到相同数量级
            
            vec_copy[vec_list]=g
            if (vec_list_len<=20):
                left_num=20-vec_list_len  #剩余再做些变化
                
                if(kind[0]==1): #如果是client hello类型
                   # print('client_hello')
                    client_list=random.sample(list(range(19,90,1)),left_num)#随机选几位
                    g=np.random.rand(left_num)-0.5
                    g=(np.linalg.norm(vec)/np.linalg.norm(g))*(left_num/vec_list_len)*g  #将norm变换到相同数量级
                    vec_copy[client_list]=g
                if(kind[2]==1): #certificate
                   # print('certificate')
                    certificate_list=random.sample(list(range(92,109,1)),left_num)#随机选几位
                    g=np.random.rand(left_num)-0.5
                    g=(np.linalg.norm(vec)/np.linalg.norm(g))*(left_num/vec_list_len)*g  #将norm变换到相同数量级
                    vec_copy[certificate_list]=g
            #step3:将tcp头部
                else:
                    g=np.random.rand(10)-0.5
                    if(vec_list_len==0):
                        g=(np.linalg.norm(vec)/np.linalg.norm(g))*g  #将norm变换到相同数量级
                    else:
                        g=(np.linalg.norm(vec)/np.linalg.norm(g))*(10/vec_list_len)*g  #将norm变换到相同数量级
                        
                    
                    vec_copy[9:19]=g
            
            
            X=np.vstack([vec,vec_copy])
            d=1-pdist(X,'cosine')
            
            #print('d',d)
        g_suc=vec_copy #成功的g
        print('g_suc',g_suc.shape)
        #print('final_d',d)
        #修改模的大小
        #turb=0.2*random.random() #0.2的模扰动
        #g_suc=(1+turb)*(np.linalg.norm(vec)/np.linalg.norm(g_suc))*g_suc
        
        #print('test')
        #print('g_suc',g_suc)
        X=np.vstack([vec,g_suc])
        d=1-pdist(X,'cosine')
        #print('d',d)
        #norm=np.linalg.norm(g_suc)
        #print('norm',norm)
        #print('suc_num',num)
        if i==0:
            grad=g_suc
            #print(grad)
        else:
            grad=np.vstack((grad,g_suc))  #(1000,109)
            
            #print('grad_shape',grad.shape)
    
    
    for j in range(seq_len_valid,len(stand[0]),1):
        grad_last=stand[0][j]
        grad=np.vstack((grad,grad_last))      
    grad=np.reshape(grad,(1,1000,109))    
    return grad
    


    
    
    
    
    
    
    
    
    