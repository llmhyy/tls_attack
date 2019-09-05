# -*- coding: utf-8 -*-
"""
Created on Mon Sep  2 14:49:54 2019

@author: yinger
"""

import numpy as np
import judge_lcs
from scipy.spatial.distance import pdist

def lcs(s1,s2):    
    '''
    input:  s1,s2  [[],[],[],……]
    output: seq length, direction matrix
    '''
    len1=len(s1) #vertical
    len2=len(s2) #horizontal
    value_mat=[[0 for i in range(len2+1)] for j in range(len1+1)] # record subsequence length in list [[],[],……]
    dir_mat= [[0 for i in range(len2+1)] for j in range(len1+1)] # record direction in list
    for p1 in range(len1):
        for p2 in range(len2):
            if (s1[p1] == s2[p2]): # match successfully
                value_mat[p1+1][p2+1]=value_mat[p1][p2]+1
                dir_mat[p1+1][p2+1]= 'ok'
            elif (value_mat[p1+1][p2] < value_mat[p1][p2+1]): # left < up
                value_mat[p1+1][p2+1]=value_mat[p1][p2+1]
                dir_mat[p1+1][p2+1]= 'up'
            else:
                value_mat[p1+1][p2+1]=value_mat[p1+1][p2] # up <=left
                dir_mat[p1+1][p2+1]= 'left'
    
            
    p1,p2=len1,len2 # p1, p2 are the index in matrix,(from bottom to top)
    sub1_order=[]  #record the order num,but it is reversed
    sub2_order=[]
    sub_kind=[]
    while value_mat[p1][p2]:
        direction=dir_mat[p1][p2]
        if (direction == 'ok'): # match successfully, so record it
            sub_kind.append(s1[p1-1])
            sub1_order.append(p1-1)
            sub2_order.append(p2-1)
            print(sub_kind)
            p1 -=1
            p2 -=1
        if (direction == 'left'): # turn left for the next,but no need to add the value to sub_kind
            p2 -=1
        if (direction == 'up'):
            p1 -=1            
    sub_kind.reverse()
    sub1_order.reverse()
    sub2_order.reverse()
    print(sub_kind)
    return sub_kind,sub1_order,sub2_order,dir_mat,value_mat



def LCS(x_1,x_2,v_len_1,v_len_2):
    '''
    input: two sequences,with the valid lenth;
    return: similarity;
    input shape: x_1:(1,1000,109), v_len_1: number
    r1: the ratio of useful step
    r2: the ratio of subsequence in the sequence extracted from the first step
    sim: average cos similarity of the corresponding vector
    similarity=r1*r2*sim 
    '''
    
    # =============================================================================
    # step1: extract useful step to form a new sequence
    # =============================================================================
    kind_list_1=[] #extract import step from the origin seqeunce
    order_list_1=[] #record the corresponding order number
    x_list_1=[] 
    for i in range(v_len_1):
        vector=x_1[0,i,:]
        kind=judge_lcs.judge_type(vector)
        if (kind != [0,0,0,0,0,0,0,0,0,0,0]):
            kind_list_1.append(kind)
            order_list_1.append(i)
            x_list_1.append(vector)
            
    new_x_1=np.array(x_list_1) #transfer list to array
    new_x1_len=len(order_list_1)
    #print(len(kind_list_1))
    #print(order_list_1)        
    kind_list_2=[]
    order_list_2=[] #record the corresponding order number 
    x_list_2=[]
    for i in range(v_len_2):
        vector=x_2[0,i,:]
        kind=judge_lcs.judge_type(vector)
        if (kind != [0,0,0,0,0,0,0,0,0,0,0]):
            kind_list_2.append(kind)
            order_list_2.append(i)
            x_list_2.append(vector)
    new_x_2=np.array(x_list_2) #transfer list to array
    new_x2_len=len(order_list_2)
    
    
    # =============================================================================
    # step2: calculate the ratio of useful information 
    # =============================================================================
    ratio_1= new_x1_len / v_len_1  
    ratio_2= new_x2_len / v_len_2
    if (ratio_1 > ratio_2):
        r1=ratio_2 / ratio_1
    else:
        r1=ratio_1 / ratio_2
    
    
    # =============================================================================
    # step3: search for the longest common subsequence
    # =============================================================================
    if (new_x1_len<new_x2_len):  #find the shorter one,
        x_min=new_x1_len         # there are two usages: 1. the order of input paramater for lcs function 
        sub_kind,sub1_order,sub2_order,dir_mat,value_mat=lcs(kind_list_1,kind_list_2) #pay attention:compare the length of two string, 1.shortrt, 2. longer
        print(sub_kind)
    else:                                               #2. calculate r2
        x_min=new_x2_len
        sub_kind,sub1_order,sub2_order,dir_mat,value_mat=lcs(kind_list_2,kind_list_1) #pay attention:compare the length of two string, 1.shortrt, 2. longer
        
                
    # =============================================================================
    # step4:calculate the cos similarity between  corresponding vector       
    # =============================================================================    
    sim_array=np.array([])
    for index in range(len(sub_kind)):
        x1_index=sub1_order[index]
        x2_index=sub2_order[index]
        vector1=new_x_1[x1_index,:]
        vector2=new_x_2[x2_index,:]
        X=np.vstack([vector1,vector2])
        d=1-pdist(X,'cosine')
        sim_array=np.append(sim_array,d)
        
    sim=(sum(sim_array))/(len(sub_kind))    
    # =============================================================================
    # step5: combine all the factors together
    # =============================================================================
        
    r2= 1.0*(len(sub_kind))/x_min
    print(r1)
    print(r2)
    print(sim)
    similarity=r1*r2*sim
    
    return similarity

    
     
        
                
                
        
        
        





