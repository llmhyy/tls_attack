# -*- coding: utf-8 -*-
"""
Created on Thu Sep  5 12:44:42 2019

@author: yinger
"""

# -*- coding: utf-8 -*-
"""
Created on Tue Jul 30 16:44:46 2019

@author: yinger
"""

#梯度下降法算
# loss:
#随机那种，先判断是否小于1/2，若大于直接成功；若小于，减小1/2-cos的值
#由原来变化那种

import numpy as np
import random
from scipy.spatial.distance import pdist
import copy
from sympy import *
import tensorflow as tf

def grad_rotation(stand,seq_len_valid):  
    '''
    in order to generate diverse adversarial sample for a same sample, we use this function to change gradient vector, the cos<> value between the
    new vector and the original one is within a random range(0.7,0.85).
    since vector has 109 demensions, it is difficult to control the vector by setting num randomly ,so we use GD method to find the value fastly. 
    
    input: original gradeint in shape of (1,1000,109) ; valid length
    output: generated new gradient
    '''
    for i in range(seq_len_valid):
        delta=0.05
        num=2000
        g1=tf.Graph()
        with g1.as_default():
            vec=stand[0][i]  # record the original vector as object        
            vec_copy=copy.copy(vec) 
            vec_tensor=tf.convert_to_tensor(vec_copy,dtype=tf.float64)
            g=tf.Variable(tf.random_uniform([109,],-1,1,dtype=tf.float64)) # initialize randomly
            numerator=tf.multiply(vec_tensor,g)
            numerator=tf.reduce_sum(numerator,0)
            denominator=(tf.linalg.norm(vec_tensor,ord=2))*(tf.linalg.norm(g,ord=2)) # define the cos<a,b>=a*b/|a|*|b| in graph
            d=numerator/denominator
            theta=random.uniform(0.7,0.85) # object range
            loss=theta-d 
            grad=(tf.gradients(loss,g))[0]
            learning_rate=0.3            
            new_g = tf.assign(g,(g - learning_rate * grad))
            init = tf.global_variables_initializer()
        
        
        with tf.Session(graph=g1) as sess: 
            sess.run(init)  
            d_origin=sess.run(d)
            if (d_origin>=theta):
                g_value=sess.run(g)
            else:
                while(d_origin<=0):                    
                    sess.run(init)
                    d_origin=sess.run(d)
                    
                for j in range(num):
                    sess.run(new_g)                    
                    d_value=sess.run(d)
                    if (theta-d_value<delta):                        
                        g_value=sess.run(g)
                        break
            
        tf.get_default_graph().finalize() # we need to finalize the graph so the subsequent loop will not be added to the original map,
        tf.reset_default_graph()          # which will result to waste time on the maintenance of graph
        X=np.vstack([g_value,vec_copy])
        d=1-pdist(X,'cosine')         
        g_suc=(np.linalg.norm(vec)/np.linalg.norm(g_value))*g_value                 
        if i==0:
            grad_return=g_suc            
        else:            
            grad_return=np.vstack((grad_return,g_suc)) 
        
    for j in range(seq_len_valid,len(stand[0]),1):
        grad_last=stand[0][j]
        grad_return=np.vstack((grad_return,grad_last))
      
    grad_return=np.reshape(grad_return,(1,1000,109))  
    
    return grad_return    
        