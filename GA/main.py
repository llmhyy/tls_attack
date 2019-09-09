# -*- coding: utf-8 -*-
"""
Created on Fri Aug 16 23:47:02 2019

@author: yinger
"""
import numpy as np
import geatpy as ea   # import geatpy
from myproblem import myproblem 

import GA_traffic
"""================================Instantiating a problem object============================="""
problem = myproblem() 
"""==================================population settings================================"""
Encoding = 'RI'       # coding method
NIND = 20           # population capacity
Field = ea.crtfld(Encoding, problem.varTypes, problem.ranges, problem.borders) 
population = ea.Population(Encoding, Field, NIND) # Instantiate a population object (at this time the population has not been initialized, 
                                                  # just complete the instantiation of the population object)
"""================================parameter setting==============================="""
myAlgorithm = GA_traffic.soea_EGA_templet(problem, population) 
myAlgorithm.MAXGEN = 50 # Maximum evolution algebra
"""===========================Calling algorithm templates for population evolution=========================="""
[population, obj_trace, var_trace] = myAlgorithm.run () # execution algorithm template
population.save () # save the last generation of population information to a file

best_gen = np.argmin(obj_trace[:, 1]) # record which generation the best manindividual is in
best_ObjV = obj_trace[best_gen, 1]# average and best
print('Optimal function value: %s'%(best_ObjV))
print('Optimal variable value: ')
for i in range(var_trace.shape[1]):
    print(var_trace[best_gen, i])
print('Number of valid generation: %s'%(obj_trace.shape[0]))
print('No. %s is the optimal generation'%(best_gen + 1))
print('evaluation times ：%s'%(myAlgorithm.evalsNum))
print('time: %s'%(myAlgorithm.passTime))