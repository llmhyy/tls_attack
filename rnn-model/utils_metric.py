import numpy as np

# Note: acc refers to cosine similarity

def calculate_acc_of_traffic(predict, true):
    # Calculates the cosine similarity for each packet by comparing predict with true for a batch of traffic
    # and returns an array of cosine similarity for each packet
    dot = np.einsum('ijk,ijk->ij', predict, true)
    vnorm = (np.linalg.norm(predict,axis=2)*np.linalg.norm(true,axis=2))
    cos_sim = np.divide(dot,vnorm,out=np.zeros_like(dot), where=vnorm!=0.0)
    return cos_sim

def calculate_squared_error_of_traffic(predict, true):
    # Calculates squared error between predict and true for a batch of traffic
    # Returns a numpy array with dimensions (num of traffic in a batch, num of packets, num of features)
    return (true - predict)**2
