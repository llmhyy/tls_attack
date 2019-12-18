import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import scipy.stats as stats
import random
import argparse

def plot_graph(data, dataset, model):
	plt.hist(data, bins=50)
	plt.xlabel('Probability')
	plt.ylabel('Frequency')
	plt.title(model + "_on_" + dataset)
	plt.show()		


def get_acc(folder, model):
	df = pd.read_csv(os.path.join(folder, "results.csv"), names=['accuracy'])
	dataset = folder.split("\\")[-2].split("_")[-1]
	accuracy_data = df['accuracy'].tolist()
	return accuracy_data

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--model', help='directory of model to evaluate', required=True)
args = parser.parse_args()

# Initializing model directory for prediction against other traffic
model_dir = args.model
model = model_dir.split("\\")[-1].split("-")[0]
print(model)
predict_dir = os.path.join(model_dir, os.listdir(model_dir)[0], "predict_results")

for folder in os.listdir(predict_dir):
	dataset = folder.split("_")[-1]
	print(dataset)
	results_dir = os.path.join(predict_dir, folder, "val")
	if(dataset == model):
		model_result = get_acc(results_dir, model)
		break

# Plotting the model against the other dataset results
for folder in os.listdir(predict_dir):
	dataset = folder.split("_")[-1]
	results_dir = os.path.join(predict_dir, folder, "val")
	test_result = get_acc(results_dir, model)

	################################################################################### 
	# Attempting the hypothesis testing 
	# Null hypothesis: Assume that the dataset follows the distribution of the model
	# Alternative hypothesis: Assume that the dataset does not follow the distribution of the model
	# p-value < 0.05 : Reject null hypothesis || else, DO NOT reject null hypothesis
	###################################################################################
	if all(v is not None for v in [model_result, test_result]):
		# Performing random sampling on the population dataset
		model_sample = random.sample(model_result, k=100)
		test_sample = random.sample(test_result, k=100)
		# Plotting graph to show distribution of sampled data
		plot_graph(test_sample, dataset, model)

		print("Testing " + str(dataset) + " on " + model)
		statistic, pVal = stats.mannwhitneyu(model_sample, test_sample)
		print ('P value: ', pVal)