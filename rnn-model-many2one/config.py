# Write your model configuration here

from datetime import datetime

DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
SEQUENCE_LEN = 1000
EPOCH = 10
SPLIT_RATIO = 0.05  # Validation dataset as a %
BATCH_SIZE = 16
SAVE_EVERY_EPOCH = 5  # Interval between each model callback
SEED = 2019