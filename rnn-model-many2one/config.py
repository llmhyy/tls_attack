# Write your model configuration here

from datetime import datetime

DATETIME_NOW = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
SEQUENCE_LEN = 1000
EPOCH = 100
SPLIT_RATIO = 0.2  # Validation dataset as a %
BATCH_SIZE = 16
SEED = 2019