import os
import csv
import logging
import argparse
import subprocess
from itertools import islice

import urlScrapping

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--csv_input', help='Input the csv file to read. URL must be on the first column')
parser.add_argument('-b', '--start_row', type=int, default=1, help='Input the row number to start scanning from')
parser.add_argument('-s', '--savedir',help='Input the directory to save the output of program')
args = parser.parse_args()

LOGGING_FILENAME = 'output.log'
LOGGING_FILEPATH = os.path.join(args.savedir, LOGGING_FILENAME)
logging.basicConfig(filename=LOGGING_FILEPATH, level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

def main():
    print('Starting program to scan given websites for vulnerability')
    vulnerabilityScanner = urlScrapping.VulnerabilityScanner(args.savedir)

    with open(args.csv_input) as f:
        csvReader = csv.reader(f)
        i = 0
        for row in islice(csvReader, args.start_row-1, None):
            url = 'https://' + row[0]
            processing_url_msg = 'Processing url {}'.format(url)
            print(processing_url_msg)
            logging.info(processing_url_msg)
            if vulnerabilityScanner.isResponsive(url) and vulnerabilityScanner.isHttps(url):
                try:
                    vulnerabilityScanner.scanURL(url)
                except subprocess.TimeoutExpired:
                    continue
                try:
                    vulnerabilityScanner.writeIntoReport()
                except IndexError:
                    continue

if __name__ == '__main__':
    main()