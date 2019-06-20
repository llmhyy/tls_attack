# iterate row by row
# test whether url is responsive
# use testssl and generate temp report
# compile back to one csv file
import os
import csv
import urllib
import logging
import requests
import argparse
import subprocess
from itertools import islice

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--csv_input', help='Input the csv file to read. URL must be on the first column')
parser.add_argument('-b', '--start_row', type=int, default=1, help='Input the row number to start scanning from')
parser.add_argument('-s', '--savedir',
                    help='Input the directory to save the output of program')
args = parser.parse_args()

TEST_NAMES = ['heartbleed','CCS','ticketbleed','ROBOT','secure_renego','secure_client_renego','CRIME_TLS','BREACH','POODLE_SSL','fallback_SCSV','SWEET32','FREAK','DROWN','LOGJAM','LOGJAM-common_primes','BEAST_CBC_TLS1','BEAST','LUCKY13','RC4']
TEMP_FILENAME = 'temp.csv'
REPORT_FILENAME = 'report.csv'
LOGGING_FILENAME = 'output.log'
TEMP_FILEPATH = os.path.join(args.savedir, TEMP_FILENAME)
REPORT_FILEPATH = os.path.join(args.savedir, REPORT_FILENAME)
LOGGING_FILEPATH = os.path.join(args.savedir, LOGGING_FILENAME)

logging.basicConfig(filename=LOGGING_FILEPATH, level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

def isHttps(url):
    parsedURL = urllib.parse.urlparse(url)
    if parsedURL.scheme == 'https':
        return True
    else:
        return False

def isResponsive(url):
    try:
        r = requests.get(url, timeout=5)
    except requests.exceptions.RequestException:
        logging.warning('URL is not responsive')
        return False

    if r.status_code == 200:
        return True
    else:
        logging.warning('Status code is not 200')
        return False

def isReportComplete():
    with open(TEMP_FILEPATH, 'r') as f:
        csvReader = csv.reader(f)
        next(csvReader, None)
        counter = 0
        for row in csvReader:
            counter += 1
            if row[0] == 'scanProblem':
                logging.warning('ScanProblem found in report. Skipping')
                return False
    return True

def checkVuln(url):
    if os.path.exists(TEMP_FILEPATH):
        os.remove(TEMP_FILEPATH)
    cmd = 'testssl.sh-3.0/testssl.sh --csvfile ' + TEMP_FILEPATH + ' -U ' + url
    subprocess.run(cmd.split(' '), stdout=subprocess.DEVNULL)

def writeIntoCSV():
    score = {'OK': [1, 0, 0, 0], 'LOW': [0, 1, 0, 0], 'MEDIUM': [0, 0, 1, 0], 'HIGH': [0, 0, 0, 1],
             'INFO': ['', '', '', ''], 'WARN': ['', '', '', '']}

    with open(TEMP_FILEPATH, 'r') as rf, open(REPORT_FILEPATH, 'a') as wf:
        csvReader = csv.reader(rf)
        csvWriter = csv.writer(wf)
        rows = []
        next(csvReader, None) # Skip the header
        for row in csvReader:
            if row[0] == 'DROWN' and row[3] == 'INFO': # Ignore this row
                continue
            rows.append(row)

        # Identify unique ip addresses in rows and group together
        unique_ips = set(list(zip(*rows))[1])
        rows_groupby_ip_groups = []
        for ip in unique_ips:
            rows_groupby_ip_groups.append({row[0]:row for row in rows if row[1]==ip})

        # Write data into output format nicely
        for group in rows_groupby_ip_groups:
            ip = group.get('service', None)[1]
            if not ip:
                logging.warning('Id service cannot be found. Skipping')
                raise AttributeError('Id Service cannot be found in the output of testssl')
            new_row = [ip]
            for test_name in TEST_NAMES:
                if test_name in group:
                    selected_row = group[test_name]
                    severity = selected_row[3]
                    finding = selected_row[4]
                    new_row.extend(score[severity])
                    new_row.append(finding)
                else:
                    new_row.extend(['']*5)
            csvWriter.writerow(new_row)

if __name__ == '__main__':
    print('Starting Program')
    with open(args.csv_input) as f:
        csvReader = csv.reader(f)
        i = 0
        for row in islice(csvReader, args.start_row-1, None):
            url = 'https://' + row[0]
            processing_url_msg = 'Processing url {}'.format(url)
            print(processing_url_msg)
            logging.info(processing_url_msg)
            if isHttps(url) and isResponsive(url):
                checkVuln(url)
                if isReportComplete():
                    try:
                        writeIntoCSV()
                        i += 1
                    except AttributeError:
                        continue

            if i%100==0:
                print('Processed {} url successfully'.format(i))

