import os
import csv
import time
import urllib
import urllib.parse
import logging
import argparse
import requests
import subprocess
import threading
import googlesearch
from itertools import islice
from random_word import RandomWords

parser = argparse.ArgumentParser()
parser.add_argument('-q', '--num_query', type=int, default=1000,
                    help='Input the number of query to search for')
parser.add_argument('-u', '--num_url', type=int, default=100,
                    help='Input the number of url to find and check vulnerability for each query')
parser.add_argument('-s', '--savedir',
                    help='Input the directory to save the output of program')
parser.add_argument('-n', '--num_thread', type=int, default=1,
                    help='Input the number of threads for pure awesomeness')
args = parser.parse_args()

THREADLOCK = threading.Lock()
MAX_ATTEMPTS = 3
TESTSSH_NUMTEST = 21
TEST_NAMES = ['heartbleed','CCS','ticketbleed','ROBOT','secure_renego','secure_client_renego','CRIME_TLS','BREACH','POODLE_SSL','fallback_SCSV','SWEET32','FREAK','DROWN','LOGJAM','LOGJAM-common_primes','BEAST_CBC_TLS1','BEAST','LUCKY13','RC4']
REPORT_FILENAME = 'report.csv'
DOMAIN_FILENAME = 'domain.csv'
LOGGING_FILENAME = 'output.log'
REPORT_FILEPATH = os.path.join(args.savedir, REPORT_FILENAME)
DOMAIN_FILEPATH = os.path.join(args.savedir, DOMAIN_FILENAME)
LOGGING_FILEPATH = os.path.join(args.savedir, LOGGING_FILENAME)

logging.basicConfig(filename=LOGGING_FILEPATH, level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')

class Error(Exception):
    '''Base class for exception in this module'''
    pass

class EmptyQueryError(Error):
    def __init__(self, message):
        self.message = message

class MaxAttemptExceededError(Error):
    def __init__(self, message):
        self.message = message

class VulnerabilityScanner(threading.Thread):
    def __init__(self, threadID, threadLock):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.threadLock = threadLock
        self.wordGen = RandomWords()
        self.foundDomains = {}
        self.lastRowNum = -1
        self.tempCSV = os.path.join(args.savedir,'tmp{}.csv'.format(self.threadID))

    def run(self):
        print('Starting Thread-{}'.format(self.threadID))
        self.findWebsitesAndCheckVuln()
        print('Exiting Thread-{}'.format(self.threadID))

    def findWebsitesAndCheckVuln(self):
        for i in range(args.num_query):
            try:
                url_list = self.findWebsites()

                for url in url_list:
                    # verify whether the url is https
                    # verify whether the url has been found
                    # verify whether the url is alive
                    if not self.isFound(url) and self.isHttps(url) and self.isResponsive(url):
                        self.checkVuln(url)
                    if self.isComplete():
                        self.safeWriteIntoCSV(url)
            except EmptyQueryError:
                continue # try another query
            except MaxAttemptExceededError:
                time.sleep(60) # sleep for 60 seconds

    def findWebsites(self):
        q_stmt = self.buildQueryStatement()

        attempt = 1
        url_list = []
        SUCCESS = 1000 # arbitrary number for success

        while attempt <= MAX_ATTEMPTS and len(url_list) == 0:
            self.threadLock.acquire()
            logging.info('Thread-{}: Attempt {}'.format(self.threadID, attempt))
            try:
                for url in self.searchWebEngine(q_stmt):
                    url_list.append(url)
                attempt = SUCCESS
            except urllib.error.HTTPError as e:
                attempt += 1
            finally:
                self.threadLock.release()

        if len(url_list) == 0 and attempt == SUCCESS:
            logging.warning('Thread-{}: Query {} yields no results. Try another query'.format(self.threadID, q_stmt))
            raise EmptyQueryError('Query {} yields no results. Try another query'.format(q_stmt))
        elif len(url_list) == 0 and attempt > MAX_ATTEMPTS and attempt != SUCCESS:
            logging.warning('Thread={}: Unsuccessful query after {} attempts'.format(self.threadID, MAX_ATTEMPTS))
            raise MaxAttemptExceededError('Unsuccessful query after {} attempts'.format(MAX_ATTEMPTS))
        return url_list

    def buildQueryStatement(self):
        q_word = self.genRandWord()
        q_stmt = 'https' + q_word
        return q_stmt

    def genRandWord(self):
        randWord = self.wordGen.get_random_word()
        return randWord

    def searchWebEngine(self, q_stmt):
        googleGen = googlesearch.search(q_stmt, stop=args.num_url, only_standard=True)
        return [url for url in googleGen]

    def isFound(self, url):
        domainName = self.getDomainName(url)

        self.threadLock.acquire()
        # Read the csv file from the last row and update dict
        with open(DOMAIN_FILEPATH) as f:
            row_count = 0
            for row in islice(csv.reader(f), self.lastRowNum+1, None):
                foundDomain = row[0]
                if foundDomain in self.foundDomains:
                    print('Warning: Possible duplicate found in the dictionary')
                    logging.warning('Thread-{}: Possible duplicate found in the domain list'.format(self.threadID))
                self.foundDomains[foundDomain] = 1
                row_count+=1
            self.lastRowNum = self.lastRowNum + row_count
        self.threadLock.release()

        # Check if it is inside the dict
        if domainName in self.foundDomains:
            logging.info('Thread-{}: Domain name {} is already found. Skipping'.format(self.threadID, domainName))
            return True
        else:
            return False

    def isHttps(self, url):
        parsedURL = urllib.parse.urlparse(url)
        if parsedURL.scheme == 'https':
            return True
        else:
            return False

    def isResponsive(self, url):
        try:
            r = requests.get(url, timeout=5)
        except requests.exceptions.RequestException:
            logging.info('Thread-{}: Failed to request from {}'.format(self.threadID, url))
            return False
        if r.status_code == 200:
            return True
        else:
            return False

    def checkVuln(self, url):
        # Delete tmp csv file
        if os.path.exists(self.tempCSV):
            os.remove(self.tempCSV)
        cmd = 'testssl.sh-3.0/testssl.sh --csvfile ' + self.tempCSV + ' -U ' + url
        subprocess.run(cmd.split(' '), stdout=subprocess.DEVNULL)

    def isComplete(self):
        with open(self.tempCSV, 'r') as f:
            csvReader = csv.reader(f)
            next(csvReader, None)
            counter = 0
            for row in csvReader:
                counter += 1
                if row[0] == 'scanProblem':
                    logging.warning('Thread-{}: ScanProblem detected for url {} due to {}. Report incomplete'.format(self.threadID, row[1], row[4]))
                    return False
        return True

    def safeWriteIntoCSV(self, url):
        formattedRowForReport = self.getFormattedRowForReport()
        formattedRowForDomain = self.getDomainName(url)

        self.threadLock.acquire()
        with open(REPORT_FILEPATH, 'a') as f:
            csvWriter = csv.writer(f)
            csvWriter.writerow(formattedRowForReport)
        with open(DOMAIN_FILEPATH, 'a') as f:
            csvWriter = csv.writer(f)
            csvWriter.writerow((formattedRowForDomain,))
        print('Thread-{} found and checked domain: {}'.format(self.threadID, formattedRowForDomain))
        logging.info('Thread-{}: Found and checked domain {}'.format(self.threadID, formattedRowForDomain))
        self.threadLock.release()

    def getFormattedRowForReport(self):
        score = {'OK': [1, 0, 0, 0], 'LOW': [0, 1, 0, 0], 'MEDIUM': [0, 0, 1, 0], 'HIGH': [0, 0, 0, 1],
                 'INFO': ['', '', '', ''], 'WARN': ['', '', '', '']}
        with open(self.tempCSV, 'r') as rf:
            csvReader = csv.reader(rf)
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
                    logging.warning('Thread-{}: Id Service cannot be found. Skipping'.format(self.threadID))
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
        return new_row

    def getDomainName(self, url):
        parsedURL = urllib.parse.urlparse(url)
        domainName = '{uri.scheme}://{uri.netloc}'.format(uri=parsedURL)
        return domainName

threads = []
# Initialize new threads
for i in range(args.num_thread):
    thread_i = VulnerabilityScanner(i+1, THREADLOCK)
    threads.append(thread_i)

# Start the threads
for thread in threads:
    thread.start()

# Wait for threads to complete
for thread in threads:
    thread.join()

print('Exiting Main Thread')


