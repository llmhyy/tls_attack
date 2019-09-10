import os
import csv
import time
import urllib
import urllib.parse
import logging
import requests
import threading
import traceback
import subprocess
import googlesearch
from itertools import islice
from random_word import RandomWords

def getDomainName(url):
    parsedURL = urllib.parse.urlparse(url)
    domain = '{uri.scheme}://{uri.netloc}'.format(uri=parsedURL)
    return domain


class Error(Exception):
    '''Base class for exception in this module'''
    pass

class EmptyQueryError(Error):
    def __init__(self, message):
        self.message = message

class MaxAttemptExceededError(Error):
    def __init__(self, message):
        self.message = message

class URLFinder:
    def __init__(self, numURLPerQuery, savedir):
        self.numURLPerQuery = numURLPerQuery
        self.domainFound = {}
        domainFilename = 'domain.csv'
        self.domainFilepath = os.path.join(savedir, domainFilename)
        self.domainFileLastRowNum = -1
        self.wordGen = RandomWords()

        # Get the domains that are already found from the domain file
        if os.path.exists(self.domainFilepath):
            self.updateDomainFound()
        else:
            os.makedirs(self.domainFilepath)

    def updateDomainFound(self):
        with open(self.domainFilepath) as f:
            rowCount = 0
            for row in islice(csv.reader(f), self.domainFileLastRowNum+1, None):
                domain = row[0]
                if domain in self.domainFound:
                    logging.warning('Warning possible duplicate found in domain file')
                self.domainFound[domain] = 1
                rowCount += 1
            self.domainFileLastRowNum = self.domainFileLastRowNum + rowCount

    def isFound(self, url):
        domain = getDomainName(url)
        if domain in self.domainFound:
            logging.info('Domain name {} is already found. Skipping'.format(domain))
            return True
        else:
            return False

    def searchURLWithQuery(self, query=None):
        if not query:
            query = self.genRandWord()
        queryStatement = self.buildQueryStatement(query)
        urlList = self.searchURL(queryStatement)
        return urlList

    def getUniqueURL(self, urlList):
        uniqueURLList = []
        self.updateDomainFound()
        for url in urlList:
            if not self.isFound(url):
                uniqueURLList.append(url)
        return uniqueURLList

    def genRandWord(self):
        randWord = self.wordGen.get_random_word()
        return randWord

    def buildQueryStatement(self, query):
        queryStatement = 'https +' + query
        return queryStatement

    def searchURL(self, queryStatement):
        urlList = []
        maxAttempts = 3
        currentAttempt = 1
        success = 1000 # aribtrary number for success
        while currentAttempt <= maxAttempts and len(urlList) == 0:
            try:
                googleGen = googlesearch.search(queryStatement, stop=self.numURLPerQuery, only_standard=True)
                for url in googleGen:
                    urlList.append(url)
                currentAttempt = success
            except urllib.error.HTTPError as e:
                currentAttempt += 1

        if len(urlList) == 0 and currentAttempt == success:
            logging.warning('Query {} yields no results'.format(queryStatement))
            raise EmptyQueryError('Query {} yields no results'.format(queryStatement))
        elif len(urlList) == 0 and currentAttempt > maxAttempts:
            logging.warning('Unsuccessful query after {} attempts'.format(maxAttempts))
            raise MaxAttemptExceededError('Unsuccessful query after {} attempts'.format(maxAttempts))

        return urlList

class VulnerabilityScanner:
    def __init__(self, savedir, threadcount=''):
        reportFilename = 'report.csv'
        tempFilename = 'temp' + threadcount + '.csv'
        domainFilename = 'domain.csv'
        self.reportFilepath = os.path.join(savedir, reportFilename)
        self.tempFilepath = os.path.join(savedir, tempFilename)
        self.domainFilepath = os.path.join(savedir, domainFilename)

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
            logging.info('Failed to request from {}'.format(url))
            return False
        if r.status_code == 200:
            return True
        else:
            logging.info('Status code is not 200')
            return False

    def scanURL(self, url):
        if os.path.exists(self.tempFilepath):
            os.remove(self.tempFilepath)
        cmd = 'testssl.sh-3.0/testssl.sh --csvfile ' + self.tempFilepath + ' -U ' + url
        try:
            subprocess.run(cmd.split(' '), stdout=subprocess.DEVNULL, timeout=1800) # timeout after 30 mins
        except subprocess.TimeoutExpired:
            logging.warning('testssl has timeout on {}'.format(url))

    def writeIntoReport(self):
        rows = self.getRowForReport()
        formattedRows = self.formatRowForReport(rows)
        with open(self.reportFilepath, 'a') as f:
            csvWriter = csv.writer(f)
            for formattedRow in formattedRows:
                csvWriter.writerow(formattedRow)

    def writeIntoDomain(self, domain):
        with open(self.domainFilepath, 'a') as f:
            csvWriter = csv.writer(f)
            csvWriter.writerow((domain,))

    def formatRowForReport(self, rows):
        score = {'OK': [1, 0, 0, 0], 'LOW': [0, 1, 0, 0], 'MEDIUM': [0, 0, 1, 0], 'HIGH': [0, 0, 0, 1],
                 'INFO': ['', '', '', ''], 'WARN': ['', '', '', ''], 'CRITICAL':[0, 0, 0, 1]}
        testNames = ['heartbleed','CCS','ticketbleed','ROBOT','secure_renego','secure_client_renego','CRIME_TLS',
                     'BREACH','POODLE_SSL','fallback_SCSV','SWEET32','FREAK','DROWN','LOGJAM','LOGJAM-common_primes',
                     'BEAST_CBC_TLS1','BEAST','LUCKY13','RC4']

        # Identify unique ip addresses in rows and group together
        try:
            unique_ips = set(list(zip(*rows))[1])
        except IndexError:
            logging.error('Rows appear to be missing')
            raise IndexError
        rows_groupby_ip_groups = []
        for ip in unique_ips:
            rows_groupby_ip_groups.append({row[0]:row for row in rows if row[1]==ip})

        formattedRows = []
        for group in rows_groupby_ip_groups:
            if 'scanProblem' in group:
                logging.warning('id ScanProblem found in testssl output')
                continue

            ip = group.get('service', None)[1]
            if not ip:
                logging.warning('id Service cannot be found in testssl output')
                raise AttributeError('id Service cannot be found in testssl output')
            formattedRow = [ip]
            for testName in testNames:
                if testName in group:
                    selected_row = group[testName]
                    severity = selected_row[3]
                    finding = selected_row[4]
                    try:
                        formattedRow.extend(score[severity])
                    except KeyError:
                        formattedRow.extend(['']*4)
                        logging.error('New severity level found {}'.format(severity))
                    formattedRow.append(finding)
                else:
                    formattedRow.extend(['']*5)

            formattedRows.append(formattedRow)

        return formattedRows

    def getRowForReport(self):
        with open(self.tempFilepath, 'r') as rf:
            csvReader = csv.reader(rf)
            rows = []
            next(csvReader, None) # Skip the header
            for row in csvReader:
                if row[0] == 'DROWN' and row[3] == 'INFO': # Ignore this row
                    continue
                rows.append(row)
        return rows

class FinderScannerWorker(threading.Thread):
    def __init__(self, threadID, threadLock, numQuery, numURL, savedir):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.threadLock = threadLock
        self.numQuery = numQuery

        self.urlFinder = URLFinder(numURL, savedir)
        self.vulnerabilityScanner = VulnerabilityScanner(savedir, str(self.threadID))

    def run(self):
        print('Starting Thread-{}'.format(self.threadID))
        for i in range(self.numQuery):
            try:
                urlList = self.urlFinder.searchURLWithQuery()
                for url in urlList:
                    domainName = getDomainName(url)

                    self.threadLock.acquire()
                    self.urlFinder.updateDomainFound()
                    self.threadLock.release()
                    if self.vulnerabilityScanner.isResponsive(url) and self.vulnerabilityScanner.isHttps(url) and \
                            not self.urlFinder.isFound(url):
                        processing_url_msg = 'Thread-{}: Processing url {}'.format(self.threadID, domainName)
                        print(processing_url_msg)
                        logging.info(processing_url_msg)

                        try:
                            self.vulnerabilityScanner.scanURL(url)
                        except subprocess.TimeoutExpired:
                            continue

                        try:
                            self.threadLock.acquire()
                            self.vulnerabilityScanner.writeIntoReport()
                            self.vulnerabilityScanner.writeIntoDomain(domainName)
                        except csv.Error:
                            logging.warning('Unable to write into csv files')
                            continue
                        except IndexError:
                            continue
                        finally:
                            self.threadLock.release()

            except EmptyQueryError:
                continue

            except MaxAttemptExceededError:
                time.sleep(60)

            except Exception:
                print('Fatal error but continuing to next query...')
                print(traceback.print_exc())
