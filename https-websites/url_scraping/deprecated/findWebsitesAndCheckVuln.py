import argparse
import logging
import subprocess
import googlesearch
from random_word import RandomWords

'''
General steps:
1.) Generate random keywords
2.) Create a query statement for Google
3.) Search using Google and return a list of url
4.) Test the vulnerability of the site using testssl
5.) Output the report into a csv file
'''

parser = argparse.ArgumentParser()
parser.add_argument('-q', '--num_query', type=int, default=1000, help='Input the number of query to search for')
parser.add_argument('-u', '--num_url', type=int, default=100,
                    help='Input the number of url to find and check vulnerability for each query')
parser.add_argument('-i', '--querydir',
                    help='Input the directory of file containing a list of words to be used for query')
parser.add_argument('-o', '--outputdir', required=True,
                    help='Input the directory of the output file to save the vulnerability report')
parser.add_argument('-n', '--num_instance', type=int, default=1,
                    help='Input the number of instances for multi-threading')
args = parser.parse_args()

logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s-%(levelname)s-%(message)s')


def findWebsitesAndCheckVuln(givenQuery=None):
    url_list = findWebsites(givenQuery)
    checkVuln(url_list)


def findWebsites(givenQuery=None):
    q_stmt = buildQueryStatement(givenQuery)
    url_list = searchWebEngine(q_stmt)
    logging.info('Found {} websites'.format(len(url_list)))
    return url_list


def buildQueryStatement(givenQuery=None):
    if givenQuery:
        q_word = givenQuery
    else:
        q_word = genRandWord()
    logging.info('Using the query \'{}\''.format(q_word))
    q_stmt = 'https + ' + q_word
    return q_stmt


def genRandWord():
    generator = RandomWords()
    randWord = generator.get_random_word()
    return randWord


def searchWebEngine(q_stmt):
    googleGen = googlesearch.search(q_stmt, stop=args.num_url, only_standard=True)
    return [url for url in googleGen]


def checkVuln(url_list):
    for url in url_list:
        logging.info('Testing on {}'.format(url))
        cmd = 'testssl.sh-3.0/testssl.sh --csvfile ' + args.outputdir + ' --append -U ' + url
        subprocess.run(cmd.split(' '), stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    logging.info('Starting web scraping...')
    print('Starting web scraping...')

    if args.querydir is not None:
        with open(args.querydir) as f:
            for query in f.readlines():
                findWebsitesAndCheckVuln(givenQuery=query)

    for i in range(args.num_query):
        findWebsitesAndCheckVuln()
        if i % 100 == 0:
            print('{} queries have been searched'.format(i))
