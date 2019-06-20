import os
import logging
import argparse
import threading
# from url_scraping import urlScrapping
import urlScrapping

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

LOGGING_FILENAME = 'output.log'
LOGGING_FILEPATH = os.path.join(args.savedir, LOGGING_FILENAME)
logging.basicConfig(filename=LOGGING_FILEPATH, level=logging.INFO, format='%(asctime)s-%(levelname)s-%(threadName)s: %(message)s')

THREADLOCK = threading.Lock()

def main():
    print('Starting main thread')
    threads = []

    for i in range(args.num_thread):
        thread_i = urlScrapping.FinderScannerWorker(i, THREADLOCK, args.num_query, args.num_url, args.savedir)
        threads.append(thread_i)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    print('Exiting main thread')

if __name__ == '__main__':
    main()