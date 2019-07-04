import argparse
import logging
import traceback
from operator import add

from ciphersuite_parser import *

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--pcapdir', help='Input the directory path containing the pcap files for analysis', required=True)
parser.add_argument('-s', '--savedir', help='Input the directory path to save the extracted feature files', required=True)
args = parser.parse_args()

temp = args.pcapdir
if temp.endswith('/'):
    temp = temp[:-1]
dataset_name = temp.split('/')[-1]

logging.basicConfig(filename=os.path.join(args.savedir,'output({}).log'.format(dataset_name)), level=logging.INFO,format='%(asctime)s-%(levelname)s-%(message)s')

if __name__ == '__main__':
    # Testing function tabulateComponentTypesFromCiphersuiteDB()
    # tabulateComponentTypesFromCiphersuiteDB()

    # Testing function parseTraffic()
    # pcapfile = 'sample_pcap/www.stripes.com_2018-12-21_16-20-12.pcap'
    # parseTraffic(pcapfile)

    # Testing function genDec2Vec()
    # dec2Vec = genDec2Vec()
    # for k,v in dec2Vec.items():
    #     print(k, v)

    logging.info('Starting parsing...')

    trafficParserGen = parseTrafficInDirectory(args.pcapdir)
    count = 0
    summed_parsedTraffic = None
    for parsedTraffic in trafficParserGen:
        try:
            if not summed_parsedTraffic:
                summed_parsedTraffic = [0] * len(parsedTraffic)
            summed_parsedTraffic = list(map(add, summed_parsedTraffic, parsedTraffic))
            count += 1
            if count % 1000 == 0:
                print('{} pcpa files have been parsed...'.format(count))
        except Exception:
            print('Serious error. Continuing...')
            traceback.print_exc()

    averaged_parsedTraffic = list(map(lambda x:x/count, summed_parsedTraffic))
    print('Summed parsed traffic: {}'.format(summed_parsedTraffic))
    print('Total # of traffic: {}'.format(count))
    print('Averaged parsed traffic: {}'.format(averaged_parsedTraffic))

    plotFreqByComponentType(averaged_parsedTraffic, dataset_name, args.savedir)