# TEST CASES for functions in utils.py

import math
from utils import *

logging.basicConfig(level=logging.ERROR)

print('Loading packets...')
sample = 'sample-pcap/tls/www.stripes.com_2018-12-21_16-20-12.pcap'

sample_filecapture = pyshark.FileCapture(sample, debug=True)
packets = [packet for packet in sample_filecapture]
sample_filecapture.close()
packet1 = packets[0]
packet4 = packets[3]
packet5 = packets[4]
packet8 = packets[7]
packet11 = packets[10]
packet21 = packets[20]
packet25 = packets[24]
packet46 = packets[45]

# Test function extractComeLeaveFromPacket()
output = extractComeLeaveFromPacket(packet1)
expected = [0]
assert output == expected
output = extractComeLeaveFromPacket(packet25)
expected = [1]
assert output == expected
print('Done testing function extractComeLeaveFromPacket()')

# Test function extractProtocolFromPacket()
output = extractProtocolFromPacket(packet1)
expected = [1, 0, 0, 0, 0, 0]
assert output == expected
output = extractProtocolFromPacket(packet4)
expected = [0, 0, 0, 1, 0, 0]
assert output == expected
output = extractProtocolFromPacket(packet8)
expected = [0, 0, 0, 0, 0, 1]
assert output == expected
print('Done testing function extractProtocolFromPacket()')

# Test extraction of protocol for TCP segments of a reassembed PDU
tcp_features = extract_tcp_features(sample,limit=100)
prot_start_idx = 1
num_prot = 6
output = tcp_features[20][prot_start_idx:prot_start_idx+num_prot]
expected = [0, 0, 0, 0, 0, 1]
assert output == expected
output = tcp_features[45][prot_start_idx:prot_start_idx+num_prot]
expected = [0, 0, 0, 0, 0, 1]
assert output == expected
output = tcp_features[5][prot_start_idx:prot_start_idx+num_prot]
expected = [1, 0, 0, 0, 0, 0]
assert output == expected
print('Done testing extraction of protocol for TCP segments of a reassembed PDU')

# Test function extractLengthFromPacket()
output = extractLengthFromPacket(packet1)
expected = [66]
assert output == expected
output = extractLengthFromPacket(packet5)
expected = [1514]
assert output == expected
print('Done testing function extractLengthFromPacket()')

# Test function extractIntervalFromPacket()
output = extractIntervalFromPacket(packet1)
expected = [0.0]
assert math.isclose(output[0], expected[0])
output = extractIntervalFromPacket(packet4)
expected = [20.716]
assert math.isclose(output[0], expected[0])
print('Done testing function extractIntervalFromPacket()')

# Test function extractFlagFromPacket()
output = extractFlagFromPacket(packet1)
expected = [0, 0, 0, 0, 0, 0, 0, 1, 0]
assert output == expected
output = extractFlagFromPacket(packet11)
expected = [0, 0, 0, 0, 1, 1, 0, 0, 0]
assert output == expected
print('Done testing function extractFlagFromPacket()')

# Test function extractWindowSizeFromPacket(packet1)
output = extractWindowSizeFromPacket(packet1)
expected = [64240]
assert output == expected
output = extractWindowSizeFromPacket(packet4)
expected = [66048]
assert output == expected
print('Done testing function extractWindowSizeFromPacket()')

# Test function extract_tcp_features()
output = extract_tcp_features(sample, limit=100)
expected_len = 100
assert len(output) == expected_len
expected_dim = 19
assert len(output[0]) == expected_dim
print('Done testing function extract_tcp_features()')

print('Loading packets...')
sample1 = 'sample-pcap/tls/www.stripes.com_2018-12-21_16-20-12.pcap'
sample1_filecapture = pyshark.FileCapture(sample1, debug=True)
sample2 = 'sample-pcap/tls/australianmuseum.net.au_2018-12-21_16-15-59.pcap'
sample2_filecapture = pyshark.FileCapture(sample2, debug=True)
sample3 = 'sample-pcap/tls/ari.nus.edu.sg_2018-12-24_14-30-02.pcap'
sample3_filecapture = pyshark.FileCapture(sample3, debug=True)
sample4 = 'sample-pcap/tls/www.zeroaggressionproject.org_2018-12-21_16-19-03.pcap'
sample4_filecapture = pyshark.FileCapture(sample4, debug=True)
sample5 = 'sample-pcap/tls/alis.alberta.ca_2019-01-22_19-26-05.pcap'
sample5_filecapture = pyshark.FileCapture(sample5, debug=True)
sample6 = 'sample-pcap/tls/dataverse.harvard.edu_2018-12-24_17-16-00.pcap'
sample6_filecapture = pyshark.FileCapture(sample6, debug=True)
sample7 = 'sample-pcap/tls/whc.unesco.org_2018-12-24_17-09-08.pcap'
sample7_filecapture = pyshark.FileCapture(sample7, debug=True)
sample8 = 'sample-pcap/tls/www.cancerresearchuk.org_2018-12-24_17-15-46.pcap'
sample8_filecapture = pyshark.FileCapture(sample8, debug=True)
sample9 = 'sample-pcap/tls/www.orkin.com_2018-12-24_17-10-27.pcap'
sample9_filecapture = pyshark.FileCapture(sample9, debug=True)
sample10 = 'sample-pcap/tls/www.tmr.qld.gov.au_2018-12-24_17-20-56.pcap'
sample10_filecapture = pyshark.FileCapture(sample10, debug=True)
sample_dos = 'sample-pcap/tls/actorsaccess.com_2019-02-26_00-09-45_0.pcap'
sample_dos_filecapture = pyshark.FileCapture(sample_dos, debug=True)
sample11 = 'sample-pcap/sslv3/www.vermonttimberworks.com_2019-01-31_21-09-06_0.pcap'
sample11_filecapture = pyshark.FileCapture(sample11, debug=True)
sample12 = 'sample-pcap/sslv3/www.anc1912.org.za_2019-01-31_21-25-40_0.pcap'
sample12_filecapture = pyshark.FileCapture(sample12, debug=True)

sample1_packets = [packet for packet in sample1_filecapture]
sample2_packets = [packet for packet in sample2_filecapture]
sample3_packets = [packet for packet in sample3_filecapture]
sample4_packets = [packet for packet in sample4_filecapture]
sample5_packets = [packet for packet in sample5_filecapture]
sample6_packets = [packet for packet in sample6_filecapture]
sample7_packets = [packet for packet in sample7_filecapture]
sample8_packets = [packet for packet in sample8_filecapture]
sample9_packets = [packet for packet in sample9_filecapture]
sample10_packets = [packet for packet in sample10_filecapture]
sampledos_packets = [packet for packet in sample_dos_filecapture]
sample11_packet = [packet for packet in sample11_filecapture]
sample12_packet = [packet for packet in sample12_filecapture]

sample1_clienthello = sample1_packets[3]
sample1_serverhello_cert_serverhellodone = sample1_packets[7]
sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec = sample1_packets[8]
sample1_changecipherspec_encryptedhandshakemsg = sample1_packets[9]
sample1_appdata_pure = sample1_packets[10]
sample1_appdata_segment = sample1_packets[24]
sample1_normal = sample1_packets[15]

sample2_clienthello = sample2_packets[3]
sample2_serverhello = sample2_packets[5]
sample2_cert_serverhellodone = sample2_packets[8]
sample2_clientkeyexchange_changecipherspec_encryptedhandshakemsg = sample2_packets[10]
sample2_appdata_pure = sample2_packets[12]
sample2_appdata_segment = sample2_packets[16]

sample3_clienthello = sample3_packets[2]
sample3_serverhello_cert_serverhellodone = sample3_packets[5]
sample3_clientkeyexchange_changecipherspec_encryptedhandshakemsg = sample3_packets[7]
sample3_changecipherspec_encryptedhandshakemsg = sample3_packets[8]
sample3_appdata_pure = sample3_packets[9]
sample3_appdata_segment = sample3_packets[26]

sample4_clienthello = sample4_packets[3]
sample4_serverhello = sample4_packets[5]
sample4_cert = sample4_packets[8]
sample4_serverhellodone = sample4_packets[9]
sample4_clientkeyexchange_changecipherspec_encryptedhandshakemsg = sample4_packets[11]
sample4_changecipherspec_encryptedhandshakemsg = sample4_packets[12]
sample4_appdata_pure = sample4_packets[13]
sample4_appdata_segment = sample4_packets[27]
sample4_appdata_double = sample4_packets[15]

sample11_encryptedhandshakemsg_duplicate = sample11_filecapture[13]

sample12_appdata_triple = sample12_filecapture[531]

# sample5_cert = sample5_packets[16]  # double ssl layer
# sample6_cert = sample6_packets[8]  # double ssl layer
# sample7_cert = sample7_packets[8]  # double ssl layer
# sample10_cert = sample10_packets[10]
#
# sampledos_clienthello = sampledos_packets[3]

# Test function extractClienthelloLength()
output = extractClienthelloLength(sample1_clienthello)
expected = [227]
assert output == expected
output = extractClienthelloLength(sample2_clienthello)
expected = [235]
assert output == expected
output = extractClienthelloLength(sample3_clienthello)
expected = [226]
assert output == expected
output = extractClienthelloLength(sample4_clienthello)
expected = [241]
assert output == expected

expected = [0]
output = extractClienthelloLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClienthelloLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClienthelloLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractClienthelloLength(sample1_normal)
assert output == expected
print('Done testing function extractClienthelloLength()')

# Test function extractClienthelloCiphersuiteAndEncode()
output = extractClienthelloCiphersuite(sample1_clienthello)
# Check KEA only. Assume other components of cipheruites are extracted identically
expected_ECDHE = 18/45
expected_DHE = 17/45
expected_RSA = 10/45
assert math.isclose(output[7], expected_ECDHE)
assert math.isclose(output[3], expected_DHE)
assert math.isclose(output[1], expected_RSA)

expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
output = extractClienthelloCiphersuite(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClienthelloCiphersuite(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClienthelloCiphersuite(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractClienthelloCiphersuite(sample1_normal)
assert output == expected
print('Done testing function extractClienthelloCiphersuiteAndEncode()')

# Test function extractClienthelloCiphersuiteLength
output = extractClienthelloCiphersuiteLength(sample1_clienthello)
expected = [92]
assert output == expected
output = extractClienthelloCiphersuiteLength(sample2_clienthello)
expected = [92]
assert output == expected
output = extractClienthelloCiphersuiteLength(sample3_clienthello)
expected = [92]
assert output == expected
output = extractClienthelloCiphersuiteLength(sample4_clienthello)
expected = [92]
assert output == expected

expected = [0]
output = extractClienthelloCiphersuiteLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClienthelloCiphersuiteLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClienthelloCiphersuiteLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractClienthelloCiphersuiteLength(sample1_normal)
assert output == expected
print('Done testing function extractClienthelloCiphersuiteLength()')

# Test function extractClienthelloCompressionmethodAndEncode
enums = [0]
output = extractClienthelloCompressionmethodAndEncode(sample1_clienthello, enums)
expected = [1, 0]
assert output == expected
output = extractClienthelloCompressionmethodAndEncode(sample2_clienthello, enums)
expected = [1, 0]
assert output == expected
output = extractClienthelloCompressionmethodAndEncode(sample3_clienthello, enums)
expected = [1, 0]
assert output == expected
output = extractClienthelloCompressionmethodAndEncode(sample4_clienthello, enums)
expected = [1, 0]
assert output == expected

expected = [0, 0]
output = extractClienthelloCompressionmethodAndEncode(sample1_serverhello_cert_serverhellodone, enums)
assert output == expected
output = extractClienthelloCompressionmethodAndEncode(sample1_changecipherspec_encryptedhandshakemsg, enums)
assert output == expected
output = extractClienthelloCompressionmethodAndEncode(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec, enums)
assert output == expected
output = extractClienthelloCompressionmethodAndEncode(sample1_normal, enums)
assert output == expected
print('Done testing function extractClienthelloCompressionmethodAndEncode()')

# Test function extractClienthelloSupportedgroupLength
output = extractClienthelloSupportedgroupLength(sample1_clienthello)
expected = [8]
assert output == expected
output = extractClienthelloSupportedgroupLength(sample2_clienthello)
expected = [8]
assert output == expected
output = extractClienthelloSupportedgroupLength(sample3_clienthello)
expected = [8]
assert output == expected
output = extractClienthelloSupportedgroupLength(sample4_clienthello)
expected = [8]
assert output == expected

expected = [0]
output = extractClienthelloSupportedgroupLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClienthelloSupportedgroupLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClienthelloSupportedgroupLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractClienthelloSupportedgroupLength(sample1_normal)
assert output == expected
print('Done testing function extractClienthelloSupportedgroupLength()')

# Test function extractClienthelloSupportedgroupAndEncode
enums = [29, 23]
output = extractClienthelloSupportedgroupAndEncode(sample1_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSupportedgroupAndEncode(sample2_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSupportedgroupAndEncode(sample3_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSupportedgroupAndEncode(sample4_clienthello, enums)
expected = [1, 1, 1]
assert output == expected

expected = [0, 0, 0]
output = extractClienthelloSupportedgroupAndEncode(sample1_serverhello_cert_serverhellodone, enums)
assert output == expected
output = extractClienthelloSupportedgroupAndEncode(sample1_changecipherspec_encryptedhandshakemsg, enums)
assert output == expected
output = extractClienthelloSupportedgroupAndEncode(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec, enums)
assert output == expected
output = extractClienthelloSupportedgroupAndEncode(sample1_normal, enums)
assert output == expected
print('Done testing function extractClienthelloSupportedgroupAndEncode()')

# Test function extractClienthelloEncryptthenmacLength
output = extractClienthelloEncryptthenmacLength(sample1_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloEncryptthenmacLength(sample2_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloEncryptthenmacLength(sample3_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloEncryptthenmacLength(sample4_clienthello)
expected = [0]
assert output == expected

expected = [0]
output = extractClienthelloEncryptthenmacLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClienthelloEncryptthenmacLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClienthelloEncryptthenmacLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractClienthelloEncryptthenmacLength(sample1_normal)
assert output == expected
print('Done testing function extractClienthelloEncryptthemacLength()')

# Test function extractClienthelloExtendedmastersecretLength
output = extractClienthelloExtendedmastersecretLength(sample1_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloExtendedmastersecretLength(sample2_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloExtendedmastersecretLength(sample3_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloExtendedmastersecretLength(sample4_clienthello)
expected = [0]
assert output == expected

expected = [0]
output = extractClienthelloExtendedmastersecretLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClienthelloExtendedmastersecretLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClienthelloExtendedmastersecretLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractClienthelloExtendedmastersecretLength(sample1_normal)
assert output == expected
print('Done testing function extractClienthelloExtendedmastersecretLength()')

# Test function extractClienthelloSignaturehashAndEncode
enums = [1537, 769]
output = extractClienthelloSignaturehashAndEncode(sample1_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSignaturehashAndEncode(sample2_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSignaturehashAndEncode(sample3_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSignaturehashAndEncode(sample4_clienthello, enums)
expected = [1, 1, 1]
assert output == expected

expected = [0, 0, 0]
output = extractClienthelloSignaturehashAndEncode(sample1_serverhello_cert_serverhellodone, enums)
assert output == expected
output = extractClienthelloSignaturehashAndEncode(sample1_changecipherspec_encryptedhandshakemsg, enums)
assert output == expected
output = extractClienthelloSignaturehashAndEncode(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec, enums)
assert output == expected
output = extractClienthelloSignaturehashAndEncode(sample1_normal, enums)
assert output == expected
print('Done testing function extractClienthelloSignaturehashAndEncode()')

# Test function extractServerhelloLength
output = extractServerhelloLength(sample1_serverhello_cert_serverhellodone)
expected = [81]
assert output == expected
output = extractServerhelloLength(sample2_serverhello)
expected = [57]
assert output == expected
output = extractServerhelloLength(sample3_serverhello_cert_serverhellodone)
expected = [81]
assert output == expected
output = extractServerhelloLength(sample4_serverhello)
expected = [61]
assert output == expected

expected = [0]
output = extractServerhelloLength(sample1_clienthello)
assert output == expected
output = extractServerhelloLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractServerhelloLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractServerhelloLength(sample1_normal)
assert output == expected
print('Done testing function extractServerhelloLength()')

# Test function extractServerhelloRenegoLength
output = extractServerhelloRenegoLength(sample1_serverhello_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhelloRenegoLength(sample2_serverhello)
expected = [0]
assert output == expected
output = extractServerhelloRenegoLength(sample3_serverhello_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhelloRenegoLength(sample4_serverhello)
expected = [0]
assert output == expected

expected = [0]
output = extractServerhelloRenegoLength(sample1_clienthello)
assert output == expected
output = extractServerhelloRenegoLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractServerhelloRenegoLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractServerhelloRenegoLength(sample1_normal)
assert output == expected
print('Done testing function extractServerhelloRenegoLength()')

# Test function extractCertificateInfo
output = extractCertificateLengthInfo(sample1_serverhello_cert_serverhellodone)
expected = [2, 1275.0, 1374, 1176]
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
output = extractCertificateLengthInfo(sample2_cert_serverhellodone)
expected = [4, 1242.0, 1548, 1101]
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
output = extractCertificateLengthInfo(sample3_serverhello_cert_serverhellodone)
expected = [2, 1508.0, 1840, 1176]
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
output = extractCertificateLengthInfo(sample4_cert)
expected = [4, 1356.25, 1548, 1082]
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])

expected = [0, 0, 0, 0]
output = extractCertificateLengthInfo(sample1_clienthello)
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
output = extractCertificateLengthInfo(sample1_changecipherspec_encryptedhandshakemsg)
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
output = extractCertificateLengthInfo(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
output = extractCertificateLengthInfo(sample1_normal)
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
print('Done testing function extractCertificateInfo()')

# Test function extractCertificateAndEncode
enums = ['1.2.840.113549.1.1.11', '1.2.840.113549.1.1.13', '1.2.840.113549.1.1.5']
output = extractCertificateAndEncode(sample1_serverhello_cert_serverhellodone, enums)
expected = [1, 0, 0, 1]
assert output == expected
output = extractCertificateAndEncode(sample2_cert_serverhellodone, enums)
expected = [1, 0, 0, 1]
assert output == expected
output = extractCertificateAndEncode(sample3_serverhello_cert_serverhellodone, enums)
expected = [1, 0, 0, 1]
assert output == expected
output = extractCertificateAndEncode(sample4_cert, enums)
expected = [1, 0, 1, 1]
assert output == expected

expected = [0, 0, 0, 0]
output = extractCertificateAndEncode(sample1_clienthello, enums)
assert output == expected
output = extractCertificateAndEncode(sample1_changecipherspec_encryptedhandshakemsg, enums)
assert output == expected
output = extractCertificateAndEncode(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec, enums)
assert output == expected
output = extractCertificateAndEncode(sample1_normal, enums)
assert output == expected
print('Done testing function extractCertificateAndEncode()')

# Test function extractServerhellodoneLength
output = extractServerhellodoneLength(sample1_serverhello_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhellodoneLength(sample2_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhellodoneLength(sample3_serverhello_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhellodoneLength(sample4_serverhellodone)
expected = [0]
assert output == expected

expected = [0]
output = extractServerhellodoneLength(sample1_clienthello)
assert output == expected
output = extractServerhellodoneLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractServerhellodoneLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractServerhellodoneLength(sample1_normal)
assert output == expected
print('Done testing function extractServerhellodoneLength()')

# Test function extractClientkeyexchangeLength
output = extractClientkeyexchangeLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
expected = [66]
assert output == expected
output = extractClientkeyexchangeLength(sample2_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [66]
assert output == expected
output = extractClientkeyexchangeLength(sample3_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [66]
assert output == expected
output = extractClientkeyexchangeLength(sample4_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [66]
assert output == expected

expected = [0]
output = extractClientkeyexchangeLength(sample1_clienthello)
assert output == expected
output = extractClientkeyexchangeLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClientkeyexchangeLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClientkeyexchangeLength(sample1_normal)
assert output == expected
print('Done testing function extractClientketexchangeLength()')

# Test function extractClientkeyexchangePubkeyLength
output = extractClientkeyexchangePubkeyLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
expected = [65]
assert output == expected
output = extractClientkeyexchangePubkeyLength(sample2_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [65]
assert output == expected
output = extractClientkeyexchangePubkeyLength(sample3_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [65]
assert output == expected
output = extractClientkeyexchangePubkeyLength(sample4_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [65]
assert output == expected

expected = [0]
output = extractClientkeyexchangePubkeyLength(sample1_clienthello)
assert output == expected
output = extractClientkeyexchangePubkeyLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractClientkeyexchangePubkeyLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractClientkeyexchangePubkeyLength(sample1_normal)
assert output == expected
print('Done testing function extractClientkeyechangePubkeyLength()')

# Test function extractEncryptedhandshakemsgLength
output = extractEncryptedhandshakemsgLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
expected = [96]
assert output == expected
output = extractEncryptedhandshakemsgLength(sample2_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [40]
assert output == expected
output = extractEncryptedhandshakemsgLength(sample3_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [96]
assert output == expected
output = extractEncryptedhandshakemsgLength(sample4_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [40]
assert output == expected
output =  extractEncryptedhandshakemsgLength(sample11_encryptedhandshakemsg_duplicate)
expected = [1296]
assert output == expected

expected = [0]
output = extractEncryptedhandshakemsgLength(sample1_clienthello)
assert output == expected
output = extractEncryptedhandshakemsgLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractEncryptedhandshakemsgLength(sample1_normal)
assert output == expected
print('Done testing function extractEncryptedhandshakemsgLength()')

# Test function extractChangeCipherSpecLength
output = extractChangeCipherSpecLength(sample1_changecipherspec_encryptedhandshakemsg)
expected = [1]
assert output == expected
output = extractChangeCipherSpecLength(sample2_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [1]
assert output == expected
output = extractChangeCipherSpecLength(sample3_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [1]
assert output == expected
output = extractChangeCipherSpecLength(sample4_clientkeyexchange_changecipherspec_encryptedhandshakemsg)
expected = [1]
assert output == expected

expected = [0]
output = extractChangeCipherSpecLength(sample1_clienthello)
assert output == expected
output = extractChangeCipherSpecLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractChangeCipherSpecLength(sample1_normal)
assert output == expected
print('Done testing function extractChangeCipherSpecLength()')

# Test function extractAppDataLength
output = extractAppDataLength(sample1_appdata_pure)
expected = [277]
assert output == expected
output = extractAppDataLength(sample1_appdata_segment)
expected = [1460]
assert output == expected
output = extractAppDataLength(sample2_appdata_pure)
expected = [233]
assert output == expected
output = extractAppDataLength(sample2_appdata_segment)
expected = [1460]
assert output == expected
output = extractAppDataLength(sample3_appdata_pure)
expected = [309]
assert output == expected
output = extractAppDataLength(sample3_appdata_segment)
expected = [1380]
assert output == expected
output = extractAppDataLength(sample4_appdata_pure)
expected = [270]
assert output == expected
output = extractAppDataLength(sample4_appdata_segment)
expected = [1460]
assert output == expected
output = extractAppDataLength(sample4_appdata_double)
expected = [1460]
assert output == expected
output = extractAppDataLength(sample12_appdata_triple)
expected = [1460]
assert output == expected

expected = [0]
output = extractAppDataLength(sample1_clienthello)
assert output == expected
output = extractAppDataLength(sample1_serverhello_cert_serverhellodone)
assert output == expected
output = extractAppDataLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
assert output == expected
output = extractAppDataLength(sample1_changecipherspec_encryptedhandshakemsg)
assert output == expected
output = extractAppDataLength(sample1_normal)
assert output == expected
print('Done testing function extractAppDataLength()')

# Test function findIdxOfAppDataSegments
output = findIdxOfAppDataSegments(sample12_appdata_triple)
expected = [525, 526, 527, 528, 529, 530, 531]
assert output == expected
print('Done testing function findIdxOfAppDataSegments')

# Test encoding of app data length
enums = {'ciphersuites': [], 'compressionmethods': [], 'supportedgroups': [], 'sighashalgorithms_client': [],
         'sighashalgorithms_cert': []}
limit = 100
sample1_tls_features = extract_tslssl_features(sample1, enums, limit)
assert sample1_tls_features[10][-1] == 277.0
assert sample1_tls_features[24][-1] == 1460.0
assert sample1_tls_features[15][-1] == 1460.0
sample2_tls_features = extract_tslssl_features(sample2, enums, limit)
assert sample2_tls_features[12][-1] == 233.0
assert sample2_tls_features[16][-1] == 1460.0
sample3_tls_features = extract_tslssl_features(sample3, enums, limit)
assert sample3_tls_features[9][-1] == 309.0
assert sample3_tls_features[26][-1] == 1380.0
sample4_tls_features = extract_tslssl_features(sample4, enums, limit)
assert sample4_tls_features[13][-1] == 270.0
assert sample4_tls_features[27][-1] == 1460.0
assert sample4_tls_features[15][-1] == 1460.0
print('Done testing encoding of app data length for TCP segments of a reassembed PDU')

# pkt = sample1_serverhello_cert_serverhellodone
# print(pkt)
# pkt = sample2_cert_serverhellodone
# print(pkt)
# pkt = sample3_serverhello_cert_serverhellodone
# print(pkt)
# pkt = sample4_cert
# print(pkt)
# pkt = sample5_cert
# print(pkt)
# pkt = sample6_cert
# print(pkt)
# pkt = sample7_cert
# print(pkt)
# pkt = sample10_cert
# print(pkt)

print('TEST PASSED!')

sample1_filecapture.close()
sample2_filecapture.close()
sample3_filecapture.close()
sample4_filecapture.close()
sample5_filecapture.close()
sample6_filecapture.close()
sample7_filecapture.close()
sample8_filecapture.close()
sample9_filecapture.close()
sample10_filecapture.close()
sample_dos_filecapture.close()
sample11_filecapture.close()
sample12_filecapture.close()