# TEST CASES for functions in utils.py

import math
from utils import *

sample = 'sample-pcap/www.stripes.com_2018-12-21_16-20-12.pcap'
packets = [packet for packet in pyshark.FileCapture(sample)]
packet1 = packets[0]
packet4 = packets[3]
packet5 = packets[4]
packet8 = packets[7]
packet11 = packets[10]
packet25 = packets[24]

# Test function extractComeLeaveFromPacket()
output = extractComeLeaveFromPacket(packet1)
expected = [0]
assert output == expected
output = extractComeLeaveFromPacket(packet25)
expected = [1]
assert output == expected

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

# Test function extractLengthFromPacket()
output = extractLengthFromPacket(packet1)
expected = [66]
assert output == expected
output = extractLengthFromPacket(packet5)
expected = [1514]
assert output == expected

# Test function extractIntervalFromPacket()
output = extractIntervalFromPacket(packet1)
expected = [0.0]
assert math.isclose(output[0], expected[0])
output = extractIntervalFromPacket(packet4)
expected = [20.716]
assert math.isclose(output[0], expected[0])

# Test function extractFlagFromPacket()
output = extractFlagFromPacket(packet1)
expected = [0, 0, 0, 0, 0, 0, 0, 1, 0]
assert output == expected
output = extractFlagFromPacket(packet11)
expected = [0, 0, 0, 0, 1, 1, 0, 0, 0]
assert output == expected

# Test function extractWindowSizeFromPacket(packet1)
output = extractWindowSizeFromPacket(packet1)
expected = [64240]
assert output == expected
output = extractWindowSizeFromPacket(packet4)
expected = [66048]
assert output == expected

# Test function extract_tcp_features()
output = extract_tcp_features(sample, limit=100)
expected_len = 100
assert len(output) == expected_len
expected_dim = 19
assert len(output[0]) == expected_dim

sample1 = 'sample-pcap/www.stripes.com_2018-12-21_16-20-12.pcap'
sample2 = 'sample-pcap/australianmuseum.net.au_2018-12-21_16-15-59.pcap'
sample3 = 'sample-pcap/ari.nus.edu.sg_2018-12-24_14-30-02.pcap'
sample4 = 'sample-pcap/www.zeroaggressionproject.org_2018-12-21_16-19-03.pcap'
sample5 = 'sample-pcap/alis.alberta.ca_2019-01-22_19-26-05.pcap'
sample6 = 'sample-pcap/dataverse.harvard.edu_2018-12-24_17-16-00.pcap'
sample7 = 'sample-pcap/whc.unesco.org_2018-12-24_17-09-08.pcap'
sample8 = 'sample-pcap/www.cancerresearchuk.org_2018-12-24_17-15-46.pcap'
sample9 = 'sample-pcap/www.orkin.com_2018-12-24_17-10-27.pcap'
sample10 = 'sample-pcap/www.tmr.qld.gov.au_2018-12-24_17-20-56.pcap'
sample_dos = 'sample-pcap/actorsaccess.com_2019-02-26_00-09-45_0.pcap'

sample1_packets = [packet for packet in pyshark.FileCapture(sample1, use_json=True)]
sample2_packets = [packet for packet in pyshark.FileCapture(sample2, use_json=True)]
sample3_packets = [packet for packet in pyshark.FileCapture(sample3, use_json=True)]
sample4_packets = [packet for packet in pyshark.FileCapture(sample4, use_json=True)]
sample5_packets = [packet for packet in pyshark.FileCapture(sample5, use_json=True)]
sample6_packets = [packet for packet in pyshark.FileCapture(sample6, use_json=True)]
sample7_packets = [packet for packet in pyshark.FileCapture(sample7, use_json=True)]
sample8_packets = [packet for packet in pyshark.FileCapture(sample8, use_json=True)]
sample9_packets = [packet for packet in pyshark.FileCapture(sample9, use_json=True)]
sample10_packets = [packet for packet in pyshark.FileCapture(sample10, use_json=True)]
sampledos_packets = [packet for packet in pyshark.FileCapture(sample_dos, use_json=True)]

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

sample5_cert = sample5_packets[16]  # double ssl layer
sample6_cert = sample6_packets[8]  # double ssl layer
sample7_cert = sample7_packets[8]  # double ssl layer
sample10_cert = sample10_packets[10]

sampledos_clienthello = sampledos_packets[3]

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

# Test function extractClienthelloCiphersuiteAndEncode()
# output = extractClienthelloCiphersuite(sample1_clienthello)
# expected = [1, 1, 1, 0, 1]
# assert output == expected_dim
output = extractClienthelloCiphersuite(sample1_normal)
expected = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
assert output == expected
# output = extractClienthelloCiphersuite(sample2_clienthello)
# expected = [1, 1, 1, 0, 1]
# assert output == expected
# output = extractClienthelloCiphersuite(sample3_clienthello)
# expected = [1, 1, 1, 0, 1]
# assert output == expected
# output = extractClienthelloCiphersuite(sample4_clienthello)
# expected = [1, 1, 1, 0, 1]
# assert output == expected
output = extractClienthelloCiphersuite(sampledos_clienthello)
expected = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0]
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])

# Test function extractClienthelloCiphersuiteLength
output = extractClienthelloCiphersuiteLength(sample1_clienthello)
expected = [92]
assert output == expected
output = extractClienthelloCiphersuiteLength(sample1_normal)
expected = [0]
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

# Test function extractClienthelloCompressionmethodAndEncode
enums = [0]
output = extractClienthelloCompressionmethodAndEncode(sample1_clienthello, enums)
expected = [1, 0]
assert output == expected
output = extractClienthelloCompressionmethodAndEncode(sample1_normal, enums)
expected = [0, 0]
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

# Test function extractClienthelloSupportedgroupLength
output = extractClienthelloSupportedgroupLength(sample1_clienthello)
expected = [10]
assert output == expected
output = extractClienthelloSupportedgroupLength(sample1_normal)
expected = [0]
assert output == expected
output = extractClienthelloSupportedgroupLength(sample2_clienthello)
expected = [10]
assert output == expected
output = extractClienthelloSupportedgroupLength(sample3_clienthello)
expected = [10]
assert output == expected
output = extractClienthelloSupportedgroupLength(sample4_clienthello)
expected = [10]
assert output == expected

# Test function extractClienthelloSupportedgroupAndEncode
enums = [29, 23]
output = extractClienthelloSupportedgroupAndEncode(sample1_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSupportedgroupAndEncode(sample1_normal, enums)
expected = [0, 0, 0]
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

# Test function extractClienthelloEncryptthenmacLength
output = extractClienthelloEncryptthenmacLength(sample1_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloEncryptthenmacLength(sample1_normal)
expected = [0]
assert output == expected
output = extractEncryptedhandshakemsgLength(sample2_clienthello)
expected = [0]
assert output == expected
output = extractEncryptedhandshakemsgLength(sample3_clienthello)
expected = [0]
assert output == expected
output = extractEncryptedhandshakemsgLength(sample4_clienthello)
expected = [0]
assert output == expected

# Test function extractClienthelloExtendedmastersecretLength
output = extractClienthelloExtendedmastersecretLength(sample1_clienthello)
expected = [0]
assert output == expected
output = extractClienthelloExtendedmastersecretLength(sample1_normal)
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

# Test function extractClienthelloSignaturehashAndEncode
enums = [1537, 769]
output = extractClienthelloSignaturehashAndEncode(sample1_clienthello, enums)
expected = [1, 1, 1]
assert output == expected
output = extractClienthelloSignaturehashAndEncode(sample1_normal, enums)
expected = [0, 0, 0]
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

# Test function extractServerhelloLength
output = extractServerhelloLength(sample1_serverhello_cert_serverhellodone)
expected = [81]
assert output == expected
output = extractServerhelloLength(sample1_normal)
expected = [0]
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

# Test function extractServerhelloRenegoLength
output = extractServerhelloRenegoLength(sample1_serverhello_cert_serverhellodone)
expected = [1]
assert output == expected
output = extractServerhelloRenegoLength(sample1_normal)
expected = [0]
assert output == expected
output = extractServerhelloRenegoLength(sample2_serverhello)
expected = [1]
assert output == expected
output = extractServerhelloRenegoLength(sample3_serverhello_cert_serverhellodone)
expected = [1]
assert output == expected
output = extractServerhelloRenegoLength(sample4_serverhello)
expected = [1]
assert output == expected

# Test function extractCertificateInfo
output = extractCertificateLengthInfo(sample1_serverhello_cert_serverhellodone)
expected = [2, 1275.0, 1374, 1176]
assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
output = extractCertificateLengthInfo(sample1_normal)
expected = [0, 0, 0, 0]
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

# Test function extractCertificateAndEncode
enums = ['1.2.840.113549.1.1.11', '1.2.840.113549.1.1.13', '1.2.840.113549.1.1.5']
output = extractCertificateAndEncode(sample1_serverhello_cert_serverhellodone, enums)
expected = [1, 0, 0, 0]
assert output == expected
output = extractCertificateAndEncode(sample1_normal, enums)
expected = [0, 0, 0, 0]
assert output == expected
output = extractCertificateAndEncode(sample2_cert_serverhellodone, enums)
expected = [1, 0, 0, 0]
assert output == expected
output = extractCertificateAndEncode(sample3_serverhello_cert_serverhellodone, enums)
expected = [1, 0, 0, 0]
assert output == expected
output = extractCertificateAndEncode(sample4_cert, enums)
expected = [1, 0, 1, 1]
assert output == expected

# Test function extractServerhellodoneLength
output = extractServerhellodoneLength(sample1_serverhello_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhellodoneLength(sample1_normal)
expected = [0]
output = extractServerhellodoneLength(sample2_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhellodoneLength(sample3_serverhello_cert_serverhellodone)
expected = [0]
assert output == expected
output = extractServerhellodoneLength(sample4_serverhellodone)
expected = [0]
assert output == expected

# Test function extractClientkeyexchangePubkeyLength
output = extractClientkeyexchangePubkeyLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
expected = [65]
assert output == expected
output = extractClientkeyexchangePubkeyLength(sample1_normal)
expected = [0]
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

# Test function extractEncryptedhandshakemsgLength
output = extractEncryptedhandshakemsgLength(sample1_clientkeyexchange_encryptedhandshakemsg_changecipherspec)
expected = [96]
assert output == expected
output = extractEncryptedhandshakemsgLength(sample1_normal)
expected = [0]
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

# Test function extractChangeCipherSpecLength
output = extractChangeCipherSpecLength(sample1_changecipherspec_encryptedhandshakemsg)
expected = [1]
assert output == expected
output = extractChangeCipherSpecLength(sample1_normal)
expected = [0]
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

# Test function extractAppDataLength
output = extractAppDataLength(sample1_appdata_pure)
expected = [272]
assert output == expected
output = extractAppDataLength(sample1_appdata_segment)
expected = [16464]
assert output == expected
output = extractAppDataLength(sample1_normal)
expected = [0]
assert output == expected
output = extractAppDataLength(sample2_appdata_pure)
expected = [228]
assert output == expected
output = extractAppDataLength(sample2_appdata_segment)
expected = [2921]
assert output == expected
output = extractAppDataLength(sample3_appdata_pure)
expected = [304]
assert output == expected
output = extractAppDataLength(sample3_appdata_segment)
expected = [16464]
assert output == expected
output = extractAppDataLength(sample4_appdata_pure)
expected = [265]
assert output == expected
output = extractAppDataLength(sample4_appdata_segment)
expected = [16408]
assert output == expected
output = extractAppDataLength(sample4_appdata_double)
expected = [31]
assert output == expected

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
