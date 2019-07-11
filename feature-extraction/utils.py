import os
import time
import pyshark
from pyshark.packet.layer import JsonLayer
import logging
import ipaddress

import ciphersuite_parser

class ZeroPacketError(Exception):
    def __init__(self, message):
        super().__init__(message)

def searchEnums(rootdir, limit):
    """
    Given a root directory containing all the pcap files, it will search for all possible enums
    and return a list of all enums

    Set a hard limit on the number of files iterated through to save time
    """
    compressionmethods = []
    supportedgroups = []
    sighashalgorithms_client = []
    sighashalgorithms_cert = []

    success = 0
    failed = 0
    logging.info("Traversing through directory to find all enums...")
    for root, dirs, files in os.walk(rootdir):
        for f in files:
            if f.endswith(".pcap"):
                try:
                    logging.info("Processing {}".format(f))
                    # Might need to close FileCapture somehow to prevent the another loop running
                    packets_json = pyshark.FileCapture(os.path.join(root, f), use_json=True)

                    starttime_traffic = time.time()
                    found_clienthello = False # Variable for ending the packet loop if ClientHello is found
                    found_certificate = False # Variable for ending the packet loop if Certificate is found

                    for packet_json in packets_json:
                        starttime_packet = time.time()
                        # Compression Methods
                        traffic_compressionmethods = extractClienthelloCompressionmethod(packet_json)
                        compressionmethods.extend(traffic_compressionmethods)
                        # Supported Groups
                        traffic_supportedgroups = extractClienthelloSupportedgroup(packet_json)
                        supportedgroups.extend(traffic_supportedgroups)
                        # Clienthello - Signature Hash Algorithm
                        traffic_sighashalgorithms_client = extractClienthelloSignaturehash(packet_json)
                        sighashalgorithms_client.extend(traffic_sighashalgorithms_client)

                        if traffic_compressionmethods or traffic_supportedgroups or traffic_sighashalgorithms_client:
                            found_clienthello = True

                        # Certificate - Signature Hash Algorithm
                        traffic_sighashalgorithms_cert = extractCertificate(packet_json)
                        sighashalgorithms_cert.extend(traffic_sighashalgorithms_cert)

                        if traffic_sighashalgorithms_cert:
                            found_certificate = True

                        logging.debug("Time spent on packet: {}s".format(time.time()-starttime_packet))

                        # Break the loop once both ClientHello and Certificate are found
                        if found_clienthello and found_certificate:
                            break

                    logging.debug("Time spent on traffic: {}s".format(time.time()-starttime_traffic))

                    # If ClientHello cannot be found in the traffic
                    if not found_clienthello:
                        logging.warning("No ClientHello found for file {}".format(os.path.join(root,f)))
                    if not found_certificate:
                        logging.warning("No Certificate found for file {}".format(os.path.join(root,f)))

                    compressionmethods = list(set(compressionmethods))
                    supportedgroups = list(set(supportedgroups))
                    sighashalgorithms_client = list(set(sighashalgorithms_client))
                    sighashalgorithms_cert = list(set(sighashalgorithms_cert))

                    success += 1

                    if success>=limit:
                        break

                # Skip this pcap file
                except (KeyError, AttributeError, TypeError):
                    logging.exception('Serious error in file {}. Traffic is skipped'.format(f))
                    failed+=1
                    continue

        if success>=limit:
            break

    logging.info("Done processing enum")
    print("Processed enums in directory {}: {} success, {} failure".format(rootdir,success, failed))

    enum = {}
    enum['compressionmethods'] = compressionmethods
    enum['supportedgroups'] = supportedgroups
    enum['sighashalgorithms_client'] = sighashalgorithms_client
    enum['sighashalgorithms_cert'] = sighashalgorithms_cert
    # return (ciphersuites, compressionmethods, supportedgroups, sighashalgorithms_client, sighashalgorithms_cert)
    return enum

def extract_tcp_features(pcapfile, limit):
    traffic_features = []
    packets = pyshark.FileCapture(pcapfile)
    for i, packet in enumerate(packets):
        if i >= limit:
            break

        packet_features = []

        # 1: COME/LEAVE
        comeLeaveFeature = extractComeLeaveFromPacket(packet)
        packet_features.extend(comeLeaveFeature)

        # 2: PROTOCOL
        protocolFeature = extractProtocolFromPacket(packet)
        packet_features.extend(protocolFeature)

        # 3: PACKET LENGTH
        lengthFeature = extractLengthFromPacket(packet)
        packet_features.extend(lengthFeature)

        # 4: INTERVAL
        intervalFeature = extractIntervalFromPacket(packet)
        packet_features.extend(intervalFeature)

        # 5: FLAG
        flagFeature = extractFlagFromPacket(packet)
        packet_features.extend(flagFeature)

        # 6: WINDOW SIZE
        windowSizeFeature = extractWindowSizeFromPacket(packet)
        packet_features.extend(windowSizeFeature)

        traffic_features.append(packet_features)

    if len(traffic_features) == 0:
        raise ZeroPacketError('Pcap file contains no packet')

    return traffic_features

def extractComeLeaveFromPacket(packet):
    feature = []
    if ipaddress.ip_address(str(packet.ip.dst)).is_private:
        feature.append(1)
    else:
        feature.append(0)
    return feature

def extractProtocolFromPacket(packet):
    # Protocol version value to encode into one-hot vector
    # prot: ['TCP' (-), 'SSL2.0' (0x0200), 'SSL3.0' (0x0300), 'TLS1.0' (0x0301), 'TLS1.1' (0x0302), 'TLS1.2' (0x0303)]
    protcol_ver = [0, 512, 768, 769, 770, 771]
    feature = [0] * len(protcol_ver)
    # Bug in detecting SSL layer despite plain TCP packet
    if ('ssl' in packet) and (packet.ssl.get('record_version') != None):
        # Convert hex into integer and return the index in the ref list
        prot = int(packet.ssl.record_version, 16)
        try:
            protocol_id = protcol_ver.index(prot)
            feature[protocol_id] = 1
        except ValueError:
            logging.warning('Found SSL packet with unknown SSL type {}'.format(prot))
    else:
        feature[0] = 1

    return feature

def extractLengthFromPacket(packet):
    return [int(packet.length)]

def extractIntervalFromPacket(packet):
    return [float(packet.frame_info.time_delta) * 1000]

def extractFlagFromPacket(packet):
    num_of_flags = 9
    try:
        # Convert hex into binary and pad left with 0 to fill 9 flags
        feature = list(bin(int(packet.tcp.flags, 16))[2:].zfill(num_of_flags))
        feature = list(map(int, feature))
    except AttributeError:
        feature = [0] * num_of_flags
    return feature

def extractWindowSizeFromPacket(packet):
    try:
        # Window size = window size value * scaling factor
        feature = [int(packet.tcp.window_size)]
    except AttributeError:
        feature = [0]
    return feature

def extract_tslssl_features(pcapfile, enums, limit):
    enumCompressionMethods = enums['compressionmethods']
    enumSupportedGroups = enums['supportedgroups']
    enumSignatureHashClient = enums['sighashalgorithms_client']
    enumSignatureHashCert = enums['sighashalgorithms_cert']

    # Traffic features for storing features of packets
    traffic_features = []
    packets_json = pyshark.FileCapture(pcapfile, use_json=True)

    for i, packet_json in enumerate(packets_json):
        # Break the loop when limit is reached
        if i>=limit:
            break
        
        packet_features = []

        # HANDSHAKE PROTOCOL
        ##################################################################
        # 1: ClientHello - LENGTH
        clienthelloLengthFeature = extractClienthelloLength(packet_json)
        packet_features.extend(clienthelloLengthFeature)

        # 2: ClientHello - CIPHER SUITE
        clienthelloCiphersuiteFeature = extractClienthelloCiphersuite(packet_json)
        packet_features.extend(clienthelloCiphersuiteFeature)

        # 3: ClientHello - CIPHER SUITE LENGTH
        clienthelloCiphersuiteLengthFeature = extractClienthelloCiphersuiteLength(packet_json)
        packet_features.extend(clienthelloCiphersuiteLengthFeature)

        # 4: ClientHello - COMPRESSION METHOD
        clienthelloCompressionMethodFeature = extractClienthelloCompressionmethodAndEncode(packet_json,
                                                                                           enumCompressionMethods)
        packet_features.extend(clienthelloCompressionMethodFeature)

        # 5: ClientHello - SUPPORTED GROUP LENGTH
        clienthelloSupportedgroupLengthFeature = extractClienthelloSupportedgroupLength(packet_json)
        packet_features.extend(clienthelloSupportedgroupLengthFeature)

        # 6: ClientHello - SUPPORTED GROUPS
        clienthelloSupportedgroupFeature = extractClienthelloSupportedgroupAndEncode(packet_json, enumSupportedGroups)
        packet_features.extend(clienthelloSupportedgroupFeature)

        # 7: ClientHello - ENCRYPT THEN MAC LENGTH
        clienthelloEncryptthenmacLengthFeature = extractClienthelloEncryptthenmacLength(packet_json)
        packet_features.extend(clienthelloEncryptthenmacLengthFeature)

        # 8: ClientHello - EXTENDED MASTER SECRET
        clienthelloExtendedmastersecretLengthFeature = extractClienthelloExtendedmastersecretLength(packet_json)
        packet_features.extend(clienthelloExtendedmastersecretLengthFeature)

        # 9: ClientHello - SIGNATURE HASH ALGORITHM
        clienthelloSignaturehashFeature = extractClienthelloSignaturehashAndEncode(packet_json, enumSignatureHashClient)
        packet_features.extend(clienthelloSignaturehashFeature)

        # 10: ServerHello - LENGTH
        serverhelloLengthFeature = extractServerhelloLength(packet_json)
        packet_features.extend(serverhelloLengthFeature)

        # 11: ServerHello - EXTENDED MASTER SECRET
        # Feature cannot be found in the packet

        # 12: ServerHello - RENEGOTIATION INFO LENGTH
        serverhelloRenegoLengthFeature = extractServerhelloRenegoLength(packet_json)
        packet_features.extend(serverhelloRenegoLengthFeature)

        # 13,14,15,16: Certificate - NUM_CERT, AVERAGE, MIN, MAX CERTIFICATE LENGTH
        certificateLengthInfoFeature = extractCertificateLengthInfo(packet_json)
        packet_features.extend(certificateLengthInfoFeature)

        # 17: Certificate - SIGNATURE ALGORITHM
        certificateFeature = extractCertificateAndEncode(packet_json, enumSignatureHashCert)
        packet_features.extend(certificateFeature)

        # 18: ServerHelloDone - LENGTH
        serverhellodoneLengthFeature = extractServerhellodoneLength(packet_json)
        packet_features.extend(serverhellodoneLengthFeature)

        # 19: ClientKeyExchange - LENGTH
        clientkeyexchangeLengthFeature = extractClientkeyexchangeLength(packet_json)
        packet_features.extend(clientkeyexchangeLengthFeature)

        # 20: ClientKeyExchange - PUBKEY LENGTH
        clientkeyexchangePubkeyLengthFeature = extractClientkeyexchangePubkeyLength(packet_json)
        packet_features.extend(clientkeyexchangePubkeyLengthFeature)

        # 21: EncryptedHandshakeMessage - LENGTH
        encryptedhandshakemsgLengthFeature = extractEncryptedhandshakemsgLength(packet_json)
        packet_features.extend(encryptedhandshakemsgLengthFeature)

        #  CHANGE CIPHER PROTOCOL
        ##################################################################
        # 22: ChangeCipherSpec - LENGTH
        changecipherspecLengthFeature = extractChangeCipherSpecLength(packet_json)
        packet_features.extend(changecipherspecLengthFeature)

        #  APPLICATION DATA PROTOCOL
        ##################################################################
        # 23: ApplicationDataProtocol - LENGTH
        appdataLengthFeature = extractAppDataLength(packet_json)
        packet_features.extend(appdataLengthFeature)
        
        # Convert to float for standardization
        packet_features = [float(i) for i in packet_features]
        traffic_features.append(packet_features)

    if len(traffic_features) == 0:
        raise ZeroPacketError('Pcap file contains no packet')

    return traffic_features

def extractClienthelloLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            feature = [int(handshake.length)]
    except AttributeError:
        pass
    return feature

def extractClienthelloCiphersuite(packet):
    feature_len = sum(map(len, [getattr(ciphersuite_parser, component) for component in ciphersuite_parser.components]))
    feature = [0] * feature_len
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            dec_ciphersuites = [int(ciphersuite) for ciphersuite in handshake.ciphersuites.ciphersuite]
            feature = ciphersuite_parser.getVecAndAggregateAndNormalize(dec_ciphersuites)
    except (AttributeError,ZeroDivisionError):
        pass
    return feature

def extractClienthelloCiphersuiteLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            feature = [int(handshake.cipher_suites_length)]
    except AttributeError:
        pass
    return feature

def extractClienthelloCompressionmethodAndEncode(packet, enum):
    compressionmethods = extractClienthelloCompressionmethod(packet)
    encoded_compressionmethods = encodeEnumIntoManyHotVec(compressionmethods, enum)
    if encoded_compressionmethods[-1] == 1:
        logging.warning('Compression methods contain unseen enums. Refer to above')
    return encoded_compressionmethods

def extractClienthelloCompressionmethod(packet):
    feature = []
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            feature = [int(compressionmethod, 16) for compressionmethod in
                       handshake._all_fields['ssl.handshake.comp_methods']['ssl.handshake.comp_method']]
    except (AttributeError, KeyError):
        pass
    return feature

def extractClienthelloSupportedgroupLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            contains_supported_groups = [v for k,v in handshake._all_fields.items() if 'supported_groups' in k]
            feature = [int(contains_supported_groups[0]['ssl.handshake.extension.len'])] # Choose the first object
    except (AttributeError, KeyError, IndexError):
        pass
    return feature

def extractClienthelloSupportedgroupAndEncode(packet, enum):
    supportedgroups = extractClienthelloSupportedgroup(packet)
    encoded_supportedgroups = encodeEnumIntoManyHotVec(supportedgroups, enum)
    if encoded_supportedgroups[-1] == 1:
        logging.warning('Supported groups contain unseen enums. Refer to above')
    return encoded_supportedgroups

def extractClienthelloSupportedgroup(packet):
    feature = []
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            contains_supported_groups = [v for k, v in handshake._all_fields.items() if 'supported_groups' in k]
            feature = [int(supported_group, 16) for supported_group in contains_supported_groups[0]  # Choose the first object
                                                                        ['ssl.handshake.extensions_supported_groups']
                                                                        ['ssl.handshake.extensions_supported_group']]
    except (AttributeError, KeyError, IndexError):
        pass
    return feature

def extractClienthelloEncryptthenmacLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            contains_encrypt_then_mac = [v for k, v in handshake._all_fields.items() if 'encrypt_then_mac' in k]
            feature = [int(contains_encrypt_then_mac[0]['ssl.handshake.extension.len'])] # Choose the first object
    except (AttributeError, KeyError, IndexError):
        pass
    return feature

def extractClienthelloExtendedmastersecretLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            contains_extended_master_secret = [v for k, v in handshake._all_fields.items() if 'extended_master_secret' in k]
            feature = [int(contains_extended_master_secret[0]['ssl.handshake.extension.len'])] # Choose the first object
    except (AttributeError, KeyError, IndexError):
        pass
    return feature

def extractClienthelloSignaturehashAndEncode(packet, enum):
    signaturehashes = extractClienthelloSignaturehash(packet)
    encoded_signaturehashes = encodeEnumIntoManyHotVec(signaturehashes, enum)
    if encoded_signaturehashes[-1] == 1:
        logging.warning('Signature hash contains unseen enums. Refer to above')
    return encoded_signaturehashes

def extractClienthelloSignaturehash(packet):
    feature = []
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            contains_signature_algorithms = [v for k, v in handshake._all_fields.items() if 'signature_algorithms' in k]
            feature = [int(signature_hash, 16) for signature_hash in contains_signature_algorithms[0]
                                                                                ['ssl.handshake.sig_hash_algs']
                                                                                ['ssl.handshake.sig_hash_alg']]
    except (AttributeError, KeyError, IndexError):
        pass
    return feature

def extractServerhelloLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=2)
        if handshake:
            feature = [int(handshake.length)]
    except (AttributeError):
        pass
    return feature

def extractServerhelloRenegoLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=2)
        contains_renego_info = [v for k,v in handshake._all_fields.items() if 'renegotiation_info' in k]
        feature = [int(contains_renego_info[0]['ssl.handshake.extension.len'])]
    except (AttributeError, KeyError, IndexError):
        pass
    return feature

def extractCertificateLengthInfo(packet):
    feature = [0,0,0,0]
    try:
        if hasattr(packet.ssl, 'value'):
            handshake = find_handshake(packet.ssl.value, target_type=11)
        else:
            handshake = find_handshake(packet.ssl, target_type=11)

        if handshake:
            cert_len = None
            if type(handshake) == JsonLayer:
                cert_len = [int(i) for i in handshake.certificates.certificate_length]
            elif type(handshake) == dict:
                cert_len = [int(i) for i in handshake['ssl.handshake.certificates']['ssl.handshake.certificate_length']]

            if cert_len:
                num_cert = len(cert_len)
                mean_cert_len = sum(cert_len)/float(num_cert)
                max_cert_len = max(cert_len)
                min_cert_len = min(cert_len)
                feature = [num_cert, mean_cert_len, max_cert_len, min_cert_len]
    except (AttributeError, KeyError):
        pass
    return feature

def extractCertificateAndEncode(packet, enum):
    certs = extractCertificate(packet)
    encoded_certs = encodeEnumIntoManyHotVec(certs, enum)
    if encoded_certs[-1] == 1:
        logging.warning('Certificates contains unseen enums. Refer to above')
    return encoded_certs

def extractCertificate(packet):
    feature = []
    try:
        if hasattr(packet.ssl, 'value'):
            handshake = find_handshake(packet.ssl.value, target_type=11)
        else:
            handshake = find_handshake(packet.ssl, target_type=11)
        if handshake:
            if type(handshake) == JsonLayer:
                temp = handshake.certificates.certificate_tree
                if type(temp) != list:
                    temp = [temp]
                feature = [str(i_temp.algorithmIdentifier_element.id) for i_temp in temp]
            elif type(handshake) == dict:
                temp = handshake['ssl.handshake.certificates']['ssl.handshake.certificate_tree']
                if type(temp) != list:
                    temp = [temp]
                contains_algoidentifier_element = [v for i_temp in temp for k,v in i_temp.items() if 'algorithmIdentifier_element' in k]
                contains_algo_id = [v for i in contains_algoidentifier_element for k,v in i.items() if 'algorithm.id' in k]
                feature = [str(cert) for cert in contains_algo_id]

    except (AttributeError, KeyError, IndexError):
        pass
    return feature

def extractServerhellodoneLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=14)
        if handshake:
            feature = [int(handshake.length)]
    except AttributeError:
        pass
    return feature

def extractClientkeyexchangeLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=16)
        if handshake:
            feature = [int(handshake.length)]
    except AttributeError:
        pass
    return feature

def extractClientkeyexchangePubkeyLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=16)
        if handshake:
            if 'EC Diffie-Hellman Client Params' in handshake._all_fields:
                feature = handshake._all_fields['EC Diffie-Hellman Client Params']['ssl.handshake.client_point_len']
            elif 'RSA Encrypted PreMaster Secret' in handshake._all_fields:
                feature = handshake._all_fields['RSA Encrypted PreMaster Secret']['ssl.handshake.epms_len']
            elif 'Diffie-Hellman Client Params' in handshake._all_fields:
                feature = handshake._all_fields['Diffie-Hellman Client Params']['ssl.handshake.yc_len']
            elif 'ssl.handshake.length' in handshake._all_fields:
                feature = handshake._all_fields['ssl.handshake.length']

            if feature != [0]: # check if feature was modified
                feature = [int(feature)]
    except (AttributeError, KeyError):
        pass
    return feature

def extractEncryptedhandshakemsgLength(packet):
    feature = [0]
    try:
        handshake = find_handshake(packet.ssl, target_type=99)
        if handshake:
            feature = [int(handshake.length)]
    except AttributeError:
        pass
    return feature

def extractChangeCipherSpecLength(packet):
    feature = [0]
    try:
        changecipher = find_changecipher(packet.ssl)
        if changecipher:
            feature = [int(changecipher.length)]
    except AttributeError:
        pass
    return feature

# If there are more than 1 app data record layer in the same packet, it will extract the latest app data record layer
def extractAppDataLength(packet):
    feature = [0]
    try:
        appdata = []
        if hasattr(packet.ssl, 'value'):
            find_appdata(packet.ssl.value, appdata)
        else:
            find_appdata(packet.ssl, appdata)

        if appdata:
            sum_len = 0
            for a_appdata in appdata:
                if type(a_appdata) == JsonLayer:
                    sum_len += int(a_appdata.length)
                elif type(a_appdata) == dict:
                    sum_len += int(a_appdata['ssl.record.length'])
            feature = [sum_len]
    except (AttributeError, KeyError):
        pass
    return feature

def find_handshake(obj, target_type):
    if type(obj) == list:
        final = None
        for a_obj in obj:
            temp = find_handshake(a_obj, target_type)
            if temp:
                final = temp
        return final

    elif type(obj) == JsonLayer:
        if obj.layer_name=='ssl' and hasattr(obj, 'record'):
            return find_handshake(obj.record, target_type)
        # elif obj.layer_name=='ssl' and hasattr(obj, 'handshake'):
        #     return find_handshake(obj.handshake, target_type)
        elif obj.layer_name=='record' and hasattr(obj, 'handshake') and target_type!=99:
            return find_handshake(obj.handshake, target_type)
        # If correct handshake is identified
        elif obj.layer_name=='handshake' and int(obj.type)==target_type:
            return obj
        # Return record containing Encrypted Handshake Message (only handshake msg without a type)
        elif obj.layer_name=='record' and hasattr(obj, 'handshake') and not(type(obj.handshake)==JsonLayer) and target_type==99:
            return obj

    elif type(obj) == dict:
        if 'ssl.record' in obj:
            return find_handshake(obj['ssl.record'], target_type)
        elif 'ssl.handshake' in obj:
            return find_handshake(obj['ssl.handshake'], target_type)
        elif 'ssl.handshake.type' in obj and int(obj['ssl.handshake.type'])==target_type:
            return obj

def find_changecipher(obj):
    if type(obj) == list:
        final = None
        for a_obj in obj:
            temp = find_changecipher(a_obj)
            if temp:
                final = temp
        return final

    elif type(obj)==JsonLayer:
        if obj.layer_name=='ssl' and hasattr(obj, 'record'):
            return find_changecipher(obj.record)
        elif obj.layer_name=='record' and hasattr(obj, 'change_cipher_spec'):
            return obj

# For identifying pure Application Data and Application Data [TCP segment of a reassembled PDU]
def find_appdata(obj, appdata):
    if type(obj) == list:
        for a_obj in obj:
            find_appdata(a_obj, appdata)

    elif type(obj)==JsonLayer:
        if obj.layer_name=='ssl' and hasattr(obj, 'record'):
            find_appdata(obj.record, appdata)
        elif obj.layer_name=='record' and hasattr(obj, 'app_data'):
            appdata.append(obj)

    elif type(obj) == dict:
        if 'ssl.record' in obj:
            find_appdata(obj['ssl.record'], appdata)
        elif 'ssl.app_data' in obj:
            appdata.append(obj)

def encodeEnumIntoManyHotVec(listOfEnum, refEnum):
    unknown_dim = [0]
    # The unknown dim occupies the last position
    encoded_enums = [0] * len(refEnum) + unknown_dim
    if listOfEnum:
        for enum in listOfEnum:
            if enum in refEnum:
                encoded_enums[refEnum.index(enum)] = 1
            else:
                encoded_enums[-1] = 1
                logging.warning('Unseen enum {}'.format(enum))
    return encoded_enums

if __name__ == '__main__':
    enums = {'ciphersuites': [], 'compressionmethods': [], 'supportedgroups': [], 'sighashalgorithms_client': [],
             'sighashalgorithms_cert': []}

    rootdir = 'sample-pcap/tls'
    # enums = searchEnums(rootdir, limit=100)
    # for k,v in enums.items():
    #     print(k, v)

    filename = 'www.stripes.com_2018-12-21_16-20-12.pcap'
    dirpath = os.path.join(rootdir, filename)

    # Traffic features for storing features of packets
    packets_json = pyshark.FileCapture(dirpath, use_json=True)

    for i, packet_json in enumerate(packets_json):
        # packet 26: normal tcp packet with ack
        # packet 27: tcp segment of a reassembled pdu
        if i == 25 or i == 26:
            x = packet_json
            print(x)
        # packet 37: application data
        if i == 36:
            x = packet_json
            print(x)