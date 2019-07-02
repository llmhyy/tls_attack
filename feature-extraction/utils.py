import os
import math
import time
import pyshark
import traceback
from pyshark.packet.layer import JsonLayer
import logging
import numpy as np
import ipaddress

class ZeroPacketError(Exception):
    def __init__(self, message):
        super().__init__(message)

def extract_tcp_features(pcapfile, limit):
    traffic_features = []
    packets = pyshark.FileCapture(pcapfile)
    for i, packet in enumerate(packets):
        if i >= limit:
            break

        packet_features = []

        comeLeaveFeature = extractComeLeaveFromPacket(packet)
        protocolFeature = extractProtocolFromPacket(packet)
        lengthFeature = extractLengthFromPacket(packet)
        intervalFeature = extractIntervalFromPacket(packet)
        flagFeature = extractFlagFromPacket(packet)
        windowSizeFeature = extractWindowSizeFromPacket(packet)

        packet_features.extend(comeLeaveFeature)
        packet_features.extend(protocolFeature)
        packet_features.extend(lengthFeature)
        packet_features.extend(intervalFeature)
        packet_features.extend(flagFeature)
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

def searchEnums(rootdir, limit):
    """
    Given a root directory containing all the pcap files, it will search for all possible enums
    and return a list of all enums

    Set a hard limit on the number of files iterated through to save time
    """
    ciphersuites = []
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

                    starttime = time.time()
                    totaltime = 0.0
                    found_clienthello = False # Variable for ending the packet loop if ClientHello is found
                    found_certificate = False # Variable for ending the packet loop if Certificate is found

                    for packet_json in packets_json:
                        starttime3 = time.time()

                        ########## For finding ClientHello ##########
                        try:
                            handshake = find_handshake(packet_json.ssl, target_type=1)
                            if handshake:
                                # Cipher Suites
                                traffic_ciphersuites = [int(j) for j in handshake.ciphersuites.ciphersuite]
                                ciphersuites.extend(traffic_ciphersuites)

                                # Compression Methods
                                traffic_compressionmethods = handshake._all_fields['ssl.handshake.comp_methods']['ssl.handshake.comp_method']
                                if type(traffic_compressionmethods)==list:
                                    traffic_compressionmethods = [int(j) for j in traffic_compressionmethods]
                                else:
                                    traffic_compressionmethods = [int(traffic_compressionmethods)]
                                compressionmethods.extend(traffic_compressionmethods)

                                # Supported Groups
                                for k,v in handshake._all_fields.items():
                                    if 'supported_groups' in k:
                                        traffic_supportedgroups = v['ssl.handshake.extensions_supported_groups']['ssl.handshake.extensions_supported_group']
                                        traffic_supportedgroups = [int(j,16) for j in traffic_supportedgroups]
                                        supportedgroups.extend(traffic_supportedgroups)

                                # Signature Hash Algorithm
                                for k,v in handshake._all_fields.items():
                                    if 'signature_algorithms' in k:
                                        traffic_sighashalgorithms_client = v['ssl.handshake.sig_hash_algs']['ssl.handshake.sig_hash_alg']
                                        traffic_sighashalgorithms_client = [int(j,16) for j in traffic_sighashalgorithms_client]
                                        sighashalgorithms_client.extend(traffic_sighashalgorithms_client)

                                found_clienthello = True

                        except AttributeError:
                            pass

                        ########## For finding Certificate ##########
                        try:
                            handshake = find_handshake(packet_json.ssl, target_type = 11)
                        except:
                            handshake = None
                        try:
                            handshake2 = find_handshake2(packet_json.ssl.value, target_type = 11)
                        except:
                            handshake2 = None

                        traffic_sighashalgorithms_cert = []
                        if handshake:
                            certificates = handshake.certificates.certificate_tree
                            traffic_sighashalgorithms_cert = [str(certificate.algorithmIdentifier_element.id) for certificate in certificates]
                            found_certificate = True

                        elif handshake2:
                            certificates = handshake2['ssl.handshake.certificates']['ssl.handshake.certificate_tree']
                            for certificate in certificates:
                                for k,v in certificate.items():
                                    if 'algorithmIdentifier_element' in k:
                                        for kk,vv in v.items():
                                            if 'algorithm.id' in kk:
                                                traffic_sighashalgorithms_cert.append(str(vv))
                            found_certificate = True

                        sighashalgorithms_cert.extend(traffic_sighashalgorithms_cert)


                        logging.debug("Time spent on packet: {}s".format(time.time()-starttime3))
                        totaltime = totaltime + (time.time()-starttime3)
                        # Break the loop once both ClientHello and Certificate are found
                        if found_clienthello and found_certificate:
                            break

                    logging.debug("Time spent on traffic: {}s".format(time.time()-starttime))
                    logging.debug("Total time accumulated on traffic: {}s".format(totaltime))

                    # If ClientHello cannot be found in the traffic
                    if not found_clienthello:
                        logging.warning("No ClientHello found for file {}".format(os.path.join(root,f)))
                    if not found_certificate:
                        logging.warning("No Certificate found for file {}".format(os.path.join(root,f)))

                    ciphersuites = list(set(ciphersuites))
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
    print("Processing enums: {} success, {} failure".format(success, failed))

    enum = {}
    enum['ciphersuites'] = ciphersuites
    enum['compressionmethods'] = compressionmethods
    enum['supportedgroups'] = supportedgroups
    enum['sighashalgorithms_client'] = sighashalgorithms_client
    enum['sighashalgorithms_cert'] = sighashalgorithms_cert
    # return (ciphersuites, compressionmethods, supportedgroups, sighashalgorithms_client, sighashalgorithms_cert)
    return enum

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

# For identifying pure Application Data
def find_appdata(obj):
    if type(obj) == list:
        final = None
        for a_obj in obj:
            temp = find_appdata(a_obj)
            if temp:
                final = temp
        return final
    elif type(obj)==JsonLayer:
        if obj.layer_name=='ssl' and hasattr(obj, 'record'):
            return find_appdata(obj.record)
        elif obj.layer_name=='record' and hasattr(obj, 'app_data'):
            return obj

# For identifying Application Data [TCP segment of a reassembled PDU]
def find_appdata2(obj):
    if type(obj) == list:
        final = None
        for a_obj in obj:
            temp = find_appdata2(a_obj)
            if temp:
                final = temp
        return final
    elif type(obj) == dict:
        if 'ssl.record' in obj:
            return find_appdata2(obj['ssl.record'])
        elif 'ssl.app_data' in obj:
            return obj

def extract_tslssl_features(pcapfile, enums, limit):

    # TODO: implement dynamic features
    # Each packet will have its own record layer. If the layer does not exist, the features in that layer
    # will be zero-ed. Hence, we still assume one packet/Eth frame as the most basic unit of traffic

    enumCipherSuites = enums['ciphersuites']
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
        clienthelloCiphersuiteFeature = extractClienthelloCiphersuiteAndEncode(packet_json, enumCipherSuites)
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
        # ServerHello Extended Master Secret cannot be found in the packet
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
        try:
            handshake = find_handshake(packet_json.ssl, target_type=14)
            if handshake:
                packet_features.append(int(handshake.length))
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 19: ClientKeyExchange - LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=16)
            if handshake:
                packet_features.append(int(handshake.length))
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 20: ClientKeyExchange - PUBKEY LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=16)
            if handshake:
                try:
                    if 'EC Diffie-Hellman Client Params' in handshake._all_fields:
                        pub_key_dict = handshake._all_fields['EC Diffie-Hellman Client Params']
                        packet_features.append(int(pub_key_dict['ssl.handshake.client_point_len']))
                    elif 'RSA Encrypted PreMaster Secret' in handshake._all_fields:
                        pub_key_dict = handshake._all_fields['RSA Encrypted PreMaster Secret']
                        packet_features.append(int(pub_key_dict['ssl.handshake.epms_len']))
                    elif 'Diffie-Hellman Client Params' in handshake._all_fields:
                        pub_key_dict = handshake._all_fields['Diffie-Hellman Client Params']
                        packet_features.append(int(pub_key_dict['ssl.handshake.yc_len']))
                    # Unseen Client Key Exchange algorithm                
                    else:
                        # Last resort: use the length of handshake as substitute
                        packet_features.append(int(handshake._all_fields['ssl.handshake.length']))
                        logging.warning('Unknown client key exchange algo in ClientKeyExchange for file {}'.format(pcapfile))
                # RSA in SSLv3 does not seem to publish the len, resulting in KeyError
                except KeyError:
                    packet_features.append(int(handshake._all_fields['ssl.handshake.length']))
                
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 21: EncryptedHandshakeMessage - LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=99)
            if handshake:
                packet_features.append(int(handshake.length))
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)


        #  CHANGE CIPHER PROTOCOL
        ##################################################################
        #  22: ChangeCipherSpec - LENGTH
        try:
            changecipher = find_changecipher(packet_json.ssl)
            if changecipher:
                packet_features.append(int(changecipher.length))
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)


        #  APPLICATION DATA PROTOCOL
        ##################################################################
        #  23: ApplicationDataProtocol - LENGTH
        
        # Attempt 1: use find_appdata to identify pure Application DAta
        try:
            appdata = find_appdata(packet_json.ssl)
        except AttributeError:
            appdata = None
        # Attempt 2: use find_appdata2 to identify Application Data[TCP segment of a reassembled PDU]
        try: 
            appdata2 = find_appdata2(packet_json.ssl.value)
        except AttributeError:
            appdata2 = None
        
        if appdata:
            packet_features.append(int(appdata.length))
        elif appdata2:
            packet_features.append(int(appdata2['ssl.record.length']))
        else:
            packet_features.append(0)
        
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

def extractClienthelloCiphersuiteAndEncode(packet, enum):
    ciphersuites = extractClienthelloCiphersuite(packet)
    encoded_ciphersuites = encodeEnumIntoManyHotVec(ciphersuites, enum)
    if encoded_ciphersuites[-1] == 1:
        logging.warning('Cipher suites contain unseen enums. Refer to above')
    return encoded_ciphersuites

def extractClienthelloCiphersuite(packet):
    feature = []
    try:
        handshake = find_handshake(packet.ssl, target_type=1)
        if handshake:
            feature = [int(ciphersuite) for ciphersuite in handshake.ciphersuites.ciphersuite]
    except AttributeError:
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
                contains_algo_id = [v for k,v in contains_algoidentifier_element[0] if 'algorithm.id' in k]
                feature = [str(cert) for cert in contains_algo_id[0]]

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
    sample = 'sample-pcap/www.stripes.com_2018-12-21_16-20-12.pcap'

    # TEST CASES
    # packets = [packet for packet in pyshark.FileCapture(sample)]
    # packet1 = packets[0]
    # packet4 = packets[3]
    # packet5 = packets[4]
    # packet8 = packets[7]
    # packet11 = packets[10]
    # packet25 = packets[24]
    #
    # # Test function extractComeLeaveFromPacket()
    # output = extractComeLeaveFromPacket(packet1)
    # expected = [0]
    # assert output == expected
    # output = extractComeLeaveFromPacket(packet25)
    # expected = [1]
    # assert output == expected
    #
    # # Test function extractProtocolFromPacket()
    # output = extractProtocolFromPacket(packet1)
    # expected = [1,0,0,0,0,0]
    # assert output == expected
    # output = extractProtocolFromPacket(packet4)
    # expected = [0,0,0,1,0,0]
    # assert output == expected
    # output = extractProtocolFromPacket(packet8)
    # expected = [0,0,0,0,0,1]
    # assert output == expected
    #
    # # Test function extractLengthFromPacket()
    # output = extractLengthFromPacket(packet1)
    # expected = [66]
    # assert output == expected
    # output = extractLengthFromPacket(packet5)
    # expected = [1514]
    # assert output == expected
    #
    # # Test function extractIntervalFromPacket()
    # output = extractIntervalFromPacket(packet1)
    # expected = [0.0]
    # assert math.isclose(output[0], expected[0])
    # output = extractIntervalFromPacket(packet4)
    # expected = [20.716]
    # assert math.isclose(output[0], expected[0])
    #
    # # Test function extractFlagFromPacket()
    # output = extractFlagFromPacket(packet1)
    # expected = [0,0,0,0,0,0,0,1,0]
    # assert output == expected
    # output = extractFlagFromPacket(packet11)
    # expected = [0,0,0,0,1,1,0,0,0]
    # assert output == expected
    #
    # # Test function extractWindowSizeFromPacket(packet1)
    # output = extractWindowSizeFromPacket(packet1)
    # expected = [64240]
    # assert output == expected
    # output = extractWindowSizeFromPacket(packet4)
    # expected = [66048]
    # assert output == expected
    #
    # # Test function extract_tcp_features()
    # output = extract_tcp_features(sample, limit=100)
    # expected_len = 100
    # assert len(output) == expected_len
    # expected_dim = 19
    # assert len(output[0]) == expected_dim

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
    sample2_changecipherspec_encryptedhandshakemsg = sample2_packets[11]
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

    sample5_cert = sample5_packets[16] # double ssl layer
    sample6_cert = sample6_packets[8] # double ssl layer
    sample7_cert = sample7_packets[8] # double ssl layer
    sample10_cert = sample10_packets[10]

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
    enums = [49196, 49200, 49195, 10000]
    output = extractClienthelloCiphersuiteAndEncode(sample1_clienthello, enums)
    expected = [1,1,1,0,1]
    assert output == expected
    output = extractClienthelloCiphersuiteAndEncode(sample1_normal, enums)
    expected = [0,0,0,0,0]
    assert output == expected
    output = extractClienthelloCiphersuiteAndEncode(sample2_clienthello, enums)
    expected = [1,1,1,0,1]
    assert output == expected
    output = extractClienthelloCiphersuiteAndEncode(sample3_clienthello, enums)
    expected = [1,1,1,0,1]
    assert output == expected
    output = extractClienthelloCiphersuiteAndEncode(sample4_clienthello, enums)
    expected = [1,1,1,0,1]
    assert output == expected

    # Test function extractClienthelloCiphersuiteLength
    output = extractClienthelloCiphersuiteLength(sample1_clienthello)
    expected = [92]
    assert output == expected
    output = extractClienthelloCiphersuiteLength(sample1_normal)
    expected = [0]
    assert output == expected
    # output = extractClienthelloCiphersuiteLength(sample2_clienthello)
    # expected = []
    # assert output == expected
    # output = extractClienthelloCiphersuiteLength(sample3_clienthello)
    # expected = []
    # assert output == expected
    # output = extractClienthelloCiphersuiteLength(sample4_clienthello)
    # expected = []
    # assert output == expected

    # Test function extractClienthelloCompressionmethodAndEncode
    enums = [0]
    output = extractClienthelloCompressionmethodAndEncode(sample1_clienthello, enums)
    expected = [1,0]
    assert output == expected
    output = extractClienthelloCompressionmethodAndEncode(sample1_normal, enums)
    expected = [0,0]
    assert output == expected
    # Test function extractClienthelloSupportedgroupLength
    output = extractClienthelloSupportedgroupLength(sample1_clienthello)
    expected = [10]
    assert output == expected
    output = extractClienthelloSupportedgroupLength(sample1_normal)
    expected = [0]
    assert output == expected
    # Test function extractClienthelloSupportedgroupAndEncode
    enums = [29, 23]
    output = extractClienthelloSupportedgroupAndEncode(sample1_clienthello, enums)
    expected = [1,1,1]
    assert output == expected
    output = extractClienthelloSupportedgroupAndEncode(sample1_normal, enums)
    expected = [0,0,0]
    assert output == expected
    # Test function extractClienthelloEncryptthenmacLength
    output = extractClienthelloEncryptthenmacLength(sample1_clienthello)
    expected = [0]
    assert output == expected
    output = extractClienthelloEncryptthenmacLength(sample1_normal)
    expected = [0]
    assert output == expected
    # Test function extractClienthelloExtendedmastersecretLength
    output = extractClienthelloExtendedmastersecretLength(sample1_clienthello)
    expected = [0]
    assert output == expected
    output = extractClienthelloExtendedmastersecretLength(sample1_normal)
    expected = [0]
    assert output == expected
    # Test function extractClienthelloSignaturehashAndEncode
    enums = [1537, 769]
    output = extractClienthelloSignaturehashAndEncode(sample1_clienthello, enums)
    expected = [1,1,1]
    assert output == expected
    output = extractClienthelloSignaturehashAndEncode(sample1_normal, enums)
    expected = [0,0,0]
    assert output == expected
    # Test function extractServerhelloLength
    output = extractServerhelloLength(sample1_serverhello_cert_serverhellodone)
    expected = [81]
    assert output == expected
    output = extractServerhelloLength(sample1_normal)
    expected = [0]
    assert output == expected
    # Test function extractServerhelloRenegoLength
    output = extractServerhelloRenegoLength(sample1_serverhello_cert_serverhellodone)
    expected = [1]
    assert output == expected
    output = extractServerhelloRenegoLength(sample1_normal)
    expected = [0]
    assert output == expected
    # Test function extractCertificateInfo
    output = extractCertificateLengthInfo(sample1_serverhello_cert_serverhellodone)
    expected = [2, 1275.0, 1374, 1176]
    assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
    output = extractCertificateLengthInfo(sample1_normal)
    expected = [0,0,0,0]
    assert all([math.isclose(output[i], expected[i]) for i in range(len(expected))])
    # Test function extractCertificateAndEncode
    enums = ['1.2.840.113549.1.1.11', '1.2.840.113549.1.1.13', '1.2.840.113549.1.1.5']
    output = extractCertificateAndEncode(sample1_serverhello_cert_serverhellodone, enums)
    expected = [1,0,0,0]
    assert output == expected
    output = extractCertificateAndEncode(sample1_normal, enums)
    expected = [0,0,0,0]
    assert output == expected
    # Test function extractServerhellodoneLength
    output = extractServerhellodoneLength(sample1_serverhello_cert_serverhellodone)
    expected = [0]
    assert output == expected
    output = extractServerhellodoneLength(sample1_normal)
    expected = [0]

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
    # Test whether all enums are generated

    # Test whether all features are extracted

    # Test whether directory is searched correctly with features extracted 
