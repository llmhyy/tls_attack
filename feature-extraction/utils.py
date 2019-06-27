import os
import math
import time
import pyshark
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

# For handling data structure of jsonlayer type
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

# For handling data structure of dict type
def find_handshake2(obj, target_type):
    if type(obj) == list:
        final = None
        for a_obj in obj:
            temp = find_handshake2(a_obj, target_type)
            if temp:
                final = temp
        return final
    elif type(obj) == dict:
        if 'ssl.record' in obj:
            return find_handshake2(obj['ssl.record'], target_type)
        elif 'ssl.handshake' in obj:
            return find_handshake2(obj['ssl.handshake'], target_type)
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
        clienthelloLengthFeature = extractClienthelloLength(packet_json)
        packet_features.extend(clienthelloLengthFeature)

        clienthelloCiphersuiteFeature = extractClienthelloCiphersuiteAndEncode(packet_json, enumCipherSuites)
        packet_features.extend(clienthelloCiphersuiteFeature)


        # 3: ClientHello - CIPHER SUITE LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=1)
            if handshake:
                packet_features.append(int(handshake.cipher_suites_length))
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 4: ClientHello - COMPRESSION METHOD
        compressionmethod_feature = np.zeros_like(enumCompressionMethods)
        compressionmethod_feature = np.concatenate((compressionmethod_feature, np.array([0]))) # For unknown dim
        try:
            handshake = find_handshake(packet_json.ssl, target_type=1)
            if handshake:
                compression_methods = handshake._all_fields['ssl.handshake.comp_methods']['ssl.handshake.comp_method']
                for compression_method in compression_methods:
                    compression_method_int = int(compression_method, 16) # in hdexdecimal
                    if compression_method_int in enumCompressionMethods:
                        compressionmethod_feature[enumCompressionMethods.index(compression_method_int)] = 1
                    else:
                        logging.warning('Unseen compression method ({}) in file {}'.format(compression_method,pcapfile))
                        compressionmethod_feature[-1] = 1
                packet_features.extend(compressionmethod_feature)
            else:
                packet_features.extend(compressionmethod_feature)
        except AttributeError:
            packet_features.extend(compressionmethod_feature)

        # 5: ClientHello - SUPPORTED GROUP LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=1)
            if handshake:
                supported_group_len = 0
                for k,v in handshake._all_fields.items():
                    if 'supported_groups' in k:
                        supported_group_len = int(v['ssl.handshake.extension.len'])
                packet_features.append(supported_group_len)
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 6: ClientHello - SUPPORTED GROUPS
        supportedgroup_feature = np.zeros_like(enumSupportedGroups)
        supportedgroup_feature = np.concatenate((supportedgroup_feature, np.array([0]))) # For unknown dim
        try:
            handshake = find_handshake(packet_json.ssl, target_type=1)
            if handshake:
                for k,v in handshake._all_fields.items():
                    if 'supported_groups' in k:
                        supported_groups = v['ssl.handshake.extensions_supported_groups']['ssl.handshake.extensions_supported_group']
                        for supported_group in supported_groups:
                            supported_group_int = int(supported_group,16) # in hexadecimal
                            if supported_group_int in enumSupportedGroups:
                                supportedgroup_feature[enumSupportedGroups.index(supported_group_int)] = 1
                            else:
                                logging.warning('Unseen supported group ({}) in file {}'.format(supported_group,pcapfile))
                                supportedgroup_feature[-1] = 1
                packet_features.extend(supportedgroup_feature)
            else:
                packet_features.extend(supportedgroup_feature)
        except AttributeError:
            packet_features.extend(supportedgroup_feature)

        # 7: ClientHello - ENCRYPT THEN MAC LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=1)
            if handshake:
                encrypt_then_mac_len = 0
                for k,v in handshake._all_fields.items():
                    if 'encrypt_then_mac' in k:
                        encrypt_then_mac_len = int(v['ssl.handshake.extension.len'])
                packet_features.append(encrypt_then_mac_len)
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 8: ClientHello - EXTENDED MASTER SECRET
        try:
            handshake = find_handshake(packet_json.ssl, target_type=1)
            if handshake:
                extended_master_secret_len = 0
                for k,v in handshake._all_fields.items():
                    if 'extended_master_secret' in k:
                        extended_master_secret_len = int(v['ssl.handshake.extension.len'])
                packet_features.append(extended_master_secret_len)
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 9: ClientHello - SIGNATURE HASH ALGORITHM
        sighash_features_client = np.zeros_like(enumSignatureHashClient)
        sighash_features_client = np.concatenate((sighash_features_client, np.array([0]))) # For unknown dim
        try:
            handshake = find_handshake(packet_json.ssl, target_type=1)
            if handshake:
                for k,v in handshake._all_fields.item():
                    if 'signature_algorithms' in k:
                        signature_algorithms = v['ssl.handshake.sig_hash_algs']['ssl.handshake.sig_hash_alg']
                        for signature_algorithm in signature_algorithms:
                            signature_algorithm_int = int(signature_algorithm,16)
                            if signature_algorithm_int in enumSignatureHashClient:
                                sighash_features_client[enumSignatureHashClient.index(signature_algorithm_int)]=1
                            else:
                                logging.warning('Unseen signature hash algo in Clienthello ({}) in file {}'.format(signature_algorithm,pcapfile))
                                sighash_features_client[-1] = 1
                packet_features.extend(sighash_features_client)
            else:
                packet_features.extend(sighash_features_client)
        except AttributeError:
            packet_features.extend(sighash_features_client)

        # 10: ServerHello - LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=2)
            if handshake:
                packet_features.append(int(handshake.length))
            else:
                packet_features.append(0)
        except AttributeError:
            packet_features.append(0)

        # 11: ServerHello - EXTENDED MASTER SECRET
        # ????????????????

        # 12: ServerHello - RENEGOTIATION INFO LENGTH
        try:
            handshake = find_handshake(packet_json.ssl, target_type=2)
            if handshake:
                renegotiation_info_len = 0
                for k,v in handshake._all_fields.items():
                    if 'renegotiation_info' in k:
                        renegotiation_info_len = int(v['ssl.handshake.extension.len'])
                packet_features.append(renegotiation_info_len)
            else:
                packet_features.append(0)
        except AttributeError as e:
            packet_features.append(0)

        # 13,14,15,16: Certificate - NUM_CERT, AVERAGE, MIN, MAX CERTIFICATE LENGTH
        # Attempt 1: use find_handshake()
        try:
            handshake = find_handshake(packet_json.ssl, target_type=11)
        except AttributeError:
            handshake = None
        # Attempt 2: certificate is more difficult to identify. Use hardcode
        try: 
            handshake2 = find_handshake2(packet_json.ssl.value, target_type=11)
        except AttributeError:
            handshake2 = None

        if handshake:
            certificates_length = [int(i) for i in handshake.certificates.certificate_length]
            mean_cert_len = sum(certificates_length)/float(len(certificates_length))
            packet_features.extend([len(certificates_length), mean_cert_len, max(certificates_length), min(certificates_length)])
        elif handshake2:
            certificates_length = handshake2['ssl.handshake.certificates']['ssl.handshake.certificate_length']
            certificates_length = [int(i) for i in certificates_length]
            mean_cert_len = sum(certificates_length)/float(len(certificates_length))
            packet_features.extend([len(certificates_length), mean_cert_len, max(certificates_length), min(certificates_length)])
        else:
            packet_features.extend([0, 0, 0, 0])

        # 17: Certificate - SIGNATURE ALGORITHM
        sighash_features_cert = np.zeros_like(enumSignatureHashCert, dtype='int32') # enumSignatureHashCert is the ref list
        sighash_features_cert = np.concatenate((sighash_features_cert, np.array([0]))) # For unknown dim
        try: 
            handshake = find_handshake(packet_json.ssl, target_type = 11)
        except:
            handshake = None
        try:
            handshake2 = find_handshake2(packet_json.ssl.value, target_type = 11)
        except:
            handshake2 = None

        if handshake:
            certificates = handshake.certificates.certificate_tree
            if type(certificates) != list:
                certificates = [certificates]
            for certificate in certificates:
                algo_id = str(certificate.algorithmIdentifier_element.id)
                if algo_id in enumSignatureHashCert:
                    sighash_features_cert[enumSignatureHashCert.index(algo_id)] = 1
                else:
                    logging.warning('Unseen signature hash algo in Cert ({}) in file {}'.format(algo_id, pcapfile))
                    sighash_features_cert[-1] = 1

        elif handshake2:
            certificates = handshake2['ssl.handshake.certificates']['ssl.handshake.certificate_tree']
            if type(certificates) != list:
                certificates = [certificates]
            for certificate in certificates:
                for k,v in certificate.items():
                    if 'algorithmIdentifier_element' in k:
                        for kk,vv in v.items():
                            if 'algorithm.id' in kk:
                                if str(vv) in enumSignatureHashCert:
                                    sighash_features_cert[enumSignatureHashCert.index(str(vv))] = 1
                                else:
                                    logging.warning('Unseen signature hash algo in Cert ({}) in file {}'.format(str(vv), pcapfile))
                                    sighash_features_cert[-1] = 1

        packet_features.extend(sighash_features_cert)

        # 18: ServerHelloDone - LENGTH
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

    unknown_dim = [0]
    encoded_ciphersuites = [0] * len(enum) + unknown_dim
    if ciphersuites:
        for ciphersuite in ciphersuites:
            if ciphersuite in enum:
                encoded_ciphersuites[enum.index(ciphersuite)] = 1
            else:
                logging.warning('Unseen cipher suite ({})'.format(ciphersuite))
                encoded_ciphersuites[-1] = 1
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
    sample1_packets = [packet for packet in pyshark.FileCapture(sample1, use_json=True)]
    sample2_packets = [packet for packet in pyshark.FileCapture(sample2, use_json=True)]
    sample3_packets = [packet for packet in pyshark.FileCapture(sample3, use_json=True)]
    sample4_packets = [packet for packet in pyshark.FileCapture(sample4, use_json=True)]

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

    sample4_clienthhello = sample4_packets[3]
    sample4_serverhello = sample4_packets[5]
    sample4_cert = sample4_packets[8]
    sample4_serverhellodone = sample4_packets[9]
    sample4_clientkeyexchange_changecipherspec_encryptedhandshakemsg = sample4_packets[11]
    sample4_changecipherspec_encryptedhandshakemsg = sample4_packets[12]
    sample4_appdata_pure = sample4_packets[13]
    sample4_appdata_segment = sample4_packets[27]
    sample4_appdata_double = sample4_packets[15]

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
    output = extractClienthelloLength(sample4_clienthhello)
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
    output = extractClienthelloCiphersuiteAndEncode(sample4_clienthhello, enums)
    expected = [1,1,1,0,1]
    assert output == expected


    print('TEST PASSED!')
    # Test whether all enums are generated

    # Test whether all features are extracted

    # Test whether directory is searched correctly with features extracted 
