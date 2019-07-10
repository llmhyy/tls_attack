import os
import json
import pyshark
import logging
import traceback

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

import utils

ciphersuite_db_filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'tlsdb','tlsdb.json')
with open(ciphersuite_db_filepath) as f:
    ciphersuite_db = json.load(f)

components = ['kea', 'auth', 'enc', 'mode', 'hash']
kea = ['NULL', 'RSA', 'DH', 'DHE', 'KRB5', 'PSK', 'ECDH', 'ECDHE', 'SRP_SHA', 'PSK_DHE']
auth = ['NULL', 'RSA', 'DSS', 'KRB5', 'PSK', 'ECDSA', 'SRP_SHA', 'PSK_DHE']
auth_secure = [False, True, False, None, None, True, None, None]
enc =  ['NULL', 'RC4_40', 'RC4_128', 'RC2_40', 'IDEA', 'DES40', 'DES', '3DES_EDE', 'AES_128', 'AES_256', 'CAMELLIA_128', 'CAMELLIA_256', 'SEED', 'ARIA_128', 'CHACHA20']
enc_secure = [False, False, False, False, False, False, False, False, True, True, False, False, False, False, True]
mode = ['NULL', 'CBC', 'GCM', 'CCM', 'POLY1305']
hash = ['NULL', 'MD5', 'SHA', 'SHA256', 'SHA384']
hash_secure = [False, False, False, True, True]
special_auth = ['KRB5', 'PSK', 'PSK_DHE']

def genDec2Vec():
    dec2Vec = {}
    suites = ciphersuite_db['suites']
    for suite_hex, suite_attr in suites.items():
        suite_dec = int(''.join([i[2:] for i in suite_hex.split(',')]), 16)
        suite_vec = []
        for component in components:
            try:
                this_type = getComponentTypeNameFromSuite(suite_attr, component)
            except Exception as e:
                print('Suite hex {}'.format(suite_hex))
                traceback.print_exc()
                raise e

            component_types = globals()[component]
            component_vec = [0] * len(component_types)
            component_vec[component_types.index(this_type)] = 1
            suite_vec.extend(component_vec)

        dec2Vec[suite_dec] = suite_vec

    return dec2Vec

def parseTrafficInDirectory(pcapdir):
    for root, dirs, files in os.walk(pcapdir):
        for f in files:
            if f.endswith('.pcap'):
                try:
                    parsedTraffic = parseTraffic(os.path.join(root, f))
                    if parsedTraffic is None:
                        logging.warning('Pcap file {} does not have a clienthello packet'.format(os.path.join(root,f)))
                        continue
                    yield parsedTraffic
                except Exception:
                    logging.warning('Error: Parsing file {} seems to have an error'.format(os.path.join(root, f)))
                    traceback.print_exc()

def parseTraffic(pcapfile):
    packets_json = pyshark.FileCapture(pcapfile, use_json=True)
    for i, packet in enumerate(packets_json):
        try:
            handshake = utils.find_handshake(packet.ssl, target_type=1)
            if handshake:
                dec_ciphersuites = handshake.ciphersuites.ciphersuite
                aggregatedCiphersuites = getVecAndAggregateAndNormalize(dec_ciphersuites)
                # Safely assume that a traffic session uses the SAME clienthello ciphersuites
                # and we only need to test 1 clienthello
                return aggregatedCiphersuites
        except AttributeError:
            continue

def getVecAndAggregateAndNormalize(dec_ciphersuites):
    vec_ciphersuites = []
    countCiphersuites = 0
    for dec_ciphersuite in dec_ciphersuites:
        try:
            vec_ciphersuites.append(dec2Vec[int(dec_ciphersuite)])
            countCiphersuites += 1
        except KeyError:
            # Unseen decimal representation of cipher suite. Append a zero-filled list instead
            vec_ciphersuites.append([0]*len(dec2Vec[list(dec2Vec.keys())[0]]))
    aggregatedCiphersuites = list(map(sum, zip(*vec_ciphersuites)))
    normalizedCiphersuites = [aggregatedCiphersuite/countCiphersuites for aggregatedCiphersuite in aggregatedCiphersuites]
    return normalizedCiphersuites

def plotFreqByComponentType(data, title, savedir):
    # Base plot
    fig = plt.gcf()
    fig.set_size_inches(15,8)

    ax = plt.gca()

    color_scheme = ['#D33F49', '#D7C0D0', '#EFF0D1', '#77BA99', '#65DEF1']
    labels = []
    legend_artists = []
    component_start_id = 0
    for i,component in enumerate(components):
        component_types = globals()[component]
        # Setting background color for component in axes
        plt.axvspan(component_start_id-0.5, component_start_id+len(component_types)-0.5, facecolor=color_scheme[i], alpha=0.4)
        component_start_id += len(component_types)
        # Setting of color for each component in legend
        legend_artists.append(mpatches.Patch(color=color_scheme[i], alpha=0.4, label=component))
        # Getting the current xticks and setting of xticks
        if i == 0:
            plt.xticks([],[])
        locs, labels = plt.xticks()
        locs = locs.tolist()
        new_locs = locs + list(range(len(locs), len(locs) + len(component_types)))
        new_labels = [label.get_text() for label in labels] + component_types
        plt.xticks(new_locs, new_labels, rotation = 45, ha='right', fontsize=7)
        # Setting of colors of xticks
        component_security_types_varname = component + '_secure'
        if (component_security_types_varname) in globals():
            component_security_types = globals()[component_security_types_varname]
            new_locs, new_labels = plt.xticks()
            for j,component_security_type in enumerate(component_security_types):
                if component_security_type is True:
                    new_labels[len(locs) + j].set_color('green')
                elif component_security_type is False:
                    new_labels[len(locs) + j].set_color('red')
    box = ax.get_position()
    ax.set_position([box.x0, box.y0, box.width * 0.9, box.height])
    ax.legend(handles=legend_artists, loc='center left', bbox_to_anchor=(1, 0.5))
    ax.xaxis.grid(True)
    plt.ylabel('Normalized Frequency')
    plt.ylim(0.0, 1.0)
    plt.title('Normalized frequency of component types for ciphersuites averaged over {} traffic'.format(title))

    # Plot data
    plt.plot(data)
    plt.savefig(os.path.join(savedir,'ciphersuite-freq-by-componenttype({}).png'.format(title)))
    # plt.show()

def tabulateComponentTypesFromCiphersuiteDB():
    component_types = {component:([],[]) for component in components}
    suites = ciphersuite_db['suites']
    for suite_hex, suite_attr in suites.items():
        for component in component_types.keys():
            list_of_names_of_component_types, list_of_security_of_component_types = component_types[component]
            try:
                this_type = getComponentTypeNameFromSuite(suite_attr, component)
                this_security = getComponentTypeSecurityFromSuite(suite_attr, component)
            except Exception as e:
                print('Suite hex {}'.format(suite_hex))
                traceback.print_exc()
                raise e

            if this_type not in list_of_names_of_component_types:
                list_of_names_of_component_types.append(this_type)
                list_of_security_of_component_types.append(this_security)

    for k,v in component_types.items():
        print('Component: ', k)
        print('Name of Component types: ', v[0])
        print('Security level of component types: ', v[1])
        print('# of {} types: {}'.format(k, len(v)))

def getComponentTypeNameFromSuite(suite_attr, component):
    if isinstance(suite_attr[component], list) or suite_attr[component] == 'NULL':
        this_type = 'NULL'
    elif suite_attr[component] in special_auth:
        this_type = suite_attr[component]
    else:
        try:
            this_type = suite_attr[component]['name']
        except Exception as e:
            print('Component {}'.format(component))
            print('Suite attr {}'.format(suite_attr[component]))
            raise e
    return this_type

def getComponentTypeSecurityFromSuite(suite_attr, component):
    try:
        if isinstance(suite_attr[component], list) or suite_attr[component] == 'NULL':
            this_security = False
        elif 'secure' not in suite_attr[component] or suite_attr[component]['secure'] is None:
            this_security = None
        else:    
            this_security = suite_attr[component]['secure']
        
        return this_security
    
    except Exception as e:
        print('Component {}'.format(component))
        print('Suite attr {}'.format(suite_attr[component]))
        raise e

dec2Vec = genDec2Vec()
