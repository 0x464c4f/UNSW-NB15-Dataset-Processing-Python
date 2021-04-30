#!/usr/bin/env python
__author__ = "Florian Gottwalt"

"""
This script allows to read and cleanse the following 3  network intrusion detection datasets as outlined in paper https://doi.org/10.1016/j.cose.2019.02.008:
- UNSW-NB-2015 dataset https://doi.org/10.26190/5d7ac5b1e8485
- NSL-KDD dataset https://www.unb.ca/cic/datasets/nsl.html
- CIC-IDS2017 dataset https://www.unb.ca/cic/datasets/ids-2017.html
"""
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load dataset / all files which are in that folder


def load_unsw_2015_dataset():
    # Create fast persistent storage that dataset can be loaded faster after initial processing/cleansing
    store = pd.HDFStore('store.h5')
    if not 'dfall' in store:
        folder = os.getcwd()
        filenames = sorted(os.listdir(folder + '\data'))
        headers = ['srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl',
                   'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin',
                   'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'Sjit', 'Djit',
                   'Stime', 'Ltime', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports',
                   'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst',
                   'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
                   'attack_cat', 'label']
        list_ = []
        for filename in filenames:
            print(filename)
            # Load data into data frames
            df = pd.read_csv(folder + '\\data\\' + filename,
                             header=None, names=headers,na_values='-', encoding='utf-8-sig')  # parse_dates=True)
            list_.append(df)

        dfall = pd.DataFrame(pd.concat(list_))


        # Data Cleanup for columns detected as objects as well as for attack categories

        # drop is_ftp_login
        dfall.drop('is_ftp_login',inplace=True, axis=1)

        print('Data cleansing started')

        dfall['sport'] = [bin for bin in cast_exception(dfall['sport'].tolist())]
        dfall['dsport'] = [bin for bin in cast_exception(dfall['dsport'].tolist())]

        dfall['ct_ftp_cmd'] = pd.to_numeric(dfall['ct_ftp_cmd'], errors='coerce', downcast='signed')
        dfall['attack_cat'] = dfall['attack_cat'].str.strip();
        dfall['attack_cat'] = dfall['attack_cat'].replace('Backdoors', 'Backdoor')

        dfall['ct_flw_http_mthd'] = dfall['ct_flw_http_mthd'].fillna(0)
        dfall['ct_ftp_cmd'] = dfall['ct_ftp_cmd'].fillna(0)

        dfall['service'] = dfall['service'].fillna('none')

        # Save data in fast HDF5 storage
        store['dfall'] = dfall
        dfall = convertCatsToNum(dfall)
        return dfall
    else:
        dfall = store['dfall']
        dfall = convertCatsToNum(dfall)
        return dfall

def cast_exception(lst):
    for item in lst:
        try:
            yield int(item)
        except:
            try:
                yield int(item, 16)
            except:
                yield 0


# Convert Categorical data to numerical data
def convertCatsToNum(data):
    data['srcip'] = data['srcip'].astype('category')
    data['srcip_num'] = data['srcip'].cat.codes
    data['dstip'] = data['dstip'].astype('category')
    data['dstip_num'] = data['dstip'].cat.codes
    data['proto'] = data['proto'].astype('category')
    data['proto_num'] = data['proto'].cat.codes
    data['state'] = data['state'].astype('category')
    data['state_num'] = data['state'].cat.codes
    data['service'] = data['service'].astype('category')
    data['service_num'] = data['service'].cat.codes
    data['attack_cat'] = data['attack_cat'].astype('category')
    data['attack_cat_num'] = data['attack_cat'].cat.codes
    data['label'] = data['label'].astype('bool')

    return data


def convert_cats_to_num_nslkkd(data):
    data['attack_cat'] = data['attack_cat'].astype('category')
    data['attack_cat_num'] = data['attack_cat'].cat.codes  # 11 is normal
    data['protocol_type'] = data['protocol_type'].astype('category')
    data['protocol_type_num'] = data['protocol_type'].cat.codes
    data['service'] = data['service'].astype('category')
    data['service'] = data['service'].cat.codes
    data['flag'] = data['flag'].astype('category')
    data['flag'] = data['flag'].cat.codes
    # data['label'] = data['label'].astype('bool')
    return data


def load_nslkdd():
    folder = os.getcwd()
    filenames = sorted(os.listdir(folder + '\\nslkdd'))
    headers = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
               'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
               'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
               'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
               'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
               'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
               'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
               'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
               'attack_cat', 'random', 'label']
    list_ = []
    # Load data into data frames
    df = pd.read_csv(folder + '\\nslkdd\\' + 'KDDTrain+.csv',
                     header=None, names=headers, na_values='?', encoding='utf-8-sig')  # parse_dates=True)
    list_.append(df)

    data = pd.DataFrame(pd.concat(list_))
    data = convert_cats_to_num_nslkkd(data)
    print(data.head())
    print(data.describe())
    print(data.head())
    print(data.dtypes)
    print(data.wrong_fragment.unique())
    print(data.num_outbound_cmds.unique())
    return data

    # Data Cleanup for columns detected as objects as well as for attack categories
    # data['sport'] = pd.to_numeric(data['sport'], errors='coerce', downcast='integer')
    # data['dsport'] = pd.to_numeric(data['dsport'], errors='coerce', downcast='integer')
    # data['ct_ftp_cmd'] = pd.to_numeric(data['ct_ftp_cmd'], errors='coerce', downcast='signed')
    # data['attack_cat'] = data['attack_cat'].str.strip();
    # data['attack_cat'] = data['attack_cat'].replace('Backdoors', 'Backdoor')

def load_cicids():
    store = pd.HDFStore('store.h5')
    if not 'cicids' in store:
        folder = os.getcwd()
        filenames = sorted(os.listdir(folder + '\\CIC2017IDS'))

        df = pd.read_csv(folder + '\\CIC2017IDS\\' + 'Tuesday-WorkingHours.pcap_ISCX.csv',
                         header=0, na_values='?',dtype = {' Destination IP': 'category',' Source IP': 'category','Flow ID': 'category',' Label': 'category'}, encoding='utf-8-sig', parse_dates=True)  # parse_dates=True)
        # print(df.columns)
        # df['srcip'] = df['Source IP'].astype('category')
        # print(df.dtypes)
        # print(df['Label'])
        # print(df['Source IP'])
        # print(df['Destination IP'])
        # print(df['Protocol'])
        # df = df[['Destination IP','Source IP','Protocol','Flow Bytes/s','Label',]]
        return df
    else:
        dfall = store['cicids']
        return dfall

