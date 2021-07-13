#!/usr/bin/env python3

import argparse
import paho.mqtt.client as mqtt 
import requests
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.pairinggroup import PairingGroup,ZR,G2,GT
from charm.core.engine.util import objectToBytes,bytesToObject
from Crypto.Cipher import AES
from base64 import b64encode
from datetime import datetime
import pytz
import time
import matplotlib.pyplot as plt

class Enc():
    def __init__(self, groupObj):
        self.util = SecretUtil(groupObj, verbose=False)
        self.group = groupObj

    def cpabe_encrypt(self, pk, M, policy_str):
        policy = self.util.createPolicy(policy_str)
        a_list = self.util.getAttributeList(policy)
        s = self.group.random(ZR)
        shares = self.util.calculateSharesDict(s, policy)
        C = pk['h'] ** s
        C_y, C_y_pr = {}, {}
        for i in shares.keys():
            j = self.util.strip_index(i)
            C_y[i] = pk['g'] ** shares[i]
            C_y_pr[i] = self.group.hash(j, G2) ** shares[i]
        return { 'C_tilde':(pk['e_gg_alpha'] ** s) * M,
                'C':C, 'Cy':C_y, 'Cyp':C_y_pr,
                'policy':policy_str, 'attributes':a_list }

    def encrypt(self, pk, payload, access_policy):
        aes_key = self.group.random(GT)
        aes_key_bytes = self.group.serialize(aes_key)
        encrypted_aes_key = self.cpabe_encrypt(pk, aes_key, access_policy)

        cipher = AES.new(aes_key_bytes[:16], AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(payload.encode())
        encrypted_data_k = ['nonce', 'ciphertext', 'tag']
        encrypted_data_v = [b64encode(x).decode('utf-8') for x in (nonce, ciphertext, tag)]
        encrypted_data = dict(zip(encrypted_data_k, encrypted_data_v))

        return objectToBytes({'encrypted_aes_key': encrypted_aes_key,
            'encrypted_data': encrypted_data}, self.group)

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--host', '-h', required=True)
    parser.add_argument('--topic', '-t', required=True)
    parser.add_argument('--message', '-m', required=True)
    parser.add_argument('--access_policy', '-ap', required=True)
    parser.add_argument('--client_id', '-i')
    args = parser.parse_args()

    mqttBroker = args.host
    topic = args.topic
    msg = str(args.message)
    access_policy = args.access_policy
    client = mqtt.Client(args.client_id)

    PORT = '8000'
    group = PairingGroup('SS512')
    pk = bytesToObject(requests.get('http://' + mqttBroker
        + ':' + PORT + '/pk').content, group)

    enc = Enc(group)

    client.connect(mqttBroker)
    client.publish(topic, enc.encrypt(pk, msg, access_policy))
    print('--------------------------------------------------------------------------------')
    print(datetime.now(pytz.timezone('America/Lima')).strftime("%d/%m/%Y %H:%M:%S"))
    print('msg: ' + str(msg))
    print('topic: ' + topic)
    print('--------------------------------------------------------------------------------')
    client.disconnect()

def performance():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--host', '-h', required=True)
    args = parser.parse_args()

    PORT = '8000'
    group = PairingGroup('SS512')
    enc = Enc(group)
    mqttBroker = args.host
    pk = bytesToObject(requests.get('http://' + mqttBroker
        + ':' + PORT + '/pk').content, group)

    atts = range(1, 21)
    ap_str = ''
    marcas = []
    plt.style.use('fivethirtyeight')
    for i in atts:
        if i < 2:
            ap_str += str(i)
        else:
            ap_str += ' or ' + str(i)
        start = time.time()
        for j in range(20):
            enc.encrypt(pk, 'test', ap_str)
        end = time.time()
        marcas.append((end-start) * 1000/20)
    plt.plot(atts, marcas, color='g', linestyle='--')
    plt.xticks(range(1, 21, 3))
    plt.title('performance encriptacion')
    plt.xlabel('numero de atributos')
    plt.ylabel('tiempo (ms)')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('performance.png')

if __name__ == '__main__':
    main()
    #performance()
