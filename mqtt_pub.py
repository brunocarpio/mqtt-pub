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

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--host', '-h', required=True)
parser.add_argument('--topic', '-t', required=True)
parser.add_argument('--message', '-m', required=True)
parser.add_argument('--access_policy', '-ap', required=True)
parser.add_argument('--client_id', '-i')
args = parser.parse_args()

PORT = '8000'
mqttBroker = args.host
topic = args.topic
msg = str(args.message)
access_policy = args.access_policy
client = mqtt.Client(args.client_id)

group = PairingGroup('SS512')
util = SecretUtil(group, verbose=False)

pk = bytesToObject(requests.get('http://'
    + mqttBroker
    + ':'
    + PORT
    + '/pk').content, group)

def cpabe_encrypt(pk, M, policy_str):
    policy = util.createPolicy(policy_str)
    a_list = util.getAttributeList(policy)
    s = group.random(ZR)
    shares = util.calculateSharesDict(s, policy)
    C = pk['h'] ** s
    C_y, C_y_pr = {}, {}
    for i in shares.keys():
        j = util.strip_index(i)
        C_y[i] = pk['g'] ** shares[i]
        C_y_pr[i] = group.hash(j, G2) ** shares[i]
    return { 'C_tilde':(pk['e_gg_alpha'] ** s) * M, 'C':C, 'Cy':C_y, 'Cyp':C_y_pr, 'policy':policy_str, 'attributes':a_list }

def encrypt(payload):
    aes_key = group.random(GT)
    aes_key_bytes = group.serialize(aes_key)
    encrypted_aes_key = cpabe_encrypt(pk, aes_key, access_policy)

    cipher = AES.new(aes_key_bytes[:16], AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(payload.encode())
    encrypted_data_k = ['nonce', 'ciphertext', 'tag']
    encrypted_data_v = [b64encode(x).decode('utf-8') for x in (nonce, ciphertext, tag)]
    encrypted_data = dict(zip(encrypted_data_k, encrypted_data_v))

    return objectToBytes({'encrypted_aes_key': encrypted_aes_key,
        'encrypted_data': encrypted_data}, group)

def main():
    client.connect(mqttBroker)
    client.publish(topic, encrypt(msg))
    print('--------------------------------------------------------------------------------')
    print(datetime.now(pytz.timezone('America/Lima')).strftime("%d/%m/%Y %H:%M:%S"))
    print('msg: ' + str(msg))
    print('topic: ' + topic)
    print('--------------------------------------------------------------------------------')
    client.disconnect()

if __name__ == '__main__':
    main()
