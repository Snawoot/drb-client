#!/usr/bin/env python3

import urllib.request
import json
import pprint
import collections.abc
import hashlib
import hmac
from math import ceil
import os

import bn256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

COORD_SIZE = 32

SERVER_ENDPOINT = 'https://drand.cloudflare.com:443/api/private'
SERVER_PUBKEY = '6302462fa9da0b7c215d0826628ae86db04751c7583097a4902dd2ab827b7c5f21e3510d83ed58d3f4bf3e892349032eb3cd37d88215e601e43f32cbbe39917d5cc2272885f2bad0620217196d86d79da14135aebb8191276f32029f69e2727a5854b21a05642546ebc54df5e6e0d9351ea32efae3cd9f469a0359078d99197c'

hash_len = 32
def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def hkdf(length, ikm, salt=b"", info=b""):
    prk = hmac_sha256(salt if len(salt) > 0 else bytes([0]*hash_len), ikm)
    t = b""
    okm = b""
    for i in range(ceil(length / hash_len)):
        t = hmac_sha256(prk, t + info + bytes([1+i]))
        okm += t
    return okm[:length]

def unmarshall_pubkey(pubkey):
    assert len(pubkey) == 4 * COORD_SIZE
    coords = tuple( int.from_bytes(pubkey[n*COORD_SIZE:(n+1) * COORD_SIZE], 'big') for n in range(4) )
    pk = bn256.curve_twist(
        bn256.gfp_2(coords[0], coords[1]),
        bn256.gfp_2(coords[2], coords[3]),
        bn256.gfp_2(0,1))
    assert pk.is_on_curve()
    return pk


def marshall_pubkey(pubkey):
    pubkey.force_affine()
    P = bn256.g2_marshall(pubkey)
    return b''.join(coord.to_bytes() for coord in P)

def keygen():
    priv, pub = bn256.g2_random()
    return priv, pub

def ecies_encrypt(recipient_pubkey, msg):
    priv, pub = keygen()
    dh_point = recipient_pubkey.scalar_mul(priv)
    dh_bin = marshall_pubkey(dh_point)
    shared_key = hkdf(32, dh_bin)
    nonce = os.urandom(12)
    aesgcm = AESGCM(shared_key)
    ct = aesgcm.encrypt(nonce, msg, None)
    return {
        'ephemeral': {
            'gid': 22,
            'point': marshall_pubkey(pub).hex(),
        },
        'nonce': nonce.hex(),
        'ciphertext': ct.hex(),
    }

def make_req_body():
    priv, pub = keygen()
    server_pub = unmarshall_pubkey(bytes.fromhex(SERVER_PUBKEY))
    pub_bin = marshall_pubkey(pub)
    box = ecies_encrypt(server_pub, pub_bin)
    print("box=%s" % repr(box))
    body = {
        "request": box,
    }
    res = json.dumps(body)
    print(res)
    return res.encode('ascii')

def make_req():
    data = make_req_body()
    headers={
        "Content-Type": 'application/json',
        "User-Agent": "curl/7.64.0",
        "Accept": '*/*',
    }
    req = urllib.request.Request(SERVER_ENDPOINT, data=b'', headers=headers)
    try:
        with urllib.request.urlopen(req) as f:
            res = f.read()
    except urllib.error.HTTPError as exc:
        res = exc.read()
    return res

def main():
    print(repr(make_req()))

if __name__ == '__main__':
    main()
