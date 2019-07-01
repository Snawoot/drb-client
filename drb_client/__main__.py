#!/usr/bin/env python3

import urllib.request
import json
import pprint
import collections.abc
import hashlib
import hmac
import asyncio
from math import ceil
import os

from . import bn256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import aiohttp

COORD_SIZE = 32

SERVER_ENDPOINT = 'https://drand.cloudflare.com/api/private'
SERVER_PUBKEY = '6302462fa9da0b7c215d0826628ae86db04751c7583097a4902dd2ab827b7c5f21e3510d83ed58d3f4bf3e892349032eb3cd37d88215e601e43f32cbbe39917d5cc2272885f2bad0620217196d86d79da14135aebb8191276f32029f69e2727a5854b21a05642546ebc54df5e6e0d9351ea32efae3cd9f469a0359078d99197c'
TIMEOUT=5

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

def key_from_point(point):
    dh_bin = marshall_pubkey(point)
    backend = default_backend()
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=None,
                backend=backend)
    shared_key = hkdf.derive(dh_bin)
    return shared_key

def ecies_encrypt(recipient_pubkey, msg):
    priv, pub = keygen()
    dh_point = recipient_pubkey.scalar_mul(priv)
    shared_key = key_from_point(dh_point)
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

def ecies_decrypt(privkey, box):
    assert box['ephemeral']['gid'] == 22 # G2
    eph_point = unmarshall_pubkey(bytes.fromhex(box['ephemeral']['point']))
    dh_point = eph_point.scalar_mul(privkey)
    shared_key = key_from_point(dh_point)
    aesgcm = AESGCM(shared_key)
    pt = aesgcm.decrypt(bytes.fromhex(box['nonce']),
                        bytes.fromhex(box['ciphertext']),
                        None)
    return pt

async def req_priv_rand():
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    priv, pub = keygen()
    server_pub = unmarshall_pubkey(bytes.fromhex(SERVER_PUBKEY))
    pub_bin = marshall_pubkey(pub)
    box = ecies_encrypt(server_pub, pub_bin)

    body = {
        "request": box,
    }
    headers={
        'user-agent': 'drb-client',
    }
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(SERVER_ENDPOINT,
                                json=body,
                                headers=headers,
                                allow_redirects=False) as resp:
            res = await resp.json()
    box = res['response']
    return ecies_decrypt(priv, box)

async def amain(loop):
    res = await req_priv_rand()
    print(res)

def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain(loop))

if __name__ == '__main__':
    main()
