#!/usr/bin/env python3

import urllib.request
import json
import pprint
import collections.abc

import bn256

COORD_SIZE = 32

SERVER_ENDPOINT = 'https://drand.cloudflare.com:443/api/private'
SERVER_PUBKEY = '6302462fa9da0b7c215d0826628ae86db04751c7583097a4902dd2ab827b7c5f21e3510d83ed58d3f4bf3e892349032eb3cd37d88215e601e43f32cbbe39917d5cc2272885f2bad0620217196d86d79da14135aebb8191276f32029f69e2727a5854b21a05642546ebc54df5e6e0d9351ea32efae3cd9f469a0359078d99197c'

def unmarshall_pubkey(pubkey):
    binary = bytes.fromhex(pubkey)
    assert len(binary) == 4 * COORD_SIZE
    coords = tuple( int.from_bytes(binary[n*COORD_SIZE:(n+1) * COORD_SIZE], 'big') for n in range(4) )
    print(SERVER_PUBKEY)
    for n in range(4):
        print(binary[n*COORD_SIZE:(n+1) * COORD_SIZE].hex())
    print(coords)
    pk = bn256.curve_twist(
        bn256.gfp_2(coords[0], coords[1]),
        bn256.gfp_2(coords[2], coords[3]),
        bn256.gfp_2(0,1))
    assert pk.is_on_curve()
    return pk


def marshall_pubkey(pubkey):
    pubkey.force_affine()
    print("pk=", pubkey)
    P = bn256.g2_marshall(pubkey)
    return b''.join(coord.to_bytes() for coord in P).hex()

def keygen():
    priv, pub = bn256.g2_random()
    return priv, pub

def make_req_body():
    priv, pub = keygen()
    server_pub = unmarshall_pubkey(SERVER_PUBKEY)
    pprint.pprint(server_pub)
    body = {
        "request": {
            "ephemeral": {
                "gid": 22,
                "point": marshall_pubkey(pub),
            },
            "nonce": "",
            "ciphertext": ""
        }
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
    req = urllib.request.Request(SERVER_ENDPOINT, data=b'')
    with urllib.request.urlopen(req) as f:
        res = f.read()
    return res

def main():
    print(repr(make_req()))

if __name__ == '__main__':
    main()
