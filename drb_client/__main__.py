#!/usr/bin/env python3

import asyncio

import aiohttp

from . import crypto

SERVER_ENDPOINT = 'https://drand.cloudflare.com/api/private'
SERVER_PUBKEY = '6302462fa9da0b7c215d0826628ae86db04751c7583097a4902dd2ab827b7c5f21e3510d83ed58d3f4bf3e892349032eb3cd37d88215e601e43f32cbbe39917d5cc2272885f2bad0620217196d86d79da14135aebb8191276f32029f69e2727a5854b21a05642546ebc54df5e6e0d9351ea32efae3cd9f469a0359078d99197c'
TIMEOUT=5

async def req_priv_rand():
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    priv, pub = crypto.keygen()
    server_pub = crypto.unmarshall_pubkey(bytes.fromhex(SERVER_PUBKEY))
    pub_bin = crypto.marshall_pubkey(pub)
    box = crypto.ecies_encrypt(server_pub, pub_bin)

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
    return crypto.ecies_decrypt(priv, box)

async def amain(loop):
    res = await req_priv_rand()
    print(res.hex())

def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain(loop))

if __name__ == '__main__':
    main()
