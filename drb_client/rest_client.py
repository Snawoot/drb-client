import aiohttp

from . import crypto

async def req_priv_rand(server_url, server_pubkey, timeout=5):
    sess_timeout = aiohttp.ClientTimeout(total=timeout)
    priv, pub = crypto.keygen()
    server_pub = crypto.unmarshall_pubkey(bytes.fromhex(server_pubkey))
    pub_bin = crypto.marshall_pubkey(pub)
    box = crypto.ecies_encrypt(server_pub, pub_bin)

    body = {
        "request": box,
    }
    headers={
        'user-agent': 'drb-client',
    }
    async with aiohttp.ClientSession(timeout=sess_timeout) as session:
        async with session.post(server_url,
                                json=body,
                                headers=headers,
                                allow_redirects=False) as resp:
            res = await resp.json()
    box = res['response']
    return crypto.ecies_decrypt(priv, box)
