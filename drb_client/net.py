import aiohttp
import collections
from abc import ABC, abstractmethod

from . import crypto

Identity = collections.namedtuple('Identity', ('address', 'pubkey', 'tls'))

class BaseEntropySource(ABC):
    @abstractmethod
    async def get(self):
        """ Get entropy portion """

    @abstractmethod
    async def start(self):
        """ Prepare source """

    @abstractmethod
    async def stop(self):
        """ Shutdown source """

class DrandRESTSource(BaseEntropySource):
    def __init__(self, identity, timeout=5):
        """ Expects Identity instance and timeout in seconds """
        self._server_pubkey = identity.pubkey
        self._url = 'https://%s/api/private' % (identity.address,)
        self._timeout = timeout

    async def start(self):
        """ No async init required """

    async def stop(self):
        """ No async shutdown required """

    async def get(self):
        return await req_priv_rand(self._url, self._server_pubkey, self._timeout)

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
