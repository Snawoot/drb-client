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
        self._server_pubkey = crypto.unmarshall_pubkey(bytes.fromhex(identity.pubkey))
        self._server_url = 'https://%s/api/private' % (identity.address,)
        self._timeout = aiohttp.ClientTimeout(total=timeout)

        self._priv, pub = crypto.keygen()
        self._pub_bin = crypto.marshall_pubkey(pub)
        self._headers = {
            'user-agent': 'drb-client',
        }

    async def start(self):
        """ No async init required """

    async def stop(self):
        """ No async shutdown required """

    async def get(self):
        body = {
            "request": crypto.ecies_encrypt(self._server_pubkey, self._pub_bin),
        }
        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.post(self._server_url,
                                    json=body,
                                    headers=self._headers,
                                    allow_redirects=False) as resp:
                res = await resp.json()
        return crypto.ecies_decrypt(self._priv, res['response'])
