import asyncio
import aiohttp
import collections
import logging
from abc import ABC, abstractmethod
import time

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

    @abstractmethod
    async def __aenter__(self):
        """ Context manager form for start() """

    @abstractmethod
    async def __aexit__(self, exc_type, exc, tb):
        """ Context manager form for stop() """

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
        self._logger = logging.getLogger(self.__class__.__name__)

    async def start(self):
        """ No async init required """

    async def stop(self):
        """ No async shutdown required """

    async def get(self):
        try:
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
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            self._logger.error("URL[%s]: Request timed out.",
                                   self._server_url)
            raise
        except Exception as exc:
            self._logger.exception("URL[%s]: Got exception: %s",
                                   self._server_url, str(exc))
            raise
        else:
            self._logger.debug("URL[%s]: Delivered entropy.")

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

class PollingSource(BaseEntropySource):
    def __init__(self, sources, mixer, *, quorum=None, period=60, queue_size=5):
        self._sources = list(sources)
        source_count = len(list(sources))
        if not quorum:
            quorum = source_count // 2 + 1
        if quorum > source_count:
            raise RuntimeError("Unreachable quorum: can't reach quorum = %d "
                               "with %d nodes" % (quorum, source_count))
        self._mixer = mixer
        self._quorum = quorum
        self._period = period
        self._queues = [asyncio.Queue(queue_size) for _ in range(source_count)]
        self._workers = []
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.info("Constructed polling entropy source: "
                          "source_count=%d, mixer=%s, period=%.2f, quorum=%d",
                          source_count, mixer.__class__.__name__, period, quorum)

    async def _worker(self, source, queue):
        while True:
            poll_start_time = time.monotonic()
            try:
                entropy = await source.get()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._logger.error("Source failed to respond: %s", str(exc))
            else:
                await queue.put(entropy)
                poll_duration = time.monotonic() - poll_start_time
                sleep_for = max(0, self._period - poll_duration)
                self._logger.debug("Delivered entropy into queue in %.2f seconds."
                                   "Sleeping for %.2f seconds.",
                                   poll_duration, sleep_for)
                await asyncio.sleep(sleep_for)

    async def start(self):
        self._workers.extend(asyncio.ensure_future(self._worker(s, q))
                             for s, q in zip(self._sources, self._queues))
        self._logger.info("Fired %d async poll workers", len(self._sources))

    async def stop(self):
        for worker in self._workers:
            worker.cancel()
        await asyncio.wait(self._workers)
        self._logger.info("Stopped %d async poll workers...", len(self._workers))

    async def get(self):
        tasks = [asyncio.ensure_future(q.get()) for q in self._queues]
        try:
            responses = []
            for fut in asyncio.as_completed(tasks):
                responses.append(await fut)
                if len(responses) >= self._quorum:
                    break
            return self._mixer.mix(responses)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

