import asyncio
import sys
from abc import ABC, abstractmethod

class BaseEntropyDrain(ABC):
    @abstractmethod
    async def start(self):
        """ Start draining entropy from given source """

    @abstractmethod
    async def stop(self):
        """ Stop entropy drain """

class StdoutEntropyDrain(BaseEntropyDrain):
    def __init__(self, source, hex=False):
        self._source = source
        self._worker = None
        self._hex = hex

    def _write(self, data):
        if self._hex:
            print(data.hex())
        else:
            with open(sys.stdout.fileno(), mode='wb', closefd=False) as out:
                out.write(data)
                out.flush()

    async def _serve(self):
        loop = asyncio.get_event_loop()
        while True:
            data = await self._source.get()
            await loop.run_in_executor(None, self._write, data)

    async def start(self):
        self._worker = asyncio.ensure_future(self._serve())

    async def stop(self):
        self._worker.cancel()
        await asyncio.wait((self._worker,))
