import asyncio
import sys
import logging
import enum
import os
import struct
import importlib
from abc import ABC, abstractmethod

RNDADDENTROPY = 1074287107

class BaseEntropySink(ABC):
    @abstractmethod
    async def start(self):
        """ Start sinking entropy from given source """

    @abstractmethod
    async def stop(self):
        """ Stop entropy sink """

    @abstractmethod
    async def __aenter__(self):
        """ Context manager form for start() """

    @abstractmethod
    async def __aexit__(self, exc_type, exc, tb):
        """ Context manager form for stop() """

class StdoutEntropySink(BaseEntropySink):
    def __init__(self, source, hex=False):
        self._source = source
        self._worker = None
        self._hex = hex
        self._logger = logging.getLogger(self.__class__.__name__)

    def _write(self, data):
        if self._hex:
            print(data.hex())
        else:
            with open(sys.stdout.fileno(), mode='wb', closefd=False) as out:
                out.write(data)
                out.flush()
        length = len(data)
        self._logger.info("Wrote %d bytes of entropy (%d bits)",
                          length, length * 8)

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

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

class DevRandomSink(BaseEntropySink):
    def __init__(self, source):
        self._source = source
        self._worker = None
        self._file = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def _open_file(self):
        return open('/dev/random', 'wb')

    def _close_file(self, f):
        return f.close()

    def _write(self, data):
        self._file.write(data)
        self._file.flush()
        length = len(data)
        self._logger.info("Wrote %d bytes of entropy (%d bits)",
                          length, length * 8)

    async def _serve(self):
        loop = asyncio.get_event_loop()
        while True:
            data = await self._source.get()
            await loop.run_in_executor(None, self._write, data)

    async def start(self):
        loop = asyncio.get_event_loop()
        self._file = await loop.run_in_executor(None, self._open_file)
        self._worker = asyncio.ensure_future(self._serve())

    async def stop(self):
        self._worker.cancel()
        await asyncio.wait((self._worker,))
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._close_file, self._file)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

class RndAddEntropySink(BaseEntropySink):
    def __init__(self, source):
        self._fcntl = importlib.import_module('fcntl')
        self._source = source
        self._worker = None
        self._file = None
        self._logger = logging.getLogger(self.__class__.__name__)

    def _open_file(self):
        return os.open("/dev/random", os.O_WRONLY)

    def _close_file(self, f):
        return os.close(f)

    def _write(self, data):
        try:
            length = len(data)
            S = struct.Struct('@ii%ds' % (length,))
            rand_pool_info = S.pack(length * 8, length, data)
            self._fcntl.ioctl(self._file, RNDADDENTROPY, rand_pool_info)
        except Exception as exc:
            self._logger.exception("Write failed with exception: %s", str(exc))
        else:
            self._logger.info("Wrote %d bytes of entropy (%d bits)",
                              length, length * 8)

    async def _serve(self):
        loop = asyncio.get_event_loop()
        while True:
            data = await self._source.get()
            await loop.run_in_executor(None, self._write, data)

    async def start(self):
        loop = asyncio.get_event_loop()
        self._file = await loop.run_in_executor(None, self._open_file)
        self._worker = asyncio.ensure_future(self._serve())

    async def stop(self):
        self._worker.cancel()
        await asyncio.wait((self._worker,))
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._close_file, self._file)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

class EntropySinkEnum(enum.Enum):
    stdout = StdoutEntropySink
    rndaddentropy = RndAddEntropySink
    devrandom = DevRandomSink

    def __str__(self):
        return self.name
