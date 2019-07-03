#!/usr/bin/env python3

import sys
import argparse
import asyncio
import logging
import signal
from functools import partial

from sdnotify import SystemdNotifier
import toml
from async_exit_stack import AsyncExitStack

from . import utils
from . import net
from . import crypto
from . import sink


def parse_args():
    parser = argparse.ArgumentParser(
        description="Distributed Randomness Beacon client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("group_config",
                        help="group config")
    parser.add_argument("-v", "--verbosity",
                        help="logging verbosity",
                        type=utils.check_loglevel,
                        choices=utils.LogLevel,
                        default=utils.LogLevel.info)
    parser.add_argument("-l", "--logfile",
                        help="log file location",
                        metavar="FILE")

    poll_group = parser.add_argument_group('poll options')
    poll_group.add_argument("-Q", "--quorum",
                            type=utils.check_positive_int,
                            help="minimal answers required on each poll. "
                            "Default value is (node_count // 2 + 1).")
    poll_group.add_argument("-T", "--period",
                            default=60,
                            type=utils.check_positive_float,
                            help="poll interval for each source")
    poll_group.add_argument("-w", "--timeout",
                            default=4,
                            type=utils.check_positive_float,
                            help="timeout for each request")

    output_group = parser.add_argument_group('output options')
    output_group.add_argument("-O", "--output",
                              type=utils.check_entropysink,
                              choices=sink.EntropySinkEnum,
                              default=sink.EntropySinkEnum.devrandom,
                              help="entropy output")

    return parser.parse_args()


async def amain(args, group_config, loop):  # pragma: no cover
    logger = logging.getLogger('MAIN')

    mixer = crypto.StatefulHKDFEntropyMixer()
    nodes = [net.Identity(I['Address'], I['Key'], I['TLS'])
             for I in group_config["Nodes"]]
    sources = [net.DrandRESTSource(identity, args.timeout)
               for identity in nodes]
    async with AsyncExitStack() as stack:
        await asyncio.gather(*(stack.enter_async_context(source) for source in sources))
        async with net.PollingSource(sources, mixer,
                                     quorum=args.quorum,
                                     period=args.period) as aggregate:
            async with args.output.value(aggregate) as output:

                exit_event = asyncio.Event()
                beat = asyncio.ensure_future(utils.heartbeat())
                sig_handler = partial(utils.exit_handler, exit_event)
                signal.signal(signal.SIGTERM, sig_handler)
                signal.signal(signal.SIGINT, sig_handler)
                notifier = await loop.run_in_executor(None, SystemdNotifier)
                await loop.run_in_executor(None, notifier.notify, "READY=1")
                await exit_event.wait()

                logger.debug("Eventloop interrupted. Shutting down server...")
                await loop.run_in_executor(None, notifier.notify, "STOPPING=1")
                beat.cancel()


def main():  # pragma: no cover
    args = parse_args()
    with utils.AsyncLoggingHandler(args.logfile) as log_handler:
        logger = utils.setup_logger('MAIN', args.verbosity, log_handler)
        for cls in ('PollingSource', 'DrandRESTSource',
                    'StatefulHKDFEntropyMixer', 'StdoutEntropySink',
                    'DevRandomSink', 'RndAddEntropySink'):
            utils.setup_logger(cls, args.verbosity, log_handler)

        with open(args.group_config) as f:
            group_config = toml.load(f)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(amain(args, group_config, loop))
        loop.close()
        logger.info("Server finished its work.")


if __name__ == '__main__':
    main()
