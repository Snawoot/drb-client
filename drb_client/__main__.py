#!/usr/bin/env python3

import sys
import argparse
import asyncio
import logging
import signal
from functools import partial

from sdnotify import SystemdNotifier

from .constants import LogLevel
from . import utils
from . import net

SERVER_ENDPOINT = 'https://drand.cloudflare.com/api/private'
SERVER_PUBKEY = '6302462fa9da0b7c215d0826628ae86db04751c7583097a4902dd2ab827b7c5f21e3510d83ed58d3f4bf3e892349032eb3cd37d88215e601e43f32cbbe39917d5cc2272885f2bad0620217196d86d79da14135aebb8191276f32029f69e2727a5854b21a05642546ebc54df5e6e0d9351ea32efae3cd9f469a0359078d99197c'

def parse_args():
    parser = argparse.ArgumentParser(
        description="Distributed Randomness Beacon client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("group_config",
                        help="group config")
    parser.add_argument("-v", "--verbosity",
                        help="logging verbosity",
                        type=utils.check_loglevel,
                        choices=LogLevel,
                        default=LogLevel.info)
    parser.add_argument("-l", "--logfile",
                        help="log file location",
                        metavar="FILE")

    poll_group = parser.add_argument_group('poll options')
    poll_group.add_argument("-Q", "--quorum",
                            type=utils.check_positive_int,
                            help="minimal answers required on each poll")
    poll_group.add_argument("-D", "--delay",
                            default=60,
                            type=utils.check_positive_float,
                            help="delay between each poll")
    poll_group.add_argument("-w", "--timeout",
                            default=4,
                            type=utils.check_positive_float,
                            help="timeout for each request")

    return parser.parse_args()


async def amain(args, loop):  # pragma: no cover
    logger = logging.getLogger('MAIN')

    #pool = ConnPool(dst_address=args.dst_address,
    #                dst_port=args.dst_port,
    #                ssl_context=context,
    #                ssl_hostname=ssl_hostname,
    #                timeout=args.timeout,
    #                backoff=args.backoff,
    #                ttl=args.ttl,
    #                size=args.pool_size,
    #                loop=loop)
    #await pool.start()
    #server = Listener(listen_address=args.bind_address,
    #                  listen_port=args.bind_port,
    #                  timeout=args.timeout,
    #                  pool=pool,
    #                  loop=loop)
    #await server.start()
    res = await net.req_priv_rand(SERVER_ENDPOINT, SERVER_PUBKEY)
    print(res.hex())
    logger.info("Server started.")

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
    #await server.stop()
    #await pool.stop()


def main():  # pragma: no cover
    args = parse_args()
    with utils.AsyncLoggingHandler(args.logfile) as log_handler:
        logger = utils.setup_logger('MAIN', args.verbosity, log_handler)
        #utils.setup_logger('Listener', args.verbosity, log_handler)
        #utils.setup_logger('ConnPool', args.verbosity, log_handler)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(amain(args, loop))
        loop.close()
        logger.info("Server finished its work.")


if __name__ == '__main__':
    main()
