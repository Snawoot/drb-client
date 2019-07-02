# drb-client

Distributed Randomness Beacon client

Fetches entropy from multiple [drand](https://github.com/dedis/drand) instances, securely mixes responses and outputs to stdout. Suitable for use with [League of Entropy](https://www.cloudflare.com/leagueofentropy/) servers (see Running section).

## Cryptography background

`drb-client` polls list of `drand` servers with given interval and requests private entropy data portion from each one. Communication between `drb-client` and `drand` is protected with regular TLS and with BN256-derived AES256-GCM encryption on top of TLS (this is imposed by `drand` API format).

`drb-client` constructs each output of entropy from at least `quorum` (`-Q` option) distinct inputs. It is assumed at least `node_count - quorum + 1` nodes produce truly unpredictable secure random numbers, so any `quorum` of distinct responses definitely contain at least one truly random input (due to [pigeonhole principle](https://en.wikipedia.org/wiki/Pigeonhole_principle)).

Entropy portions from beacon servers are mixed using stateful HKDF-based mixer. Each sufficient set of random responses is used to produce random output and new salt value for HKDF mixer. Therefore, after successful generation of first output, mixer output becomes unpredictable even if all beacon servers get compromised and start feeding client with biased data.

Default poll interval is 60 seconds and such interval is chosen for a reason. `drand` generates entropy for each response using its `/dev/urandom`. On Linux `urandom` gets reinitialized from `/dev/random` each 1 minute. So there is no reason to fetch random data more often: responses between reinitializations are in functional dependence.

## Installation

```
pip3 install .
```

Requires Python 3.5+

## Running

```
drb-client group.toml
```

You may obtain latest `group.toml` config with list of League of Entropy servers [here](https://github.com/dedis/drand/tree/master/deploy).

Program will start write random bytes to stdout and log messages to stderr. For logging into file see Synopsis section. At this moment stdout is only supported entropy drain.

## Synopsis

```
$ drb-client --help
usage: drb-client [-h] [-v {debug,info,warn,error,fatal}] [-l FILE]
                  [-Q QUORUM] [-T PERIOD] [-w TIMEOUT] [-O]
                  group_config

Distributed Randomness Beacon client

positional arguments:
  group_config          group config

optional arguments:
  -h, --help            show this help message and exit
  -v {debug,info,warn,error,fatal}, --verbosity {debug,info,warn,error,fatal}
                        logging verbosity (default: info)
  -l FILE, --logfile FILE
                        log file location (default: None)

poll options:
  -Q QUORUM, --quorum QUORUM
                        minimal answers required on each poll (default: None)
  -T PERIOD, --period PERIOD
                        poll interval for each source (default: 60)
  -w TIMEOUT, --timeout TIMEOUT
                        timeout for each request (default: 4)

output options:
  -O, --stdout          dump random data into stdout (default: False)
```


## Credits

* [League of Entropy](https://www.cloudflare.com/leagueofentropy/) project
* [drand](https://github.com/dedis/drand) project
* Jack Lloyd for [BN256 implementation for Python](https://github.com/randombit/pairings.py)
