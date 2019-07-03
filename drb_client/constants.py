import enum
import logging


class LogLevel(enum.IntEnum):
    debug = logging.DEBUG
    info = logging.INFO
    warn = logging.WARN
    error = logging.ERROR
    fatal = logging.FATAL
    crit = logging.CRITICAL

    def __str__(self):
        return self.name

class EntropySink(enum.Enum):
    stdout = 1
    rndaddentropy = 2
    devrandom = 3

    def __str__(self):
        return self.name
