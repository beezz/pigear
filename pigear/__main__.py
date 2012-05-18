import logging

logging.basicConfig(level=logging.DEBUG)
_logger = logging.getLogger(name=__file__)
_logger.addHandler(logging.StreamHandler())

def main():
    from .core import DataHandler, SocketHandler
    _logger.debug("Starting pigear ...")
    print SocketHandler().logdir

main()
